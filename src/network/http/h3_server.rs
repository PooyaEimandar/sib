use crate::network::http::session::HAsyncService;
use tracing::error;

#[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))]
pub(crate) async fn serve<T>(
    connection: quinn::Connection,
    service: T,
    peer_addr: std::net::IpAddr,
) -> std::io::Result<()>
where
    T: HAsyncService + Send + 'static,
{
    let mut h3_conn = match h3::server::builder()
        .build::<h3_quinn::Connection, bytes::Bytes>(h3_quinn::Connection::new(connection))
        .await
    {
        Ok(h) => h,
        Err(e) => {
            error!("h3 handshake failed: {e:?}");
            return Err(std::io::Error::other(format!("h3 handshake failed: {e:?}")));
        }
    };

    let svc = std::rc::Rc::new(service);

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                match resolver.resolve_request().await {
                    Ok((req, stream)) => {
                        let service = std::rc::Rc::clone(&svc);
                        glommio::spawn_local(async move {
                            use crate::network::http::h3_session::H3Session;
                            let result = service
                                .call(&mut H3Session::new(peer_addr, req, stream))
                                .await;

                            if let Err(e) = result {
                                error!("h3 service error: {e}");
                            }
                        })
                        .detach();
                    }
                    Err(e) => {
                        error!("resolve_request: {e:?}");
                    }
                };
            }
            Ok(None) => break,
            Err(e) => {
                error!("h3 accept error: {e:?}");
                break;
            }
        }
        glommio::yield_if_needed().await;
    }
    Ok(())
}

#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
pub(crate) async fn serve<T>(
    connection: quinn::Connection,
    service: T,
    peer_addr: std::net::IpAddr,
) -> std::io::Result<()>
where
    T: HAsyncService + Send + 'static,
{
    // Build h3 connection over quinn (Tokio runtime underneath via h3-quinn)
    let mut h3_conn = match h3::server::builder()
        .build::<h3_quinn::Connection, bytes::Bytes>(h3_quinn::Connection::new(connection))
        .await
    {
        Ok(h) => h,
        Err(e) => {
            error!("h3 handshake failed: {e:?}");
            return Err(std::io::Error::other(format!("h3 handshake failed: {e:?}")));
        }
    };

    let svc = std::rc::Rc::new(service);

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => match resolver.resolve_request().await {
                Ok((req, stream)) => {
                    let service = std::rc::Rc::clone(&svc);
                    tokio::task::spawn_local(async move {
                        use crate::network::http::h3_session::H3Session;
                        let result = service
                            .call(&mut H3Session::new(peer_addr, req, stream))
                            .await;

                        if let Err(e) = result {
                            error!("h3 service error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("resolve_request: {e:?}");
                }
            },
            Ok(None) => break, // graceful close
            Err(e) => {
                error!("h3 accept error: {e:?}");
                break;
            }
        }

        // Cooperative yield to keep the LocalSet responsive
        tokio::task::yield_now().await;
    }

    Ok(())
}
