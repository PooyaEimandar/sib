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

    // Share the per-connection service among request tasks
    let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

    loop {
        let svc_rc = std::rc::Rc::clone(&svc);
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                match resolver.resolve_request().await {
                    Ok((req, stream)) => {
                        glommio::spawn_local(async move {
                            let mut service = loop {
                                if let Some(s) = {
                                    let mut guard = svc_rc.borrow_mut();
                                    guard.take()
                                } {
                                    break s;
                                }
                                glommio::yield_if_needed().await;
                            };

                            // run the service
                            use crate::network::http::h3_session::H3Session;
                            let result = service
                                .call(&mut H3Session::new(peer_addr, req, stream))
                                .await;

                            // Put the service back for the next request.
                            *svc_rc.borrow_mut() = Some(service);

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

    // Shared per-connection service among request tasks (kept on the same LocalSet thread)
    let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

    loop {
        let svc_rc = std::rc::Rc::clone(&svc);

        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                match resolver.resolve_request().await {
                    Ok((req, stream)) => {
                        tokio::task::spawn_local(async move {
                            // Spin-yield until we can take the service (single owner at a time)
                            let mut service = loop {
                                if let Some(s) = {
                                    let mut guard = svc_rc.borrow_mut();
                                    guard.take()
                                } {
                                    break s;
                                }
                                tokio::task::yield_now().await;
                            };

                            // Run the service
                            use crate::network::http::h3_session::H3Session;
                            let result = service
                                .call(&mut H3Session::new(peer_addr, req, stream))
                                .await;

                            // Put the service back for the next request
                            *svc_rc.borrow_mut() = Some(service);

                            if let Err(e) = result {
                                error!("h3 service error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("resolve_request: {e:?}");
                    }
                }
            }
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
