use crate::network::http::server::H2Config;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))] {

        use core::task::{Context, Poll};
        use core::pin::Pin;
        struct IoStream<S>(pub S);

        impl<S: futures_lite::io::AsyncRead + Unpin> tokio::io::AsyncRead for IoStream<S> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                let unfilled = buf.initialize_unfilled();
                match Pin::new(&mut self.0).poll_read(cx, unfilled) {
                    Poll::Ready(Ok(n)) => {
                        unsafe { buf.assume_init(n) };
                        buf.advance(n);
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        impl<S: futures_lite::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IoStream<S> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, data)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_close(cx)
            }
        }

        pub(crate) async fn serve<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + Send + 'static,
        {
            let builder = make_server(config);
            let mut conn: h2::server::Connection<IoStream<S>, bytes::Bytes> = builder
                .handshake(IoStream(stream))
                .await
                .map_err(|e| std::io::Error::other(format!("h2 handshake error: {e}")))?;

            // Share the per-connection service among request tasks
            let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

            while let Some(r) = conn.accept().await {
                let (request, respond) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        if e.is_io() {
                            return Ok(());
                        }
                        break;
                    }
                };

                let svc_rc = std::rc::Rc::clone(&svc);

                glommio::spawn_local(async move {
                    use crate::network::http::h2_session::H2Session;

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
                    let result = service
                        .call(&mut H2Session::new(peer_addr, request, respond))
                        .await;

                    // Put the service back for the next request.
                    *svc_rc.borrow_mut() = Some(service);

                    if let Err(e) = result {
                        eprintln!("h2 service error: {e}");
                    }
                })
                .detach();

                glommio::yield_if_needed().await;
            }

            Ok(())
        }
    }
    else if #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))] {
        pub(crate) async fn serve<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + 'static,
        {
            // make h2 server builder
            let builder = make_server(config);

            // Handshake H2 connection
            let mut conn = builder.handshake(stream).await.map_err(|e| {
                std::io::Error::other(format!("h2 handshake error: {e}"))
            })?;

            // One service instance per connection, shared across streams on this conn
            let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

            // Serve multiplexed requests
            loop {
                let svc_rc = std::rc::Rc::clone(&svc);
                match conn.accept().await {
                    Some(Ok((request, respond))) => {

                        // Each request/response stream runs on the same LocalSet thread
                        tokio::task::spawn_local(async move {
                            use crate::network::http::h2_session::H2Session;

                            // Wait until the connection-level service is available
                            let mut service = loop {
                                if let Some(s) = {
                                    let mut guard = svc_rc.borrow_mut();
                                    guard.take()
                                } {
                                    break s;
                                }
                                tokio::task::yield_now().await;
                            };

                            // run the service
                            let result = service
                                .call(&mut H2Session::new(peer_addr, request, respond))
                                .await;

                            // Put the service back for the next request.
                            *svc_rc.borrow_mut() = Some(service);

                            if let Err(e) = result {
                                eprintln!("h2 service error: {e}");
                            }
                        });
                    }
                    Some(Err(e)) => {
                        eprintln!("accept stream error from {peer_addr}: {e}");
                        break;
                    }
                    None => break, // connection closed
                }
            }
            Ok(())
        }
    }
}

fn make_server(config: &H2Config) -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    if config.enable_connect_protocol {
        builder.enable_connect_protocol();
    }
    builder
        .initial_connection_window_size(config.initial_connection_window_size)
        .initial_window_size(config.initial_window_size)
        .max_concurrent_streams(config.max_concurrent_streams)
        .max_frame_size(config.max_frame_size)
        .max_header_list_size(config.max_header_list_size);
    builder
}
