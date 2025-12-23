use crate::network::http::server::H2Config;
cfg_if::cfg_if! {
    // Glommio runtime (Linux)
    if #[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))] {

        use core::pin::Pin;
        use core::task::{Context, Poll};

        struct IoStream<S>(pub S);

        // Adapt glommio's AsyncRead/AsyncWrite to the tokio::io traits
        // that h2 expects.
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

            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_close(cx)
            }
        }

        pub(crate) async fn serve_h2<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + Send + 'static,
        {
            use crate::network::http::h2_session::H2Session;

            let builder = make_h2_server_builder(config);
            let mut conn: h2::server::Connection<IoStream<S>, bytes::Bytes> = builder
                .handshake(IoStream(stream))
                .await
                .map_err(|e| std::io::Error::other(format!("h2 handshake error: {e}")))?;

            // Per-connection service shared among streams
            let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

            while let Some(r) = conn.accept().await {
                let (request, respond) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        if e.is_io() {
                            // connection-level IO error, just stop this conn
                            return Ok(());
                        }
                        break;
                    }
                };

                let svc_rc = std::rc::Rc::clone(&svc);

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

                    // run the service on this H2 stream
                    let result = service
                        .call(&mut H2Session::new(peer_addr, request, respond))
                        .await;

                    // put service back for the next stream
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

        pub(crate) async fn serve_h1<S, T>(
            mut stream: S,
            _service: T,
            config: &H2Config,
            _peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + Send + 'static,
        {
            use futures_lite::{AsyncReadExt, AsyncWriteExt};
            use std::str;

            let mut buf = vec![0u8; 8192];
            let mut read = 0usize;

            loop {
                let n = stream.read(&mut buf[read..]).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed before full request",
                    ));
                }
                read += n;
                if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if read == buf.len() {
                    buf.resize(buf.len() * 2, 0);
                }
            }

            // Parse request line + headers (minimal)
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut req = httparse::Request::new(&mut headers);
            let status = req.parse(&buf[..read]).map_err(|e| {
                std::io::Error::other(format!("httparse error: {e}"))
            })?;

            let header_len = match status {
                httparse::Status::Complete(len) => len,
                httparse::Status::Partial => {
                    return Err(std::io::Error::other("partial HTTP request"));
                }
            };

            let method = req.method.unwrap_or("GET");
            let path = req.path.unwrap_or("/");
            let version_dbg = match req.version {
                Some(0) => "HTTP/1.0",
                _ => "HTTP/1.1",
            };

            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| str::from_utf8(h.value).ok())
                .unwrap_or("");

            let content_length = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| str::from_utf8(h.value).ok())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            // Read body if present
            let mut body = buf[header_len..read].to_vec();
            while body.len() < content_length {
                let mut chunk = vec![0u8; content_length - body.len()];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }

            let body_str = String::from_utf8_lossy(&body);

            let response_body = format!(
                "Http version: {version_dbg:?}, Echo: {method:?} {host:?} {path:?}\r\nBody: {body_str:?}"
            );

            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: {}\r\n\r\n",
                response_body.len(),
                if config.keep_alive { "keep-alive" } else { "close" },
            );

            stream.write_all(headers.as_bytes()).await?;
            stream.write_all(response_body.as_bytes()).await?;
            stream.flush().await?;

            Ok(())
        }
    }
    else if #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))] {

        pub(crate) async fn serve<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
            is_h1_tunnel: bool
        ) -> std::io::Result<()>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + 'static,
        {
            use crate::network::http::h2_session::H2Session;

            // make h2 server builder
            let builder = make_h2_server_builder(config);

            // Handshake H2 connection
            let mut conn = builder.handshake(stream).await.map_err(|e| {
                std::io::Error::other(format!("h2 handshake error: {e}"))
            })?;

            // One service instance per connection, shared across streams on this conn
            let svc = std::rc::Rc::new(std::cell::RefCell::new(Some(service)));

            // Clone config values needed in the spawned tasks
            let io_timeout = config.io_timeout;
            let max_header_bytes = config.max_header_bytes;
            let max_body_bytes = config.max_body_bytes;

            // Serve multiplexed requests
            loop {
                let svc_rc = std::rc::Rc::clone(&svc);
                match conn.accept().await {
                    Some(Ok((request, respond))) => {
                        tokio::task::spawn_local(async move {
                            let mut service = loop {
                                if let Some(s) = svc_rc.borrow_mut().take() {
                                    break s;
                                }
                                tokio::task::yield_now().await;
                            };

                            use crate::network::http::session::Session;
                            let mut sess = H2Session::new(peer_addr, request, respond);

                            // Run handler
                            let result: std::io::Result<()> = async {
                                if is_h1_tunnel {
                                    sess.enable_h1_over_h2(
                                        io_timeout,
                                        max_header_bytes,
                                        max_body_bytes,
                                    )
                                    .await?;
                                }

                                // call service
                                service
                                    .call(&mut sess)
                                    .await
                                    .map_err(|e| std::io::Error::other(format!("{e}")))?;

                                Ok(())
                            }
                            .await;

                            *svc_rc.borrow_mut() = Some(service); // restore back

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

fn make_h2_server_builder(config: &H2Config) -> h2::server::Builder {
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
