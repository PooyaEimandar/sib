use crate::network::http::server::H2Config;
use tracing::error;

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
                        error!("h2 service error: {e}");
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

        pub(crate) async fn serve_h1<S, T>(
            mut stream: S,
            mut service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + 'static,
        {
            use crate::network::http::h1_session_async::H1SessionAsync;
            use bytes::Bytes;
            use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};
            use tokio::io::AsyncReadExt;

            let mut buf: Vec<u8> = vec![0u8; 8192];

            loop {
                // read headers
                let mut read: usize = 0;
                loop {
                    let n = stream.read(&mut buf[read..]).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    read += n;

                    if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if read == buf.len() {
                        buf.resize(buf.len() * 2, 0);
                    }
                }

                // parse request line + headers
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);

                let status = req
                    .parse(&buf[..read])
                    .map_err(|e| std::io::Error::other(format!("httparse error: {e}")))?;

                let header_len = match status {
                    httparse::Status::Complete(len) => len,
                    httparse::Status::Partial => return Err(std::io::Error::other("partial HTTP request")),
                };

                let method = req
                    .method
                    .map(|m| Method::from_bytes(m.as_bytes()).unwrap_or(Method::GET))
                    .unwrap_or(Method::GET);

                let uri = req
                    .path
                    .and_then(|p| p.parse::<Uri>().ok())
                    .unwrap_or_else(|| Uri::from_static("/"));

                let version = match req.version {
                    Some(0) => Version::HTTP_10,
                    _ => Version::HTTP_11,
                };

                let mut req_headers = HeaderMap::new();
                for h in req.headers.iter() {
                    let name = HeaderName::from_bytes(h.name.as_bytes()).map_err(std::io::Error::other)?;
                    let value = HeaderValue::from_bytes(h.value).map_err(std::io::Error::other)?;
                    req_headers.append(name, value);
                }

                // keep-alive decision
                let conn_hdr = req_headers
                    .get(header::CONNECTION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_ascii_lowercase();

                let keep_alive = if version == Version::HTTP_11 {
                    conn_hdr != "close"
                } else {
                    conn_hdr == "keep-alive"
                };

                // WS detection BEFORE session creation
                #[cfg(feature = "net-ws-server")]
                let is_ws = crate::network::http::ws::is_h1_ws_upgrade(&method, &req_headers);

                #[cfg(not(feature = "net-ws-server"))]
                let is_ws = false;

                // If WS upgrade: DO NOT read body (service will do ws_accept + ws loop).
                let body_bytes = if is_ws {
                    Bytes::new()
                } else {
                    let content_length = req_headers
                        .get(header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);

                    if content_length > config.max_frame_size as usize {
                        return Err(std::io::Error::other("content-length exceeds max frame size"));
                    }

                    let mut body: Vec<u8> = Vec::with_capacity(content_length);
                    body.extend_from_slice(&buf[header_len..read]);

                    while body.len() < content_length {
                        let need = content_length - body.len();
                        let mut tmp = vec![0u8; need.min(64 * 1024)];
                        let n = stream.read(&mut tmp).await?;
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }

                    Bytes::from(body)
                };

                // create session with is_ws
                let mut session = H1SessionAsync::new(
                    peer_addr,
                    &mut stream,
                    (method,version),
                    uri,
                    (req_headers, body_bytes),
                    keep_alive,
                    is_ws
                );

                #[cfg(feature = "net-ws-server")]
                if is_ws && read > header_len {
                    session.ws_seed(&buf[header_len..read]);
                }

                // delegate to service (service does ws_accept + ws loop if is_ws)
                use crate::network::http::session::Session;

                let r = service.call(&mut session).await;

                if is_ws {
                    // Service owns the socket now; it will run WS loop and end.
                    // If service uses ConnectionAborted("ws done") to signal end, treat it as normal.
                    return match r {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => Ok(()),
                        Err(e) => Err(e),
                    };
                }

                // Normal HTTP error handling
                if let Err(e) = r {
                    error!("h1 service error: {e}");
                    if !session.response_sent() {
                        let _ = session
                            .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Bytes::new())
                            .eom_async()
                            .await;
                    }
                } else if !session.response_sent() {
                    let _ = session
                        .status_code(http::StatusCode::OK)
                        .body(Bytes::new())
                        .eom_async()
                        .await;
                }

                if !session.keep_alive() {
                    return Ok(());
                }
            }
        }

        pub(crate) async fn serve_h2<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
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

            // Serve multiplexed requests
            loop {
                let svc_rc = std::rc::Rc::clone(&svc);
                match conn.accept().await {
                    Some(Ok((request, respond))) => {
                        // Each H2 stream runs on the same LocalSet thread
                        tokio::task::spawn_local(async move {
                            let mut service = loop {
                                if let Some(s) = {
                                    let mut guard = svc_rc.borrow_mut();
                                    guard.take()
                                } {
                                    break s;
                                }
                                tokio::task::yield_now().await;
                            };

                            let result = service
                                .call(&mut H2Session::new(peer_addr, request, respond))
                                .await;

                            *svc_rc.borrow_mut() = Some(service);

                            if let Err(e) = result {
                                error!("h2 service error: {e}");
                            }
                        });
                    }
                    Some(Err(e)) => {
                        error!("accept stream error from {peer_addr}: {e}");
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
