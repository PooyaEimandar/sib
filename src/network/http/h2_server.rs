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

            let svc = std::rc::Rc::new(service);

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

                let service = std::rc::Rc::clone(&svc);

                glommio::spawn_local(async move {
                    let result = service
                        .call(&mut H2Session::new(peer_addr, request, respond))
                        .await;

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
            _config: &H2Config,
            _peer_addr: std::net::IpAddr,
        ) -> std::io::Result<()>
        where
            S: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + Send + 'static,
        {
            use futures_lite::{AsyncReadExt, AsyncWriteExt};

            // Full HTTP/1.1 request serving is NOT implemented on the glommio runtime.
            // This fallback previously echoed the request back — which both reflected
            // client input and bypassed the service (and therefore any auth / rate
            // limiting wrapped around it). Until a real glommio H1 session is wired to
            // `service`, refuse http/1.1 with 501 rather than serve an unauthenticated
            // echo. Clients should negotiate h2 (the default ALPN protocol) instead.
            //
            // Drain up to the end of headers (bounded) so the peer's write completes,
            // then close. We do not parse or reflect any request content.
            let mut buf = vec![0u8; 8192];
            let mut read = 0usize;
            const MAX_HEADER_BYTES: usize = 64 * 1024;
            loop {
                let n = stream.read(&mut buf[read..]).await?;
                if n == 0 {
                    break;
                }
                read += n;
                if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if read >= MAX_HEADER_BYTES {
                    break;
                }
                if read == buf.len() {
                    buf.resize((buf.len() * 2).min(MAX_HEADER_BYTES), 0);
                }
            }

            let response =
                b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(response).await?;
            stream.flush().await?;

            Ok(())
        }
    }
    else if #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))] {

        pub(crate) async fn serve_h1<S, T>(
            stream: S,
            service: T,
            config: &H2Config,
            peer_addr: std::net::IpAddr,
            shutdown: tokio_util::sync::CancellationToken,
        ) -> std::io::Result<()>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + 'static,
        {
            use crate::network::http::h1_session_async::H1SessionAsync;
            use bytes::Bytes;
            use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};
            use tokio::io::AsyncReadExt;

            let mut stream = IdleIo::new(stream, config.io_timeout);
            let mut buf: Vec<u8> = Vec::with_capacity(8192);

            loop {
                // Check for shutdown before each new request
                if shutdown.is_cancelled() {
                    return Ok(());
                }

                let header_deadline = tokio::time::Instant::now() + config.io_timeout;
                // read headers
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if buf.len() >= config.max_header_list_size as usize {
                        return Err(std::io::Error::other("request headers exceed max header list size"));
                    }

                    let mut tmp = vec![0u8; 8192];
                    let n = tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        r = tokio::time::timeout_at(header_deadline, stream.read(&mut tmp)) => r??
                    };
                    if n == 0 {
                        if buf.is_empty() {
                            return Ok(());
                        }
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                // parse request line + headers
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);

                let status = req
                    .parse(&buf)
                    .map_err(|e| std::io::Error::other(format!("httparse error: {e}")))?;

                let header_len = match status {
                    httparse::Status::Complete(len) => len,
                    httparse::Status::Partial => return Err(std::io::Error::other("partial HTTP request")),
                };

                if header_len > config.max_header_list_size as usize {
                    return Err(std::io::Error::other("request headers exceed max header list size"));
                }
                let method = Method::from_bytes(req.method.unwrap_or("").as_bytes())
                    .map_err(std::io::Error::other)?;

                let uri = req.path.unwrap_or("").parse::<Uri>().map_err(std::io::Error::other)?;

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
                let connection_tokens: Vec<_> = req_headers.get_all(header::CONNECTION).iter()
                    .filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(','))
                    .map(|v| v.trim().to_ascii_lowercase()).collect();
                let keep_alive = config.keep_alive && !connection_tokens.iter().any(|v| v == "close")
                    && (version == Version::HTTP_11 || connection_tokens.iter().any(|v| v == "keep-alive"));
                if req_headers.contains_key(header::TRANSFER_ENCODING) {
                    return Err(std::io::Error::other("Transfer-Encoding is not supported on requests"));
                }
                let content_length = parse_content_length(&req_headers)?;

                // WS detection BEFORE session creation
                #[cfg(feature = "net-ws-server")]
                let is_ws = crate::network::http::ws::is_h1_ws_upgrade(&method, &req_headers);

                #[cfg(not(feature = "net-ws-server"))]
                let is_ws = false;

                // If WS upgrade: DO NOT read body (service will do ws_accept + ws loop).
                let body_bytes = if is_ws {
                    if content_length != 0 { return Err(std::io::Error::other("WebSocket upgrade cannot carry a request body")); }
                    Bytes::new()
                } else {
                    if content_length > config.max_frame_size as usize {
                        return Err(std::io::Error::other("content-length exceeds max frame size"));
                    }

                    let mut body: Vec<u8> = Vec::with_capacity(content_length);
                    let buffered_body_len = (buf.len() - header_len).min(content_length);
                    body.extend_from_slice(&buf[header_len..header_len + buffered_body_len]);

                    while body.len() < content_length {
                        let need = content_length - body.len();
                        let mut tmp = vec![0u8; need.min(64 * 1024)];
                        let n = tokio::select! {
                            _ = shutdown.cancelled() => return Ok(()),
                            r = stream.read(&mut tmp) => r?
                        };
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed before full request body",
                            ));
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }

                    let consumed = header_len + buffered_body_len;
                    buf.drain(..consumed);

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
                if is_ws && buf.len() > header_len {
                    session.ws_seed(&buf[header_len..]);
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
                    // A partial fixed-length response cannot be followed by another
                    // response on this connection (for example after file truncation).
                    if e.kind() == std::io::ErrorKind::ConnectionAborted {
                        return Err(e);
                    }
                    error!("h1 service error: {e}");
                    if session.response_started() && !session.response_sent() {
                        // Part of the response is already on the wire.
                        return Err(e);
                    }
                    if !session.response_sent() {
                        // Headers the handler staged, such as Content-Length, must not frame the 500.
                        session.reset_response();
                        let _ = session
                            .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Bytes::new())
                            .eom_async()
                            .await;
                    }
                } else if !session.response_sent() {
                    if session.response_started() {
                        return Err(std::io::Error::other(
                            "h1 handler returned before finishing its streamed response",
                        ));
                    }
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
            shutdown: tokio_util::sync::CancellationToken,
        ) -> std::io::Result<()>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
            T: crate::network::http::session::HAsyncService + 'static,
        {
            use crate::network::http::h2_session::H2Session;

            // make h2 server builder
            let builder = make_h2_server_builder(config);

            let stream = IdleIo::new(stream, config.io_timeout);
            // Handshake H2 connection
            let mut conn = tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                r = tokio::time::timeout(config.io_timeout, builder.handshake(stream)) => r?
            }
            .map_err(|e| std::io::Error::other(format!("h2 handshake error: {e}")))?;

            let svc = std::rc::Rc::new(service);

            // Own stream tasks for this connection; dropping the connection cancels them.
            let mut tasks = tokio::task::JoinSet::new();
            // Serve multiplexed requests
            loop {
                if shutdown.is_cancelled() {
                    return Ok(());
                }
                let next = tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                    r = conn.accept() => r
                };

                match next {
                    Some(Ok((request, respond))) => {
                        let service = std::rc::Rc::clone(&svc);

                        // Each H2 stream runs on the same LocalSet thread
                        tasks.spawn_local(async move {
                            let result = service
                                .call(&mut H2Session::new(peer_addr, request, respond))
                                .await;

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

fn parse_content_length(headers: &http::HeaderMap) -> std::io::Result<usize> {
    let mut parsed = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let value = value.to_str().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Content-Length")
        })?;
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Content-Length",
            ));
        }
        let len = value.parse::<usize>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Content-Length")
        })?;
        if let Some(prev) = parsed
            && prev != len
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "conflicting Content-Length headers",
            ));
        }
        parsed = Some(len);
    }
    Ok(parsed.unwrap_or(0))
}

// Time out a stalled transport, not a long transfer that keeps making progress.
#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
struct IdleIo<S> {
    inner: S,
    idle: std::time::Duration,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
}
#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
impl<S> IdleIo<S> {
    fn new(inner: S, idle: std::time::Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }
    fn progress(&mut self) {
        self.deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle);
    }
    fn stalled<T>(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<T>> {
        use std::future::Future;
        if self.deadline.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP transport idle timeout",
            )))
        } else {
            std::task::Poll::Pending
        }
    }
}
#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(result) => {
                if buf.filled().len() > before {
                    self.progress();
                }
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Pending => self.stalled(cx),
        }
    }
}
#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(result) => {
                if matches!(result, Ok(n) if n > 0) {
                    self.progress();
                }
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Pending => self.stalled(cx),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.inner).poll_flush(cx) {
            std::task::Poll::Ready(r) => std::task::Poll::Ready(r),
            std::task::Poll::Pending => self.stalled(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.inner).poll_shutdown(cx) {
            std::task::Poll::Ready(r) => std::task::Poll::Ready(r),
            std::task::Poll::Pending => self.stalled(cx),
        }
    }
}

#[cfg(all(test, feature = "rt-tokio", not(feature = "rt-glommio")))]
#[path = "../../../tests/unit/network/http/h2_runtime_tests.rs"]
mod runtime_tests;
