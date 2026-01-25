use crate::network::http::session::Session;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header};
use std::net::IpAddr;

#[cfg(feature = "net-ws-server")]
use crate::network::http::ws;

/// Async HTTP/1.x session
pub struct H1SessionAsync<'a, S> {
    peer: IpAddr,

    // request
    method: Method,
    req_body: Bytes,
    req_headers: HeaderMap,
    uri: Uri,
    version: Version,

    // response
    rsp_body: Bytes,
    rsp_headers: HeaderMap,
    rsp_status: StatusCode,

    // connection state
    keep_alive: bool,
    sent: bool,

    // streaming state (HTTP/1.1 chunked)
    h1_streaming_headers_sent: bool,
    h1_streaming: bool,

    // underlying transport
    stream: &'a mut S,

    #[cfg(feature = "net-ws-server")]
    ws_scratch: bytes::BytesMut,

    #[cfg(feature = "net-ws-server")]
    is_ws: bool,
}

impl<'a, S> H1SessionAsync<'a, S> {
    #[allow(unused_variables)]
    pub fn new(
        peer: IpAddr,
        stream: &'a mut S,
        method_version: (Method, Version),
        uri: Uri,
        req: (HeaderMap, Bytes),
        keep_alive: bool,
        is_ws: bool,
    ) -> Self {
        Self {
            peer,
            stream,
            method: method_version.0,
            uri,
            version: method_version.1,
            req_headers: req.0,
            req_body: req.1,

            rsp_body: Bytes::new(),
            rsp_headers: HeaderMap::new(),
            rsp_status: StatusCode::OK,

            keep_alive,
            sent: false,

            h1_streaming_headers_sent: false,
            h1_streaming: false,

            #[cfg(feature = "net-ws-server")]
            ws_scratch: bytes::BytesMut::new(),

            #[cfg(feature = "net-ws-server")]
            is_ws,
        }
    }

    #[inline]
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    #[inline]
    pub fn response_sent(&self) -> bool {
        self.sent
    }

    fn write_blocking(&mut self, data: &[u8]) -> std::io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| std::io::Error::other("H1SessionAsync requires a Tokio runtime"))?;

        // block_in_place is only valid on multi-thread runtime.
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
            return Err(std::io::Error::other(
                "H1SessionAsync blocking writes are not supported on Tokio current-thread runtime. \
                 Use the async APIs (eom_async / streaming async) or run a multi-thread runtime.",
            ));
        }

        tokio::task::block_in_place(|| {
            handle.block_on(async {
                self.stream.write_all(data).await?;
                self.stream.flush().await?;
                Ok::<(), std::io::Error>(())
            })
        })
    }

    #[inline]
    fn response_must_not_have_body(&self) -> bool {
        let code = self.rsp_status.as_u16();
        self.method == Method::HEAD
            || (100..200).contains(&code)
            || self.rsp_status == StatusCode::NO_CONTENT
            || self.rsp_status == StatusCode::NOT_MODIFIED
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    pub fn ws_seed(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.ws_scratch.extend_from_slice(data);
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<'a, S> Session for H1SessionAsync<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    #[inline]
    fn peer_addr(&self) -> &IpAddr {
        &self.peer
    }

    #[inline]
    fn req_host(&self) -> Option<(String, Option<u16>)> {
        let v = self.req_headers.get(header::HOST)?.to_str().ok()?;
        crate::network::http::server::parse_authority(v)
    }

    #[inline]
    fn req_method(&self) -> Method {
        self.method.clone()
    }

    #[inline]
    fn req_method_str(&self) -> Option<&str> {
        Some(self.method.as_str())
    }

    #[inline]
    fn req_path(&self) -> String {
        self.uri.path().to_string()
    }

    #[inline]
    fn req_query(&self) -> String {
        self.uri.query().map(|q| q.to_string()).unwrap_or_default()
    }

    #[inline]
    fn req_http_version(&self) -> Version {
        self.version
    }

    #[inline]
    fn req_headers(&self) -> HeaderMap {
        self.req_headers.clone()
    }

    #[inline]
    fn req_header(&self, header: &HeaderName) -> Option<HeaderValue> {
        self.req_headers.get(header).cloned()
    }

    #[inline]
    fn req_body(&mut self, _timeout: std::time::Duration) -> std::io::Result<&[u8]> {
        Ok(&self.req_body)
    }

    #[inline]
    async fn req_body_async(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Option<std::io::Result<Bytes>> {
        Some(Ok(self.req_body.clone()))
    }

    #[inline]
    fn write_all_eom(&mut self, status: &[u8]) -> std::io::Result<()> {
        self.status_code(StatusCode::from_bytes(status).map_err(std::io::Error::other)?);
        self.eom()
    }

    #[inline]
    fn status_code(&mut self, code: StatusCode) -> &mut Self {
        self.rsp_status = code;
        self
    }

    #[inline]
    fn start_h1_streaming(&mut self) -> std::io::Result<()> {
        // If we’re on a current-thread runtime, this returns an error instead of panicking.
        // Prefer calling the handler using async + send_h1_data_async() via the service layer
        // or switch the server runtime to multi-thread
        if self.sent {
            return Err(std::io::Error::other("response already sent"));
        }
        if self.h1_streaming {
            return Ok(());
        }
        self.h1_streaming = true;
        self.rsp_headers.remove(header::CONTENT_LENGTH);
        self.rsp_headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );

        if !self.keep_alive {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        } else if self.version == Version::HTTP_10 {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        }

        let ver = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        let reason = self.rsp_status.canonical_reason().unwrap_or("OK");

        let mut head = String::with_capacity(256);
        head.push_str(ver);
        head.push(' ');
        head.push_str(self.rsp_status.as_str());
        head.push(' ');
        head.push_str(reason);
        head.push_str("\r\n");

        for (k, v) in self.rsp_headers.iter() {
            head.push_str(k.as_str());
            head.push_str(": ");
            head.push_str(v.to_str().unwrap_or_default());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");

        self.write_blocking(head.as_bytes())?;
        self.h1_streaming_headers_sent = true;
        Ok(())
    }

    /// Async header flush for H1 streaming (chunked).
    async fn start_h1_streaming_async(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        if self.sent {
            return Err(std::io::Error::other("response already sent"));
        }
        if self.h1_streaming {
            return Ok(());
        }

        self.h1_streaming = true;
        self.h1_streaming_headers_sent = false;

        // Switch to chunked mode
        self.rsp_headers.remove(header::CONTENT_LENGTH);
        self.rsp_headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );

        // Connection header
        if !self.keep_alive {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        } else if self.version == Version::HTTP_10 {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        }

        // Status line + headers
        let ver = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        let reason = self.rsp_status.canonical_reason().unwrap_or("OK");

        let mut head = String::with_capacity(256);
        head.push_str(ver);
        head.push(' ');
        head.push_str(self.rsp_status.as_str());
        head.push(' ');
        head.push_str(reason);
        head.push_str("\r\n");

        for (k, v) in self.rsp_headers.iter() {
            head.push_str(k.as_str());
            head.push_str(": ");
            head.push_str(v.to_str().unwrap_or_default());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");

        self.stream.write_all(head.as_bytes()).await?;
        self.stream.flush().await?;
        self.h1_streaming_headers_sent = true;
        Ok(())
    }

    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::H2Stream> {
        Err(std::io::Error::other(
            "start_h2_streaming is not supported in H1SessionAsync",
        ))
    }

    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h3_streaming is not supported in H1SessionAsync",
        ))
    }

    #[inline]
    fn send_h1_data(&mut self, data: &[u8], last: bool) -> std::io::Result<()> {
        if self.sent {
            return Err(std::io::Error::other("response already sent"));
        }
        if !self.h1_streaming {
            return Err(std::io::Error::other(
                "start_h1_streaming() must be called before send_h1_data()",
            ));
        }
        if !self.h1_streaming_headers_sent {
            return Err(std::io::Error::other(
                "internal error: streaming headers not sent",
            ));
        }

        // Chunk frame: "<HEX>\r\n<data>\r\n"
        if !data.is_empty() {
            use core::fmt::Write;
            let mut s = heapless::String::<32>::new();
            write!(&mut s, "{:X}\r\n", data.len()).map_err(std::io::Error::other)?;
            self.write_blocking(s.as_bytes())?;
            self.write_blocking(data)?;
            self.write_blocking(b"\r\n")?;
        }

        if last {
            self.write_blocking(b"0\r\n\r\n")?;
            self.sent = true;
        }

        Ok(())
    }

    /// Async chunk send. If `last` is true, sends terminating chunk.
    async fn send_h1_data_async(&mut self, data: &[u8], last: bool) -> std::io::Result<()> {
        use core::fmt::Write as _;
        use tokio::io::AsyncWriteExt;

        if self.sent {
            return Err(std::io::Error::other("response already sent"));
        }
        if !self.h1_streaming {
            return Err(std::io::Error::other(
                "start_h1_streaming() must be called before send_h1_data()",
            ));
        }
        if !self.h1_streaming_headers_sent {
            // If someone toggled state without emitting headers, fix it
            self.start_h1_streaming_async().await?;
        }

        // Chunk frame: "<HEX>\r\n<data>\r\n"
        if !data.is_empty() {
            let mut s = heapless::String::<32>::new();
            write!(&mut s, "{:X}\r\n", data.len()).map_err(std::io::Error::other)?;
            self.stream.write_all(s.as_bytes()).await?;
            self.stream.write_all(data).await?;
            self.stream.write_all(b"\r\n").await?;
        }

        if last {
            self.stream.write_all(b"0\r\n\r\n").await?;
            self.stream.flush().await?;
            self.sent = true;
        } else {
            self.stream.flush().await?;
        }

        Ok(())
    }

    #[inline]
    async fn send_h3_data(&mut self, _chunk: Bytes, _end_stream: bool) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h3_data is not supported in H1SessionAsync",
        ))
    }

    #[inline]
    fn header(&mut self, key: HeaderName, val: HeaderValue) -> std::io::Result<&mut Self> {
        self.rsp_headers.insert(key, val);
        Ok(self)
    }

    #[inline]
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(std::io::Error::other)?;
        let header_value = HeaderValue::from_str(value).map_err(std::io::Error::other)?;
        self.rsp_headers.insert(header_name, header_value);
        Ok(self)
    }

    #[inline]
    fn headers(&mut self, headers: &HeaderMap) -> std::io::Result<&mut Self> {
        for (k, v) in headers.iter() {
            self.rsp_headers.insert(k.clone(), v.clone());
        }
        Ok(self)
    }

    #[inline]
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val.iter() {
            let header_name =
                HeaderName::from_bytes(name.as_bytes()).map_err(std::io::Error::other)?;
            let header_value = HeaderValue::from_str(value).map_err(std::io::Error::other)?;
            self.rsp_headers.insert(header_name, header_value);
        }
        Ok(self)
    }

    #[inline]
    fn body(&mut self, body: Bytes) -> &mut Self {
        self.rsp_body = body;
        self
    }

    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        if self.sent {
            return Err(std::io::Error::other("response already sent"));
        }

        if self.h1_streaming {
            if !self.h1_streaming_headers_sent {
                // will error (not panic) on current-thread runtime
                self.start_h1_streaming()?;
            }
            self.write_blocking(b"0\r\n\r\n")?;
            self.sent = true;
            return Ok(());
        }

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| std::io::Error::other("H1SessionAsync requires a Tokio runtime"))?;

        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
            return Err(std::io::Error::other(
                "H1SessionAsync::eom() (sync) is not supported on Tokio current-thread runtime; \
                 use eom_async().await or run a multi-thread runtime.",
            ));
        }

        tokio::task::block_in_place(|| handle.block_on(async { self.eom_async().await }))
    }

    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        // If the response MUST NOT have a body, force empty body and Content-Length: 0
        if self.response_must_not_have_body() {
            self.rsp_body = Bytes::new();
            self.rsp_headers.remove(header::TRANSFER_ENCODING);
            self.rsp_headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        } else {
            // Ensure Content-Length cause we’re not doing chunked responses here
            if !self.rsp_headers.contains_key(header::CONTENT_LENGTH) {
                let len = self.rsp_body.len().to_string();
                self.rsp_headers.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len).map_err(std::io::Error::other)?,
                );
            }
        }

        // Connection header
        if !self.keep_alive {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        } else if self.version == Version::HTTP_10 {
            self.rsp_headers
                .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        }

        let ver = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        let reason = self.rsp_status.canonical_reason().unwrap_or("OK");

        let mut head = String::with_capacity(256);
        head.push_str(ver);
        head.push(' ');
        head.push_str(self.rsp_status.as_str());
        head.push(' ');
        head.push_str(reason);
        head.push_str("\r\n");

        for (k, v) in self.rsp_headers.iter() {
            head.push_str(k.as_str());
            head.push_str(": ");
            head.push_str(v.to_str().unwrap_or_default());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");

        self.stream.write_all(head.as_bytes()).await?;
        if !self.rsp_body.is_empty() {
            self.stream.write_all(&self.rsp_body).await?;
        }
        self.stream.flush().await?;
        self.sent = true;
        Ok(())
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn is_ws(&self) -> bool {
        self.is_ws
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_accept(&mut self) -> io::Result<()> {
        Err(std::io::Error::other(
            "ws_accept is not implemented for H1SessionAsync, use ws_accept_async instead",
        ))
    }

    #[cfg(feature = "net-ws-server")]
    async fn ws_accept_async(&mut self) -> std::io::Result<()> {
        use crate::network::http::ws;

        let key = self
            .req_headers
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| std::io::Error::other("missing sec-websocket-key"))?;

        let accept = ws::sec_websocket_accept(key)?;
        // You already have response builder primitives; simplest:
        self.status_code(http::StatusCode::SWITCHING_PROTOCOLS);
        self.header(
            http::header::UPGRADE,
            http::HeaderValue::from_static("websocket"),
        )?;
        self.header(
            http::header::CONNECTION,
            http::HeaderValue::from_static("Upgrade"),
        )?;
        self.header(
            http::header::SEC_WEBSOCKET_ACCEPT,
            http::HeaderValue::from_str(&accept).map_err(std::io::Error::other)?,
        )?;

        // End response headers with empty body
        self.body(bytes::Bytes::new());
        self.eom_async().await?;

        self.is_ws = true;
        Ok(())
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_read(&mut self) -> io::Result<(crate::network::http::ws::OpCode, &[u8], bool)> {
        Err(std::io::Error::other(
            "ws_read is not implemented for H1SessionAsync, use ws_read_async instead",
        ))
    }

    #[cfg(feature = "net-ws-server")]
    async fn ws_read_async(&mut self) -> std::io::Result<(ws::OpCode, bytes::Bytes, bool)> {
        use crate::network::http::ws;
        if !self.is_ws {
            return Err(std::io::Error::other(
                "ws_read_async before ws_accept_async",
            ));
        }
        ws::ws_read_from_io(&mut self.stream, &mut self.ws_scratch, 1 << 20).await
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_write(
        &mut self,
        _op: crate::network::http::ws::OpCode,
        _payload: &[u8],
        _fin: bool,
    ) -> io::Result<()> {
        Err(std::io::Error::other(
            "ws_write is not implemented for H1SessionAsync, use ws_write_async instead",
        ))
    }

    #[cfg(feature = "net-ws-server")]
    async fn ws_write_async(
        &mut self,
        op: ws::OpCode,
        payload: bytes::Bytes,
        fin: bool,
    ) -> std::io::Result<()> {
        use crate::network::http::ws;
        if !self.is_ws {
            return Err(std::io::Error::other(
                "ws_write_async before ws_accept_async",
            ));
        }
        ws::ws_write_to_io(&mut self.stream, op, payload, fin).await
    }

    #[cfg(feature = "net-ws-server")]
    async fn ws_close_async(&mut self, reason: Option<bytes::Bytes>) -> std::io::Result<()> {
        use crate::network::http::ws;
        let payload = reason.unwrap_or_else(|| ws::close_payload(1000, "bye"));
        let _ = self.ws_write_async(ws::OpCode::Close, payload, true).await;
        Ok(())
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_close(&mut self, _reason: Option<&[u8]>) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_close is not implemented for H1SessionAsync",
        ))
    }
}
