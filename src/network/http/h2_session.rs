use crate::network::http::session::Session;
use bytes::Bytes;
use h2::{RecvStream, SendStream, server::SendResponse};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use std::{net::IpAddr, str::FromStr, time::Duration};

pub struct H2Session {
    peer_addr: IpAddr,
    req: http::Request<RecvStream>,
    res: SendResponse<Bytes>,
    res_status: StatusCode,
    resp_headers: HeaderMap,
    resp_body: Bytes,
}

pub struct H2Stream {
    stream: SendStream<Bytes>,
}

impl H2Stream {
    /// Get the HTTP/2 stream ID
    pub fn stream_id(&self) -> u32 {
        self.stream.stream_id().as_u32()
    }

    /// get capacity
    pub fn capacity(&self) -> usize {
        self.stream.capacity()
    }

    /// Request to reserve capacity to send data
    pub fn reserve_capacity(&mut self, size: usize) {
        self.stream.reserve_capacity(size);
    }

    /// Async: wait until the peer grants more capacity
    pub async fn next_capacity(&mut self) -> std::io::Result<usize> {
        use futures_lite::future::poll_fn;
        match poll_fn(|cx| self.stream.poll_capacity(cx)).await {
            Some(res) => {
                res.map_err(|e| std::io::Error::other(format!("failed to poll capacity: {}", e)))
            }
            None => Err(std::io::Error::other(
                "h2 stream capacity == None (reset/closed)",
            )),
        }
    }

    /// Send a chunk of data. If `end_stream` is true, this also ends the stream.
    pub fn send_data(&mut self, data: Bytes, end_stream: bool) -> std::io::Result<()> {
        self.stream
            .send_data(data, end_stream)
            .map_err(|e| std::io::Error::other(format!("failed to send data frame: {e}")))
    }

    /// Send a RST_STREAM with the given reason code.
    pub fn send_reset(&mut self, reason: u32) {
        self.stream.send_reset(reason.into());
    }
}

impl H2Session {
    pub fn new(
        peer_addr: IpAddr,
        req: http::Request<RecvStream>,
        res: SendResponse<Bytes>,
    ) -> Self {
        Self {
            peer_addr,
            req,
            res,
            res_status: StatusCode::OK,
            resp_headers: HeaderMap::new(),
            resp_body: Bytes::new(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Session for H2Session {
    #[inline]
    fn peer_addr(&self) -> &IpAddr {
        &self.peer_addr
    }

    #[inline]
    fn req_method(&self) -> http::Method {
        self.req.method().clone()
    }

    #[inline]
    fn req_method_str(&self) -> Option<&str> {
        Some(self.req.method().as_str())
    }

    #[inline]
    fn req_path(&self) -> String {
        self.req.uri().path().into()
    }

    #[inline]
    fn req_http_version(&self) -> Version {
        self.req.version()
    }

    #[inline]
    fn req_headers(&self) -> http::HeaderMap {
        self.req.headers().clone()
    }

    #[inline]
    fn req_header(&self, header: &HeaderName) -> Option<http::HeaderValue> {
        self.req.headers().get(header).cloned()
    }

    #[cfg(feature = "net-h1-server")]
    #[inline]
    fn req_body(&mut self, _timeout: std::time::Duration) -> std::io::Result<&[u8]> {
        Err(std::io::Error::other(
            "req_body_h1 not supported in H2Session",
        ))
    }

    #[inline]
    async fn req_body_async(&mut self, timeout: Duration) -> Option<std::io::Result<Bytes>> {
        use futures_lite::future::race;
        use glommio::timer::Timer;

        let data_fut = async {
            match self.req.body_mut().data().await {
                Some(Ok(bytes)) => Some(Ok(bytes)),
                Some(Err(e)) => Some(Err(std::io::Error::other(e.to_string()))),
                None => None, // peer ended stream, no more data
            }
        };

        let timeout_fut = async {
            Timer::new(timeout).await;
            Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "req_body_h2 timed out",
            )))
        };

        race(data_fut, timeout_fut).await
    }

    /// Start an HTTP/2 streaming response: send headers now, return a `H2Stream`
    /// so the caller later can push data frames and decide when to end the stream.
    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<H2Stream> {
        let mut builder = http::Response::builder().status(self.res_status);

        {
            // Move headers in (no clones)
            // no Content-Length or Transfer-Encoding for streaming
            let h = builder.headers_mut().ok_or_else(|| {
                std::io::Error::other("failed to get mutable headers from response builder")
            })?;
            h.extend(self.resp_headers.drain());
        }

        let resp = builder
            .body(())
            .map_err(|e| std::io::Error::other(format!("failed to build body response: {e}")))?;

        // more frames will be sent later
        let send = self
            .res
            .send_response(resp, false)
            .map_err(|e| std::io::Error::other(format!("failed to send frame headers: {e}")))?;

        // reset for reuse
        self.res_status = StatusCode::OK;
        self.resp_body = Bytes::new();

        Ok(H2Stream { stream: send })
    }

    #[cfg(all(target_os = "linux", feature = "net-h3-server"))]
    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h3_streaming not supported in H2Session",
        ))
    }

    #[cfg(all(target_os = "linux", feature = "net-h3-server"))]
    #[inline]
    async fn send_h3_data(
        &mut self,
        _chunk: bytes::Bytes,
        _end_stream: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h3_data not supported in H2Session",
        ))
    }

    #[inline]
    fn status_code(&mut self, status: StatusCode) -> &mut Self {
        self.res_status = status;
        self
    }

    #[inline]
    fn header(&mut self, name: HeaderName, value: HeaderValue) -> std::io::Result<&mut Self> {
        self.resp_headers.append(name, value);
        Ok(self)
    }

    #[inline]
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        use http::HeaderValue;
        let header_name = HeaderName::from_str(name).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid header name {}: {}", name, e),
            )
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid header value {}: {}", value, e),
            )
        })?;
        self.resp_headers.append(header_name, header_value);
        Ok(self)
    }

    #[inline]
    fn headers(&mut self, headers: &HeaderMap) -> std::io::Result<&mut Self> {
        for (k, v) in headers {
            self.resp_headers.append(k, v.clone());
        }
        Ok(self)
    }

    #[inline]
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header_str(name, value)?;
        }
        Ok(self)
    }

    #[inline]
    fn body(&mut self, body: Bytes) -> &mut Self {
        self.resp_body = body;
        self
    }

    // end of message: send the response all at once (headers + body)
    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        // Build HEADERS
        let mut builder = http::Response::builder().status(self.res_status);
        {
            let header_map = builder.headers_mut().ok_or_else(|| {
                std::io::Error::other("failed to get mutable headers from response builder")
            })?;
            header_map.extend(self.resp_headers.drain());

            // Add Content-Length when sending a single buffered body
            if !header_map.contains_key(http::header::CONTENT_LENGTH) {
                use http::HeaderValue;
                let len = self.resp_body.len();
                header_map.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len.to_string()).map_err(|e| {
                        std::io::Error::other(format!("invalid content-length {}: {}", len, e))
                    })?,
                );
            }
        }

        // Body is sent as DATA frames by h2 from this Bytes
        let resp = builder
            .body(())
            .map_err(|e| std::io::Error::other(format!("build resp: {e}")))?;

        // Send headers
        let mut send = self
            .res
            .send_response(resp, false)
            .map_err(|e| std::io::Error::other(format!("send headers: {e}")))?;

        // Send body and END_STREAM
        send.send_data(std::mem::take(&mut self.resp_body), true)
            .map_err(|e| std::io::Error::other(format!("send body: {e}")))?;

        // reset for reuse
        self.res_status = StatusCode::OK;
        self.resp_body = Bytes::new();

        Ok(())
    }

    // end of message: send the response (headers + body) asyncronously
    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        use futures_lite::future::poll_fn;
        use std::io;

        // Build HEADERS
        let mut builder = http::Response::builder().status(self.res_status);
        {
            let h = builder
                .headers_mut()
                .ok_or_else(|| io::Error::other("resp builder headers_mut"))?;
            h.extend(self.resp_headers.drain());
            if !h.contains_key(http::header::CONTENT_LENGTH) {
                use http::HeaderValue;
                let len = self.resp_body.len();
                h.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len.to_string())
                        .map_err(|e| io::Error::other(format!("content-length {len}: {e}")))?,
                );
            }
        }
        let resp = builder
            .body(())
            .map_err(|e| io::Error::other(format!("build resp: {e}")))?;

        // Send HEADERS and take the SendStream
        let mut send = self
            .res
            .send_response(resp, false)
            .map_err(|e| io::Error::other(format!("send headers: {e}")))?;

        // Drain BODY with flow control
        let mut body = std::mem::take(&mut self.resp_body);
        let mut end = body.is_empty();

        // Reserve based on body size
        send.reserve_capacity(body.len());

        while !end {
            // Wait until peer/window grants capacity
            let cap = if send.capacity() == 0 {
                match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(n)) => n,
                    Some(Err(e)) => return Err(io::Error::other(format!("poll_capacity: {e}"))),
                    None => return Err(io::Error::other("stream closed while sending")),
                }
            } else {
                send.capacity()
            };

            let n = std::cmp::min(cap, body.len());
            // Split off exactly what we can send now
            let chunk = body.split_to(n);
            end = body.is_empty();

            send.send_data(chunk, end)
                .map_err(|e| io::Error::other(format!("send_data: {e}")))?;

            glommio::yield_if_needed().await;
        }

        // Reset fields for potential reuse (optional)
        self.res_status = http::StatusCode::OK;
        // headers already drained; body already moved
        Ok(())
    }
}
