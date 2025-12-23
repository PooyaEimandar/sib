use crate::network::http::session::Session;
use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use std::{net::IpAddr, str::FromStr, time::Duration};

pub struct H3Session {
    peer_addr: IpAddr,
    req: http::Request<()>,
    req_body_max_bytes: usize,
    stream: RequestStream<BidiStream<Bytes>, Bytes>,
    res_status: StatusCode,
    resp_headers: HeaderMap,
    resp_body: Bytes,
}

impl H3Session {
    pub fn new(
        peer_addr: IpAddr,
        req: http::Request<()>,
        stream: RequestStream<BidiStream<Bytes>, Bytes>,
    ) -> Self {
        Self {
            peer_addr,
            req,
            req_body_max_bytes: 4 * 1024 * 1024, // 4MB
            stream,
            res_status: StatusCode::OK,
            resp_headers: HeaderMap::new(),
            resp_body: Bytes::new(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Session for H3Session {
    #[inline]
    fn peer_addr(&self) -> &IpAddr {
        &self.peer_addr
    }

    #[inline]
    fn req_host(&self) -> Option<(String, Option<u16>)> {
        // Prefer :authority (exposed as URI authority)
        if let Some(a) = self.req.uri().authority()
            && let Some(x) = super::server::parse_authority(a.as_str())
        {
            return Some(x);
        }
        // Fallback to Host header if a client sent one
        if let Some(hv) = self.req.headers().get(http::header::HOST)
            && let Ok(s) = hv.to_str()
            && let Some(x) = super::server::parse_authority(s.trim())
        {
            return Some(x);
        }
        None
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
    fn req_query(&self) -> String {
        self.req.uri().query().unwrap_or("").into()
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
            "req_body_h1 is not supported in H2Session",
        ))
    }

    #[inline]
    async fn req_body_async(&mut self, timeout: Duration) -> Option<std::io::Result<Bytes>> {
        use futures_lite::future::race;
        use std::time::Instant;

        let deadline = Instant::now() + timeout;
        let mut out = bytes::BytesMut::with_capacity(self.req_body_max_bytes);

        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "body timeout",
                )));
            }

            // Read future
            let read_fut = async {
                match self.stream.recv_data().await {
                    Ok(Some(mut buf)) => {
                        let bytes = buf.copy_to_bytes(buf.remaining());
                        Some(Ok(bytes))
                    }
                    Ok(None) => None, // EOS
                    Err(e) => Some(Err(std::io::Error::other(e.to_string()))),
                }
            };

            // Timeout future
            cfg_if::cfg_if! {
                if #[cfg(all(target_os = "linux", feature = "rt-glommio"))] {
                    let timeout_fut = async {
                        glommio::timer::Timer::new(remain).await;
                        Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "req_body_h3 timed out",
                        )))
                    };
                } else if #[cfg(feature = "rt-tokio")] {
                    let timeout_fut = async {
                        tokio::time::sleep(remain).await;
                        Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "req_body_h3 timed out",
                        )))
                    };
                } else {
                    compile_error!("Enable either `rt-glommio` (Linux) or `rt-tokio` to use req_body_async.");
                }
            }

            // read with timeout
            match race(read_fut, timeout_fut).await {
                Some(Ok(chunk)) => {
                    // Enforce max body size
                    if out.len() + chunk.len() > self.req_body_max_bytes {
                        // Stop the peer from sending more
                        let _ = self
                            .stream
                            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                        return Some(Err(std::io::Error::other("payload too large")));
                    }
                    out.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Some(Err(e)), // read error OR timeout
                None => break,                       // EOS
            }

            // Cooperative yield per RT
            cfg_if::cfg_if! {
                if #[cfg(all(target_os = "linux", feature = "rt-glommio"))] {
                    glommio::yield_if_needed().await;
                } else if #[cfg(feature = "rt-tokio")] {
                    tokio::task::yield_now().await;
                }
            }
        }

        Some(Ok(out.freeze()))
    }

    #[cfg(feature = "net-h2-server")]
    async fn enable_h1_over_h2(
        &mut self,
        timeout: std::time::Duration,
        max_header_bytes: usize,
        max_body_bytes: usize,
    ) -> std::io::Result<()> {
        Err(io::Error::other(
            "enable_h1_over_h2 is not supported in H3Session",
        ))
    }

    #[cfg(any(feature = "net-h1-server", feature = "net-h2-server"))]
    fn start_h1_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h1_streaming is not supported in H3Session",
        ))
    }

    #[cfg(feature = "net-h2-server")]
    /// Start an HTTP/2 streaming response: send headers now, return a `HStream`
    /// so the caller later can push data frames and decide when to end the stream.
    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::HStream> {
        Err(std::io::Error::other(
            "start_h2_streaming is not supported in H3Session",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        // Build response head from current status + accumulated headers
        let mut res = http::Response::builder().status(self.res_status);
        for (k, v) in self.resp_headers.iter() {
            res = res.header(k, v);
        }

        // Send only headers (no body, no FIN)
        self.stream
            .send_response(res.body(()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid H3 response: {e}"),
                )
            })?)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    #[cfg(any(feature = "net-h1-server", feature = "net-h2-server"))]
    fn send_h1_data(&mut self, _chunk: &[u8], _end_stream: bool) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h1_data is not supported in H3Session",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn send_h3_data(&mut self, chunk: bytes::Bytes, end_stream: bool) -> std::io::Result<()> {
        self.stream
            .send_data(chunk)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if end_stream {
            self.stream
                .finish()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    #[inline]
    fn write_all_eom(&mut self, _status: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "write_all_eom is not supported in H3Session",
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

    // end of message: send the response (headers + body)
    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("eom is not supported in H3Session"))
    }

    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        // Build and send head
        let mut res = http::Response::builder().status(self.res_status);
        for (k, v) in self.resp_headers.iter() {
            res = res.header(k, v);
        }
        self.stream
            .send_response(res.body(()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid H3 response: {e}"),
                )
            })?)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Send body
        let body = std::mem::take(&mut self.resp_body);
        if !body.is_empty() {
            self.stream
                .send_data(body)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }

        // Finish H3 stream
        self.stream
            .finish()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
