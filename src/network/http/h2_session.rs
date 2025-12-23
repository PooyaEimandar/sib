use crate::network::http::session::Session;
use bytes::Bytes;
use h2::{RecvStream, SendStream, server::SendResponse};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use std::{net::IpAddr, str::FromStr, time::Duration};

struct H1Parsed {
    method: http::Method,
    path: String,
    query: String,
    version: http::Version,
    headers: http::HeaderMap,
    host: Option<(String, Option<u16>)>,
    body: bytes::Bytes,
    body_taken: bool,
}

pub struct H2Session {
    peer_addr: IpAddr,
    req: http::Request<RecvStream>,
    res: SendResponse<Bytes>,
    res_status: StatusCode,
    resp_headers: HeaderMap,
    resp_body: Bytes,
    // H1-over-H2
    h1_stream: Option<HStream>,
    h1_req: Option<H1Parsed>,
}

pub struct HStream {
    stream: SendStream<Bytes>,
}

impl HStream {
    pub fn stream_id(&self) -> u32 {
        self.stream.stream_id().as_u32()
    }

    pub fn capacity(&self) -> usize {
        self.stream.capacity()
    }

    pub fn reserve_capacity(&mut self, size: usize) {
        self.stream.reserve_capacity(size);
    }

    pub async fn next_capacity(&mut self) -> std::io::Result<usize> {
        use futures_lite::future::poll_fn;
        match poll_fn(|cx| self.stream.poll_capacity(cx)).await {
            Some(res) => {
                res.map_err(|e| std::io::Error::other(format!("failed to poll capacity: {e}")))
            }
            None => Err(std::io::Error::other(
                "h2 stream capacity == None (reset/closed)",
            )),
        }
    }

    pub fn send_data(&mut self, data: Bytes, end_stream: bool) -> std::io::Result<()> {
        self.stream
            .send_data(data, end_stream)
            .map_err(|e| std::io::Error::other(format!("failed to send data frame: {e}")))
    }

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
            h1_stream: None,
            h1_req: None,
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
    fn req_host(&self) -> Option<(String, Option<u16>)> {
        if let Some(h1) = &self.h1_req {
            return h1.host.clone();
        }
        if let Some(a) = self.req.uri().authority()
            && let Some(x) = super::server::parse_authority(a.as_str())
        {
            return Some(x);
        }
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
        if let Some(h1) = &self.h1_req {
            return h1.method.clone();
        }
        self.req.method().clone()
    }

    #[inline]
    fn req_method_str(&self) -> Option<&str> {
        if let Some(h1) = &self.h1_req {
            return Some(h1.method.as_str());
        }
        Some(self.req.method().as_str())
    }

    #[inline]
    fn req_path(&self) -> String {
        if let Some(h1) = &self.h1_req {
            return h1.path.clone();
        }
        self.req.uri().path().to_string()
    }

    #[inline]
    fn req_query(&self) -> String {
        if let Some(h1) = &self.h1_req {
            return h1.query.clone();
        }
        self.req.uri().query().unwrap_or("").to_string()
    }

    #[inline]
    fn req_http_version(&self) -> Version {
        if let Some(h1) = &self.h1_req {
            return h1.version;
        }
        self.req.version()
    }

    #[inline]
    fn req_headers(&self) -> http::HeaderMap {
        if let Some(h1) = &self.h1_req {
            return h1.headers.clone();
        }
        self.req.headers().clone()
    }

    #[inline]
    fn req_header(&self, header: &HeaderName) -> Option<HeaderValue> {
        if let Some(h1) = &self.h1_req {
            return h1.headers.get(header).cloned();
        }
        self.req.headers().get(header).cloned()
    }

    #[cfg(feature = "net-h1-server")]
    #[inline]
    fn req_body(&mut self, _timeout: Duration) -> std::io::Result<&[u8]> {
        if let Some(h1) = &self.h1_req {
            return Ok(h1.body.as_ref());
        }
        Err(std::io::Error::other(
            "req_body_h1 is not supported in H2Session",
        ))
    }

    #[inline]
    async fn req_body_async(&mut self, timeout: Duration) -> Option<std::io::Result<Bytes>> {
        if let Some(h1) = &mut self.h1_req {
            if h1.body_taken || h1.body.is_empty() {
                return None;
            }
            h1.body_taken = true;
            return Some(Ok(h1.body.clone()));
        }

        // existing H2 streaming logic
        use futures_lite::future::race;
        let data_fut = async {
            match self.req.body_mut().data().await {
                Some(Ok(bytes)) => Some(Ok(bytes)),
                Some(Err(e)) => Some(Err(std::io::Error::other(e.to_string()))),
                None => None,
            }
        };

        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "linux", feature = "rt-glommio"))] {
                let timeout_fut = async {
                    glommio::timer::Timer::new(timeout).await;
                    Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "req_body_h2 timed out",
                    )))
                };
                race(data_fut, timeout_fut).await
            } else if #[cfg(feature = "rt-tokio")] {
                let timeout_fut = async {
                    tokio::time::sleep(timeout).await;
                    Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "req_body_h2 timed out",
                    )))
                };
                race(data_fut, timeout_fut).await
            } else {
                compile_error!("Either feature `rt-glommio` or `rt-tokio` must be enabled to use h2 server.");
            }
        }
    }

    #[inline]
    fn start_h1_streaming(&mut self) -> std::io::Result<()> {
        use std::io;

        // HEADERS without Content-Length (H2 DATA frames will follow)
        let mut builder = http::Response::builder().status(self.res_status);
        {
            let h = builder.headers_mut().ok_or_else(|| {
                io::Error::other("failed to get mutable headers from response builder")
            })?;
            h.extend(self.resp_headers.drain());
        }

        let resp = builder
            .body(())
            .map_err(|e| io::Error::other(format!("failed to build H1-over-H2 response: {e}")))?;

        // send HEADERS; keep stream open
        let send = self
            .res
            .send_response(resp, false)
            .map_err(|e| io::Error::other(format!("failed to send H1-over-H2 headers: {e}")))?;

        self.h1_stream = Some(HStream { stream: send });

        // reset for reuse
        self.res_status = StatusCode::OK;
        self.resp_body = Bytes::new();

        Ok(())
    }

    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<HStream> {
        let mut builder = http::Response::builder().status(self.res_status);
        {
            let h = builder.headers_mut().ok_or_else(|| {
                std::io::Error::other("failed to get mutable headers from response builder")
            })?;
            h.extend(self.resp_headers.drain());
        }

        let resp = builder
            .body(())
            .map_err(|e| std::io::Error::other(format!("failed to build body response: {e}")))?;

        let send = self
            .res
            .send_response(resp, false)
            .map_err(|e| std::io::Error::other(format!("failed to send frame headers: {e}")))?;

        self.res_status = StatusCode::OK;
        self.resp_body = Bytes::new();

        Ok(HStream { stream: send })
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h3_streaming is not supported in H2Session",
        ))
    }

    #[inline]
    fn send_h1_data(&mut self, chunk: &[u8], end_stream: bool) -> std::io::Result<()> {
        use std::io;

        let stream = self
            .h1_stream
            .as_mut()
            .ok_or_else(|| io::Error::other("send_h1_data called before start_h1_streaming"))?;

        stream.reserve_capacity(chunk.len());

        let data = Bytes::copy_from_slice(chunk);
        stream.send_data(data, end_stream)?;

        if end_stream {
            self.h1_stream = None;
        }

        Ok(())
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn send_h3_data(
        &mut self,
        _chunk: bytes::Bytes,
        _end_stream: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h3_data is not supported in H2Session",
        ))
    }

    #[inline]
    fn write_all_eom(&mut self, status: &[u8]) -> std::io::Result<()> {
        self.status_code(
            StatusCode::from_str(std::str::from_utf8(status).map_err(|e| {
                std::io::Error::other(format!("invalid utf8 status code {}: {}", status.len(), e))
            })?)
            .map_err(|e| {
                std::io::Error::other(format!(
                    "invalid status code {}: {}",
                    std::str::from_utf8(status).unwrap_or("<invalid utf8>"),
                    e
                ))
            })?,
        );
        self.eom()
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

    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        let mut builder = http::Response::builder().status(self.res_status);
        {
            let header_map = builder.headers_mut().ok_or_else(|| {
                std::io::Error::other("failed to get mutable headers from response builder")
            })?;
            header_map.extend(self.resp_headers.drain());

            if !header_map.contains_key(http::header::CONTENT_LENGTH) {
                let len = self.resp_body.len();
                header_map.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len.to_string()).map_err(|e| {
                        std::io::Error::other(format!("invalid content-length {}: {}", len, e))
                    })?,
                );
            }
        }

        let resp = builder
            .body(())
            .map_err(|e| std::io::Error::other(format!("build resp: {e}")))?;

        let mut send = self
            .res
            .send_response(resp, false)
            .map_err(|e| std::io::Error::other(format!("send headers: {e}")))?;

        send.send_data(std::mem::take(&mut self.resp_body), true)
            .map_err(|e| std::io::Error::other(format!("send body: {e}")))?;

        self.res_status = StatusCode::OK;
        self.resp_body = Bytes::new();

        Ok(())
    }

    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        use futures_lite::future::poll_fn;
        use std::io;

        let mut builder = http::Response::builder().status(self.res_status);
        {
            let h = builder
                .headers_mut()
                .ok_or_else(|| io::Error::other("resp builder headers_mut"))?;
            h.extend(self.resp_headers.drain());
        }
        let resp = builder
            .body(())
            .map_err(|e| io::Error::other(format!("build resp: {e}")))?;

        let mut body = std::mem::take(&mut self.resp_body);
        let end_on_headers = body.is_empty();

        let mut send = self
            .res
            .send_response(resp, end_on_headers)
            .map_err(|e| io::Error::other(format!("send headers: {e}")))?;

        if end_on_headers {
            self.res_status = StatusCode::OK;
            return Ok(());
        }

        send.reserve_capacity(body.len());

        while !body.is_empty() {
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
            let chunk = body.split_to(n);
            let is_end = body.is_empty();

            send.send_data(chunk, is_end)
                .map_err(|e| io::Error::other(format!("send_data: {e}")))?;

            #[cfg(all(feature = "rt-glommio", target_os = "linux"))]
            glommio::yield_if_needed().await;

            #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
            tokio::task::yield_now().await;
        }

        self.res_status = StatusCode::OK;
        Ok(())
    }

    async fn enable_h1_over_h2(
        &mut self,
        timeout: Duration,
        max_header_bytes: usize,
        max_body_bytes: usize,
    ) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(8192);

        // read until \r\n\r\n
        let header_len = loop {
            if buf.len() > max_header_bytes {
                return Err(std::io::Error::other("H1-over-H2 header too large"));
            }

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }

            let next = recv_h2_data_with_timeout(self, timeout).await?;
            match next {
                Some(chunk) => buf.extend_from_slice(&chunk),
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "closed before H1 headers complete",
                    ));
                }
            }
        };

        // httparse headers
        let mut headers_arr = [httparse::EMPTY_HEADER; 64];
        let mut reqp = httparse::Request::new(&mut headers_arr);

        let st = reqp
            .parse(&buf[..header_len])
            .map_err(|e| std::io::Error::other(format!("httparse error: {e}")))?;

        let _parsed = match st {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => return Err(std::io::Error::other("partial H1 request")),
        };

        let method_str = reqp.method.unwrap_or("GET");
        let path_with_query = reqp.path.unwrap_or("/");

        let (path, query) = if let Some(i) = path_with_query.find('?') {
            (
                path_with_query[..i].to_string(),
                path_with_query[i + 1..].to_string(),
            )
        } else {
            (path_with_query.to_string(), String::new())
        };

        let version = match reqp.version {
            Some(0) => http::Version::HTTP_10,
            _ => http::Version::HTTP_11,
        };

        let method = http::Method::from_bytes(method_str.as_bytes()).unwrap_or(http::Method::GET);

        let mut headers = http::HeaderMap::new();
        for h in reqp.headers.iter() {
            if h.name.is_empty() {
                continue;
            }
            let name = http::HeaderName::from_bytes(h.name.as_bytes())
                .map_err(|e| std::io::Error::other(format!("bad header name: {e}")))?;
            let value = http::HeaderValue::from_bytes(h.value)
                .map_err(|e| std::io::Error::other(format!("bad header value: {e}")))?;
            headers.append(name, value);
        }

        let host = headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| super::server::parse_authority(s.trim()));

        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        if content_length > max_body_bytes {
            return Err(std::io::Error::other("H1-over-H2 body too large"));
        }

        // bytes after headers already in buf
        let mut body: Vec<u8> = Vec::with_capacity(content_length);
        if buf.len() > header_len {
            body.extend_from_slice(&buf[header_len..]);
        }

        while body.len() < content_length {
            let next = recv_h2_data_with_timeout(self, timeout).await?;
            match next {
                Some(chunk) => {
                    let need = content_length - body.len();
                    if chunk.len() <= need {
                        body.extend_from_slice(&chunk);
                    } else {
                        body.extend_from_slice(&chunk[..need]);
                    }
                }
                None => break,
            }
        }

        self.h1_req = Some(H1Parsed {
            method,
            path,
            query,
            version,
            headers,
            host,
            body: bytes::Bytes::from(body),
            body_taken: false,
        });

        Ok(())
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn is_ws(&self) -> bool {
        self.req.method() == http::Method::CONNECT
            && self
                .req
                .headers()
                .get(http::header::HeaderName::from_static(":protocol"))
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_accept(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_accept is not supported in H2Session",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_read(&mut self) -> std::io::Result<(crate::network::http::ws::OpCode, &[u8], bool)> {
        Err(std::io::Error::other(
            "ws_read is not supported in H2Session",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_write(
        &mut self,
        _op: crate::network::http::ws::OpCode,
        _payload: &[u8],
        _fin: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_write is not supported in H2Session",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_close(&mut self, _reason: Option<&[u8]>) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_close is not supported in H2Session",
        ))
    }
}

async fn recv_h2_data_with_timeout(
    session: &mut H2Session,
    timeout: Duration,
) -> std::io::Result<Option<bytes::Bytes>> {
    use futures_lite::future::race;
    use std::io;

    let data_fut = async {
        match session.req.body_mut().data().await {
            Some(Ok(b)) => Ok(Some(b)),
            Some(Err(e)) => Err(io::Error::other(e.to_string())),
            None => Ok(None),
        }
    };

    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "linux", feature = "rt-glommio"))] {
            let timeout_fut = async {
                glommio::timer::Timer::new(timeout).await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "h1-over-h2 read timed out"))
            };
            race(data_fut, timeout_fut).await
        } else if #[cfg(feature = "rt-tokio")] {
            let timeout_fut = async {
                tokio::time::sleep(timeout).await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "h1-over-h2 read timed out"))
            };
            race(data_fut, timeout_fut).await
        } else {
            compile_error!("Either feature `rt-glommio` or `rt-tokio` must be enabled.");
        }
    }
}
