use crate::network::http::session::Session;
use arc_swap::ArcSwap;
use bytes::{Buf, BufMut, BytesMut};
use http::{HeaderName, HeaderValue};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) const BUF_LEN: usize = 8 * 4096;
pub(crate) const MAX_HEADERS: usize = 32;
pub static CURRENT_DATE: once_cell::sync::Lazy<Arc<ArcSwap<Arc<str>>>> =
    once_cell::sync::Lazy::new(|| {
        let now = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
        let swap = Arc::new(ArcSwap::from_pointee(Arc::from(now.into_boxed_str())));
        let swap_clone: Arc<ArcSwap<Arc<str>>> = Arc::clone(&swap);
        may::go!(move || loop {
            let now = std::time::SystemTime::now();
            let subsec = now
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_millis();
            let delay = 1_000u64.saturating_sub(subsec as u64);
            may::coroutine::sleep(std::time::Duration::from_millis(delay));
            let new_date = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
            swap_clone.store(Arc::<str>::from(new_date.into_boxed_str()).into());
        });
        swap
    });

pub struct H1Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
    'buf: 'stream,
{
    peer_addr: &'stream IpAddr,
    // request headers
    req: httparse::Request<'header, 'buf>,
    // request buffer
    req_buf: &'buf mut BytesMut,
    // length of response headers
    rsp_headers_len: usize,
    // buffer for response
    rsp_buf: &'buf mut BytesMut,
    // stream to read body from
    stream: &'stream mut S,
}

#[async_trait::async_trait(?Send)]
impl<'buf, 'header, 'stream, S> Session for H1Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
{
    #[inline]
    fn peer_addr(&self) -> &IpAddr {
        self.peer_addr
    }

    #[inline]
    fn req_host(&self) -> Option<(String, Option<u16>)> {
        use super::server::parse_authority;
        // Host header (HTTP/1.1)
        if let Some(host) = self
            .req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
        {
            if let Some(a) = parse_authority(host.trim()) {
                return Some(a);
            }
        }

        // CONNECT authority-form: "CONNECT host:port HTTP/1.1"
        if matches!(self.req.method, Some("CONNECT")) {
            if let Some(path) = self.req.path {
                if let Some(a) = parse_authority(path.trim()) {
                    return Some(a);
                }
            }
        }

        // Absolute-form: "GET http://example.com:8080/path HTTP/1.1"
        if let Some(path) = self.req.path {
            if let Some((scheme, rest)) = path.split_once("://") {
                if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
                    let auth_end = rest.find('/').unwrap_or(rest.len());
                    if let Some(a) = parse_authority(rest[..auth_end].trim()) {
                        return Some(a);
                    }
                }
            }
        }

        None
    }

    #[inline]
    fn req_method(&self) -> http::Method {
        if let Some(str) = self.req.method {
            return http::Method::from_str(str).unwrap_or_default();
        }
        http::Method::GET
    }

    #[inline]
    fn req_method_str(&self) -> Option<&str> {
        self.req.method
    }

    #[inline]
    fn req_path(&self) -> String {
        self.req.path.unwrap_or_default().into()
    }

    #[inline]
    fn req_http_version(&self) -> http::Version {
        match self.req.version {
            Some(1) => http::Version::HTTP_11,
            Some(0) => http::Version::HTTP_10,
            _ => http::Version::HTTP_09,
        }
    }

    #[inline]
    fn req_headers(&self) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for h in self.req.headers.iter() {
            if let Ok(v) = HeaderValue::from_bytes(h.value)
                && let Ok(header_name) = HeaderName::from_str(h.name)
            {
                map.insert(header_name, v);
            }
        }
        map
    }

    #[inline]
    fn req_header(&self, header: &http::HeaderName) -> Option<http::HeaderValue> {
        for h in self.req.headers.iter() {
            if h.name.eq_ignore_ascii_case(header.as_str()) {
                return HeaderValue::from_bytes(h.value).ok();
            }
        }
        None
    }

    #[inline]
    fn req_body(&mut self, timeout: std::time::Duration) -> io::Result<&[u8]> {
        let content_length = self
            .req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        if content_length == 0 {
            return Ok(&[]);
        }

        if self.req_buf.len() >= content_length {
            // already buffered enough
            return Ok(&self.req_buf[..content_length]);
        }

        self.req_buf.reserve(content_length - self.req_buf.len());

        let mut read = self.req_buf.len();
        let deadline = std::time::Instant::now() + timeout;

        while read < content_length {
            if std::time::Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "body read timed out",
                ));
            }

            let spare = self.req_buf.spare_capacity_mut();
            let to_read = spare.len().min(content_length - read);

            if to_read == 0 {
                may::coroutine::yield_now();
                continue;
            }

            let buf =
                unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, to_read) };

            match self.stream.read(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before body fully read",
                    ));
                }
                Ok(n) => {
                    unsafe {
                        self.req_buf.advance_mut(n);
                    }
                    read += n;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    may::coroutine::yield_now();
                }
                Err(e) => return Err(e),
            }

            if read % 1024 == 0 {
                may::coroutine::yield_now();
            }
        }

        Ok(&self.req_buf[..content_length])
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[inline]
    async fn req_body_async(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Option<std::io::Result<bytes::Bytes>> {
        None
    }

    #[inline]
    fn write_all_eom(&mut self, status: &[u8]) -> std::io::Result<()> {
        self.rsp_buf.extend_from_slice(status);
        Ok(())
    }

    #[inline]
    fn status_code(&mut self, status: http::StatusCode) -> &mut Self {
        const SERVER_NAME: &str =
            concat!("\r\nServer: Sib ", env!("SIB_BUILD_VERSION"), "\r\nDate: ");

        self.rsp_buf.extend_from_slice(b"HTTP/1.1 ");
        self.rsp_buf.extend_from_slice(status.as_str().as_bytes());
        self.rsp_buf.extend_from_slice(b" ");
        if let Some(reason) = status.canonical_reason() {
            self.rsp_buf.extend_from_slice(reason.as_bytes());
        }
        self.rsp_buf.extend_from_slice(SERVER_NAME.as_bytes());
        self.rsp_buf
            .extend_from_slice(CURRENT_DATE.load().as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self
    }

    #[cfg(feature = "net-h2-server")]
    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::H2Stream> {
        Err(io::Error::other(
            "start_h2_streaming is not supported in H1Session",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h3_streaming is not supported in H1Session",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn send_h3_data(
        &mut self,
        _chunk: bytes::Bytes,
        _end_stream: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h3_data is not supported in H1Session",
        ))
    }

    #[inline]
    fn header(&mut self, name: HeaderName, value: HeaderValue) -> std::io::Result<&mut Self> {
        if self.rsp_headers_len >= MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::ArgumentListTooLong,
                "too many headers",
            ));
        }
        self.rsp_buf.extend_from_slice(format!("{name}").as_bytes());
        self.rsp_buf.extend_from_slice(b": ");
        self.rsp_buf.extend_from_slice(value.as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_headers_len += 1;
        Ok(self)
    }

    #[inline]
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        if self.rsp_headers_len >= MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::ArgumentListTooLong,
                "too many headers",
            ));
        }
        self.rsp_buf.extend_from_slice(name.as_bytes());
        self.rsp_buf.extend_from_slice(b": ");
        self.rsp_buf.extend_from_slice(value.as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_headers_len += 1;
        Ok(self)
    }

    #[inline]
    fn headers(&mut self, headers: &http::HeaderMap) -> std::io::Result<&mut Self> {
        for (k, v) in headers {
            self.header(k.clone(), v.clone())?;
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
    fn body(&mut self, body: bytes::Bytes) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(&body);
        self
    }

    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        // eom, end of message
        #[cfg(debug_assertions)]
        eprintln!("sent: {:?}", self.rsp_buf);
        Ok(())
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        Err(io::Error::other("eom_async is not supported in H1Session"))
    }
}

pub fn new_session<'header, 'buf, 'stream, S>(
    stream: &'stream mut S,
    peer_addr: &'stream IpAddr,
    headers: &'header mut [MaybeUninit<httparse::Header<'buf>>; MAX_HEADERS],
    req_buf: &'buf mut BytesMut,
    rsp_buf: &'buf mut BytesMut,
) -> io::Result<Option<H1Session<'buf, 'header, 'stream, S>>>
where
    S: Read + Write,
{
    let mut req = httparse::Request::new(&mut []);
    let buf: &[u8] = unsafe { std::mem::transmute(req_buf.chunk()) };
    let status = match req.parse_with_uninit_headers(buf, headers) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to parse http request: {e:?}");
            //s_error!("{msg}");
            return Err(io::Error::other(msg));
        }
    };

    let len = match status {
        httparse::Status::Complete(amt) => amt,
        httparse::Status::Partial => return Ok(None),
    };
    req_buf.advance(len);

    // reserve rsp_buf
    let rem = rsp_buf.capacity() - rsp_buf.len();
    if rem < 1024 {
        rsp_buf.reserve(BUF_LEN - rem);
    }

    Ok(Some(H1Session {
        peer_addr,
        req,
        req_buf,
        rsp_headers_len: 0,
        rsp_buf,
        stream,
    }))
}
