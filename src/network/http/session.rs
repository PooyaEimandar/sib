use crate::network::http::h1::reserve_buf;
use crate::network::http::message::HttpHeader;
use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;

pub(crate) const MAX_HEADERS: usize = 16;

pub struct Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
    'buf: 'stream,
{
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
impl<'buf, 'header, 'stream, S> Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
{
    pub fn req_method(&self) -> Option<&str> {
        self.req.method
    }

    pub fn req_path(&self) -> Option<&str> {
        self.req.path
    }

    pub fn req_http_version(&self) -> Option<u8> {
        self.req.version
    }

    pub fn req_headers(&self) -> &[httparse::Header<'_>] {
        self.req.headers
    }

    pub fn req_header(&self, header: &str) -> std::io::Result<&str> {
        for h in self.req.headers.iter() {
            if h.name.eq_ignore_ascii_case(header) {
                return std::str::from_utf8(h.value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} header not found", header),
        ))
    }

    pub fn req_body(&mut self, timeout: std::time::Duration) -> io::Result<&[u8]> {
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

        if self.req_buf.remaining_mut() < content_length {
            self.req_buf.reserve(content_length);
        }

        let mut read = 0;
        let mut last_yield = 0;
        let deadline = std::time::Instant::now() + timeout;

        while read < content_length {
            if std::time::Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "body read timed out",
                ));
            }

            let remaining = content_length - read;
            let buf = &mut self.req_buf.as_mut()[..remaining];

            match self.stream.read(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "connection closed before body fully read (read: {}, expected: {})",
                            read, content_length
                        ),
                    ));
                }
                Ok(n) => {
                    unsafe { self.req_buf.advance_mut(n) };
                    read += n;
                    if read - last_yield >= 1024 {
                        may::coroutine::yield_now();
                        last_yield = read;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    may::coroutine::yield_now();
                }
                Err(e) => return Err(e),
            }
        }

        Ok(&self.req_buf[..content_length])
    }

    #[inline]
    pub fn status_code(&mut self, status: super::message::Status) -> &mut Self {
        const SERVER_NAME: &str =
            concat!("\r\nServer: Sib", env!("SIB_BUILD_VERSION"), "\r\nDate: ");
        let (code, reason) = status.as_parts();

        self.rsp_buf.extend_from_slice(b"HTTP/1.1 ");
        self.rsp_buf.extend_from_slice(code.as_bytes());
        self.rsp_buf.extend_from_slice(b" ");
        self.rsp_buf.extend_from_slice(reason.as_bytes());
        self.rsp_buf.extend_from_slice(SERVER_NAME.as_bytes());
        self.rsp_buf
            .extend_from_slice(super::message::CURRENT_DATE.load().as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self
    }

    pub fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
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

    pub fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header_str(name, value)?;
        }
        Ok(self)
    }

    pub fn header(&mut self, name: &HttpHeader, value: &str) -> std::io::Result<&mut Self> {
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

    pub fn headers(&mut self, header_val: &[(HttpHeader, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header(name, value)?;
        }
        Ok(self)
    }

    pub fn body(&mut self, body: &bytes::Bytes) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(body);
        self
    }

    pub fn body_static(&mut self, body: &'static str) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(body.as_bytes());
        self
    }

    #[inline]
    pub fn eom(&mut self) {
        // eom, end of message
    }
}

pub fn new_session<'header, 'buf, 'stream, S>(
    stream: &'stream mut S,
    headers: &'header mut [MaybeUninit<httparse::Header<'buf>>; MAX_HEADERS],
    req_buf: &'buf mut BytesMut,
    rsp_buf: &'buf mut BytesMut,
) -> io::Result<Option<Session<'buf, 'header, 'stream, S>>>
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

    reserve_buf(rsp_buf);

    Ok(Some(Session {
        req,
        req_buf,
        rsp_headers_len: 0,
        rsp_buf,
        stream,
    }))
}
