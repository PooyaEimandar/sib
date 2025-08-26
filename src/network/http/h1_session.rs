use crate::network::http::server::reserve_buf;
use crate::network::http::{session::Session, util::HttpHeader};
use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;

pub(crate) const MAX_HEADERS: usize = 32;

pub struct H1Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
    'buf: 'stream,
{
    peer_addr: &'stream std::net::SocketAddr,
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

impl<'buf, 'header, 'stream, S> Session for H1Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
{
    #[inline]
    fn peer_addr(&self) -> &std::net::SocketAddr {
        self.peer_addr
    }

    #[inline]
    fn is_h3(&self) -> bool {
        false
    }

    #[inline]
    fn req_method(&self) -> Option<&str> {
        self.req.method
    }

    #[inline]
    fn req_path(&self) -> Option<&str> {
        self.req.path
    }

    #[inline]
    fn req_http_version(&self) -> Option<u8> {
        self.req.version
    }

    #[inline]
    fn req_headers(&self) -> &[httparse::Header<'_>] {
        self.req.headers
    }

    #[inline]
    fn req_headers_vec(&self) -> Vec<httparse::Header<'_>> {
        self.req.headers.to_vec()
    }

    #[inline]
    fn req_header(&self, header: &HttpHeader) -> std::io::Result<&str> {
        self.req_header_str(&header.to_string())
    }

    #[inline]
    fn req_header_str(&self, header: &str) -> std::io::Result<&str> {
        for h in self.req.headers.iter() {
            if h.name.eq_ignore_ascii_case(header) {
                return std::str::from_utf8(h.value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{header} header not found"),
        ))
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

            let buf = unsafe {
                std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, to_read)
            };

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

    #[inline]
    fn status_code(&mut self, status: super::util::Status) -> &mut Self {
        const SERVER_NAME: &str =
            concat!("\r\nServer: Sib ", env!("SIB_BUILD_VERSION"), "\r\nDate: ");
        let (code, reason) = status.as_parts();

        self.rsp_buf.extend_from_slice(b"HTTP/1.1 ");
        self.rsp_buf.extend_from_slice(code.as_bytes());
        self.rsp_buf.extend_from_slice(b" ");
        self.rsp_buf.extend_from_slice(reason.as_bytes());
        self.rsp_buf.extend_from_slice(SERVER_NAME.as_bytes());
        self.rsp_buf
            .extend_from_slice(super::util::CURRENT_DATE.load().as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self
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
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header_str(name, value)?;
        }
        Ok(self)
    }

    #[inline]
    fn header(&mut self, name: &HttpHeader, value: &str) -> std::io::Result<&mut Self> {
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
    fn headers(&mut self, header_val: &[(HttpHeader, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header(name, value)?;
        }
        Ok(self)
    }

    #[inline]
    fn headers_vec(&mut self, header_val: &[(HttpHeader, String)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header(name, value)?;
        }
        Ok(self)
    }

    #[inline]
    fn body(&mut self, body: &bytes::Bytes) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(body);
        self
    }

    #[inline]
    fn body_slice(&mut self, body: &[u8]) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(body);
        self
    }

    #[inline]
    fn body_static(&mut self, body: &'static str) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(body.as_bytes());
        self
    }

    #[cfg(feature = "net-file-server")]
    #[inline]
    fn body_mmap(&mut self, map: std::sync::Arc<memmap2::Mmap>, lo: usize, hi: usize) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"\r\n");
        self.rsp_buf.extend_from_slice(&map[lo..hi]);
        self
    }

    #[inline]
    fn eom(&mut self) {
        // eom, end of message
        #[cfg(debug_assertions)]
        eprintln!("sent: {:?}", self.rsp_buf);
    }
}


pub fn new_session<'header, 'buf, 'stream, S>(
    stream: &'stream mut S,
    peer_addr: &'stream std::net::SocketAddr,
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

    reserve_buf(rsp_buf);

    Ok(Some(H1Session {
        peer_addr,
        req,
        req_buf,
        rsp_headers_len: 0,
        rsp_buf,
        stream,
    }))
}
