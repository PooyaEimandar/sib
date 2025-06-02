use super::reader::Reader;
use super::server::reserve_buf;
use bytes::{Buf, BytesMut};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;

pub(crate) const MAX_HEADERS: usize = 16;

pub struct Session<'buf, 'header, 'stream, S>
where
    S: Read + Write,
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

impl<'buf, 'stream, S> Session<'buf, '_, 'stream, S>
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
        // Return an error if the header is not found
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} header not found", header),
        ))
    }

    pub fn req_body(self) -> std::io::Result<Reader<'buf, 'stream, S>> {
        let content_length = self.req_header("content-length")?.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content-length header: {e}"),
            )
        })?;
        Ok(Reader {
            body_limit: content_length,
            total_read: 0,
            stream: self.stream,
            req_buf: self.req_buf,
        })
    }

    #[inline]
    pub fn status_code(&mut self, status: super::message::Status) -> &mut Self {
        let (code, reason) = status.as_parts();
        self.rsp_buf.extend_from_slice(b"HTTP/1.1 ");
        self.rsp_buf.extend_from_slice(code.as_bytes());
        self.rsp_buf.extend_from_slice(b" ");
        self.rsp_buf.extend_from_slice(reason.as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\nServer: Sib\r\nDate: ");
        self.rsp_buf
            .extend_from_slice(super::message::CURRENT_DATE.load().as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\n");
        self
    }

    pub fn header(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
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
        if !self.rsp_buf.ends_with(b"\r\n") {
            self.rsp_buf.extend_from_slice(b"\r\n");
        }
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

    // println!("req: {:?}", std::str::from_utf8(req_buf).unwrap());
    Ok(Some(Session {
        req,
        req_buf,
        rsp_headers_len: 0,
        rsp_buf,
        stream,
    }))
}
