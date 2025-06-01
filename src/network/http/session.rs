#![allow(dead_code)]

use super::reader::Reader;
use super::server::{BUF_LEN, reserve_buf};
use bytes::{Buf, BytesMut};
use may::net::TcpStream;
use std::io::{self};
use std::mem::MaybeUninit;

pub(crate) const MAX_HEADERS: usize = 16;

pub struct Session<'buf, 'header, 'stream> {
    // request headers
    req: httparse::Request<'header, 'buf>,
    // request buffer
    req_buf: &'buf mut BytesMut,
    // length of response headers
    rsp_headers_len: usize,
    // buffer for response
    rsp_buf: BytesMut,
    // stream to read body from
    stream: &'stream mut TcpStream,
}

// impl Drop for Request<'_, '_, '_> {
//     fn drop(&mut self) {
//         //let _ = self.body_mut();
//         self.req_buf.clear();
//         self.rsp_buf.clear();
//     }
// }

impl<'buf, 'stream> Session<'buf, '_, 'stream> {
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

    pub fn req_body(self) -> std::io::Result<Reader<'buf, 'stream>> {
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
    pub fn status_code(&mut self, code: usize, msg: &'static str) -> &mut Self {
        self.rsp_buf.extend_from_slice(b"HTTP/1.1 ");
        let mut code_buf = itoa::Buffer::new();
        self.rsp_buf
            .extend_from_slice(code_buf.format(code).as_bytes());
        self.rsp_buf.extend_from_slice(b" ");
        self.rsp_buf.extend_from_slice(msg.as_bytes());
        self.rsp_buf.extend_from_slice(b"\r\nServer: Sib\r\nDate: ");
        self.rsp_buf
            .extend_from_slice(super::date::CURRENT_DATE.load().as_bytes());
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
    pub fn send(&mut self) -> std::io::Result<usize> {
        write(self.stream.inner_mut(), &mut self.rsp_buf)
    }
}

#[cfg(unix)]
#[inline]
fn write(stream: &mut impl std::io::Write, rsp_buf: &mut BytesMut) -> io::Result<usize> {
    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    let mut write_cnt = 0;
    while write_cnt < len {
        match stream.write(unsafe { write_buf.get_unchecked(write_cnt..) }) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed")),
            Ok(n) => write_cnt += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    rsp_buf.advance(write_cnt);
    Ok(write_cnt)
}

pub fn new_session<'header, 'buf, 'stream>(
    headers: &'header mut [MaybeUninit<httparse::Header<'buf>>; MAX_HEADERS],
    req_buf: &'buf mut BytesMut,
    stream: &'stream mut TcpStream,
) -> io::Result<Option<Session<'buf, 'header, 'stream>>> {
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

    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);
    reserve_buf(&mut rsp_buf);

    // println!("req: {:?}", std::str::from_utf8(req_buf).unwrap());
    Ok(Some(Session {
        req,
        req_buf,
        rsp_headers_len: 0,
        rsp_buf,
        stream,
    }))
}
