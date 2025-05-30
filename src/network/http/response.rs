use super::{date::append_date, request::MAX_HEADERS};
use bytes::{Bytes, BytesMut};
use std::io;

pub struct Response<'a> {
    headers: [&'static str; MAX_HEADERS],
    headers_len: usize,
    status_message: StatusMessage,
    body: bytes::Bytes,
    rsp_buf: &'a mut BytesMut,
}

struct StatusMessage {
    code: usize,
    msg: &'static str,
}

impl<'a> Response<'a> {
    pub(crate) fn new(rsp_buf: &'a mut BytesMut) -> Response<'a> {
        let headers: [&'static str; 16] = [""; 16];

        Response {
            headers,
            headers_len: 0,
            body: Bytes::new(),
            status_message: StatusMessage {
                code: 200,
                msg: "Ok",
            },
            rsp_buf,
        }
    }

    #[inline]
    pub fn status_code(&mut self, code: usize, msg: &'static str) -> &mut Self {
        self.status_message = StatusMessage { code, msg };
        self
    }

    #[inline]
    pub fn header(&mut self, header: &'static str) -> &mut Self {
        if self.headers_len < self.headers.len() {
            self.headers[self.headers_len] = header;
            self.headers_len += 1;
        } else {
            //s_error!("Too many headers");
        }
        self
    }

    #[inline]
    pub fn body(&mut self, bytes: bytes::Bytes) {
        self.body = bytes;
    }

    #[inline]
    pub fn body_mut(&mut self) -> &mut BytesMut {
        self.rsp_buf.extend_from_slice(&self.body);
        self.rsp_buf
    }

    #[inline]
    fn body_len(&self) -> usize {
        self.body.len()
    }

    #[inline]
    fn get_body(&mut self) -> &[u8] {
        self.rsp_buf.extend_from_slice(&self.body);
        &self.rsp_buf
    }
}

impl Drop for Response<'_> {
    fn drop(&mut self) {
        let _ = self.body_mut();
        self.rsp_buf.clear();
    }
}

pub(crate) fn encode(mut rsp: Response, buf: &mut BytesMut) {
    if rsp.status_message.code == 200 {
        buf.extend_from_slice(b"HTTP/1.1 200 Ok\r\nServer: Sib\r\nDate: ");
    } else {
        buf.extend_from_slice(b"HTTP/1.1 ");
        let mut code = itoa::Buffer::new();
        buf.extend_from_slice(code.format(rsp.status_message.code).as_bytes());
        buf.extend_from_slice(b" ");
        buf.extend_from_slice(rsp.status_message.msg.as_bytes());
        buf.extend_from_slice(b"\r\nServer: Sib\r\nDate: ");
    }
    append_date(buf);
    buf.extend_from_slice(b"\r\nContent-Length: ");
    let mut length = itoa::Buffer::new();
    buf.extend_from_slice(length.format(rsp.body_len()).as_bytes());

    // SAFETY: we already have bound check when insert headers
    let headers = unsafe { rsp.headers.get_unchecked(..rsp.headers_len) };
    for h in headers {
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(h.as_bytes());
    }

    buf.extend_from_slice(b"\r\n\r\n");
    buf.extend_from_slice(rsp.get_body());
}

#[cold]
pub(crate) fn encode_error(e: io::Error, buf: &mut BytesMut) {
    //s_error!("error in service: err = {e:?}");
    let msg_string = e.to_string();
    let msg = msg_string.as_bytes();

    buf.extend_from_slice(b"HTTP/1.1 500 Internal Server Error\r\nServer: Sib\r\nDate: ");
    append_date(buf);
    buf.extend_from_slice(b"\r\nContent-Length: ");
    let mut length = itoa::Buffer::new();
    buf.extend_from_slice(length.format(msg.len()).as_bytes());

    buf.extend_from_slice(b"\r\n\r\n");
    buf.extend_from_slice(msg);
}
