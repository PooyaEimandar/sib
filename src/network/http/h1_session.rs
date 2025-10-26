use crate::network::http::session::Session;
use arc_swap::ArcSwap;
use bytes::{Buf, BufMut, BytesMut};
use http::{HeaderName, HeaderValue};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

const HTTP11: &[u8] = b"HTTP/1.1 ";
const CRLF: &[u8] = b"\r\n";

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
                .unwrap_or_default()
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
    // length of response headers (those you append with header/header_str)
    rsp_headers_len: usize,
    // buffer for response (your headers + blank line + body)
    rsp_buf: &'buf mut BytesMut,
    // stream to write to
    stream: &'stream mut S,
    // whether a status was set explicitly
    status_set: bool,
    // status line + Server + Date + CRLF (tiny, on-stack)
    status_buf: heapless::Vec<u8, 192>,
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
        if let Some(host) = self
            .req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            && let Some(a) = parse_authority(host.trim())
        {
            return Some(a);
        }
        if matches!(self.req.method, Some("CONNECT"))
            && let Some(path) = self.req.path
            && let Some(a) = parse_authority(path.trim())
        {
            return Some(a);
        }
        if let Some(path) = self.req.path
            && let Some((scheme, rest)) = path.split_once("://")
            && (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        {
            let auth_end = rest.find('/').unwrap_or(rest.len());
            if let Some(a) = parse_authority(rest[..auth_end].trim()) {
                return Some(a);
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

            // SAFETY: req_buf has contiguous spare capacity after reserve
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
                    // SAFETY: we have just initialized `n` bytes above
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

            if read.is_multiple_of(1024) {
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

    // build only the status + fixed headers into tiny status_buf
    #[inline]
    fn status_code(&mut self, status: http::StatusCode) -> &mut Self {
        const SERVER_NAME: &str =
            concat!("\r\nServer: Sib ", env!("SIB_BUILD_VERSION"), "\r\nDate: ");

        self.status_buf.clear();
        self.status_buf.extend_from_slice(HTTP11).ok();
        self.status_buf
            .extend_from_slice(status.as_str().as_bytes())
            .ok();
        self.status_buf.extend_from_slice(b" ").ok();
        if let Some(reason) = status.canonical_reason() {
            self.status_buf.extend_from_slice(reason.as_bytes()).ok();
        }
        self.status_buf
            .extend_from_slice(SERVER_NAME.as_bytes())
            .ok();
        self.status_buf
            .extend_from_slice(CURRENT_DATE.load().as_bytes())
            .ok();
        self.status_buf.extend_from_slice(CRLF).ok();

        self.status_set = true;
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

    // headers go straight into rsp_buf
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
        self.rsp_buf.extend_from_slice(CRLF);
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
        self.rsp_buf.extend_from_slice(CRLF);
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

    // If body is called before status, synthesize 200 OK once.
    #[inline]
    fn body(&mut self, body: bytes::Bytes) -> &mut Self {
        if !self.status_set {
            self.status_code(http::StatusCode::OK);
        }
        self.rsp_buf.extend_from_slice(CRLF);
        self.rsp_buf.extend_from_slice(&body);
        self
    }

    // eom performs a single vectored write: status_buf then rsp_buf
    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        use std::io::{ErrorKind, IoSlice};

        if !self.status_set {
            // default 200 if nothing set yet
            self.status_code(http::StatusCode::OK);
        }

        let mut off_status = 0usize;
        let mut off_body = 0usize;

        // Loop until both status_buf and rsp_buf are fully written
        loop {
            let s1 = &self.status_buf[off_status..];
            let s2 = &self.rsp_buf[off_body..];

            if s1.is_empty() && s2.is_empty() {
                break;
            }

            let bufs = if !s1.is_empty() && !s2.is_empty() {
                [IoSlice::new(s1), IoSlice::new(s2)]
            } else if !s1.is_empty() {
                [IoSlice::new(s1), IoSlice::new(&[])]
            } else {
                [IoSlice::new(s2), IoSlice::new(&[])]
            };

            match self.stream.write_vectored(&bufs) {
                Ok(0) => return Err(io::Error::new(ErrorKind::WriteZero, "write zero")),
                Ok(n) => {
                    let s1_len = s1.len();
                    if n < s1_len {
                        off_status += n;
                    } else {
                        off_status = s1_len;
                        off_body += n - s1_len;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    may::coroutine::yield_now();
                }
                Err(e) => return Err(e),
            }
        }

        // We fully sent the response; clear buffers for reuse if desired
        self.rsp_buf.clear();
        self.status_buf.clear();
        self.status_set = false;

        Ok(())
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        Err(io::Error::other("eom_async is not supported in H1Session"))
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn is_ws(&self) -> bool {
        self.req.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("upgrade") && h.value.eq_ignore_ascii_case(b"websocket")
        })
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn ws_accept(&mut self) -> std::io::Result<()> {
        let header_val = match self.req_header(&HeaderName::from_static("sec-websocket-key")) {
            Some(val) => val,
            None => {
                return self
                    .status_code(http::StatusCode::BAD_REQUEST)
                    .header_str("Connection", "close")?
                    .eom();
            }
        };
        let accept = compute_accept(&header_val);

        // complete handshake (101)
        let mut resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
        );
        if let Some(sub_protocol) =
            self.req_header(&HeaderName::from_static("sec-websocket-protocol"))
        {
            resp.push_str(&format!(
                "Sec-WebSocket-Protocol: {}\r\n",
                sub_protocol.to_str().unwrap_or("")
            ));
        }
        resp.push_str("\r\n");
        self.stream.write_all(resp.as_bytes())?;

        // stream is ready for websocket frames
        Ok(())
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn ws_read(
        &mut self,
    ) -> std::io::Result<(crate::network::http::ws::OpCode, bytes::Bytes, bool)> {
        use crate::network::http::ws::OpCode;

        // get first two bytes
        let h = take_exact_nb(self.stream, self.req_buf, 2)?;
        let b0 = h[0];
        let b1 = h[1];
        let fin = (b0 & 0x80) != 0;
        if (b0 & 0x70) != 0 {
            return Err(std::io::Error::other("WS RSV set"));
        }

        let opcode = match b0 & 0x0F {
            0x0 => OpCode::Continue,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            x => return Err(std::io::Error::other(format!("bad WS opcode {x}"))),
        };

        let is_control = matches!(opcode, OpCode::Close | OpCode::Ping | OpCode::Pong);
        if is_control && !fin {
            return Err(std::io::Error::other("WS control fragmented"));
        }

        if (b1 & 0x80) == 0 {
            return Err(std::io::Error::other("WS client not masked"));
        }
        let mut len = (b1 & 0x7F) as u64;
        if len == 126 {
            len = u16::from_be_bytes(
                take_exact_nb(self.stream, self.req_buf, 2)?
                    .as_ref()
                    .try_into()
                    .map_err(|e| std::io::Error::other(format!("failed to read ws length: {e}")))?,
            ) as u64;
        } else if len == 127 {
            len = u64::from_be_bytes(
                take_exact_nb(self.stream, self.req_buf, 8)?
                    .as_ref()
                    .try_into()
                    .map_err(|e| std::io::Error::other(format!("failed to read ws length: {e}")))?,
            ) as u64;
        }
        if is_control && len > 125 {
            return Err(std::io::Error::other("WS control too long"));
        }
        if len > (isize::MAX as u64) {
            return Err(std::io::Error::other("WS frame too large"));
        }

        let mask = take_exact_nb(self.stream, self.req_buf, 4)?;
        let need = len as usize;
        if need > BUF_LEN {
            return Err(std::io::Error::other(format!(
                "max WS frame is {}",
                BUF_LEN
            )));
        }

        // read payload into req_buf then unmask in place
        let payload = if need == 0 {
            bytes::Bytes::new()
        } else {
            // fill exactly needed bytes
            ensure_bytes(self.stream, self.req_buf, need)?;

            // Unmask in place on the first `need` bytes
            {
                let data = &mut self.req_buf[..need];
                // `mask` is a Bytes; indexing is cheap
                for i in 0..need {
                    data[i] ^= mask[i & 3];
                }
            }

            // Hand out the exact payload as Bytes, leaving any extra bytes
            // (next frame) in req_buf.
            self.req_buf.split_to(need).freeze()
        };

        Ok((opcode, payload, fin))
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn ws_write(
        &mut self,
        code: crate::network::http::ws::OpCode,
        payload: &bytes::Bytes,
        fin: bool,
    ) -> std::io::Result<()> {
        use crate::network::http::h1_server::write;
        use std::io::{ErrorKind, IoSlice};

        // Build WS header (server frames are unmasked)
        let mut hdr = [0u8; 10];
        let mut pos = 0;
        hdr[pos] = (if fin { 0x80 } else { 0 }) | (code as u8);
        pos += 1;

        let len = payload.len();
        if len < 126 {
            hdr[pos] = len as u8;
            pos += 1;
        } else if len <= 0xFFFF {
            hdr[pos] = 126;
            pos += 1;
            hdr[pos..pos + 2].copy_from_slice(&(len as u16).to_be_bytes());
            pos += 2;
        } else {
            hdr[pos] = 127;
            pos += 1;
            hdr[pos..pos + 8].copy_from_slice(&(len as u64).to_be_bytes());
            pos += 8;
        }

        // If we already have bytes queued, preserve order: buffer + drain.
        if !self.rsp_buf.is_empty() {
            self.rsp_buf.extend_from_slice(&hdr[..pos]);
            self.rsp_buf.extend_from_slice(payload);
            while !self.rsp_buf.is_empty() {
                let (_, blocked) = write(self.stream, self.rsp_buf)?;
                if blocked && !self.rsp_buf.is_empty() {
                    may::coroutine::yield_now();
                }
            }
            return Ok(());
        }

        // Fast path: try one zero-copy vectored write (header + payload)
        let total = pos + len;
        let bufs = [IoSlice::new(&hdr[..pos]), IoSlice::new(payload)];
        match self.stream.write_vectored(&bufs) {
            Ok(n) if n == total => {
                // All done, nothing buffered.
                return Ok(());
            }
            Ok(n) => {
                // Partial write: buffer whatever remains, then drain.
                let mut remaining_hdr_off = 0usize;
                let mut remaining_payload_off = 0usize;

                if n < pos {
                    remaining_hdr_off = n;
                } else {
                    remaining_payload_off = n - pos;
                }

                if remaining_hdr_off < pos {
                    self.rsp_buf.extend_from_slice(&hdr[remaining_hdr_off..pos]);
                }
                if remaining_payload_off < len {
                    // Copies only the tail we couldn't write
                    self.rsp_buf
                        .extend_from_slice(&payload[remaining_payload_off..]);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // Socket not ready: buffer entire frame, then drain later.
                self.rsp_buf.extend_from_slice(&hdr[..pos]);
                self.rsp_buf.extend_from_slice(payload);
            }
            Err(e) => return Err(e),
        }

        // Buffered drain using your existing nonblocking writer
        while !self.rsp_buf.is_empty() {
            let (_, blocked) = write(self.stream, self.rsp_buf)?;
            if blocked && !self.rsp_buf.is_empty() {
                may::coroutine::yield_now();
            }
        }
        Ok(())
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn ws_close(&mut self, reason: Option<&bytes::Bytes>) -> std::io::Result<()> {
        use crate::network::http::h1_server::write;

        // RFC 6455 §5.5.1 — Close frame payload: 2-byte code + UTF-8 reason (optional)
        let mut payload = [0u8; 2 + 123]; // max 125 total (control frame limit)
        payload[..2].copy_from_slice(&1000u16.to_be_bytes()); // normal closure

        let rlen = reason.map(|r| r.len()).unwrap_or(0);
        if rlen > 123 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "close reason too long",
            ));
        }

        if let Some(r) = reason {
            // RFC requires UTF-8 for reason string
            if std::str::from_utf8(r).is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "close reason not utf8",
                ));
            }
            payload[2..2 + rlen].copy_from_slice(r);
        }

        let total = 2 + rlen;

        // Build the WS frame header (FIN | CLOSE opcode)
        let mut hdr = [0u8; 4];
        hdr[0] = 0x88; // FIN + opcode = Close (0x8)
        hdr[1] = total as u8; // always <126 (control frame limit)

        // Append to the shared rsp_buf
        self.rsp_buf.extend_from_slice(&hdr[..2]);
        self.rsp_buf.extend_from_slice(&payload[..total]);

        // Non-blocking drain using same helper as HTTP
        while !self.rsp_buf.is_empty() {
            let (_, blocked) = write(&mut self.stream, &mut self.rsp_buf)?;
            if blocked && !self.rsp_buf.is_empty() {
                may::coroutine::yield_now();
            }
        }

        Ok(())
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

    // SAFETY: headers is MaybeUninit, we are initializing it now
    let buf: &[u8] = unsafe { std::mem::transmute(req_buf.chunk()) };
    let status = match req.parse_with_uninit_headers(buf, headers) {
        Ok(s) => s,
        Err(e) => {
            return Err(io::Error::other(format!(
                "failed to parse http request: {e:?}"
            )));
        }
    };

    let count = match status {
        httparse::Status::Complete(num) => num,
        httparse::Status::Partial => return Ok(None),
    };
    req_buf.advance(count);

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
        status_set: false,
        status_buf: heapless::Vec::new(),
    }))
}

#[cfg(feature = "net-ws-server")]
#[inline]
fn compute_accept(sec_key: &http::HeaderValue) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use sha1::{Digest, Sha1};

    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut sha = Sha1::new();
    sha.update(sec_key.as_bytes());
    sha.update(WS_GUID.as_bytes());
    B64.encode(sha.finalize())
}

#[cfg(feature = "net-ws-server")]
#[inline]
fn take_exact_nb<S: Read + Write>(
    stream: &mut S,
    buf: &mut BytesMut,
    need: usize,
) -> std::io::Result<bytes::Bytes> {
    use crate::network::http::h1_server::read;
    while buf.len() < need {
        let _blocked = read(stream, buf)?;
        if buf.len() < need {
            may::coroutine::yield_now();
        }
    }
    Ok(buf.split_to(need).freeze())
}

#[cfg(feature = "net-ws-server")]
#[inline]
fn ensure_bytes<S: Read + Write>(
    stream: &mut S,
    buf: &mut BytesMut,
    need: usize,
) -> std::io::Result<()> {
    use crate::network::http::h1_server::read;
    while buf.len() < need {
        let _ = read(stream, buf)?; // fills buf.chunk_mut()
        if buf.len() < need {
            may::coroutine::yield_now(); // cooperate with may
        }
    }
    Ok(())
}
