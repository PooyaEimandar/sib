// WebSocket (RFC6455) utilities.
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::HeaderMap;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Continue,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    #[inline]
    pub fn to_u8(self) -> u8 {
        match self {
            OpCode::Continue => 0x0,
            OpCode::Text => 0x1,
            OpCode::Binary => 0x2,
            OpCode::Close => 0x8,
            OpCode::Ping => 0x9,
            OpCode::Pong => 0xA,
        }
    }

    #[inline]
    pub fn from_u8(v: u8) -> io::Result<Self> {
        Ok(match v {
            0x0 => OpCode::Continue,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ws opcode")),
        })
    }
}

/// Minimal WS frame representation.
#[derive(Debug)]
pub struct Frame {
    pub fin: bool,
    pub op: OpCode,
    pub payload: Bytes,
    pub masked: bool,
    pub mask_key: [u8; 4],
}

fn io_other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// HTTP/1.1 Upgrade: compute Sec-WebSocket-Accept from Sec-WebSocket-Key.
pub(crate) fn sec_websocket_accept(key: &str) -> io::Result<String> {
    // GUID defined by RFC6455
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut s = String::with_capacity(key.len() + GUID.len());
    s.push_str(key.trim());
    s.push_str(GUID);

    // sha1 + base64
    use sha1::{Digest, Sha1};
    let hash = Sha1::digest(s.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(hash))
}

/// Returns true if H1 headers look like a WebSocket upgrade request.
pub(crate) fn is_h1_ws_upgrade(method: &http::Method, headers: &HeaderMap) -> bool {
    if *method != http::Method::GET {
        return false;
    }

    let upgrade_ok = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let conn_ok = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            // RFC allows: "Upgrade" or "keep-alive, Upgrade" etc
            v.split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    let key_ok = headers.contains_key("sec-websocket-key");

    let ver_ok = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "13")
        .unwrap_or(false);

    upgrade_ok && conn_ok && key_ok && ver_ok
}

/// Try to parse one client-to-server WS frame from `buf`.
/// If incomplete, returns Ok(None). Protocol errors are terminal: the caller
/// must close the connection without processing any further frames.
pub(crate) fn try_parse_frame(buf: &mut BytesMut, max_frame: usize) -> io::Result<Option<Frame>> {
    // Need at least 2 bytes
    if buf.len() < 2 {
        return Ok(None);
    }

    let b0 = buf[0];
    let b1 = buf[1];

    // RSV bits must be zero unless extensions negotiated (we don't support any).
    if (b0 & 0x70) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ws rsv not supported",
        ));
    }

    let fin = (b0 & 0x80) != 0;
    let op = OpCode::from_u8(b0 & 0x0F)?;
    let masked = (b1 & 0x80) != 0;
    // RFC 6455 section 5.1 requires masking on every client frame, including
    // empty/control frames and TLS connections. Reject at the base header so
    // an invalid peer cannot make us wait for or buffer its declared payload.
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client WebSocket frames must be masked",
        ));
    }

    let mut idx = 2usize;
    let mut len7 = (b1 & 0x7F) as u64;

    if matches!(op, OpCode::Close | OpCode::Ping | OpCode::Pong) && (!fin || len7 > 125) {
        return Err(protocol_error("invalid WebSocket control frame header"));
    }

    if len7 == 126 {
        if buf.len() < idx + 2 {
            return Ok(None);
        }
        len7 = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as u64;
        idx += 2;
        if len7 < 126 {
            return Err(protocol_error("nonminimal WebSocket payload length"));
        }
    } else if len7 == 127 {
        if buf.len() < idx + 8 {
            return Ok(None);
        }
        let mut x = [0u8; 8];
        x.copy_from_slice(&buf[idx..idx + 8]);
        len7 = u64::from_be_bytes(x);
        idx += 8;

        if len7 < 65536 || len7 & (1u64 << 63) != 0 {
            return Err(protocol_error("invalid WebSocket 64-bit payload length"));
        }
    }

    let payload_len =
        usize::try_from(len7).map_err(|_| protocol_error("WebSocket payload length overflow"))?;
    if payload_len > max_frame {
        return Err(protocol_error("WebSocket frame exceeds configured limit"));
    }

    let mut mask_key = [0u8; 4];
    if masked {
        if buf.len() < idx + 4 {
            return Ok(None);
        }
        mask_key.copy_from_slice(&buf[idx..idx + 4]);
        idx += 4;
    }

    let frame_len = idx
        .checked_add(payload_len)
        .ok_or_else(|| protocol_error("WebSocket frame length overflow"))?;
    if buf.len() < frame_len {
        return Ok(None);
    }

    // Consume header bytes
    buf.advance(idx);

    let mut payload = buf.split_to(payload_len);
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask_key[i & 3];
    }
    let payload = payload.freeze();
    validate_control(op, &payload, fin)?;
    if op == OpCode::Text && fin {
        validate_text(&payload)?;
    }

    Ok(Some(Frame {
        fin,
        op,
        payload,
        masked,
        mask_key,
    }))
}

fn protocol_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_text(bytes: &[u8]) -> io::Result<()> {
    std::str::from_utf8(bytes)
        .map(|_| ())
        .map_err(|_| protocol_error("invalid WebSocket UTF-8"))
}

fn validate_control(op: OpCode, payload: &[u8], fin: bool) -> io::Result<()> {
    if !matches!(op, OpCode::Close | OpCode::Ping | OpCode::Pong) {
        return Ok(());
    }
    if !fin || payload.len() > 125 {
        return Err(protocol_error("invalid WebSocket control frame"));
    }
    if op == OpCode::Close && !payload.is_empty() {
        if payload.len() == 1 {
            return Err(protocol_error("incomplete WebSocket close code"));
        }
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) {
            return Err(protocol_error("invalid WebSocket close code"));
        }
        validate_text(&payload[2..])?;
    }
    Ok(())
}

/// Assemble complete data messages with explicit byte and fragment limits.
///
/// Keep one assembler per connection. `read`/`read_async` use the existing
/// session frame limit; this additional limit applies to the *whole message*.
/// Ping, Pong and Close are returned immediately, even between fragments.
/// The application must reply to Ping and perform the Close handshake itself.
/// Close or any error makes the assembler terminal; close the connection.
/// A receive timeout and application authorization remain the host's policy.
///
/// For a packet gateway, use its negotiated maximum packet size as
/// `max_message_size`, forward only Binary messages, and handle control frames
/// separately. Do not mix raw reads and assembler reads on one connection.
///
/// ```
/// use bytes::Bytes;
/// use sib::network::http::ws::{MessageAssembler, OpCode};
/// let mut messages = MessageAssembler::new(1024, 8)?;
/// assert!(messages.push_frame(OpCode::Binary, Bytes::from_static(b"pack"), false)?.is_none());
/// let message = messages.push_frame(OpCode::Continue, Bytes::from_static(b"et"), true)?;
/// assert_eq!(message, Some((OpCode::Binary, Bytes::from_static(b"packet"))));
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct MessageAssembler {
    max_message_size: usize,
    max_fragments: usize,
    opcode: Option<OpCode>,
    fragments: usize,
    data: BytesMut,
    stopped: bool,
}

impl MessageAssembler {
    pub fn new(max_message_size: usize, max_fragments: usize) -> io::Result<Self> {
        if max_fragments == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_fragments must be nonzero",
            ));
        }
        Ok(Self {
            max_message_size,
            max_fragments,
            opcode: None,
            fragments: 0,
            data: BytesMut::new(),
            stopped: false,
        })
    }

    fn stop(&mut self) {
        self.stopped = true;
        self.opcode = None;
        self.fragments = 0;
        self.data = BytesMut::new();
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket reader is closed",
            ));
        }
        Ok(())
    }

    /// Consume one decoded frame (the payload is already unmasked).
    /// `None` means a data message is still fragmented.
    /// Control frames do not count toward the data message's limits.
    pub fn push_frame(
        &mut self,
        op: OpCode,
        payload: Bytes,
        fin: bool,
    ) -> io::Result<Option<(OpCode, Bytes)>> {
        self.ensure_open()?;
        let result = self.push_inner(op, payload, fin);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn push_inner(
        &mut self,
        op: OpCode,
        payload: Bytes,
        fin: bool,
    ) -> io::Result<Option<(OpCode, Bytes)>> {
        validate_control(op, &payload, fin)?;
        if matches!(op, OpCode::Close | OpCode::Ping | OpCode::Pong) {
            if op == OpCode::Close {
                self.stop();
            }
            return Ok(Some((op, payload)));
        }
        match (self.opcode, op) {
            (None, OpCode::Continue) => {
                return Err(protocol_error("unexpected WebSocket continuation"));
            }
            (Some(_), OpCode::Text | OpCode::Binary) => {
                return Err(protocol_error("interleaved WebSocket data messages"));
            }
            _ => {}
        }
        let size = self
            .data
            .len()
            .checked_add(payload.len())
            .ok_or_else(|| protocol_error("WebSocket message length overflow"))?;
        if size > self.max_message_size || self.fragments >= self.max_fragments {
            return Err(protocol_error(
                "WebSocket message exceeds configured limits",
            ));
        }
        let opcode = self.opcode.unwrap_or(op);
        if self.opcode.is_none() && fin {
            if opcode == OpCode::Text {
                validate_text(&payload)?;
            }
            return Ok(Some((opcode, payload)));
        }
        self.opcode = Some(opcode);
        self.fragments += 1;
        self.data.extend_from_slice(&payload);
        if !fin {
            return Ok(None);
        }
        if opcode == OpCode::Text {
            validate_text(&self.data)?;
        }
        self.opcode = None;
        self.fragments = 0;
        Ok(Some((opcode, self.data.split().freeze())))
    }

    #[cfg(feature = "net-h1-server")]
    pub fn read<S: crate::network::http::session::Session>(
        &mut self,
        session: &mut S,
    ) -> io::Result<(OpCode, Bytes)> {
        self.ensure_open()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
        loop {
            let result = session
                .ws_read()
                .and_then(|(op, payload, fin)| self.push_frame(op, payload, fin));
            match result {
                Ok(Some(message)) => return Ok(message),
                Ok(None) => {}
                Err(error) => {
                    self.stop();
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, error));
                }
            }
        }
    }

    #[cfg(feature = "net-h2-server")]
    pub async fn read_async<S: crate::network::http::session::Session>(
        &mut self,
        session: &mut S,
    ) -> io::Result<(OpCode, Bytes)> {
        self.ensure_open()?;
        loop {
            let result = session
                .ws_read_async()
                .await
                .and_then(|(op, payload, fin)| self.push_frame(op, payload, fin));
            match result {
                Ok(Some(message)) => return Ok(message),
                Ok(None) => {}
                Err(error) => {
                    self.stop();
                    return Err(error);
                }
            }
        }
    }
}

/// Encode a WS frame. `mask: None` means unmasked (server->client).
/// If `Some(mask_key)`, payload will be masked (client->server use).
pub(crate) fn encode_frame(op: OpCode, payload: &Bytes, fin: bool, mask: Option<[u8; 4]>) -> Bytes {
    let masked = mask.is_some();
    let mask_key = mask.unwrap_or([0u8; 4]);

    // 2 (base) + 8 (len) + 4 (mask) + payload
    let mut out = BytesMut::with_capacity(2 + 8 + 4 + payload.len());

    let b0 = (if fin { 0x80 } else { 0x00 }) | op.to_u8();
    out.put_u8(b0);

    let len = payload.len();
    if len <= 125 {
        out.put_u8((if masked { 0x80 } else { 0x00 }) | (len as u8));
    } else if len <= 0xFFFF {
        out.put_u8((if masked { 0x80 } else { 0x00 }) | 126);
        out.put_u16(len as u16);
    } else {
        out.put_u8((if masked { 0x80 } else { 0x00 }) | 127);
        out.put_u64(len as u64);
    }

    if masked {
        out.put_slice(&mask_key);
        // masked payload
        let mut tmp = payload.to_vec();
        for (i, b) in tmp.iter_mut().enumerate() {
            *b ^= mask_key[i & 3];
        }
        out.put_slice(&tmp);
    } else {
        out.put_slice(payload);
    }

    out.freeze()
}

/// Read a client-to-server frame. On an error, the caller must close the connection.
#[cfg(feature = "net-h2-server")]
pub async fn ws_read_from_io<R>(
    io: &mut R,
    scratch: &mut BytesMut,
    max_frame: usize,
) -> io::Result<(OpCode, Bytes, bool)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    loop {
        if let Some(frame) = try_parse_frame(scratch, max_frame)? {
            return Ok((frame.op, frame.payload, frame.fin));
        }

        // Pull more bytes (reuse a stack buffer, no heap vec allocation per read)
        let mut tmp = [0u8; 8 * 1024];
        let n = io.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws eof"));
        }
        scratch.extend_from_slice(&tmp[..n]);

        // Hard cap scratch to avoid memory blow-ups
        if scratch.len() > max_frame.saturating_add(64 * 1024) {
            return Err(io_other("ws buffered data too large"));
        }
    }
}

#[cfg(feature = "net-h2-server")]
pub async fn ws_write_to_io<W>(io: &mut W, op: OpCode, payload: Bytes, fin: bool) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Server-to-client: unmasked frames
    let frame = encode_frame(op, &payload, fin, None);
    io.write_all(&frame).await?;
    io.flush().await?;
    Ok(())
}

#[cfg(feature = "net-h2-server")]
pub(crate) fn close_payload(code: u16, reason: &str) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + reason.len());
    out.put_u16(code);
    out.put_slice(reason.as_bytes());
    out.freeze()
}

#[cfg(test)]
#[path = "../../../tests/unit/network/http/ws_tests.rs"]
mod tests;
