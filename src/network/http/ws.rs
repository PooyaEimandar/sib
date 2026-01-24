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

/// Try parse one complete WS frame from `buf`.
/// If incomplete, returns Ok(None).
pub(crate) fn try_parse_frame(buf: &mut BytesMut) -> io::Result<Option<Frame>> {
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

    let mut idx = 2usize;
    let mut len7 = (b1 & 0x7F) as u64;

    if len7 == 126 {
        if buf.len() < idx + 2 {
            return Ok(None);
        }
        len7 = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as u64;
        idx += 2;
    } else if len7 == 127 {
        if buf.len() < idx + 8 {
            return Ok(None);
        }
        let mut x = [0u8; 8];
        x.copy_from_slice(&buf[idx..idx + 8]);
        len7 = u64::from_be_bytes(x);
        idx += 8;

        // Most-significant bit must be 0 (RFC6455).
        if (len7 & (1u64 << 63)) != 0 {
            return Err(io_other("ws invalid 64-bit length"));
        }

        // Avoid absurd sizes
        if len7 > (usize::MAX as u64) {
            return Err(io_other("ws payload too large"));
        }
    }

    let payload_len = len7 as usize;

    // Control frames: FIN must be set and len <= 125
    if matches!(op, OpCode::Close | OpCode::Ping | OpCode::Pong) {
        if !fin {
            return Err(io_other("ws control frame must not be fragmented"));
        }
        if payload_len > 125 {
            return Err(io_other("ws control frame too large"));
        }
    }

    let mut mask_key = [0u8; 4];
    if masked {
        if buf.len() < idx + 4 {
            return Ok(None);
        }
        mask_key.copy_from_slice(&buf[idx..idx + 4]);
        idx += 4;
    }

    if buf.len() < idx + payload_len {
        return Ok(None);
    }

    // Consume header bytes
    buf.advance(idx);

    // Consume payload
    let mut payload = buf.split_to(payload_len).freeze();

    // Unmask if needed
    if masked && payload_len > 0 {
        let mut tmp = payload.to_vec();
        for (i, b) in tmp.iter_mut().enumerate() {
            *b ^= mask_key[i & 3];
        }
        payload = Bytes::from(tmp);
    }

    Ok(Some(Frame {
        fin,
        op,
        payload,
        masked,
        mask_key,
    }))
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
        if let Some(frame) = try_parse_frame(scratch)? {
            if frame.payload.len() > max_frame {
                return Err(io_other("ws frame too large"));
            }
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
