#[cfg(feature = "rt-tokio")]
pub use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(all(feature = "rt-glommio", not(feature = "rt-tokio")))]
pub use tokio::io::{AsyncRead, AsyncWrite};

pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Shared helpers
pub fn compute_accept(sec_key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};

    let mut sha = Sha1::new();
    sha.update(sec_key.as_bytes());
    sha.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

// Frame codec
#[derive(Debug, Clone, Copy)]
pub enum OpCode {
    Continue = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

pub(crate) fn read_frame_sync<R: std::io::Read>(
    mut r: R,
    scratch: &mut Vec<u8>,
) -> std::io::Result<(OpCode, Vec<u8>, bool)> {
    let mut h2 = [0u8; 2];
    read_exact_blocking(&mut r, &mut h2)?;
    let fin = (h2[0] & 0x80) != 0;
    let opcode = match h2[0] & 0x0F {
        0x0 => OpCode::Continue,
        0x1 => OpCode::Text,
        0x2 => OpCode::Binary,
        0x8 => OpCode::Close,
        0x9 => OpCode::Ping,
        0xA => OpCode::Pong,
        x => return Err(std::io::Error::other(format!("unsupported WS opcode {x}"))),
    };
    let masked = (h2[1] & 0x80) != 0;
    let mut len = (h2[1] & 0x7F) as u64;
    if len == 126 {
        let mut e = [0; 2];
        read_exact_blocking(&mut r, &mut e)?;
        len = u16::from_be_bytes(e) as u64;
    } else if len == 127 {
        let mut e = [0; 8];
        read_exact_blocking(&mut r, &mut e)?;
        len = u64::from_be_bytes(e);
    }
    if !masked {
        return Err(std::io::Error::other("client frame not masked"));
    }
    let mut mask = [0u8; 4];
    read_exact_blocking(&mut r, &mut mask)?;
    scratch.resize(len as usize, 0);
    if len > 0 {
        read_exact_blocking(&mut r, scratch)?;
        for (i, b) in scratch.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((opcode, scratch.clone(), fin))
}

pub(crate) fn write_frame_sync<W: std::io::Write>(
    mut w: W,
    op: OpCode,
    payload: &[u8],
) -> std::io::Result<()> {
    let fin = 0x80u8;
    let mut hdr = vec![fin | (op as u8), 0u8];
    if payload.len() < 126 {
        hdr[1] = payload.len() as u8;
    } else if payload.len() <= 0xFFFF {
        hdr[1] = 126;
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        hdr[1] = 127;
        hdr.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    w.write_all(&hdr)?;
    w.write_all(payload)
}

#[inline]
fn read_exact_blocking<R: std::io::Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                ));
            }
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                may::coroutine::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(crate) async fn read_frame_async<R: AsyncRead + Unpin>(
    mut r: R,
    scratch: &mut Vec<u8>,
) -> std::io::Result<(OpCode, Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;
    let mut h2 = [0u8; 2];
    r.read_exact(&mut h2).await?;
    let fin = (h2[0] & 0x80) != 0;
    let opcode = match h2[0] & 0x0F {
        0x0 => OpCode::Continue,
        0x1 => OpCode::Text,
        0x2 => OpCode::Binary,
        0x8 => OpCode::Close,
        0x9 => OpCode::Ping,
        0xA => OpCode::Pong,
        x => return Err(std::io::Error::other(format!("unsupported opcode {x}"))),
    };
    let masked = (h2[1] & 0x80) != 0;
    if !masked {
        return Err(std::io::Error::other("client frame not masked"));
    }
    let mut len = (h2[1] & 0x7F) as u64;
    if len == 126 {
        let mut e = [0; 2];
        r.read_exact(&mut e).await?;
        len = u16::from_be_bytes(e) as u64;
    } else if len == 127 {
        let mut e = [0; 8];
        r.read_exact(&mut e).await?;
        len = u64::from_be_bytes(e);
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask).await?;
    scratch.resize(len as usize, 0);
    if len > 0 {
        r.read_exact(scratch).await?;
        for (i, b) in scratch.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((opcode, scratch.clone(), fin))
}

pub(crate) async fn write_frame_async<W: AsyncWrite + Unpin>(
    mut w: W,
    op: OpCode,
    payload: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let fin = 0x80u8;
    let mut hdr = vec![fin | (op as u8), 0u8];
    if payload.len() < 126 {
        hdr[1] = payload.len() as u8;
    } else if payload.len() <= 0xFFFF {
        hdr[1] = 126;
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        hdr[1] = 127;
        hdr.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    w.write_all(&hdr).await?;
    w.write_all(payload).await?;
    w.flush().await
}
