// Frame codec (sync)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Continue = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

// Shared helpers
pub(crate) fn compute_accept(sec_key: &http::HeaderValue) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use sha1::{Digest, Sha1};

    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut sha = Sha1::new();
    sha.update(sec_key.as_bytes());
    sha.update(WS_GUID.as_bytes());
    B64.encode(sha.finalize())
}
