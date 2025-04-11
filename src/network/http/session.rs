use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::SinkExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use pingora::{http::ResponseHeader, protocols::http::ServerSession};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio_quiche::{
    buf_factory::BufFactory,
    http3::{
        H3AuditStats,
        driver::{InboundFrameStream, OutboundFrame, OutboundFrameSender},
    },
    quiche::h3::{self, NameValue},
};

use crate::s_error;

const MAX_PATH_LENGTH: usize = 1024;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB limit
const MAX_WS_PAYLOAD_SIZE: usize = 64 * 1024 * 1024; // 64MB limit

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WsOpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

#[derive(Debug, Clone, Copy)]
pub enum WsCloseCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    InvalidPayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalServerError = 1011,
}

impl WsCloseCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Supported HTTPMethod. See the definitions in RFC2616 5.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HTTPMethod {
    Get,
    Post,
    Options,
    Delete,
    Head,
    Connect,
    ConnectUdp,
    Put,
    Trace,
    Patch,
    Sub,
    Pub,
    UnSub,
    UnDefined,
}

impl std::fmt::Display for HTTPMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let method_str = match self {
            HTTPMethod::Get => "GET",
            HTTPMethod::Post => "POST",
            HTTPMethod::Options => "OPTIONS",
            HTTPMethod::Delete => "DELETE",
            HTTPMethod::Head => "HEAD",
            HTTPMethod::Connect => "CONNECT",
            HTTPMethod::ConnectUdp => "CONNECT-UDP",
            HTTPMethod::Put => "PUT",
            HTTPMethod::Trace => "TRACE",
            HTTPMethod::Patch => "PATCH",
            HTTPMethod::Sub => "SUB",
            HTTPMethod::Pub => "PUB",
            HTTPMethod::UnSub => "UNSUB",
            HTTPMethod::UnDefined => "UNDEFINED",
        };
        write!(f, "{}", method_str)
    }
}

impl std::str::FromStr for HTTPMethod {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(match name {
            "GET" => HTTPMethod::Get,
            "POST" => HTTPMethod::Post,
            "OPTIONS" => HTTPMethod::Options,
            "DELETE" => HTTPMethod::Delete,
            "HEAD" => HTTPMethod::Head,
            "CONNECT" => HTTPMethod::Connect,
            "CONNECT-UDP" => HTTPMethod::ConnectUdp,
            "PUT" => HTTPMethod::Put,
            "TRACE" => HTTPMethod::Trace,
            "PATCH" => HTTPMethod::Patch,
            "SUB" => HTTPMethod::Sub,
            "PUB" => HTTPMethod::Pub,
            "UNSUB" => HTTPMethod::UnSub,
            _ => HTTPMethod::UnDefined,
        })
    }
}

pub struct H3Session {
    _stream_id: u64,
    headers: HeaderMap,
    in_frame: InboundFrameStream,
    out_frame: OutboundFrameSender,
    read_fin: bool,
    _h3_audit_stats: Arc<H3AuditStats>,
}

pub struct Session {
    method: HTTPMethod,
    path: String,
    host: String,
    queries: HashMap<String, Vec<String>>,
    res_headers: http::HeaderMap,
    h2: Option<ServerSession>,
    h3: Option<H3Session>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            method: HTTPMethod::UnDefined,
            path: "".to_owned(),
            host: "".to_owned(),
            queries: HashMap::new(),
            res_headers: http::HeaderMap::new(),
            h2: None,
            h3: None,
        }
    }
}

impl Session {
    pub(crate) fn new_h2(session: ServerSession) -> Self {
        let req_summary = session.request_summary();
        let mut parts = req_summary.split(", ");
        // Extract Method and Path (first part)
        let mut first_part = parts.next().unwrap_or("").split_whitespace();
        let method = first_part.next().unwrap_or("");
        let mut path = first_part.next().unwrap_or("").to_string();

        // Extract Host header (second part)
        let host = parts
            .find(|s| s.starts_with("Host: "))
            .map(|s| s.trim_start_matches("Host: ").trim())
            .unwrap_or("");

        path = Self::normalize_slashes(&path);
        let queries = Self::parse_query_params(&mut path);

        Self {
            method: HTTPMethod::from_str(method).unwrap_or(HTTPMethod::UnDefined),
            path: path.to_string(),
            host: host.to_string(),
            queries,
            h2: Some(session),
            ..Default::default()
        }
    }

    pub(crate) fn new_h3(
        stream_id: u64,
        headers: Vec<h3::Header>,
        send: OutboundFrameSender,
        recv: InboundFrameStream,
        read_fin: bool,
        h3_audit_stats: Arc<H3AuditStats>,
    ) -> Self {
        let mut method: String = "".to_owned();
        let mut path: String = "".to_owned();
        let mut host: String = "".to_owned();
        let mut http_headers = HeaderMap::new();

        for header in headers {
            // Extract pseudo-headers
            match header.name() {
                b":method" => method = String::from_utf8_lossy(header.value()).to_string(),
                b":path" => path = String::from_utf8_lossy(header.value()).to_string(),
                b"host" => host = String::from_utf8_lossy(header.value()).to_string(),
                b":authority" if host.is_empty() => {
                    host = String::from_utf8_lossy(header.value()).to_string();
                }
                _ => {
                    // Parse header name safely
                    let name = match HeaderName::from_bytes(header.name()) {
                        Ok(n) => n,
                        Err(_) => {
                            s_error!("Invalid header name: {:?}", header.name());
                            continue; // Skip invalid headers
                        }
                    };

                    // Parse header value safely
                    let value = match HeaderValue::from_bytes(header.value()) {
                        Ok(v) => v,
                        Err(_) => {
                            s_error!("Invalid header value for {:?}: {:?}", name, header.value());
                            continue; // Skip invalid headers
                        }
                    };

                    http_headers.insert(name, value.clone());
                }
            }
        }

        // Normalize path by removing consecutive slashes
        path = Self::normalize_slashes(&path);
        let queries = Self::parse_query_params(&mut path);

        Self {
            method: HTTPMethod::from_str(&method).unwrap_or(HTTPMethod::UnDefined),
            path,
            host,
            queries,
            h3: Some(H3Session {
                _stream_id: stream_id,
                headers: http_headers,
                in_frame: recv,
                out_frame: send,
                read_fin,
                _h3_audit_stats: h3_audit_stats,
            }),
            ..Default::default()
        }
    }

    /// Upgrades the session to a WebSocket connection.
    // pub async fn upgrade_to_websocket(&mut self) -> anyhow::Result<()> {
    //     if let Some(h2) = &mut self.h2 {
    //         // Check if the request is a WebSocket upgrade request
    //         if h2
    //             .get_header(http::header::UPGRADE)
    //             .map(|v| v.as_bytes() == b"websocket")
    //             .unwrap_or(false)
    //         {
    //             let key = h2
    //                 .get_header(http::header::SEC_WEBSOCKET_KEY)
    //                 .map(|v| v.as_bytes())
    //                 .unwrap_or_default();

    //             let mut hasher = Sha256::new();
    //             hasher.update(key);
    //             hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    //             let result = hasher.finalize();
    //             let sec_ws_accept_value = base64::engine::general_purpose::STANDARD.encode(result);

    //             // Perform the WebSocket handshake
    //             let mut response = ResponseHeader::build(101, None)?;
    //             response.append_header(http::header::UPGRADE, "websocket")?;
    //             response.append_header(http::header::CONNECTION, "Upgrade")?;
    //             response.append_header(http::header::SEC_WEBSOCKET_ACCEPT, sec_ws_accept_value)?;
    //             h2.write_response_header(Box::new(response)).await?;

    //             return Ok(());
    //         }
    //     }
    //     anyhow::bail!("Not a WebSocket upgrade request");
    // }

    /// Normalizes a path by removing duplicate `/` and preventing traversal attacks.
    fn normalize_slashes(path: &str) -> String {
        // Truncate excessively long paths to prevent stack overflow attacks
        let truncated = if path.len() > MAX_PATH_LENGTH {
            &path[..MAX_PATH_LENGTH]
        } else {
            path
        };

        let mut normalized = PathBuf::new();
        for component in Path::new(truncated).components() {
            match component {
                std::path::Component::Normal(c) => {
                    if let Some(s) = c.to_str() {
                        normalized.push(s); // Append only valid parts
                    }
                }
                std::path::Component::RootDir => normalized.push("/"),
                _ => {} // Ignore `..` to prevent directory traversal attacks
            }
        }

        normalized.to_string_lossy().into_owned() // Convert safely
    }

    /// Decodes percent-encoded characters in a string (e.g., `%20` -> ` `)
    fn percent_decode(input: &str) -> String {
        let mut decoded = String::new();
        let mut chars = input.chars();

        while let Some(c) = chars.next() {
            if c == '%' {
                if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                    if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                        decoded.push(byte as char);
                        continue;
                    }
                }
            }
            decoded.push(c);
        }
        decoded
    }

    /// Parses query parameters from a mutable path and removes the query part and prevents query manipulation attacks as well.
    fn parse_query_params(path: &mut String) -> HashMap<String, Vec<String>> {
        if let Some(pos) = path.find('?') {
            let query = path[pos + 1..].to_string();
            path.truncate(pos); // Remove query string from path

            let mut params = HashMap::new();
            for pair in query.split('&') {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().map(Self::percent_decode).unwrap_or_default();
                let value = parts.next().map(Self::percent_decode).unwrap_or_default();

                if !key.is_empty() {
                    params.entry(key).or_insert_with(Vec::new).push(value);
                }
            }
            params
        } else {
            HashMap::new() // No query parameters
        }
    }

    pub fn get_query_param(&self, key: &str) -> Option<Vec<String>> {
        self.queries.get(key).cloned()
    }

    pub fn get_query_params(&self) -> &HashMap<String, Vec<String>> {
        &self.queries
    }

    pub fn get_method(&self) -> &HTTPMethod {
        &self.method
    }

    pub fn get_path(&self) -> &str {
        self.path.as_str()
    }

    pub fn get_host(&self) -> &str {
        self.host.as_str()
    }

    pub fn get_is_h1(&self) -> bool {
        self.h2
            .as_ref()
            .map(|session| !session.is_http2())
            .unwrap_or(false)
    }

    pub fn get_is_h2(&self) -> bool {
        self.h2
            .as_ref()
            .map(|session| session.is_http2())
            .unwrap_or(false)
    }

    pub fn get_is_h3(&self) -> bool {
        self.h3.is_some()
    }

    pub async fn read_ws_msg(&mut self, timeout: Duration) -> anyhow::Result<(Bytes, WsOpCode)> {
        if let Some(h2) = &mut self.h2 {
            let mut full_payload = Vec::new();
            let mut message_opcode: Option<WsOpCode> = None;

            loop {
                // Read raw frame
                let body_opt = pingora::time::timeout(timeout, h2.read_request_body()).await??;
                let buf =
                    body_opt.ok_or_else(|| anyhow::anyhow!("Failed to read WebSocket frame"))?;
                let mut cursor = std::io::Cursor::new(&buf);

                // FIN + OPCODE
                let b0 = cursor.get_u8();
                let fin = b0 & 0b1000_0000 != 0;
                let opcode_raw = b0 & 0x0F;
                let opcode = match opcode_raw {
                    0x0 => WsOpCode::Continuation,
                    0x1 => WsOpCode::Text,
                    0x2 => WsOpCode::Binary,
                    0x8 => WsOpCode::Close,
                    0x9 => WsOpCode::Ping,
                    0xA => WsOpCode::Pong,
                    code => anyhow::bail!("Unsupported opcode: {}", code),
                };

                // LEN + MASK
                let b1 = cursor.get_u8();
                let masked = b1 & 0x80 != 0;
                let mut payload_len = (b1 & 0x7F) as usize;

                if payload_len == 126 {
                    payload_len = cursor.get_u16() as usize;
                } else if payload_len == 127 {
                    payload_len = cursor.get_u64() as usize;
                }

                // Validate control frame size
                if matches!(opcode, WsOpCode::Ping | WsOpCode::Pong | WsOpCode::Close)
                    && payload_len > 125
                {
                    anyhow::bail!("Control frame payload too large");
                }

                // Mask key
                let mask_key = if masked {
                    let mut key = [0u8; 4];
                    cursor.copy_to_slice(&mut key);
                    Some(key)
                } else {
                    None
                };

                // Payload
                if cursor.remaining() < payload_len {
                    anyhow::bail!("Invalid frame length");
                }

                let mut payload = BytesMut::with_capacity(payload_len);
                payload.resize(payload_len, 0);
                cursor.copy_to_slice(&mut payload[..]);

                if let Some(mask) = mask_key {
                    for i in 0..payload_len {
                        payload[i] ^= mask[i % 4];
                    }
                }

                // Handle control frames immediately
                match opcode {
                    WsOpCode::Ping => {
                        let pong = Self::ws_frame(WsOpCode::Pong, &payload.freeze(), true);
                        h2.write_response_body(pong, false).await?;
                        continue; // Continue reading next frame
                    }

                    WsOpCode::Pong => {
                        continue; // Ignore pong frames
                    }

                    WsOpCode::Close => {
                        let code = if payload.len() >= 2 {
                            u16::from_be_bytes([payload[0], payload[1]])
                        } else {
                            1005 // No status code
                        };
                        let reason = if payload.len() > 2 {
                            String::from_utf8_lossy(&payload[2..]).to_string()
                        } else {
                            String::new()
                        };
                        anyhow::bail!(
                            "Connection closed by peer (code {}, reason: '{}')",
                            code,
                            reason
                        );
                    }

                    WsOpCode::Text | WsOpCode::Binary => {
                        if message_opcode.is_none() {
                            message_opcode = Some(opcode);
                        }
                        full_payload.extend(payload);

                        if full_payload.len() > MAX_WS_PAYLOAD_SIZE {
                            anyhow::bail!("Fragmented WebSocket message too large (>64MB)");
                        }
                    }

                    WsOpCode::Continuation => {
                        if message_opcode.is_none() {
                            anyhow::bail!("Unexpected continuation frame");
                        }
                        full_payload.extend(payload);

                        if full_payload.len() > MAX_WS_PAYLOAD_SIZE {
                            anyhow::bail!("Fragmented WebSocket message too large (>64MB)");
                        }
                    }
                }

                if fin {
                    let final_opcode =
                        message_opcode.ok_or_else(|| anyhow::anyhow!("Empty fragmented frame"))?;
                    return Ok((Bytes::from(full_payload), final_opcode));
                }
            }
        }

        anyhow::bail!("WebSocket session not available");
    }

    pub fn read_req_header(&self, key: http::HeaderName) -> Option<&http::HeaderValue> {
        if let Some(h2) = &self.h2 {
            return h2.get_header(key);
        } else if let Some(h3) = &self.h3 {
            return h3.headers.get(&key);
        }
        None
    }

    pub fn read_req_headers(&self) -> Option<&http::HeaderMap> {
        self.h2
            .as_ref()
            .map(|h2| &h2.req_header().headers)
            .or_else(|| self.h3.as_ref().map(|h3| &h3.headers))
    }

    pub async fn read_req_body(&mut self, timeout: Duration) -> anyhow::Result<Option<Bytes>> {
        if let Some(h2) = &mut self.h2 {
            let body = match pingora::time::timeout(timeout, h2.read_request_body()).await {
                Ok(Ok(b)) => {
                    if let Some(ref b) = b {
                        if b.len() > MAX_BODY_SIZE {
                            anyhow::bail!(
                                "Request body too large ({}>{} bytes)",
                                b.len(),
                                MAX_BODY_SIZE
                            );
                        }
                    }
                    b
                }
                _ => {
                    anyhow::bail!("Got timeout while reading h2 request body");
                }
            };
            return Ok(body);
        } else if let Some(h3) = &mut self.h3 {
            // Properly read the h3 body in a non-blocking manner
            if !h3.read_fin {
                let body = match pingora::time::timeout(timeout, async move {
                    let mut body = bytes::BytesMut::new();
                    while let Some(chunk) = h3.in_frame.recv().await {
                        match chunk {
                            tokio_quiche::http3::driver::InboundFrame::Body(data, fin) => {
                                body.extend_from_slice(&data);
                                if fin || body.len() > MAX_BODY_SIZE {
                                    break; // End of stream or too large body
                                }
                            }
                            _ => break, // Stop on unexpected frame
                        }
                    }
                    body.freeze()
                })
                .await
                {
                    Ok(body) => body,
                    _ => {
                        anyhow::bail!("Got timeout while reading h3 request body");
                    }
                };

                return Ok(Some(body));
            }
        }
        Ok(None)
    }

    pub fn append_header(&mut self, name: &HeaderName, value: HeaderValue) {
        self.res_headers.append(name, value);
    }

    pub fn append_header_str(&mut self, name: &str, value: &str) -> anyhow::Result<()> {
        let header_name = HeaderName::from_str(name)?;
        let header_value = HeaderValue::from_str(value)?;
        self.res_headers.append(header_name, header_value);
        Ok(())
    }

    pub fn insert_header(&mut self, name: &HeaderName, value: HeaderValue) {
        self.res_headers.insert(name, value);
    }

    pub fn insert_header_str(&mut self, name: &str, value: &str) -> anyhow::Result<()> {
        let header_name = HeaderName::from_str(name)?;
        let header_value = HeaderValue::from_str(value)?;
        self.res_headers.insert(header_name, header_value);
        Ok(())
    }

    pub fn append_headers(&mut self, items: &[(HeaderName, HeaderValue)]) {
        for (name, value) in items {
            self.res_headers.append(name, value.clone());
        }
    }

    pub fn append_headers_str(&mut self, items: &[(&str, &str)]) -> anyhow::Result<()> {
        for (name, value) in items {
            let header_name = HeaderName::from_str(name)?;
            let header_value = HeaderValue::from_str(value)?;
            self.res_headers.append(header_name, header_value);
        }
        Ok(())
    }

    pub async fn send_status_eom(&mut self, status_code: http::StatusCode) -> anyhow::Result<()> {
        self.send_status(status_code).await?;
        self.send_eom().await
    }

    pub async fn send_status(&mut self, status_code: http::StatusCode) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            let mut response = ResponseHeader::build_no_case(status_code, None)?;

            for (name, value) in &self.res_headers {
                response.append_header(name, value)?;
            }

            h2.write_response_header(Box::new(response)).await?;
        } else if let Some(h3) = &mut self.h3 {
            let mut res_headers = Vec::with_capacity(10); // Preallocate
            res_headers.push(h3::Header::new(b":status", status_code.as_str().as_bytes()));

            res_headers.extend(self.res_headers.iter().filter_map(|(name, value)| {
                value.to_str().ok().map(|value_str| {
                    h3::Header::new(name.as_str().as_bytes(), value_str.as_bytes())
                })
            }));

            h3.out_frame
                .send(OutboundFrame::Headers(res_headers))
                .await?;
        }
        Ok(())
    }

    pub async fn send_body(&mut self, body: bytes::Bytes, finish: bool) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            h2.write_response_body(body, false).await?;
        } else if let Some(h3) = &mut self.h3 {
            if let Err(e) = h3
                .out_frame
                .send(OutboundFrame::body(
                    BufFactory::buf_from_slice(&body),
                    finish,
                ))
                .await
            {
                anyhow::bail!("Failed to send response body: {:?}", e);
            }
        }
        Ok(())
    }

    pub async fn send_eom(&mut self) -> anyhow::Result<()> {
        if let Some(h2) = self.h2.take() {
            h2.finish().await.ok();
        } else if let Some(h3) = &mut self.h3 {
            h3.out_frame.close();
        }
        Ok(())
    }

    pub async fn send_ws_msg(
        &mut self,
        opcode: WsOpCode,
        payload: &Bytes,
        fin: bool,
    ) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            // Send the frame
            h2.write_response_body(Self::ws_frame(opcode, payload, fin), false)
                .await?;
            Ok(())
        } else {
            anyhow::bail!("WebSocket session not available");
        }
    }

    pub async fn send_ws_close(&mut self, code: WsCloseCode, reason: &str) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            let mut payload = BytesMut::with_capacity(2 + reason.len());
            payload.put_u16(code.as_u16()); // Close code
            payload.put_slice(reason.as_bytes()); // Reason

            let payload = payload.freeze();
            h2.write_response_body(Self::ws_frame(WsOpCode::Close, &payload, true), false)
                .await?;
            Ok(())
        } else {
            anyhow::bail!("WebSocket session not available");
        }
    }

    fn ws_frame(opcode: WsOpCode, payload: &Bytes, fin: bool) -> Bytes {
        // Estimate size: 2 + len + extended len + payload
        let estimated_capacity = 2 + payload.len() + 8;
        let mut frame = BytesMut::with_capacity(estimated_capacity);

        // First byte: FIN + OpCode
        let opcode_val = match opcode {
            WsOpCode::Continuation => 0x0,
            WsOpCode::Text => 0x1,
            WsOpCode::Binary => 0x2,
            WsOpCode::Close => 0x8,
            WsOpCode::Ping => 0x9,
            WsOpCode::Pong => 0xA,
        };
        let first_byte = if fin { 0x80 | opcode_val } else { opcode_val };
        frame.put_u8(first_byte);

        // Second byte: No mask
        let len = payload.len();
        if len < 126 {
            frame.put_u8(len as u8);
        } else if len <= u16::MAX as usize {
            frame.put_u8(126);
            frame.put_u16(len as u16);
        } else {
            frame.put_u8(127);
            frame.put_u64(len as u64);
        }

        // Payload
        frame.put_slice(payload);

        frame.freeze() // Converts BytesMut → Bytes
    }
}
