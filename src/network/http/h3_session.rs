use std::{collections::HashMap, net::SocketAddr, time::Duration};
use crate::network::http::{session::Session, util::{HttpHeader, Status}};
use bytes::Bytes;
use quiche::h3::{Header, NameValue};

#[derive(Default)]
pub enum BodySource {
    #[default]
    Empty,
    Bytes(bytes::Bytes),
    
    #[cfg(feature = "net-file-server")]
    Mmap { map: std::sync::Arc<memmap2::Mmap>, lo: usize, hi: usize },
}

impl BodySource {
    #[inline] 
    pub fn len(&self) -> usize {
        match self {
            BodySource::Empty => 0,
            BodySource::Bytes(b) => b.len(),

            #[cfg(feature = "net-file-server")]
            BodySource::Mmap { lo, hi, .. } => hi.saturating_sub(*lo),
        }
    }

    #[inline] 
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline] 
    pub fn chunk_at(&self, off: usize, cap: usize) -> &[u8] {
        match self {
            BodySource::Empty => &[],
            BodySource::Bytes(b) => {
                let end = (off + cap).min(b.len());
                if off >= end { &[] } else { &b[off..end] }
            }

            #[cfg(feature = "net-file-server")]
            BodySource::Mmap { map, lo, hi } => {
                let base = *lo + off;
                if base >= *hi { return &[]; }
                let end = (base + cap).min(*hi);
                &map[base..end]
            }
        }
    }
}

pub(crate) struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,
    pub body: BodySource,
    pub written: usize,
}

pub(crate) struct H3Session {
    pub peer_addr: SocketAddr,
    pub conn: quiche::Connection,
    pub http3_conn: Option<quiche::h3::Connection>,
    pub req_headers: Option<Vec<quiche::h3::Header>>,
    pub req_body_map: HashMap<u64, Vec<u8>>,
    pub current_stream_id: Option<u64>,
    pub rsp_headers: Vec<quiche::h3::Header>,
    pub rsp_body: BodySource, 
    pub partial_responses: HashMap<u64, PartialResponse>,
}

impl Session for H3Session {
    #[inline]
    fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }

    #[inline]
    fn is_h3(&self) -> bool {
        self.http3_conn.is_some()
    }

    #[inline]
    fn req_method(&self) -> Option<&str> {
        if let Some(headers) = &self.req_headers {
            headers.iter().find(|h| h.name() == b":method").and_then(|h| std::str::from_utf8(h.value()).ok())
        } else {
            None
        }
    }

    #[inline]
    fn req_path(&self) -> Option<&str> {
        if let Some(headers) = &self.req_headers {
            headers.iter().find(|h| h.name() == b":path").and_then(|h| std::str::from_utf8(h.value()).ok())
        } else {
            None
        }
    }

    #[inline]
    fn req_http_version(&self) -> Option<u8> {
        Some(3)
    }

    /// HTTP/3 headers are not compatible with httparse::Header, use req_headers_vec instead
    #[inline]
    fn req_headers(&self) -> &[httparse::Header<'_>] {
        //assert!(false, "HTTP/3 headers are not compatible with httparse::Header, use req_headers_vec instead");
        &[]
    }

    #[inline]
    fn req_headers_vec(&self) -> Vec<httparse::Header<'_>> {
        if let Some(headers) = &self.req_headers {
            headers
            .iter()
            .filter_map(|h| {
                if let Ok(name_str) = std::str::from_utf8(h.name()) {
                    Some(httparse::Header {
                        name: name_str,
                        value: h.value(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
        }
        else {
            vec![]
        }
    }

    #[inline]
    fn req_header(&self, header: &HttpHeader) -> std::io::Result<&str> {
        self.req_header_str(header.as_str())
    }

    #[inline]
    fn req_header_str(&self, name: &str) -> std::io::Result<&str> {
        if let Some(headers) = &self.req_headers {
            let name_bytes = name.as_bytes();
            headers
                .iter()
                .find(|h| h.name() == name_bytes)
                .map(|h| std::str::from_utf8(h.value()).map_err(std::io::Error::other))
                .transpose()?
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Header not found"))
        }
        else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No h3 request headers available"))
        }
    }

    #[inline]
    fn req_body(&mut self, _timeout: Duration) -> std::io::Result<&[u8]> {
        if let Some(id) = self.current_stream_id {
            if let Some(body) = self.req_body_map.get(&id) {
                return Ok(body);
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No h3 request body available"))
    }

    #[inline]
    fn status_code(&mut self, status: Status) -> &mut Self {
        let (code, _reason) = status.as_parts();
        self.rsp_headers[0] = Header::new(b":status", code.as_bytes());
        self
    }

    #[inline]
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        let name_bytes = name.as_bytes();
        let value_bytes = value.as_bytes();

        // If a header with the same name exists, remove it
        if let Some(pos) = self.rsp_headers.iter().position(|h| h.name() == name_bytes) {
            self.rsp_headers.remove(pos);
        }
        self.rsp_headers.push(Header::new(name_bytes, value_bytes));
        Ok(self)
    }

    #[inline]
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header_str(n, v)?;
        }
        Ok(self)
    }

    #[inline]
    fn header(&mut self, name: &HttpHeader, value: &str) -> std::io::Result<&mut Self> {
        self.header_str(name.as_str(), value)
    }

    #[inline]
    fn headers(&mut self, header_val: &[(HttpHeader, &str)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header(n, v)?;
        }
        Ok(self)
    }

    #[inline]
    fn headers_vec(&mut self, header_val: &[(HttpHeader, String)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header(n, v)?;
        }
        Ok(self)
    }

    #[inline]
    fn body(&mut self, data: &Bytes) -> &mut Self {
        self.rsp_body = BodySource::Bytes(data.clone());
        self
    }

    #[inline]
    fn body_slice(&mut self, body: &[u8]) -> &mut Self {
        self.rsp_body = BodySource::Bytes(Bytes::copy_from_slice(body));
        self
    }

    #[inline]
    fn body_static(&mut self, body: &'static str) -> &mut Self {
        self.rsp_body = BodySource::Bytes(Bytes::from_static(body.as_bytes()));
        self
    }

    #[cfg(feature = "net-file-server")]
    #[inline]
    fn body_mmap(&mut self, map: std::sync::Arc<memmap2::Mmap>, lo: usize, hi: usize) -> &mut Self {
        self.rsp_body = BodySource::Mmap { map, lo, hi };
        self
    }

    #[inline]
    fn eom(&mut self) {
        //#[cfg(debug_assertions)]
        //{
            // eprintln!("h3 headers are {:?}", self.rsp_headers);
            // eprintln!("h3 body is {:?}", self.rsp_body);
        //}
    }
}

fn default_headers() -> Vec<Header> {
    let server_name = concat!("Sib ", env!("SIB_BUILD_VERSION"));
    vec![
        Header::new(b":status", b"200"),
        Header::new(b"server", server_name.as_bytes()),
        Header::new(b"date", super::util::CURRENT_DATE.load().as_bytes()),
    ]
}

pub(crate) fn init_session(session: &mut H3Session) {
    if session.rsp_headers.is_empty() {
        let headers = default_headers();
        session.rsp_headers.extend_from_slice(&headers);
    }
}

pub(crate) fn new_session(peer_addr: SocketAddr, conn: quiche::Connection) -> H3Session {
    H3Session {
        peer_addr,
        conn,
        http3_conn: None,
        req_headers: None,
        req_body_map: HashMap::new(),
        current_stream_id: None,
        rsp_headers: default_headers(),
        rsp_body: BodySource::Empty,
        partial_responses: HashMap::new(),
    }
}