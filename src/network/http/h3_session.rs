use std::{collections::HashMap, net::SocketAddr, time::Duration};
use crate::network::http::{session::Session, util::{HttpHeader, Status}};
use bytes::Bytes;
use quiche::h3::{Header, NameValue};

pub(crate) struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,
    pub body: Vec<u8>,
    pub written: usize,
}

pub(crate) struct H3Session {
    pub peer_addr: SocketAddr,
    pub conn: quiche::Connection,
    pub http3_conn: Option<quiche::h3::Connection>,
    pub req_headers: Option<Vec<quiche::h3::Header>>,
    pub rsp_headers: Vec<quiche::h3::Header>,
    pub rsp_body: Vec<u8>,
    pub partial_responses: HashMap<u64, PartialResponse>,
}

impl Session for H3Session {
    
    fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }

    fn is_h3(&self) -> bool
    {
        self.http3_conn.is_some()
    }

    fn req_method(&self) -> Option<&str> {
        if let Some(headers) = &self.req_headers {
            headers.iter().find(|h| h.name() == b":method").and_then(|h| std::str::from_utf8(h.value()).ok())
        } else {
            None
        }
    }

    fn req_path(&self) -> Option<&str> {
        if let Some(headers) = &self.req_headers {
            headers.iter().find(|h| h.name() == b":path").and_then(|h| std::str::from_utf8(h.value()).ok())
        } else {
            None
        }
    }

    fn req_http_version(&self) -> Option<u8> {
        Some(3)
    }

    /// HTTP/3 headers are not compatible with httparse::Header, use req_headers_vec instead
    fn req_headers(&self) -> &[httparse::Header<'_>] {
        //assert!(false, "HTTP/3 headers are not compatible with httparse::Header, use req_headers_vec instead");
        &[]
    }

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

    fn req_header(&self, header: &HttpHeader) -> std::io::Result<&str> {
        self.req_header_str(header.as_str())
    }

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
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No request headers available"))
        }
    }

    fn req_body(&mut self, _timeout: Duration) -> std::io::Result<&[u8]> {
        Ok(&[0u8; 0]) 
    }

    fn status_code(&mut self, status: Status) -> &mut Self {
        let (code, _reason) = status.as_parts();
        self.rsp_headers[0] = Header::new(b":status", code.as_bytes());
        self
    }

    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        self.rsp_headers.push(Header::new(name.as_bytes(), value.as_bytes()));
        Ok(self)
    }

    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header_str(n, v)?;
        }
        Ok(self)
    }

    fn header(&mut self, name: &HttpHeader, value: &str) -> std::io::Result<&mut Self> {
        self.header_str(name.as_str(), value)
    }

    fn headers(&mut self, header_val: &[(HttpHeader, &str)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header(n, v)?;
        }
        Ok(self)
    }

    fn headers_vec(&mut self, header_val: &[(HttpHeader, String)]) -> std::io::Result<&mut Self> {
        for (n, v) in header_val {
            self.header(n, v)?;
        }
        Ok(self)
    }

    fn body(&mut self, data: &Bytes) -> &mut Self {
        self.rsp_body = data.to_vec();
        self
    }

    fn body_slice(&mut self, body: &[u8]) -> &mut Self {
        self.rsp_body = body.to_vec();
        self
    }

    fn body_static(&mut self, body: &'static str) -> &mut Self {
        self.rsp_body = body.as_bytes().to_vec();
        self
    }

    fn eom(&mut self) {
        // #[cfg(debug_assertions)]
        // eprintln!("sent: {:?}", self);
    }
}

pub(crate) fn new_session(peer_addr: SocketAddr, conn: quiche::Connection) -> H3Session {
    const SERVER_NAME: &str =
            concat!("Sib ", env!("SIB_BUILD_VERSION"));
    let rsp_headers = vec![
        Header::new(b":status", b"200"),
        Header::new(b"server", SERVER_NAME.as_bytes())
    ];
    H3Session {
        peer_addr,
        conn,
        http3_conn: None,
        req_headers: None,
        rsp_headers,
        rsp_body: Vec::new(),
        partial_responses: HashMap::new(),
    }
}