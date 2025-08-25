use crate::network::http::util::HttpHeader;

pub trait Session {
    fn peer_addr(&self) -> &std::net::SocketAddr;
    fn is_h3(&self) -> bool;
    fn req_method(&self) -> Option<&str>;
    fn req_path(&self) -> Option<&str>;
    fn req_http_version(&self) -> Option<u8>;
    fn req_headers(&self) -> &[httparse::Header<'_>];
    fn req_headers_vec(&self) -> Vec<httparse::Header<'_>>;
    fn req_header(&self, header: &HttpHeader) -> std::io::Result<&str>;
    fn req_header_str(&self, header: &str) -> std::io::Result<&str>;
    fn req_body(&mut self, timeout: std::time::Duration) -> std::io::Result<&[u8]>;

    fn status_code(&mut self, status: super::util::Status) -> &mut Self;

    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self>;
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self>;
    fn header(&mut self, name: &HttpHeader, value: &str) -> std::io::Result<&mut Self>;
    fn headers(&mut self, header_val: &[(HttpHeader, &str)]) -> std::io::Result<&mut Self>;
    fn headers_vec(&mut self, header_val: &[(HttpHeader, String)]) -> std::io::Result<&mut Self>;

    fn body(&mut self, data: &bytes::Bytes) -> &mut Self;
    fn body_slice(&mut self, body: &[u8]) -> &mut Self;
    fn body_static(&mut self, body: &'static str) -> &mut Self;
    
    fn eom(&mut self);
}

pub trait HService {
    fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()>;
}

#[cfg(feature = "net-h3-server")]
pub trait HServiceWebTransport {
    fn on_wt_open<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64) {}
    fn on_wt_close<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64) {}
    fn on_wt_datagram<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64, _ctx: Option<u64>, _payload: &[u8]) {}
    fn on_wt_unistream_open<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64, _stream_id: u64) {}
    fn on_wt_unistream_data<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64, _stream_id: u64, _chunk: &[u8]) {}
    fn on_wt_bistream_open<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64, _stream_id: u64) {}
    fn on_wt_bistream_data<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64, _stream_id: u64, _chunk: &[u8]) {}
}