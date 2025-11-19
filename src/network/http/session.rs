use http::{HeaderName, HeaderValue};

#[async_trait::async_trait(?Send)]
pub trait Session {
    fn peer_addr(&self) -> &std::net::IpAddr;
    fn req_host(&self) -> Option<(String, Option<u16>)>;
    fn req_method(&self) -> http::Method;
    fn req_method_str(&self) -> Option<&str>;
    fn req_path(&self) -> String;
    fn req_query(&self) -> String;
    fn req_http_version(&self) -> http::Version;
    fn req_headers(&self) -> http::HeaderMap;
    fn req_header(&self, header: &http::HeaderName) -> Option<http::HeaderValue>;

    #[cfg(feature = "net-h1-server")]
    fn req_body(&mut self, timeout: std::time::Duration) -> std::io::Result<&[u8]>;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    async fn req_body_async(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<std::io::Result<bytes::Bytes>>;

    fn write_all_eom(&mut self, status: &[u8]) -> std::io::Result<()>;

    fn status_code(&mut self, status: http::StatusCode) -> &mut Self;

    #[cfg(any(feature = "net-h1-server", feature = "net-h2-server"))]
    fn start_h1_streaming(&mut self) -> std::io::Result<()>;

    #[cfg(feature = "net-h2-server")]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::H2Stream>;

    #[cfg(feature = "net-h3-server")]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()>;

    #[cfg(any(feature = "net-h1-server", feature = "net-h2-server"))]
    fn send_h1_data(&mut self, chunk: &[u8], end_stream: bool) -> std::io::Result<()>;

    #[cfg(feature = "net-h3-server")]
    async fn send_h3_data(&mut self, chunk: bytes::Bytes, end_stream: bool) -> std::io::Result<()>;

    fn header(&mut self, name: HeaderName, value: HeaderValue) -> std::io::Result<&mut Self>;
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self>;
    fn headers(&mut self, headers: &http::HeaderMap) -> std::io::Result<&mut Self>;
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self>;
    fn body(&mut self, body: bytes::Bytes) -> &mut Self;
    fn eom(&mut self) -> std::io::Result<()>;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    async fn eom_async(&mut self) -> std::io::Result<()>;

    #[cfg(feature = "net-ws-server")]
    fn is_ws(&self) -> bool;

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_accept(&mut self) -> std::io::Result<()>;

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_read(
        &mut self,
    ) -> std::io::Result<(crate::network::http::ws::OpCode, bytes::Bytes, bool)>;

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_write(
        &mut self,
        op: crate::network::http::ws::OpCode,
        payload: &bytes::Bytes,
        fin: bool,
    ) -> std::io::Result<()>;

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    fn ws_close(&mut self, reason: Option<&bytes::Bytes>) -> std::io::Result<()>;
}

pub trait HService {
    fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()>;
}

#[async_trait::async_trait(?Send)]
pub trait HAsyncService {
    async fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()>;
}
