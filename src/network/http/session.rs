use http::{HeaderName, HeaderValue};

#[async_trait::async_trait(?Send)]
pub trait Session {
    fn peer_addr(&self) -> &std::net::IpAddr;
    fn req_method(&self) -> http::Method;
    fn req_method_str(&self) -> Option<&str>;
    fn req_path(&self) -> String;
    fn req_http_version(&self) -> http::Version;
    fn req_headers(&self) -> http::HeaderMap;
    fn req_header(&self, header: &http::HeaderName) -> Option<http::HeaderValue>;

    #[cfg(feature = "net-h1-server")]
    fn req_body(&mut self, timeout: std::time::Duration) -> std::io::Result<&[u8]>;

    #[cfg(all(
        target_os = "linux",
        any(feature = "net-h2-server", feature = "net-h3-server")
    ))]
    async fn req_body_async(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<std::io::Result<bytes::Bytes>>;

    fn status_code(&mut self, status: http::StatusCode) -> &mut Self;

    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::H2Stream>;

    fn header(&mut self, name: HeaderName, value: HeaderValue) -> std::io::Result<&mut Self>;
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self>;
    fn headers(&mut self, headers: &http::HeaderMap) -> std::io::Result<&mut Self>;
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self>;
    fn body(&mut self, body: bytes::Bytes) -> &mut Self;
    fn eom(&mut self) -> std::io::Result<()>;

    #[cfg(all(
        target_os = "linux",
        any(feature = "net-h2-server", feature = "net-h3-server")
    ))]
    async fn eom_async(&mut self) -> std::io::Result<()>;
}

pub trait HService {
    fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()>;
}

#[async_trait::async_trait(?Send)]
pub trait HAsyncService {
    async fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()>;
}
