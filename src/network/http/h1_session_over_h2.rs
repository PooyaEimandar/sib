use crate::network::http::session::Session;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use hyper::Request;
use hyper::body::Incoming as HBody;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

pub struct H1SessionOverH2 {
    peer_addr: IpAddr,
    req: Request<HBody>,
    res_status: StatusCode,
    resp_headers: HeaderMap,
    resp_body: Bytes,
}

impl H1SessionOverH2 {
    pub fn new(req: Request<HBody>, peer_addr: IpAddr) -> Self {
        Self {
            peer_addr,
            req,
            res_status: StatusCode::OK,
            resp_headers: HeaderMap::new(),
            resp_body: Bytes::new(),
        }
    }

    pub fn into_hyper_response(self) -> std::io::Result<hyper::Response<bytes::Bytes>> {
        let mut builder = hyper::Response::builder().status(self.res_status);

        {
            let headers = builder.headers_mut().unwrap();
            headers.extend(self.resp_headers.into_iter());

            if !headers.contains_key(http::header::CONTENT_LENGTH) {
                use http::HeaderValue;
                let len = self.resp_body.len();
                headers.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len.to_string()).unwrap(),
                );
            }
        }

        builder.body(self.resp_body).map_err(|e| {
            std::io::Error::other(format!(
                "failed to build hyper response in H1SessionOverH2: {}",
                e
            ))
        })
    }
}

#[async_trait::async_trait(?Send)]
impl Session for H1SessionOverH2 {
    #[inline]
    fn peer_addr(&self) -> &IpAddr {
        &self.peer_addr
    }

    #[inline]
    fn req_host(&self) -> Option<(String, Option<u16>)> {
        if let Some(a) = self.req.uri().authority()
            && let Some(x) = crate::network::http::server::parse_authority(a.as_str())
        {
            return Some(x);
        }

        if let Some(hv) = self.req.headers().get(http::header::HOST)
            && let Ok(s) = hv.to_str()
            && let Some(x) = crate::network::http::server::parse_authority(s.trim())
        {
            return Some(x);
        }
        None
    }

    #[inline]
    fn req_method(&self) -> http::Method {
        self.req.method().clone()
    }

    #[inline]
    fn req_method_str(&self) -> Option<&str> {
        Some(self.req.method().as_str())
    }

    #[inline]
    fn req_path(&self) -> String {
        self.req.uri().path().to_string()
    }

    #[inline]
    fn req_http_version(&self) -> http::Version {
        self.req.version()
    }

    #[inline]
    fn req_headers(&self) -> http::HeaderMap {
        self.req.headers().clone()
    }

    #[inline]
    fn req_header(&self, header: &HeaderName) -> Option<HeaderValue> {
        self.req.headers().get(header).cloned()
    }

    #[cfg(feature = "net-h1-server")]
    #[inline]
    fn req_body(&mut self, timeout: Duration) -> std::io::Result<&[u8]> {
        Err(std::io::Error::other(
            "req_body is not implemented for H1SessionOverH2",
        ))
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[inline]
    async fn req_body_async(&mut self, timeout: Duration) -> Option<std::io::Result<Bytes>> {
        use futures_lite::future::race;
        use http_body_util::BodyExt;

        let data_fut = async {
            match self.req.body_mut().frame().await {
                Some(Ok(frame)) => {
                    if let Some(bytes) = frame.data_ref() {
                        Some(Ok(Bytes::copy_from_slice(bytes)))
                    } else {
                        None
                    }
                }
                Some(Err(e)) => Some(Err(std::io::Error::other(e.to_string()))),
                None => None,
            }
        };

        let timeout_fut = async move {
            #[cfg(feature = "rt-tokio")]
            tokio::time::sleep(timeout).await;
            #[cfg(all(feature = "rt-glommio", target_os = "linux"))]
            glommio::timer::Timer::new(timeout).await;

            Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "req_body_h1 (hyper) timed out",
            )))
        };

        race(data_fut, timeout_fut).await
    }

    #[inline]
    fn write_all_eom(&mut self, status: &[u8]) -> std::io::Result<()> {
        self.status_code(
            StatusCode::from_str(std::str::from_utf8(status).map_err(|e| {
                std::io::Error::other(format!("invalid utf8 status code {}: {}", status.len(), e))
            })?)
            .map_err(|e| {
                std::io::Error::other(format!(
                    "invalid status code {}: {}",
                    std::str::from_utf8(status).unwrap_or("<invalid utf8>"),
                    e
                ))
            })?,
        );
        self.eom()
    }

    #[inline]
    fn status_code(&mut self, status: http::StatusCode) -> &mut Self {
        self.res_status = status;
        self
    }

    #[inline]
    fn start_h2_streaming(&mut self) -> std::io::Result<super::h2_session::H2Stream> {
        Err(std::io::Error::other(
            "start_h2_streaming is not avaiable for H1SessionOverH2",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn start_h3_streaming(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "start_h3_streaming is not avaiable for H1SessionOverH2",
        ))
    }

    #[cfg(feature = "net-h3-server")]
    #[inline]
    async fn send_h3_data(&mut self, chunk: bytes::Bytes, end_stream: bool) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "send_h3_data is not avaiable for H1SessionOverH2",
        ))
    }

    #[inline]
    fn header(&mut self, name: HeaderName, value: HeaderValue) -> std::io::Result<&mut Self> {
        self.resp_headers.append(name, value);
        Ok(self)
    }

    #[inline]
    fn header_str(&mut self, name: &str, value: &str) -> std::io::Result<&mut Self> {
        let hname = HeaderName::from_str(name)
            .map_err(|e| std::io::Error::other(format!("invalid header name {name}: {e}")))?;
        let hval = HeaderValue::from_str(value)
            .map_err(|e| std::io::Error::other(format!("invalid header value {value}: {e}")))?;
        self.resp_headers.append(hname, hval);
        Ok(self)
    }

    #[inline]
    fn headers(&mut self, headers: &http::HeaderMap) -> std::io::Result<&mut Self> {
        for (k, v) in headers {
            self.resp_headers.append(k, v.clone());
        }
        Ok(self)
    }

    #[inline]
    fn headers_str(&mut self, header_val: &[(&str, &str)]) -> std::io::Result<&mut Self> {
        for (name, value) in header_val {
            self.header_str(name, value)?;
        }
        Ok(self)
    }

    #[inline]
    fn body(&mut self, body: Bytes) -> &mut Self {
        self.resp_body = body;
        self
    }

    #[inline]
    fn eom(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[inline]
    async fn eom_async(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(feature = "net-ws-server")]
    #[inline]
    fn is_ws(&self) -> bool {
        false
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_accept(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_accept is not implemented for H1SessionOverH2",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_read(
        &mut self,
    ) -> std::io::Result<(crate::network::http::ws::OpCode, bytes::Bytes, bool)> {
        Err(std::io::Error::other(
            "ws_read is not implemented for H1SessionOverH2",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_write(
        &mut self,
        op: crate::network::http::ws::OpCode,
        payload: &bytes::Bytes,
        fin: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_write is not implemented for H1SessionOverH2",
        ))
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[inline]
    fn ws_close(&mut self, reason: Option<&bytes::Bytes>) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "ws_close is not implemented for H1SessionOverH2",
        ))
    }
}
