use crate::s_error;
use bytes::Bytes;
use futures_lite::{AsyncRead, AsyncWrite, Future};
use futures_rustls::{TlsAcceptor, server::TlsStream};
use hyper::body::Incoming;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::slice;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
struct HyperExecutor;
impl<F> hyper::rt::Executor<F> for HyperExecutor
where
    F: Future + 'static,
    F::Output: 'static,
{
    fn execute(&self, p_fut: F) {
        glommio::spawn_local(p_fut).detach();
    }
}

struct HyperStream(pub TlsStream<glommio::net::TcpStream>);

impl hyper::rt::Write for HyperStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl hyper::rt::Read for HyperStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unsafe {
            let read_slice = {
                let buffer = buf.as_mut();
                buffer.as_mut_ptr().write_bytes(0, buffer.len());
                slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len())
            };
            Pin::new(&mut self.0).poll_read(cx, read_slice).map(|n| {
                if let Ok(n) = n {
                    buf.advance(n);
                }
                Ok(())
            })
        }
    }
}

pub struct ResponseBody {
    // Our ResponseBody type is !Send and !Sync
    _marker: PhantomData<*const ()>,
    data: Option<Bytes>,
}

impl From<&'static str> for ResponseBody {
    fn from(data: &'static str) -> Self {
        ResponseBody {
            _marker: PhantomData,
            data: Some(Bytes::from(data)),
        }
    }
}

impl hyper::body::Body for ResponseBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::io::Result<hyper::body::Frame<Bytes>>>> {
        Poll::Ready(
            self.get_mut()
                .data
                .take()
                .map(|d| Ok(hyper::body::Frame::data(d))),
        )
    }
}

pub fn load_tls_aconfig() -> rustls::ServerConfig {
    let cert_file =
        "/home/parallels/sib-cpp/dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem";

    let private_key_file =
        "/home/parallels/sib-cpp/dep/proxygen/proxygen/httpserver/tests/certs/ca_key.pem";

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap()
}

async fn accept_tls(
    stream: glommio::net::TcpStream,
    tls_acceptor: Arc<TlsAcceptor>,
) -> std::io::Result<futures_rustls::server::TlsStream<glommio::net::TcpStream>> {
    tls_acceptor.accept(stream).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("TLS handshake error: {e}"),
        )
    })
}

pub async fn serve_http1<S, F, R, A>(
    addr: A,
    service: S,
    max_connections: usize,
    tls_acceptor: Arc<TlsAcceptor>,
) -> std::io::Result<()>
where
    S: Fn(http::Request<Incoming>) -> F + 'static + Copy,
    F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
    R: std::error::Error + 'static + Send + Sync,
    A: Into<SocketAddr>,
{
    let listener = glommio::net::TcpListener::bind(addr.into())?;
    let conn_control = std::rc::Rc::new(glommio::sync::Semaphore::new(max_connections as _));
    loop {
        match listener.accept().await {
            Err(x) => {
                return Err(x.into());
            }
            Ok(stream) => {
                let addr = stream.local_addr().unwrap();
                let tls_acceptor = tls_acceptor.clone();
                let stream = accept_tls(stream, tls_acceptor).await?;
                let io = HyperStream(stream);

                glommio::spawn_local(glommio::enclose! {(conn_control) async move {
                        let _permit = conn_control.acquire_permit(1).await;
                        if let Err(err) = hyper::server::conn::http1::Builder::new().serve_connection(io, hyper::service::service_fn(service)).await {
                            if !err.is_incomplete_message() {
                                s_error!("HTTP1.1 stream from {addr:?} failed with error {err:?}");
                            }
                        }
                    }}).detach();
            }
        }
    }
}

pub async fn serve_http2<S, F, R, A>(
    addr: A,
    service: S,
    max_connections: usize,
    tls_acceptor: Arc<TlsAcceptor>,
) -> std::io::Result<()>
where
    S: Fn(http::Request<Incoming>) -> F + 'static + Copy,
    F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
    R: std::error::Error + 'static + Send + Sync,
    A: Into<SocketAddr>,
{
    let listener = glommio::net::TcpListener::bind(addr.into())?;
    let conn_control = std::rc::Rc::new(glommio::sync::Semaphore::new(max_connections as _));
    loop {
        match listener.accept().await {
            Err(x) => {
                return Err(x.into());
            }
            Ok(stream) => {
                let addr = stream.local_addr().unwrap();
                let tls_acceptor = tls_acceptor.clone();
                let stream = accept_tls(stream, tls_acceptor).await?;
                let io = HyperStream(stream);
                glommio::spawn_local(glommio::enclose! {(conn_control) async move {
                        let _permit = conn_control.acquire_permit(1).await;
                        if let Err(err) = hyper::server::conn::http2::Builder::new(HyperExecutor).serve_connection(io, hyper::service::service_fn(service)).await {
                            if !err.is_incomplete_message() {
                                s_error!("HTTP2.1 stream from {addr:?} failed with error {err:?}");
                            }
                        }
                    }}).detach();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        s_info,
        system::log::{LogFileConfig, LogFilterLevel, LogRolling, init_log},
    };
    use glommio::prelude::*;
    use http::{Method, Request, Response, StatusCode};

    async fn h_handler(
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<ResponseBody>, std::convert::Infallible> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/hello") => Ok(Response::new(ResponseBody::from("world"))),
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(ResponseBody::from("Hello from Sib!"))
                .unwrap()),
        }
    }

    #[test]
    fn test_http1() {
        const MAX_EXECUTORS: usize = 1;
        const MAX_CONNECTIONS: usize = 16384;
        LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(
            MAX_EXECUTORS,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(|| async move {
            let id = glommio::executor().id();

            // initialize once
            let log_file = LogFileConfig {
                roller: LogRolling::DAILY,
                dir: "log".to_owned(),
                file_name: format!("exec{}.log", id),
                ansi: false,
            };
            let _log = init_log(LogFilterLevel::TRACE, Some(log_file), None).await;
            let tls_config = load_tls_aconfig();
            let tls = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));
            s_info!("Starting http1 server on 0.0.0.0:8443 via executor: {id}");
            serve_http1(([0, 0, 0, 0], 8443), h_handler, MAX_CONNECTIONS, tls)
                .await
                .unwrap();
        })
        .unwrap()
        .join_all();
    }

    #[test]
    fn test_http2() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        const MAX_EXECUTORS: usize = 1;
        const MAX_CONNECTIONS: usize = 16384;
        LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(
            MAX_EXECUTORS,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(|| async move {
            let id = glommio::executor().id();

            // initialize once
            let log_file = LogFileConfig {
                roller: LogRolling::DAILY,
                dir: "log".to_owned(),
                file_name: format!("exec{}.log", id),
                ansi: false,
            };
            let _log = init_log(LogFilterLevel::TRACE, Some(log_file), None).await;
            let mut tls_config = load_tls_aconfig();
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));
            s_info!("Starting http2 server on 0.0.0.0:8443 via executor: {id}");
            serve_http2(([0, 0, 0, 0], 8443), h_handler, MAX_CONNECTIONS, tls)
                .await
                .unwrap();
        })
        .unwrap()
        .join_all();
    }
}
