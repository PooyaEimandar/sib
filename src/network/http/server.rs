// use crate::{s_error, s_warn};
// use bytes::Bytes;
// use futures_lite::{AsyncRead, AsyncWrite, Future};
// use futures_rustls::{TlsAcceptor, server::TlsStream};
// use rustls::pki_types::pem::PemObject;
// use rustls::pki_types::{CertificateDer, PrivateKeyDer};
// use std::marker::PhantomData;
// use std::net::SocketAddr;
// use std::pin::Pin;
// use std::slice;
// use std::sync::Arc;
// use std::task::{Context, Poll};

// #[derive(Clone)]
// struct HyperExecutor;
// impl<F> hyper::rt::Executor<F> for HyperExecutor
// where
//     F: Future + 'static,
//     F::Output: 'static,
// {
//     fn execute(&self, p_fut: F) {
//         glommio::spawn_local(p_fut).detach();
//     }
// }

// struct HyperStream(pub glommio::net::TcpStream);

// impl hyper::rt::Write for HyperStream {
//     fn poll_write(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context,
//         buf: &[u8],
//     ) -> Poll<std::io::Result<usize>> {
//         Pin::new(&mut self.0).poll_write(cx, buf)
//     }

//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
//         Pin::new(&mut self.0).poll_flush(cx)
//     }

//     fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
//         Pin::new(&mut self.0).poll_close(cx)
//     }
// }

// impl hyper::rt::Read for HyperStream {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         mut buf: hyper::rt::ReadBufCursor<'_>,
//     ) -> std::task::Poll<std::io::Result<()>> {
//         unsafe {
//             let read_slice = {
//                 let buffer = buf.as_mut();
//                 buffer.as_mut_ptr().write_bytes(0, buffer.len());
//                 slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len())
//             };
//             Pin::new(&mut self.0).poll_read(cx, read_slice).map(|n| {
//                 if let Ok(n) = n {
//                     buf.advance(n);
//                 }
//                 Ok(())
//             })
//         }
//     }
// }

// struct HyperTlsStream(pub TlsStream<glommio::net::TcpStream>);

// impl hyper::rt::Write for HyperTlsStream {
//     fn poll_write(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context,
//         buf: &[u8],
//     ) -> Poll<std::io::Result<usize>> {
//         Pin::new(&mut self.0).poll_write(cx, buf)
//     }

//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
//         Pin::new(&mut self.0).poll_flush(cx)
//     }

//     fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
//         Pin::new(&mut self.0).poll_close(cx)
//     }
// }

// impl hyper::rt::Read for HyperTlsStream {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         mut buf: hyper::rt::ReadBufCursor<'_>,
//     ) -> std::task::Poll<std::io::Result<()>> {
//         unsafe {
//             let read_slice = {
//                 let buffer = buf.as_mut();
//                 buffer.as_mut_ptr().write_bytes(0, buffer.len());
//                 slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len())
//             };
//             Pin::new(&mut self.0).poll_read(cx, read_slice).map(|n| {
//                 if let Ok(n) = n {
//                     buf.advance(n);
//                 }
//                 Ok(())
//             })
//         }
//     }
// }

// pub struct ResponseBody {
//     // Our ResponseBody type is !Send and !Sync
//     _marker: PhantomData<*const ()>,
//     data: Option<Bytes>,
// }

// impl From<&'static str> for ResponseBody {
//     fn from(data: &'static str) -> Self {
//         ResponseBody {
//             _marker: PhantomData,
//             data: Some(Bytes::from(data)),
//         }
//     }
// }

// impl hyper::body::Body for ResponseBody {
//     type Data = Bytes;
//     type Error = std::io::Error;
//     fn poll_frame(
//         self: Pin<&mut Self>,
//         _: &mut Context<'_>,
//     ) -> Poll<Option<std::io::Result<hyper::body::Frame<Bytes>>>> {
//         Poll::Ready(
//             self.get_mut()
//                 .data
//                 .take()
//                 .map(|d| Ok(hyper::body::Frame::data(d))),
//         )
//     }
// }

// async fn accept_tls(
//     stream: glommio::net::TcpStream,
//     tls_acceptor: TlsAcceptor,
// ) -> Result<futures_rustls::server::TlsStream<glommio::net::TcpStream>, glommio::GlommioError<()>> {
//     match tls_acceptor.accept(stream).await {
//         Ok(tls_stream) => Ok(tls_stream),
//         Err(e) => Err(glommio::GlommioError::from(std::io::Error::new(
//             std::io::ErrorKind::Other,
//             format!("TLS handshake error: {e}"),
//         ))),
//     }
// }

// pub fn tls_config_from_files(cert_file: &str, key_file: &str) -> rustls::ServerConfig {
//     let certs = CertificateDer::pem_file_iter(cert_file)
//         .unwrap()
//         .map(|cert| cert.unwrap())
//         .collect();
//     let private_key = PrivateKeyDer::from_pem_file(key_file).unwrap();
//     rustls::ServerConfig::builder()
//         .with_no_client_auth()
//         .with_single_cert(certs, private_key)
//         .unwrap()
// }

// pub fn tls_config_from_mem(cert: &[u8], key: &[u8]) -> rustls::ServerConfig {
//     let certs = CertificateDer::from_pem_slice(cert).unwrap();
//     let private_key = PrivateKeyDer::from_pem_slice(key).unwrap();
//     rustls::ServerConfig::builder()
//         .with_no_client_auth()
//         .with_single_cert(vec![certs], private_key)
//         .unwrap()
// }

// pub async fn serve_http1<S, F, R, A>(
//     addr: A,
//     service: S,
//     max_connections: u64,
// ) -> std::io::Result<()>
// where
//     S: Fn(http::Request<hyper::body::Incoming>) -> F + 'static + Copy,
//     F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
//     R: std::error::Error + 'static + Send + Sync,
//     A: Into<SocketAddr>,
// {
//     let listener = glommio::net::TcpListener::bind(addr.into())?;
//     let conn_control = std::rc::Rc::new(glommio::sync::Semaphore::new(max_connections));

//     loop {
//         match listener.accept().await {
//             Err(e) => {
//                 s_error!("TCP accept error: {e}");
//                 continue;
//             }
//             Ok(stream) => {
//                 let addr = stream
//                     .local_addr()
//                     .unwrap_or_else(|_| "unknown".parse().unwrap());
//                 let conn_control = conn_control.clone();

//                 glommio::spawn_local(async move {
//                     let io = HyperStream(stream);
//                     let _permit = conn_control.acquire_permit(1).await;

//                     if let Err(err) = hyper::server::conn::http1::Builder::new()
//                         .serve_connection(io, hyper::service::service_fn(service))
//                         .await
//                     {
//                         if !err.is_incomplete_message() {
//                             s_error!("HTTP/1.1 stream from {addr:?} failed with error: {err:?}");
//                         }
//                     }
//                 })
//                 .detach();
//             }
//         }
//     }
// }

// pub async fn serve_http1_tls<S, F, R, A>(
//     addr: A,
//     service: S,
//     max_connections: u64,
//     tls_acceptor: TlsAcceptor,
// ) -> std::io::Result<()>
// where
//     S: Fn(http::Request<hyper::body::Incoming>) -> F + 'static + Copy,
//     F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
//     R: std::error::Error + 'static + Send + Sync,
//     A: Into<SocketAddr>,
// {
//     let listener = glommio::net::TcpListener::bind(addr.into())?;
//     let conn_control = std::rc::Rc::new(glommio::sync::Semaphore::new(max_connections));

//     loop {
//         match listener.accept().await {
//             Err(e) => {
//                 s_error!("TCP accept error: {e}");
//                 continue;
//             }
//             Ok(stream) => {
//                 let addr = stream
//                     .local_addr()
//                     .unwrap_or_else(|_| "unknown".parse().unwrap());
//                 let tls_acceptor = tls_acceptor.clone();
//                 let conn_control = conn_control.clone();

//                 glommio::spawn_local(async move {
//                     match accept_tls(stream, tls_acceptor).await {
//                         Ok(tls_stream) => {
//                             let io = HyperTlsStream(tls_stream);
//                             let _permit = conn_control.acquire_permit(1).await;
//                             if let Err(err) = hyper::server::conn::http1::Builder::new()
//                                 .serve_connection(io, hyper::service::service_fn(service))
//                                 .await
//                             {
//                                 if !err.is_incomplete_message() {
//                                     s_error!(
//                                         "HTTP/1.1 stream from {addr:?} failed with error: {err:?}"
//                                     );
//                                 }
//                             }
//                         }
//                         Err(e) => {
//                             s_error!("TLS handshake from {addr:?} failed: {e}");
//                         }
//                     }
//                 })
//                 .detach();
//             }
//         }
//     }
// }

// async fn server_h2<S, F, R>(
//     tls_stream: futures_rustls::server::TlsStream<glommio::net::TcpStream>,
//     service: S,
//     io_timeout: std::time::Duration,
//     peer_addr: SocketAddr,
// ) -> Result<(), glommio::GlommioError<()>>
// where
//     S: Fn(http::Request<hyper::body::Incoming>) -> F + 'static + Copy,
//     F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
//     R: std::error::Error + 'static + Send + Sync,
// {
//     let result = glommio::timer::timeout(io_timeout, async {
//         hyper::server::conn::http2::Builder::new(HyperExecutor)
//             .initial_stream_window_size(65535 * 4)
//             .initial_connection_window_size(65535 * 8)
//             .serve_connection(
//                 HyperTlsStream(tls_stream),
//                 hyper::service::service_fn(service),
//             )
//             .await
//             .map_err(|e| {
//                 s_error!("HTTP/2 connection error from {peer_addr:?}: {e}");
//                 glommio::GlommioError::from(std::io::Error::new(
//                     std::io::ErrorKind::Other,
//                     "connection error",
//                 ))
//             })
//     })
//     .await;

//     match result {
//         Ok(()) => return Ok(()),
//         Err(glommio::GlommioError::TimedOut(_)) => {
//             s_warn!("HTTP/2 from {peer_addr:?} timed out after {io_timeout:?}");
//             return Err(glommio::GlommioError::from(std::io::Error::new(
//                 std::io::ErrorKind::Other,
//                 "timed out",
//             )));
//         }
//         Err(err) => {
//             s_error!("HTTP/2 error from {peer_addr:?}: {err:?}");
//             return Err(glommio::GlommioError::from(std::io::Error::new(
//                 std::io::ErrorKind::Other,
//                 "timed out",
//             )));
//         }
//     }
// }

// pub async fn serve_http2<S, F, R, A>(
//     addr: A,
//     service: S,
//     max_connections: u64,
//     tls_handshake_timeout: std::time::Duration,
//     io_timeout: std::time::Duration,
//     tls_acceptor: TlsAcceptor,
// ) -> std::io::Result<()>
// where
//     A: Into<SocketAddr>,
//     S: Fn(http::Request<hyper::body::Incoming>) -> F + 'static + Copy,
//     F: Future<Output = Result<http::Response<ResponseBody>, R>> + 'static,
//     R: std::error::Error + 'static + Send + Sync,
// {
//     let listener = glommio::net::TcpListener::bind(addr.into())?;
//     let conn_control = Arc::new(glommio::sync::Semaphore::new(max_connections));

//     loop {
//         // Wait for connection slot with exponential backoff
//         let mut backoff = 1;
//         while conn_control.available() == 0 {
//             glommio::timer::sleep(std::time::Duration::from_micros(backoff)).await;
//             backoff = (backoff * 2).min(5000); // max 5ms
//         }

//         let stream = match listener.accept().await {
//             Ok(s) => s,
//             Err(err) => {
//                 s_error!("Failed to accept connection: {err}");
//                 continue;
//             }
//         };

//         let peer_addr = stream
//             .peer_addr()
//             .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());

//         stream.set_nodelay(true).unwrap_or_else(|err| {
//             s_warn!("Failed to set TCP_NODELAY on {peer_addr:?}: {err}");
//         });

//         let tls_acceptor = tls_acceptor.clone();
//         let conn_control = conn_control.clone();

//         glommio::spawn_local(async move {
//             match conn_control.acquire_permit(1).await {
//                 Ok(permit) => {
//                     let tls_stream = match glommio::timer::timeout(
//                         tls_handshake_timeout,
//                         accept_tls(stream, tls_acceptor),
//                     )
//                     .await
//                     {
//                         Ok(tls) => tls,
//                         Err(err) => {
//                             s_error!("TLS handshake from {peer_addr:?} got an error: {err:?}");
//                             drop(permit);
//                             return;
//                         }
//                     };

//                     let _ = server_h2(tls_stream, service, io_timeout, peer_addr).await;

//                     drop(permit);
//                 }
//                 Err(_) => {
//                     s_warn!("Connection from {peer_addr:?} refused: max connections reached");
//                     let res = stream.shutdown(std::net::Shutdown::Both).await;
//                     if let Err(err) = res {
//                         s_error!("Failed to shutdown connection from {peer_addr:?}: error: {err}");
//                     }
//                 }
//             }
//         })
//         .detach();
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{
//         s_info,
//         system::log::{LogFileConfig, LogFilterLevel, LogRolling, init_log},
//     };
//     use glommio::prelude::*;
//     use http::{Method, Request, Response, StatusCode};

//     pub fn generate_self_signed_cert() -> rustls::ServerConfig {
//         use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
//         use std::net::IpAddr;

//         let mut params = CertificateParams::default();
//         params.not_before = rcgen::date_time_ymd(1975, 1, 1);
//         params.not_after = rcgen::date_time_ymd(7000, 1, 1);

//         let mut dn = DistinguishedName::new();
//         dn.push(DnType::CommonName, "localhost");
//         params.distinguished_name = dn;

//         // Add dynamic IP addresses
//         match get_if_addrs::get_if_addrs() {
//             Ok(ifaces) => {
//                 for iface in ifaces {
//                     match iface.ip() {
//                         IpAddr::V4(ipv4) => {
//                             params
//                                 .subject_alt_names
//                                 .push(SanType::IpAddress(IpAddr::V4(ipv4)));
//                         }
//                         IpAddr::V6(ipv6) => {
//                             params
//                                 .subject_alt_names
//                                 .push(SanType::IpAddress(IpAddr::V6(ipv6)));
//                         }
//                     }
//                 }
//             }
//             Err(e) => {
//                 eprintln!("Failed to get network interfaces: {e}");
//             }
//         }

//         let key_pair = rcgen::KeyPair::generate().unwrap();
//         let cert = params.self_signed(&key_pair).unwrap();

//         tls_config_from_mem(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes())
//     }

//     async fn h_handler(
//         p_req: Request<hyper::body::Incoming>,
//     ) -> Result<Response<ResponseBody>, std::convert::Infallible> {
//         match (p_req.method(), p_req.uri().path()) {
//             (&Method::GET, "/plaintext") => Ok(Response::new(ResponseBody::from("Hello, World!"))),
//             _ => Ok(Response::builder()
//                 .status(StatusCode::NOT_FOUND)
//                 .body(ResponseBody::from("404"))
//                 .expect("Failed to build response")),
//         }
//     }

//     #[test]
//     fn test_http1() {
//         rustls::crypto::ring::default_provider()
//             .install_default()
//             .unwrap();

//         const MAX_EXECUTORS: usize = 1;
//         const MAX_CONNECTIONS: u64 = 50_000;
//         LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(
//             MAX_EXECUTORS,
//             glommio::CpuSet::online().ok(),
//         ))
//         .on_all_shards(|| async move {
//             let id = glommio::executor().id();

//             // initialize once
//             let log_file = LogFileConfig {
//                 roller: LogRolling::DAILY,
//                 dir: "log".to_owned(),
//                 file_name: format!("exec{}.log", id),
//                 ansi: false,
//             };
//             let _log = init_log(LogFilterLevel::TRACE, Some(log_file), None).await;
//             let addr = ([0, 0, 0, 0], 8080);
//             s_info!("Starting http1 server on {addr:?} via executor: {id}");
//             serve_http1(addr, h_handler, MAX_CONNECTIONS).await.unwrap();
//         })
//         .unwrap()
//         .join_all();
//     }

//     #[test]
//     fn test_http1_tls() {
//         rustls::crypto::ring::default_provider()
//             .install_default()
//             .unwrap();

//         const MAX_EXECUTORS: usize = 1;
//         const MAX_CONNECTIONS: u64 = 50_000;
//         LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(
//             MAX_EXECUTORS,
//             glommio::CpuSet::online().ok(),
//         ))
//         .on_all_shards(|| async move {
//             let id = glommio::executor().id();

//             // initialize once
//             let log_file = LogFileConfig {
//                 roller: LogRolling::DAILY,
//                 dir: "log".to_owned(),
//                 file_name: format!("exec{}.log", id),
//                 ansi: false,
//             };
//             let _log = init_log(LogFilterLevel::TRACE, Some(log_file), None).await;
//             let addr = ([0, 0, 0, 0], 8080);
//             let tls_config = generate_self_signed_cert();
//             let tls = TlsAcceptor::from(Arc::new(tls_config));
//             s_info!("Starting http1 server on {addr:?} via executor: {id}");
//             serve_http1_tls(addr, h_handler, MAX_CONNECTIONS, tls)
//                 .await
//                 .unwrap();
//         })
//         .unwrap()
//         .join_all();
//     }

//     #[test]
//     fn test_http2_tls() {
//         rustls::crypto::ring::default_provider()
//             .install_default()
//             .unwrap();

//         const MAX_EXECUTORS: usize = 1;
//         const MAX_CONNECTIONS: u64 = 32768;
//         LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(
//             MAX_EXECUTORS,
//             glommio::CpuSet::online().ok(),
//         ))
//         .on_all_shards(|| async move {
//             let id = glommio::executor().id();

//             // initialize once
//             let log_file = LogFileConfig {
//                 roller: LogRolling::DAILY,
//                 dir: "log".to_owned(),
//                 file_name: format!("exec{}.log", id),
//                 ansi: false,
//             };
//             let _log = init_log(LogFilterLevel::WARN, Some(log_file), None).await;
//             let mut tls_config = generate_self_signed_cert();
//             tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

//             let addr = ([0, 0, 0, 0], 8080);
//             let tls = TlsAcceptor::from(Arc::new(tls_config));
//             s_info!("Starting http2 server on {addr:?} via executor: {id}");
//             serve_http2(
//                 addr,
//                 h_handler,
//                 MAX_CONNECTIONS,
//                 std::time::Duration::from_secs(10),
//                 std::time::Duration::from_secs(30),
//                 tls,
//             )
//             .await
//             .unwrap();
//         })
//         .unwrap()
//         .join_all();
//     }
// }
