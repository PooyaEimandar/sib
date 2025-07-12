use crate::network::http::ratelimit::{RateLimiter, RateLimiterKind};

use super::session::{self, Session};
use bytes::{BufMut, BytesMut};
use may::net::{TcpListener, TcpStream};
use may::{coroutine, go};
use std::{io::{self, Read}};
use std::mem::MaybeUninit;

#[cfg(unix)]
use std::net::SocketAddr;
use std::net::{Shutdown, ToSocketAddrs};

#[cfg(unix)]
use may::io::WaitIo;

const MIN_BUF_LEN: usize = 1024;
const MAX_BODY_LEN: usize = 4096;
pub const BUF_LEN: usize = MAX_BODY_LEN * 8;
    
macro_rules! mc {
    ($exp: expr) => {
        match $exp {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Accept error: {e}");
                continue;
            }
        }
    };
}

pub trait H1Service {
    fn call<S: Read + std::io::Write>(&mut self, session: &mut Session<S>) -> io::Result<()>;
}

pub trait H1ServiceFactory: Send + Sized + 'static {
    type Service: H1Service + Send;
    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

    /// Start the http service
    fn start<L: ToSocketAddrs>(
        self,
        addr: L,
        number_of_workers: usize,
        stack_size: usize,
        rate_limiter: Option<RateLimiterKind>,
    ) -> io::Result<coroutine::JoinHandle<()>> {
        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };
        may::config()
            .set_workers(number_of_workers)
            .set_stack_size(stacksize);
        let listener = TcpListener::bind(addr)?;
        go!(
            coroutine::Builder::new().name("H1ServiceFactory".to_owned()),
            move || {
                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream in listener.incoming() {
                    let mut stream = mc!(stream);

                    // get the client IP address
                    let peer_addr = stream.peer_addr().unwrap_or(
                        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    );
                    // Check if the client IP is rate limited
                    if let Some(rl) = &rate_limiter {
                        if !peer_addr.ip().is_unspecified() {
                            let result = rl.check(peer_addr.ip().to_string().into());
                            if !result.allowed {
                                eprintln!("Dropped client {peer_addr} (rate limited)");
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                        }
                    }

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;
                    mc!(stream.set_nodelay(true));
                    let service = self.service(id);
                    let builder = may::coroutine::Builder::new().id(id);
                    let _ = go!(
                        builder,
                        move || if let Err(_e) = serve(&mut stream, peer_addr, service) {
                            //s_error!("service err = {e:?}");
                            stream.shutdown(std::net::Shutdown::Both).ok();
                        }
                    );
                }
            }
        )
    }

    #[cfg(feature = "sys-boring-ssl")]
    fn start_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        number_of_workers: usize,
        ssl: &super::util::SSL,
        stack_size: usize,
        rate_limiter: Option<RateLimiterKind>,
    ) -> io::Result<coroutine::JoinHandle<()>> {
        use std::net::Shutdown;

        let cert = boring::x509::X509::from_pem(ssl.cert_pem).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Cert error: {e}"))
        })?;
        let pkey = boring::pkey::PKey::private_key_from_pem(ssl.key_pem).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Key error: {e}"))
        })?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = ssl.chain_pem {
            let chain_x509 = boring::x509::X509::from_pem(chain).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("Chain error: {e}"))
            })?;
            tls_builder.add_extra_chain_cert(chain_x509)?;
        }
        tls_builder.set_min_proto_version(ssl.min_version.to_boring())?;
        tls_builder.set_max_proto_version(ssl.max_version.to_boring())?;
        tls_builder.set_alpn_protos(b"\x08http/1.1")?;

        tls_builder.set_servername_callback(|ssl_ref, _| {
            if ssl_ref.servername(boring::ssl::NameType::HOST_NAME).is_none() {
                eprintln!("SNI not provided, rejecting connection");
                return Err(boring::ssl::SniError::ALERT_FATAL);
            }
            Ok(())
        });

        let stacksize = if stack_size > 0 { stack_size } else { 2 * 1024 * 1024 };
        may::config()
            .set_workers(number_of_workers)
            .set_stack_size(stacksize);

        let io_timeout = ssl.io_timeout;
        let tls_acceptor = std::sync::Arc::new(tls_builder.build());
        let listener = TcpListener::bind(addr)?;

        go!(coroutine::Builder::new().name("H1TLSServiceFactory".to_owned()), move || {
            #[cfg(unix)]
            use std::os::fd::AsRawFd;
            #[cfg(windows)]
            use std::os::windows::io::AsRawSocket;

            for stream_incoming in listener.incoming() {

                let stream = mc!(stream_incoming);
                let _ = stream.set_nodelay(true);
                let _ = stream.set_write_timeout(Some(io_timeout));
                let _ = stream.set_read_timeout(Some(io_timeout));

                let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                });
                let ip = peer_addr.ip();

                if let Some(rl) = &rate_limiter {
                    if !ip.is_unspecified() {
                        let result = rl.check(ip.to_string().into());
                        if !result.allowed {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                    }
                }

                #[cfg(unix)]
                let id = stream.as_raw_fd() as usize;
                #[cfg(windows)]
                let id = stream.as_raw_socket() as usize;
                
                let builder = may::coroutine::Builder::new().id(id);
                let service = self.service(id);
                let stream_cloned = stream.try_clone();
                let tls_acceptor_cloned = tls_acceptor.clone();

                let _ = go!(
                    builder, 
                    move || {
                        match tls_acceptor_cloned.accept(stream) {
                            Ok(mut tls_stream) => {
                                if let Err(e) = serve_tls(&mut tls_stream, peer_addr, service) {
                                    tls_stream.get_mut().shutdown(Shutdown::Both).ok();
                                    eprintln!("serve_tls failed with error: {e} from {peer_addr}");
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS handshake failed {e} from {peer_addr}");
                                match stream_cloned
                                {
                                    Ok(stream_owned) => {
                                        stream_owned.shutdown(Shutdown::Both).ok();
                                    },
                                    Err(e) => {
                                        eprintln!("Failed to shut down the stream after TLS handshake failure: {e} from {peer_addr}");
                                    },
                                };
                            }
                        }
                    }
                );            
            }
        })
    }
}

#[inline]
pub(crate) fn reserve_buf(buf: &mut BytesMut) {
    let rem = buf.capacity() - buf.len();
    if rem < MIN_BUF_LEN {
        buf.reserve(BUF_LEN - rem);
    }
}

#[cfg(unix)]
#[inline]
fn read(stream: &mut impl Read, buf: &mut BytesMut) -> io::Result<bool> {
    reserve_buf(buf);
    let chunk = buf.chunk_mut();
    let len = chunk.len();

    // SAFETY: We ensure exclusive access and will commit the right amount
    let read_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), len) };

    let mut io_slice = [std::io::IoSliceMut::new(read_buf)];
    let n = match stream.read_vectored(&mut io_slice) {
        Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "read closed")),
        Ok(n) => n,
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e),
    };

    unsafe {
        buf.advance_mut(n);
    }
    Ok(n < len)
}

#[cfg(unix)]
#[inline]
fn write(stream: &mut impl std::io::Write, rsp_buf: &mut BytesMut) -> io::Result<usize> {
    use bytes::Buf;
    use std::io::IoSlice;

    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    let mut write_cnt = 0;
    while write_cnt < len {
        let slice = IoSlice::new(unsafe { write_buf.get_unchecked(write_cnt..) });
        match stream.write_vectored(std::slice::from_ref(&slice)) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed")),
            Ok(n) => write_cnt += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    rsp_buf.advance(write_cnt);
    Ok(write_cnt)
}

#[cfg(unix)]
fn read_write<S, T>(
    stream: &mut S,
    peer_addr: &SocketAddr,
    req_buf: &mut BytesMut,
    rsp_buf: &mut BytesMut,
    service: &mut T,
) -> io::Result<bool>
where
    S: Read + io::Write,
    T: H1Service,
{
    // read the socket for requests
    let blocked = read(stream, req_buf)?;
    loop {
        // create a new session
        let mut headers = [MaybeUninit::uninit(); session::MAX_HEADERS];
        let mut sess = match session::new_session(stream, peer_addr, &mut headers, req_buf, rsp_buf)? {
            Some(sess) => sess,
            None => break,
        };
        // call the service with the session
        if let Err(e) = service.call(&mut sess) {
            if e.kind() == std::io::ErrorKind::ConnectionAborted {
                return Err(e);
            }
        }
    }
    // send the response back to client
    write(stream, rsp_buf)?;
    Ok(blocked)
}

#[cfg(unix)]
fn serve<T: H1Service>(stream: &mut TcpStream, peer_addr: SocketAddr,mut service: T) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, &peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.wait_io();
        }
    }
}

#[cfg(all(unix, feature = "sys-boring-ssl"))]
fn serve_tls<T: H1Service>(
    stream: &mut boring::ssl::SslStream<may::net::TcpStream>,
    peer_addr: SocketAddr,
    mut service: T,
) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, &peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.get_mut().wait_io();
        }
    }
}

#[cfg(not(unix))]
fn serve<T: H1Service>(stream: &mut TcpStream, mut service: T) -> io::Result<()> {
    use std::io::Write;

    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);
    loop {
        // read the socket for requests
        reserve_buf(&mut req_buf);
        let read_buf: &mut [u8] = unsafe { std::mem::transmute(&mut *req_buf.chunk_mut()) };
        let read_cnt = stream.read(read_buf)?;
        if read_cnt == 0 {
            //connection was closed
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        unsafe { req_buf.advance_mut(read_cnt) };

        // prepare the requests
        if read_cnt > 0 {
            loop {
                let mut headers = [MaybeUninit::uninit(); session::MAX_HEADERS];
                let mut sess =
                    match session::new_session(stream, &mut headers, &mut req_buf, &mut rsp_buf)? {
                        Some(sess) => sess,
                        None => break,
                    };

                if let Err(e) = service.call(&mut sess) {
                    if e.kind() == std::io::ErrorKind::ConnectionAborted {
                        // abort the connection immediately
                        return Err(e);
                    }
                }
            }
        }

        // send the result back to client
        stream.write_all(&rsp_buf)?;
    }
}

#[cfg(test)]
mod tests {
    use crate::network::http::{
        h1::{H1Service, H1ServiceFactory},
        util::Status,
        session::Session,
    };
    use may::net::TcpStream;
    use std::{
        io::{Read, Write},
        time::Duration,
    };

    struct H1Server<T>(pub T);

    struct EchoService;

    impl H1Service for EchoService {
        fn call<S: Read + Write>(&mut self, session: &mut Session<S>) -> std::io::Result<()> {
            let req_method = session.req_method().unwrap_or_default().to_owned();
            let req_path = session.req_path().unwrap_or_default().to_owned();
            let req_body = session.req_body(std::time::Duration::from_secs(1))?;
            let body = bytes::Bytes::from(format!(
                "Echo: {req_method:?} {req_path:?}\r\nBody: {req_body:?}"
            ));
            let mut body_len = itoa::Buffer::new();
            let body_len_str = body_len.format(body.len());

            session
                .status_code(Status::Ok)
                .header_str("Content-Type", "text/plain")?
                .header_str("Content-Length", body_len_str)?
                .body(&body)
                .eom();
            Ok(())
        }
    }

    impl H1ServiceFactory for H1Server<EchoService> {
        type Service = EchoService;

        fn service(&self, _id: usize) -> EchoService {
            EchoService
        }
    }

    #[cfg(feature = "sys-boring-ssl")]
    fn create_self_signed_tls_pems() -> (String, String) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        let mut params: CertificateParams = Default::default();
        params.not_before = rcgen::date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn test_h1_gracefull_shutdown() {
        let addr = "127.0.0.1:8080";
        let server_handle = H1Server(EchoService)
            .start(addr, 1, 0, None)
            .expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    #[test]
    fn test_h1_server_response() {
        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = H1Server(EchoService)
            .start(addr, 1, 0, None)
            .expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));

            // Client sends HTTP request
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();

            assert!(response.contains("/test"));
            print!("Response: {response}");
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(feature = "sys-boring-ssl")]
    #[test]
    fn test_tls_h1_gracefull_shutdown() {
        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let ssl = crate::network::http::util::SSL
        {
            cert_pem: cert_pem.as_bytes(),
            key_pem: key_pem.as_bytes(),
            chain_pem: None,
            min_version: crate::network::http::util::SSLVersion::TLS1_2,
            max_version: crate::network::http::util::SSLVersion::TLS1_3,
            io_timeout: std::time::Duration::from_secs(10)
        };
        let addr = "127.0.0.1:8080";
        let server_handle = H1Server(EchoService)
            .start_tls(addr, 1, &ssl, 0, None)
            .expect("h1 TLS start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    // #[test]
    // fn test_tls_h1_server_response() {
    //     let (cert_pem, key_pem) = create_self_signed_tls_pems();
    //     // Pick a port and start the server
    //     let addr = "127.0.0.1:8080";
    //     let server_handle = H1Server(EchoService)
    //         .start_tls(addr, cert_pem.as_bytes(), key_pem.as_bytes())
    //         .expect("h1 start server");

    //     may::join!(server_handle);

    //     std::thread::sleep(Duration::from_secs(200));
    // }
}
