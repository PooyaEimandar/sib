use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(feature = "net-h1-server")]
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

#[cfg(all(feature = "net-h2-server", target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct H2Config {
    pub backlog: usize,
    pub enable_connect_protocol: bool,
    pub initial_connection_window_size: u32,
    pub initial_window_size: u32,
    pub io_timeout: std::time::Duration,
    pub max_concurrent_streams: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub max_sessions: u64,
    pub num_of_shards: usize,
}

#[cfg(all(feature = "net-h2-server", target_os = "linux"))]
impl Default for H2Config {
    fn default() -> Self {
        Self {
            backlog: 512,
            enable_connect_protocol: false,
            initial_connection_window_size: 64 * 1024,
            initial_window_size: 256 * 1024,
            io_timeout: std::time::Duration::from_secs(60),
            max_concurrent_streams: 4096,
            max_frame_size: 32 * 1024,
            max_header_list_size: 32 * 1024,
            max_sessions: 1024,
            num_of_shards: 2,
        }
    }
}

pub trait HFactory: Send + Sync + Sized + 'static {
    #[cfg(feature = "net-h1-server")]
    type Service: crate::network::http::session::HService + Send;

    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    type HAsyncService: crate::network::http::session::HAsyncService + Send;

    // create a new http service for each connection
    #[cfg(feature = "net-h1-server")]
    fn service(&self, id: usize) -> Self::Service;

    // create a new http async service for each connection
    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    fn async_service(&self, id: usize) -> Self::HAsyncService;

    /// Start the http service
    #[cfg(feature = "net-h1-server")]
    fn start_h1<L: ToSocketAddrs>(
        self,
        addr: L,
        stack_size: usize,
    ) -> std::io::Result<may::coroutine::JoinHandle<()>> {
        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };
        let listener = may::net::TcpListener::bind(addr)?;
        may::go!(
            may::coroutine::Builder::new()
                .name("Sib_H1_Factory".to_owned())
                .stack_size(stacksize),
            move || {
                use crate::network::http::h1_server::serve;

                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream in listener.incoming() {
                    let mut stream = mc!(stream);

                    // get the client IP address
                    let peer_addr = stream.peer_addr().unwrap_or(SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    ));

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;

                    mc!(stream.set_nodelay(true));
                    let service = self.service(id);
                    let builder = may::coroutine::Builder::new().id(id);
                    let _ = may::go!(builder, move || if let Err(_e) =
                        serve(&mut stream, peer_addr, service)
                    {
                        //s_error!("service err = {e:?}");
                        stream.shutdown(std::net::Shutdown::Both).ok();
                    });
                }
            }
        )
    }

    #[cfg(feature = "net-h1-server")]
    fn start_h1_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        io_timeout: std::time::Duration,
        stack_size: usize,
        rate_limiter: Option<super::ratelimit::RateLimiterKind>,
    ) -> std::io::Result<may::coroutine::JoinHandle<()>> {
        use std::net::Shutdown;

        let cert = boring::x509::X509::from_pem(chain_cert_key.1).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Cert error: {e}"))
        })?;
        let pkey = boring::pkey::PKey::private_key_from_pem(chain_cert_key.2).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Key error: {e}"))
        })?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| std::io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = chain_cert_key.0 {
            // add chain
            for extra in boring::x509::X509::stack_from_pem(chain).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Chain error: {e}"),
                )
            })? {
                tls_builder.add_extra_chain_cert(extra)?;
            }
        }
        tls_builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
        tls_builder.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
        tls_builder.set_options(boring::ssl::SslOptions::NO_TICKET);
        tls_builder.set_session_id_context(b"sib\0")?;
        tls_builder.set_alpn_protos(b"\x08http/1.1")?;

        #[cfg(not(debug_assertions))]
        {
            tls_builder.set_servername_callback(|ssl_ref, _| {
                if ssl_ref
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .is_none()
                {
                    eprintln!("SNI not provided, rejecting connection");
                    return Err(boring::ssl::SniError::ALERT_FATAL);
                }
                Ok(())
            });
        }

        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024
        };
        let tls_acceptor = std::sync::Arc::new(tls_builder.build());
        let listener = may::net::TcpListener::bind(addr)?;

        may::go!(
            may::coroutine::Builder::new()
                .name("Sib_H1_TLS_Factory".to_owned())
                .stack_size(stacksize),
            move || {
                use crate::network::http::h1_server::serve_tls;

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

                    if let Some(rl) = &rate_limiter
                        && !ip.is_unspecified()
                    {
                        use super::ratelimit::RateLimiter;
                        let result = rl.check(ip.to_string().into());
                        if !result.allowed {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
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

                    let _ = may::go!(builder, move || {
                        match tls_acceptor_cloned.accept(stream) {
                            Ok(mut tls_stream) => {
                                if let Err(e) = serve_tls(&mut tls_stream, peer_addr, service) {
                                    tls_stream.get_mut().shutdown(Shutdown::Both).ok();
                                    eprintln!("serve_tls failed with error: {e} from {peer_addr}");
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS handshake failed {e} from {peer_addr}");
                                match stream_cloned {
                                    Ok(stream_owned) => {
                                        stream_owned.shutdown(Shutdown::Both).ok();
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to shut down the stream after TLS handshake failure: {e} from {peer_addr}"
                                        );
                                    }
                                };
                            }
                        }
                    });
                }
            }
        )
    }

    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    fn start_h2_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        h2_cfg: H2Config,
        rate_limiter: Option<super::ratelimit::RateLimiterKind>,
    ) -> std::io::Result<()> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls_pemfile::{certs, pkcs8_private_keys};

        let certs: Vec<CertificateDer<'static>> = {
            let mut reader = std::io::Cursor::new(chain_cert_key.1);
            certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect()
        };

        let key: PrivateKeyDer<'static> = {
            let mut reader = std::io::Cursor::new(chain_cert_key.2);
            let keys: Result<Vec<_>, std::io::Error> = pkcs8_private_keys(&mut reader)
                .map(|res| {
                    res.map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("bad key: {e}"),
                        )
                    })
                })
                .collect();
            let keys = keys?;
            if let Some(key) = keys.into_iter().next() {
                PrivateKeyDer::from(key)
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no private key found",
                ));
            }
        };

        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("could not load cert/key: {e}"),
                )
            })?;

        // Set ALPN protocols to support HTTP/2 and HTTP/1.1
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = futures_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let socket_addr = addr.to_socket_addrs()?.next().unwrap();

        let factory = std::sync::Arc::new(self);
        let rate_limiter_arc = std::sync::Arc::new(rate_limiter);
        glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
            h2_cfg.num_of_shards,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(move || {
            let tls_acceptor = tls_acceptor.clone();
            let factory = factory.clone();
            let h2_cfg = h2_cfg.clone();
            let rate_limiter_arc = rate_limiter_arc.clone();

            async move {
                let id = glommio::executor().id();
                #[cfg(unix)]
                let listener = match make_listener(
                    socket_addr,
                    socket2::Protocol::TCP,
                    h2_cfg.backlog,
                    h2_cfg.io_timeout,
                ) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("Failed to create h2 listener on address {socket_addr}: {e}");
                        return;
                    }
                };
                #[cfg(not(unix))]
                let listener = match TcpListener::bind(addr) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("Failed to create h2 listener on address {socket_addr}: {e}");
                        return;
                    }
                };

                // Generous concurrency budget (tune to your box)
                let sem = std::rc::Rc::new(glommio::sync::Semaphore::new(h2_cfg.max_sessions));

                println!("Shard {id} listening on H2/TLS on {socket_addr}");

                loop {
                    let permit = std::rc::Rc::clone(&sem).acquire(1).await;

                    let stream = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => {
                            drop(permit);
                            continue;
                        }
                    };
                    // Reduce head-of-line pauses within a stream mux
                    stream.set_nodelay(true).ok();

                    let factory = factory.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let h2_cfg = h2_cfg.clone();
                    let rate_limiter_arc = rate_limiter_arc.clone();
                    glommio::spawn_local(async move {
                        // Hold the permit until the end of this session
                        let _p = permit;

                        let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                            SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                0,
                            )
                        });
                        let ip = peer_addr.ip();

                        if let Some(rl) = rate_limiter_arc.as_ref()
                            && !ip.is_unspecified()
                        {
                            use super::ratelimit::RateLimiter;
                            let result = rl.check(ip.to_string().into());
                            if !result.allowed {
                                let _ = stream.shutdown(std::net::Shutdown::Both).await;
                                return;
                            }
                        }

                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("H2 TLS handshake error: {e}");
                                return;
                            }
                        };

                        use crate::network::http::h2_server::serve;
                        let service = factory.async_service(id);
                        if let Err(e) = serve(tls_stream, service, &h2_cfg, peer_addr).await {
                            eprintln!("h2 serve got an error: {e}");
                        }
                    })
                    .detach();
                }
            }
        })
        .unwrap()
        .join_all();
        Ok(())
    }
}

fn make_listener(
    addr: SocketAddr,
    protocol: socket2::Protocol,
    backlog: usize,
    io_timeout: std::time::Duration,
) -> std::io::Result<glommio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    use std::os::fd::{FromRawFd, IntoRawFd};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = if protocol == socket2::Protocol::TCP {
        Socket::new(domain, Type::STREAM.nonblocking(), Some(protocol))?
    } else {
        Socket::new(domain, Type::DGRAM, Some(protocol))?
    };

    sock.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    sock.set_reuse_port(true)?;
    sock.set_read_timeout(Some(io_timeout))?;
    sock.set_write_timeout(Some(io_timeout))?;
    sock.bind(&addr.into())?;

    let backlog: i32 = if backlog == 0 {
        1024
    } else {
        match i32::try_from(backlog) {
            Ok(y) => y,
            Err(_) => {
                eprintln!("backlog too large, using 1024");
                1024
            }
        }
    };
    sock.listen(backlog)?;

    let listener = unsafe { glommio::net::TcpListener::from_raw_fd(sock.into_raw_fd()) };
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use crate::network::http::server::HFactory;
    use crate::network::http::session::{HAsyncService, HService, Session};
    use std::sync::Once;

    static INIT: Once = Once::new();

    struct EchoServer;

    impl HService for EchoServer {
        fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            let req_method = session.req_method();
            let req_path = session.req_path();
            let req_body = session.req_body_h1(std::time::Duration::from_secs(5))?;
            let body = bytes::Bytes::from(format!(
                "Echo: {req_method:?} {req_path:?}\r\nBody: {req_body:?}"
            ));

            session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Type", "text/plain")?
                .header_str("Content-Length", &body.len().to_string())?
                .body(body)
                .eom()?;

            if req_method == "POST" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "H1 POST should return WouldBlock",
                ));
            }
            Ok(())
        }
    }
    #[async_trait::async_trait(?Send)]
    impl HAsyncService for EchoServer {
        async fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            let req_method = session.req_method();
            let req_path = session.req_path().to_owned();
            let req_body = session.req_body_h2(std::time::Duration::from_secs(5)).await;
            let body = bytes::Bytes::from(format!(
                "Echo: {req_method:?} {req_path:?}\r\nBody: {req_body:?}"
            ));

            let content_len = body.len().to_string();
            session
                .status_code(http::StatusCode::OK)
                .header(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/plain"),
                )?
                .header(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_str(&content_len).expect("content_len"),
                )?
                .body(body)
                .eom()?;
            Ok(())
        }
    }

    impl HFactory for EchoServer {
        type Service = Self;
        type HAsyncService = Self;

        #[cfg(feature = "net-h1-server")]
        fn service(&self, _id: usize) -> Self::Service {
            EchoServer
        }

        #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
        fn async_service(&self, _id: usize) -> Self::HAsyncService {
            EchoServer
        }
    }

    fn create_self_signed_tls_pems() -> (String, String) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        use sha2::{Digest, Sha256};

        let mut params: CertificateParams = Default::default();
        params.not_before = date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        // Get PEM strings
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Convert PEM -> DER by stripping header/footer and base64-decoding
        let mut der_b64 = String::with_capacity(cert_pem.len());
        for line in cert_pem.lines() {
            if !line.starts_with("-----") {
                der_b64.push_str(line.trim());
            }
        }
        let cert_der = b64.decode(der_b64).expect("PEM base64 decode");

        // SHA-256 over DER, base64 encode result
        let hash = Sha256::digest(&cert_der);
        let base64_hash = b64.encode(hash);

        println!("BASE64_SHA256_OF_DER_CERT: {}", base64_hash);

        INIT.call_once(|| {
            rustls::crypto::CryptoProvider::install_default(
                rustls::crypto::aws_lc_rs::default_provider(),
            )
            .expect("install aws-lc-rs");
        });

        (cert_pem, key_pem)
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_tls_server_gracefull_shutdown() {
        use std::time::Duration;
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 0);

        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1_tls(
                addr,
                (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                Duration::from_secs(10),
                0,
                None,
            )
            .expect("H1 TLS server failed to start");

        let handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        handler.join().expect("shutdown signaler failed");
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_get() {
        use may::net::TcpStream;
        use std::{
            io::{Read, Write},
            time::Duration,
        };

        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // Pick a port and start the server
        let addr = "127.0.0.1:8081";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(500));

            // Client sends HTTP request
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();

            eprintln!("H1 GET Response: {response}");
            assert!(response.contains("/test"));
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_millis(500));
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_post() {
        use may::net::TcpStream;
        use std::time::Duration;
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8082";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            use std::io::{Read, Write};
            may::coroutine::sleep(Duration::from_millis(500));

            let mut stream = TcpStream::connect(addr).expect("connect");

            let body = b"hello=world";
            let req = format!(
                "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );

            stream.write_all(req.as_bytes()).unwrap();
            stream.write_all(body).unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();
            eprintln!("H1 POST Response: {response}");

            // Should include method, path, and echoed body contents
            assert!(response.contains("POST"));
            assert!(response.contains("/submit"));
        });

        may::join!(server_handle, client_handler);
        std::thread::sleep(Duration::from_millis(500));
    }

    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    #[test]
    fn test_h2_server_get() {
        let addr = "127.0.0.1:8083";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H2Config;
            let h2_cfg = H2Config::default();
            // Pick a port and start the server
            EchoServer
                .start_h2_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h2_cfg, None)
                .expect("start_h2_tls");
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http2_adaptive_window(true)
            .build()
            .expect("reqwest client");

        let resp = client
            .get(format!("https://{}", addr))
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        eprintln!("Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        eprintln!("Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }

    #[cfg(all(feature = "net-h2-server", target_os = "linux"))]
    #[test]
    fn test_h2_server_post() {
        let addr = "127.0.0.1:8084";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H2Config;
            let h2_cfg = H2Config::default();
            // Pick a port and start the server
            EchoServer
                .start_h2_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h2_cfg, None)
                .expect("start_h2_tls");
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http2_adaptive_window(true)
            .build()
            .expect("reqwest client");

        let resp = client
            .get(format!("https://{}", addr))
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        eprintln!("Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        eprintln!("Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }
}
