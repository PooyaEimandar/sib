#[cfg(unix)]
use std::net::{SocketAddr, ToSocketAddrs};

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

pub trait HFactory: Send + Sync + Sized + 'static {
    type Service: crate::network::http::session::HService + Send;

    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

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
                    let peer_addr = stream.peer_addr().unwrap_or(std::net::SocketAddr::new(
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

    #[cfg(all(feature = "net-h1-server", feature = "sys-boring-ssl"))]
    fn start_h1_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        ssl: &super::util::SSL,
        stack_size: usize,
        rate_limiter: Option<super::ratelimit::RateLimiterKind>,
    ) -> std::io::Result<may::coroutine::JoinHandle<()>> {
        use std::net::Shutdown;

        let cert = boring::x509::X509::from_pem(ssl.cert_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Cert error: {e}"))
        })?;
        let pkey = boring::pkey::PKey::private_key_from_pem(ssl.key_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Key error: {e}"))
        })?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| std::io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = ssl.chain_pem {
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
        tls_builder.set_min_proto_version(ssl.min_version.to_boring())?;
        tls_builder.set_max_proto_version(ssl.max_version.to_boring())?;
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
        let io_timeout = ssl.io_timeout;
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

                    if let Some(rl) = &rate_limiter {
                        if !ip.is_unspecified() {
                            use super::ratelimit::RateLimiter;
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

    #[cfg(feature = "net-h3-server")]
    fn start_h3_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        (cert_pem_file_path, key_pem_file_path): (&str, &str),
        io_timeout: std::time::Duration,
        verify_peer: bool,
        (stack_size, num_of_workers): (usize, usize),
        extend_connect: bool,
    ) -> std::io::Result<()> {
        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };

        // share a service factory safely across dispatchers
        let factory: std::sync::Arc<dyn Fn(usize) -> Self::Service + Send + Sync> =
            std::sync::Arc::new(move |id| self.service(id));

        let address = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("Failed to get address info"))?;
        let sockets = bind_udp_sockets(address, io_timeout, num_of_workers)?;
        for socket in sockets {
            let local_addr = socket.local_addr().map_err(|e| {
                std::io::Error::other(format!("Failed to get local address: {e:?}"))
            })?;

            use crate::network::http::h3_server::build_quiche_config;
            let cfg = build_quiche_config(
                cert_pem_file_path,
                key_pem_file_path,
                io_timeout,
                verify_peer,
                extend_connect,
            )?;

            let factory_cloned = factory.clone();
            let _ = may::go!(
                may::coroutine::Builder::new()
                    .name("H3ServiceFactory".to_owned())
                    .stack_size(stacksize),
                move || {
                    use crate::network::http::h3_server::quic_dispatcher;
                    quic_dispatcher(socket, cfg, local_addr, extend_connect, factory_cloned);
                }
            );
        }
        Ok(())
    }
}

fn bind_udp_sockets(
    addr: SocketAddr,
    io_timeout: std::time::Duration,
    n: usize,
) -> std::io::Result<Vec<std::sync::Arc<may::net::UdpSocket>>> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::{FromRawFd, IntoRawFd};

    // Only fan out on Linux (REUSEPORT)
    let fanout = if cfg!(any(target_os = "linux", target_os = "android")) {
        n
    } else {
        1
    };

    let mut v = Vec::with_capacity(fanout);
    for _ in 0..fanout {
        let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.set_read_timeout(Some(io_timeout))?;
        s.set_write_timeout(Some(io_timeout))?;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        s.set_reuse_port(true)?; // enable only on Linux/Android

        s.bind(&addr.into())?;
        s.set_recv_buffer_size(32 * 1024 * 1024)?;
        s.set_send_buffer_size(32 * 1024 * 1024)?;
        s.set_nonblocking(true)?;

        // Transfer ownership of the FD to may::net::UdpSocket
        let fd = s.into_raw_fd();
        let may_udp = unsafe { may::net::UdpSocket::from_raw_fd(fd) };
        v.push(std::sync::Arc::new(may_udp));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use crate::network::http::{
        server::HFactory,
        session::{HService, Session},
        util::{SSLVersion, Status},
    };
    use may::net::TcpStream;
    use std::{
        io::{Read, Write},
        time::Duration,
    };

    struct EchoServer;

    impl HService for EchoServer {
        fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            let req_method = session.req_method().unwrap_or_default().to_owned();
            let req_path = session.req_path().unwrap_or_default().to_owned();
            let req_body = session.req_body(std::time::Duration::from_secs(5))?;
            let body = bytes::Bytes::from(format!(
                "Echo: {req_method:?} {req_path:?}\r\nBody: {req_body:?}"
            ));

            session
                .status_code(Status::Ok)
                .header_str("Content-Type", "text/plain")?
                .header_str("Content-Length", &body.len().to_string())?
                .body(&body)
                .eom();

            if !session.is_h3() && req_method == "POST" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "H1 POST should return WouldBlock",
                ));
            }
            Ok(())
        }
    }

    impl HFactory for EchoServer {
        type Service = EchoServer;

        fn service(&self, _id: usize) -> EchoServer {
            EchoServer
        }
    }

    #[cfg(feature = "sys-boring-ssl")]
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

        (cert_pem, key_pem)
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        handler.join().expect("shutdown signaler failed");
    }

    #[cfg(all(feature = "sys-boring-ssl", feature = "net-h1-server"))]
    #[test]
    fn test_h1_tls_server_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let ssl = crate::network::http::util::SSL {
            cert_pem: cert_pem.as_bytes(),
            key_pem: key_pem.as_bytes(),
            chain_pem: None,
            min_version: SSLVersion::TLS1_2,
            max_version: SSLVersion::TLS1_3,
            io_timeout: std::time::Duration::from_secs(10),
        };
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1_tls(addr, &ssl, 0, None)
            .expect("h1 TLS start server");

        let handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        handler.join().expect("shutdown signaler failed");
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_get() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

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
            eprintln!("\r\nH1 GET Response: {response}");
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_post() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            use std::io::{Read, Write};
            may::coroutine::sleep(Duration::from_millis(100));

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

            // Should include method, path, and echoed body contents
            assert!(response.contains("POST"));
            assert!(response.contains("/submit"));
            eprintln!("\r\nH1 POST Response: {response}");
        });

        may::join!(server_handle, client_handler);
        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(feature = "net-h3-server")]
    #[tokio::test]
    async fn test_quiche_server_response() -> Result<(), Box<dyn std::error::Error>> {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        std::fs::write("/tmp/cert.pem", certs.0)?;
        std::fs::write("/tmp/key.pem", certs.1)?;

        // Start the server in a background thread
        std::thread::spawn(|| {
            println!("Starting H3 server...");
            EchoServer
                .start_h3_tls(
                    "0.0.0.0:8080",
                    ("/tmp/cert.pem", "/tmp/key.pem"),
                    std::time::Duration::from_secs(10),
                    true,
                    (0, NUMBER_OF_WORKERS),
                    false,
                )
                .expect("h3 start server");
        });

        // Wait for the server to be ready
        std::thread::sleep(std::time::Duration::from_millis(100000));

        let client = reqwest::Client::builder()
            .http3_prior_knowledge()
            .danger_accept_invalid_certs(true)
            .build()?;
        let url = "https://127.0.0.1:8080/";
        let res = client
            .get(url)
            .version(reqwest::Version::HTTP_3)
            .send()
            .await?;

        println!("Response: {:?} {}", res.version(), res.status());
        println!("Headers: {:#?}\n", res.headers());
        let body = res.text().await?;
        println!("{body}");

        Ok(())
    }
}
