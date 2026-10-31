use crate::network::http::{
    server::{H2Config, HFactory},
    session::{HAsyncService, Session},
    wt::{WTConfig, WtService, WtSession},
};
use bytes::Bytes;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct SharedService {
    thread: std::thread::ThreadId,
    runtime: tokio::runtime::Id,
    http_requests: Arc<AtomicUsize>,
    wt_sessions: Arc<AtomicUsize>,
}

impl SharedService {
    fn new() -> Self {
        Self {
            thread: std::thread::current().id(),
            runtime: tokio::runtime::Handle::current().id(),
            http_requests: Arc::new(AtomicUsize::new(0)),
            wt_sessions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn assert_caller_runtime(&self) {
        assert_eq!(std::thread::current().id(), self.thread);
        assert_eq!(tokio::runtime::Handle::current().id(), self.runtime);
    }
}

impl HFactory for SharedService {
    #[cfg(feature = "net-h1-server")]
    type Service = super::tests::EchoServer;
    type HAsyncService = Self;
    type WtService = Self;

    #[cfg(feature = "net-h1-server")]
    fn service(&self, _id: usize) -> Self::Service {
        super::tests::EchoServer
    }

    fn async_service(&self, _id: usize) -> Self {
        self.assert_caller_runtime();
        self.clone()
    }

    fn wt_service(&self, _id: usize) -> Self {
        self.assert_caller_runtime();
        self.clone()
    }
}

#[async_trait::async_trait(?Send)]
impl HAsyncService for SharedService {
    async fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        self.assert_caller_runtime();
        #[cfg(feature = "net-ws-server")]
        if session.is_ws() {
            use crate::network::http::ws::{MessageAssembler, OpCode};
            session.ws_accept_async().await?;
            let mut messages = MessageAssembler::new(32, 4)?;
            loop {
                let (op, payload) = messages.read_async(session).await?;
                self.assert_caller_runtime();
                match op {
                    OpCode::Ping => session.ws_write_async(OpCode::Pong, payload, true).await?,
                    OpCode::Close => {
                        return session.ws_write_async(OpCode::Close, payload, true).await;
                    }
                    _ => session.ws_write_async(op, payload, true).await?,
                }
            }
        }
        // Exercise the non-Send service futures supported by Sib's API.
        let body = std::rc::Rc::new(Bytes::from_static(b"shared runtime"));
        tokio::task::yield_now().await;
        self.assert_caller_runtime();
        self.http_requests.fetch_add(1, Ordering::SeqCst);
        session
            .status_code(http::StatusCode::OK)
            .header_str("content-length", &body.len().to_string())?
            .body((*body).clone())
            .eom_async()
            .await
    }
}

struct ActiveSession(Arc<AtomicUsize>);
impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait(?Send)]
impl WtService for SharedService {
    async fn call(&mut self, session: &mut WtSession) -> std::io::Result<()> {
        self.wt_sessions.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveSession(self.wt_sessions.clone());
        loop {
            self.assert_caller_runtime();
            let data = session.recv_dgram().await?;
            self.assert_caller_runtime();
            session.send_dgram(&data)?;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn http_webtransport_and_udp_share_the_callers_runtime() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let identity = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");
        let service = SharedService::new();
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let wt_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let wt_addr = wt_socket.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();

        let http = service.clone().serve_h2_tls(
            http_listener,
            (
                None,
                identity.server_cert_pem.as_bytes(),
                identity.server_key_pem.as_bytes(),
            ),
            H2Config::default(),
            shutdown.clone(),
        );
        let wt = service.clone().serve_wt_tls(
            wt_socket,
            (
                identity.server_cert_pem.as_bytes(),
                identity.server_key_pem.as_bytes(),
            ),
            WTConfig::default(),
            shutdown.clone(),
        );

        let clients = async {
            for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
                let builder = reqwest::Client::builder()
                    .tls_backend_rustls()
                    .no_proxy()
                    .add_root_certificate(
                        reqwest::Certificate::from_pem(identity.ca_cert_pem.as_bytes()).unwrap(),
                    );
                let builder = if version == http::Version::HTTP_11 {
                    builder.http1_only()
                } else {
                    builder.http2_prior_knowledge()
                };
                let response = builder
                    .build()
                    .unwrap()
                    .get(format!("https://{http_addr}/"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(response.version(), version);
                assert_eq!(response.bytes().await.unwrap(), "shared runtime");
            }

            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(identity.ca_cert_pem.as_bytes()) {
                roots.add(cert.unwrap()).unwrap();
            }
            let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            #[cfg(feature = "net-ws-server")]
            let mut websocket = {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut ws_tls = tls.clone();
                ws_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
                let connector = tokio_rustls::TlsConnector::from(Arc::new(ws_tls));
                let socket = tokio::net::TcpStream::connect(http_addr).await.unwrap();
                let mut socket = connector.connect("localhost".try_into().unwrap(), socket).await.unwrap();
                socket.write_all(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").await.unwrap();
                let mut response = Vec::new();
                while !response.ends_with(b"\r\n\r\n") {
                    response.push(socket.read_u8().await.unwrap());
                }
                assert!(response.starts_with(b"HTTP/1.1 101 "));
                // Begin a fragmented binary message, then leave it pending while
                // WT and UDP operate on the very same runtime thread.
                socket.write_all(b"\x02\x83\0\0\0\0ws ").await.unwrap();
                socket
            };
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let config = wtransport::ClientConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_tls(tls)
                .build();
            let endpoint = wtransport::Endpoint::client(config).unwrap();
            let connection = endpoint
                .connect(format!("https://{wt_addr}/"))
                .await
                .unwrap();
            connection.send_datagram(b"wt packet").unwrap();
            assert_eq!(&*connection.receive_datagram().await.unwrap(), b"wt packet");

            udp_client
                .send_to(b"udp packet", udp.local_addr().unwrap())
                .await
                .unwrap();
            let mut buf = [0; 32];
            let (length, _) = udp_client.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..length], b"udp packet");
            #[cfg(feature = "net-ws-server")]
            {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                websocket.write_all(b"\x89\x81\0\0\0\0?\x80\x86\0\0\0\0packet").await.unwrap();
                let mut response = [0; 14];
                websocket.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"\x8a\x01?\x82\x09ws packet");
                websocket.write_all(b"\x88\x82\0\0\0\0\x03\xe8").await.unwrap();
                let mut close = [0; 4];
                websocket.read_exact(&mut close).await.unwrap();
                assert_eq!(&close, b"\x88\x02\x03\xe8");
            }
            assert_eq!(service.http_requests.load(Ordering::SeqCst), 2);
            assert_eq!(service.wt_sessions.load(Ordering::SeqCst), 1);
            // Leave an active WT receive blocked when the servers are cancelled.
            shutdown.cancel();
            connection.closed().await;
            endpoint.wait_idle().await;
            Ok::<(), std::io::Error>(())
        };
        let udp_echo = async {
            let mut buf = [0; 32];
            let (length, peer) = udp.recv_from(&mut buf).await?;
            udp.send_to(&buf[..length], peer).await?;
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(http, wt, clients, udp_echo).unwrap();
        assert_eq!(service.wt_sessions.load(Ordering::SeqCst), 0);
        // Closing these servers must leave the caller's runtime and other sockets usable.
        udp_client
            .send_to(b"still running", udp.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0; 32];
        let (length, _) = udp.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..length], b"still running");
        assert!(tokio::net::TcpStream::connect(http_addr).await.is_err());
    })
    .await
    .expect("shared runtime services and shutdown must complete");
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_servers_return_without_waiting_for_clients() {
    let identity = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");
    let service = SharedService::new();
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let http = service.clone().serve_h2_tls(
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        (
            None,
            identity.server_cert_pem.as_bytes(),
            identity.server_key_pem.as_bytes(),
        ),
        H2Config::default(),
        shutdown.clone(),
    );
    let wt = service.clone().serve_wt_tls(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        (
            identity.server_cert_pem.as_bytes(),
            identity.server_key_pem.as_bytes(),
        ),
        WTConfig::default(),
        shutdown,
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(http, wt).unwrap();
    })
    .await
    .expect("pre-cancelled servers must return promptly");
    assert_eq!(service.http_requests.load(Ordering::SeqCst), 0);
    assert_eq!(service.wt_sessions.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_tls_handshake_releases_connection_capacity() {
    use tokio::io::AsyncReadExt;
    let identity = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let run = SharedService::new().serve_h2_tls(
        listener,
        (
            None,
            identity.server_cert_pem.as_bytes(),
            identity.server_key_pem.as_bytes(),
        ),
        H2Config {
            max_sessions: 1,
            io_timeout: Duration::from_millis(100),
            ..Default::default()
        },
        shutdown.clone(),
    );
    let verify = async {
        let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stalled.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            .no_proxy()
            .add_root_certificate(
                reqwest::Certificate::from_pem(identity.ca_cert_pem.as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        let response = client
            .get(format!("https://{addr}/after-timeout"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "shared runtime");
        shutdown.cancel();
    };
    let (result, ()) = tokio::join!(run, verify);
    result.unwrap();
}
