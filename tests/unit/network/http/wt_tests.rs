use super::{WTConfig, WtAdmission, WtRequest, WtService, WtSession};
use crate::network::http::server::HFactory;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use wtransport::{
    endpoint::{ConnectOptions, endpoint_side::Client},
    error::ConnectingError,
};

#[derive(Debug)]
struct ObservedRequest {
    authority: String,
    path: String,
    origin: Option<String>,
    user_agent: Option<String>,
    peer: SocketAddr,
    cookie: Option<String>,
}

#[derive(Default)]
struct State {
    requests: Mutex<Vec<ObservedRequest>>,
    calls: AtomicUsize,
    live_services: AtomicUsize,
    dropped: Notify,
    admission_pending: Notify,
}

impl State {
    async fn wait_idle(&self) {
        loop {
            let dropped = self.dropped.notified();
            if self.live_services.load(Ordering::SeqCst) == 0 {
                return;
            }
            dropped.await;
        }
    }
}

struct Factory(Arc<State>);
struct Service {
    state: Arc<State>,
    identity: Option<&'static str>,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.state.live_services.fetch_sub(1, Ordering::SeqCst);
        self.state.dropped.notify_one();
    }
}

impl HFactory for Factory {
    #[cfg(feature = "net-h1-server")]
    type Service = crate::network::http::server::tests::EchoServer;
    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    type HAsyncService = crate::network::http::server::tests::EchoServer;
    type WtService = Service;

    #[cfg(feature = "net-h1-server")]
    fn service(&self, _id: usize) -> Self::Service {
        crate::network::http::server::tests::EchoServer
    }
    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        crate::network::http::server::tests::EchoServer
    }
    fn wt_service(&self, _id: usize) -> Self::WtService {
        self.0.live_services.fetch_add(1, Ordering::SeqCst);
        Service {
            state: self.0.clone(),
            identity: None,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl WtService for Service {
    async fn admit(&mut self, request: &WtRequest<'_>) -> std::io::Result<WtAdmission> {
        self.state.requests.lock().unwrap().push(ObservedRequest {
            authority: request.authority().to_owned(),
            path: request.path().to_owned(),
            origin: request.origin().map(str::to_owned),
            user_agent: request.user_agent().map(str::to_owned),
            peer: request.remote_address(),
            cookie: request.headers().get("cookie").cloned(),
        });
        match request.path() {
            "/pending" => {
                self.state.admission_pending.notify_one();
                return std::future::pending().await;
            }
            "/error" => return Err(std::io::Error::other("policy lookup failed")),
            "/game?room=lobby" => {}
            _ => return Ok(WtAdmission::NotFound),
        }
        if request.origin() != Some("https://game.example")
            || request.headers().get("cookie").map(String::as_str) != Some("session=test-session")
        {
            return Ok(WtAdmission::Forbidden);
        }
        if request.headers().contains_key("x-test-quota-exceeded") {
            return Ok(WtAdmission::TooManyRequests);
        }
        tokio::task::yield_now().await;
        self.identity = Some("test-player");
        Ok(WtAdmission::Accept)
    }

    async fn call(&mut self, session: &mut WtSession) -> std::io::Result<()> {
        assert_eq!(self.identity, Some("test-player"));
        self.state.calls.fetch_add(1, Ordering::SeqCst);
        loop {
            let data = session.recv_dgram().await?;
            session.send_dgram(&data)?;
        }
    }
}

async fn with_server<F, Fut>(request_timeout: Duration, run: F)
where
    F: FnOnce(Arc<State>, SocketAddr, wtransport::Endpoint<Client>, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::time::timeout(Duration::from_secs(15), async {
        let identity = crate::MtlsIdentity::generate(&[], &[], false);
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
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let client = wtransport::Endpoint::client(
            wtransport::ClientConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_tls(tls)
                .build(),
        )
        .unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let state = Arc::new(State::default());
        let shutdown = CancellationToken::new();
        // A rejected or timed-out request must release the only available slot.
        let config = WTConfig {
            max_sessions: 1,
            request_timeout,
            ..WTConfig::default()
        };
        let server = Factory(state.clone()).serve_wt_tls(
            socket,
            (
                identity.server_cert_pem.as_bytes(),
                identity.server_key_pem.as_bytes(),
            ),
            config,
            shutdown.clone(),
        );
        let clients = async {
            run(state.clone(), addr, client, shutdown.clone()).await;
            shutdown.cancel();
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(server, clients).unwrap();
        assert_eq!(state.live_services.load(Ordering::SeqCst), 0);
    })
    .await
    .expect("WebTransport admission test must finish");
}

fn authorized(addr: SocketAddr) -> ConnectOptions {
    ConnectOptions::builder(format!("https://{addr}/game?room=lobby"))
        .add_header("origin", "https://game.example")
        .add_header("cookie", "session=test-session")
        .add_header("user-agent", "sib-admission-test")
        .build()
}

async fn exchange(client: &wtransport::Endpoint<Client>, addr: SocketAddr) {
    let conn = client.connect(authorized(addr)).await.unwrap();
    conn.send_datagram(b"admitted packet").unwrap();
    assert_eq!(&*conn.receive_datagram().await.unwrap(), b"admitted packet");
    conn.close(wtransport::VarInt::from_u32(0), b"test complete");
}

#[tokio::test(flavor = "current_thread")]
async fn checks_request_before_accept_and_retains_identity() {
    with_server(
        Duration::from_secs(10),
        |state, addr, client, _| async move {
            for (path, origin, cookie, quota) in [
                (
                    "/missing",
                    Some("https://game.example"),
                    Some("session=test-session"),
                    false,
                ),
                (
                    "/game?room=lobby",
                    None,
                    Some("session=test-session"),
                    false,
                ),
                (
                    "/game?room=lobby",
                    Some("https://other.example"),
                    Some("session=test-session"),
                    false,
                ),
                (
                    "/game?room=lobby",
                    Some("https://game.example"),
                    None,
                    false,
                ),
                (
                    "/game?room=lobby",
                    Some("https://game.example"),
                    Some("session=invalid"),
                    false,
                ),
                (
                    "/game?room=lobby",
                    Some("https://game.example"),
                    Some("session=test-session"),
                    true,
                ),
                (
                    "/error",
                    Some("https://game.example"),
                    Some("session=test-session"),
                    false,
                ),
            ] {
                let mut options = ConnectOptions::builder(format!("https://{addr}{path}"));
                if let Some(origin) = origin {
                    options = options.add_header("origin", origin);
                }
                if let Some(cookie) = cookie {
                    options = options.add_header("cookie", cookie);
                }
                if quota {
                    options = options.add_header("x-test-quota-exceeded", "true");
                }
                let result = client.connect(options.build()).await;
                assert!(matches!(result, Err(ConnectingError::SessionRejected)));
                state.wait_idle().await;
                assert_eq!(state.calls.load(Ordering::SeqCst), 0);
            }
            exchange(&client, addr).await;
            state.wait_idle().await;
            assert_eq!(state.calls.load(Ordering::SeqCst), 1);
            let requests = state.requests.lock().unwrap();
            assert_eq!(requests.len(), 8);
            let accepted = requests.last().unwrap();
            assert_eq!(accepted.authority, addr.to_string());
            assert_eq!(accepted.path, "/game?room=lobby");
            assert_eq!(accepted.origin.as_deref(), Some("https://game.example"));
            assert_eq!(accepted.cookie.as_deref(), Some("session=test-session"));
            assert_eq!(accepted.user_agent.as_deref(), Some("sib-admission-test"));
            assert_eq!(accepted.peer, client.local_addr().unwrap());
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn admission_timeout_releases_the_session_slot() {
    with_server(
        Duration::from_secs(2),
        |state, addr, client, _| async move {
            let result = client.connect(format!("https://{addr}/pending")).await;
            assert!(
                result.is_err(),
                "a pending policy must not accept the request"
            );
            state.wait_idle().await;
            assert_eq!(state.calls.load(Ordering::SeqCst), 0);
            assert_eq!(state.requests.lock().unwrap()[0].path, "/pending");
            exchange(&client, addr).await;
            state.wait_idle().await;
            assert_eq!(state.calls.load(Ordering::SeqCst), 1);
        },
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_cancels_pending_admission() {
    with_server(Duration::from_secs(60), |state, addr, client, shutdown| async move {
        let connecting = client.connect(format!("https://{addr}/pending"));
        tokio::pin!(connecting);
        tokio::select! {
            _ = &mut connecting => panic!("request completed before the pending policy was cancelled"),
            _ = state.admission_pending.notified() => {}
        }
        shutdown.cancel();
        assert!(connecting.await.is_err());
        state.wait_idle().await;
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    }).await;
}
