#![cfg(all(
    feature = "net-h2-server",
    feature = "rt-tokio",
    not(feature = "rt-glommio")
))]

use async_trait::async_trait;
use sib::network::http::{
    server::{H2Config, HFactory},
    session::{HAsyncService, Session},
};
use std::{
    net::TcpListener,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct CountingService {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
}

#[async_trait(?Send)]
impl HAsyncService for CountingService {
    async fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);

        let max = self.max_in_flight.load(Ordering::SeqCst);
        let body = bytes::Bytes::from(format!("{} max={max}", session.req_path()));
        let content_length =
            http::HeaderValue::from_str(&body.len().to_string()).map_err(std::io::Error::other)?;
        session
            .status_code(http::StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, content_length)?
            .body(body)
            .eom_async()
            .await
    }
}

#[derive(Clone)]
struct CountingFactory {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
}

impl HFactory for CountingFactory {
    type HAsyncService = CountingService;

    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        CountingService {
            in_flight: self.in_flight.clone(),
            max_in_flight: self.max_in_flight.clone(),
        }
    }
}

fn unused_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").to_string()
}

#[test]
fn h2_streams_call_shared_service_concurrently() {
    let addr = unused_addr();
    let mtls = sib::MtlsIdentity::generate(&[], &[], false);
    let cancel = tokio_util::sync::CancellationToken::new();
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let factory = CountingFactory {
        in_flight: Arc::new(AtomicUsize::new(0)),
        max_in_flight: max_in_flight.clone(),
    };

    let server_cancel = cancel.clone();
    let server_addr = addr.clone();
    let server_cert = mtls.server_cert_pem.clone();
    let server_key = mtls.server_key_pem.clone();
    let server = std::thread::spawn(move || {
        factory
            .start_h2_tls(
                server_addr,
                (None, server_cert.as_bytes(), server_key.as_bytes()),
                H2Config {
                    max_sessions: 1,
                    num_of_shards: 1,
                    ..Default::default()
                },
                server_cancel,
            )
            .expect("start h2 server");
    });

    std::thread::sleep(Duration::from_millis(500));

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .expect("build h2 client");
    let barrier = Arc::new(Barrier::new(3));

    let mut workers = Vec::new();
    for path in ["/a", "/b"] {
        let client = client.clone();
        let url = format!("https://{addr}{path}");
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            client
                .get(url)
                .version(reqwest::Version::HTTP_2)
                .send()
                .expect("send h2 request")
                .text()
                .expect("read h2 body")
        }));
    }

    barrier.wait();
    let bodies: Vec<String> = workers
        .into_iter()
        .map(|worker| worker.join().expect("request thread"))
        .collect();

    cancel.cancel();
    server.join().expect("server thread");

    assert!(
        bodies.iter().all(|body| body.contains("max=")),
        "unexpected bodies: {bodies:?}"
    );
    assert_eq!(
        max_in_flight.load(Ordering::SeqCst),
        2,
        "H2 requests did not overlap on the shared service"
    );
}
