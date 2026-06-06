use crate::network::http::{
    ratelimit::{IpLimiter, RateLimitedService, UserLimiter},
    rlid::RlidSigner,
    server::HFactory,
    server::tests::EchoServer,
};
use reqwest::{
    blocking::Client,
    header::{COOKIE, HeaderMap, HeaderValue, SET_COOKIE},
};
use std::sync::Arc;

struct RlEchoFactory {
    user_rl: Arc<UserLimiter>,
    ip_rl: Arc<IpLimiter>,
    signer: Arc<RlidSigner>,
}

impl HFactory for RlEchoFactory {
    #[cfg(feature = "net-h1-server")]
    type Service = RateLimitedService<EchoServer>;

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    type HAsyncService = RateLimitedService<EchoServer>;

    #[cfg(feature = "net-wt-server")]
    type WtService = EchoServer;

    #[cfg(feature = "net-h1-server")]
    fn service(&self, _id: usize) -> Self::Service {
        use crate::network::http::ratelimit::RLKey;
        RateLimitedService::new(
            EchoServer,
            self.user_rl.clone(),
            self.ip_rl.clone(),
            RLKey {
                cookie_name: "rlid",
                trusted_proxies: vec![],
            },
            self.signer.clone(),
        )
    }

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        use crate::network::http::ratelimit::RLKey;
        RateLimitedService::new(
            EchoServer,
            self.user_rl.clone(),
            self.ip_rl.clone(),
            RLKey {
                cookie_name: "rlid",
                trusted_proxies: vec![],
            },
            self.signer.clone(),
        )
    }

    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, _id: usize) -> Self::WtService {
        EchoServer
    }
}

fn do_req(
    client: &Client,
    url: &str,
    cookie: Option<&str>,
    version: reqwest::Version,
) -> (u16, HeaderMap, String) {
    let mut req = client.get(url).version(version);
    if let Some(c) = cookie {
        req = req.header(COOKIE, HeaderValue::from_str(c).expect("cookie hdr"));
    }
    let resp = req.send().expect("send");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().unwrap_or_default();
    (status, headers, body)
}

// Generous IP limiter, strict per-user: 2 total tokens in any 1s window (1 rps + burst 1)
fn build_test_limiters() -> (Arc<IpLimiter>, Arc<UserLimiter>) {
    use governor::{Quota, RateLimiter as GovLimiter};
    use nonzero_ext::nonzero;

    let ip = Arc::new(GovLimiter::keyed(
        Quota::per_second(nonzero!(1000u32)).allow_burst(nonzero!(1000u32)),
    ));

    // 2 total tokens in any given second: rate 1/sec + burst 1
    // => 1st OK, 2nd OK, 3rd within the same second -> 429
    let user = Arc::new(GovLimiter::keyed(
        Quota::per_second(nonzero!(1u32)).allow_burst(nonzero!(1u32)),
    ));
    (ip, user)
}

fn build_signer() -> Arc<RlidSigner> {
    let cur: [u8; 32] = [1u8; 32];
    let old: [u8; 32] = [2u8; 32];
    Arc::new(RlidSigner::new(
        "rlid",
        std::time::Duration::from_secs(60),
        (1, cur),
        vec![(0, old)],
    ))
}

fn verify_cookie_flow(client: &Client, url: &str, version: reqwest::Version) {
    // 1) First request (no cookie): expect 200 and Set-Cookie: rlid=...
    let (s1, h1, _b1) = do_req(client, url, None, version);
    assert_eq!(s1, 200, "first request should be 200 OK, got: {s1}");
    let set_cookie_line = h1
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|hv| hv.to_str().ok())
        .expect("Set-Cookie header missing on first response");
    assert!(
        set_cookie_line.contains("rlid=v1."),
        "rlid cookie not issued: {set_cookie_line}"
    );

    // Extract "rlid=..." pair and reuse it manually
    let cookie_pair = set_cookie_line
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_string();

    // 2) Second request with same cookie => 200
    let (s2, _h2, _b2) = do_req(client, url, Some(&cookie_pair), version);
    assert_eq!(s2, 200, "second request should be 200 OK, got: {s2}");

    // 3) Third request with same cookie within same second => 429
    let (s3, _h3, _b3) = do_req(client, url, Some(&cookie_pair), version);
    assert_eq!(s3, 429, "third request should be 429, got: {s3}");
}

#[cfg(feature = "net-h1-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_ratelimit_h1_server() {
    use crate::network::http::server::{H1Config, HFactory};
    use std::time::Duration;

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 1024 * 1024);

    let (ip_rl, user_rl) = build_test_limiters();
    let signer = build_signer();
    let factory = RlEchoFactory {
        user_rl,
        ip_rl,
        signer,
    };

    let addr = "127.0.0.1:8091";
    let url = format!("http://{addr}/test");

    let server_handle = factory
        .start_h1(addr, H1Config::default())
        .expect("start h1 RL server");

    // Let server start
    may::coroutine::sleep(Duration::from_millis(300));

    // reqwest client
    let client = Client::builder().build().expect("client");

    verify_cookie_flow(&client, &url, reqwest::Version::HTTP_11);

    // cleanup
    may::coroutine::sleep(Duration::from_millis(100));
    unsafe { server_handle.coroutine().cancel() };
}

#[cfg(feature = "net-h2-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_ratelimit_h2_tls_server() {
    use crate::network::http::server::{H2Config, HFactory};
    use reqwest::blocking::Client;
    use std::time::Duration;

    // Spin up H2/TLS server
    let addr = "127.0.0.1:8092";
    let url = format!("https://{addr}/test");

    let (ip_rl, user_rl) = build_test_limiters();
    let signer = build_signer();
    let factory = RlEchoFactory {
        user_rl,
        ip_rl,
        signer,
    };

    let tls = crate::MtlsIdentity::generate(&[], &[], false);
    let cert_pem = tls.server_cert_pem;
    let key_pem = tls.server_key_pem;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let _server_thread = std::thread::spawn(move || {
        factory
            .start_h2_tls(
                addr,
                (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                H2Config::default(),
                shutdown,
            )
            .expect("start_h2_tls rl server");
    });

    std::thread::sleep(Duration::from_millis(500));

    // HTTP/2 client
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_adaptive_window(true)
        .build()
        .expect("client");

    verify_cookie_flow(&client, &url, reqwest::Version::HTTP_2);
}

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_ratelimit_h3_tls_server() {
    use crate::network::http::server::H3Config;
    use reqwest::blocking::Client;
    use std::time::Duration;

    let addr = "127.0.0.1:8093";
    let url = format!("https://{addr}/test");

    let (ip_rl, user_rl) = build_test_limiters();
    let signer = build_signer();
    let factory = RlEchoFactory {
        user_rl,
        ip_rl,
        signer,
    };

    let (cert_pem, key_pem) = crate::network::http::server::tests::create_self_signed_tls_pems();

    let _server_thread = std::thread::spawn(move || {
        factory
            .start_h3_tls(
                addr,
                (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                H3Config::default(),
            )
            .expect("start_h3_tls rl server");
    });

    std::thread::sleep(Duration::from_millis(500));

    // HTTP/3 client (reqwest)
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .http3_prior_knowledge()
        .build()
        .expect("client");

    verify_cookie_flow(&client, &url, reqwest::Version::HTTP_3);
}
