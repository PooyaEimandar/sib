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
    use governor::Quota;
    use nonzero_ext::nonzero;

    let ip = Arc::new(IpLimiter::keyed(
        Quota::per_second(nonzero!(1000u32)).allow_burst(nonzero!(1000u32)),
    ));

    // 2 total tokens in any given second: rate 1/sec + burst 1
    // => 1st OK, 2nd OK, 3rd within the same second -> 429
    let user = Arc::new(UserLimiter::keyed(
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

    let tls = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");
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

    let tls = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");
    let (cert_pem, key_pem) = (tls.server_cert_pem, tls.server_key_pem);

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

fn assert_429_framing(wire: &[u8]) {
    let wire = std::str::from_utf8(wire).unwrap();
    let (headers, body) = wire.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 429"));
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert_eq!(length, body.len());
    assert_eq!(body, "Too Many Requests");
}

#[cfg(feature = "net-h1-server")]
#[test]
fn sync_429_has_correct_content_length() {
    use crate::network::http::h1_session::new_session;
    let mut stream = std::io::Cursor::new(Vec::new());
    let mut req = bytes::BytesMut::from(&b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"[..]);
    let mut rsp = bytes::BytesMut::new();
    let peer = "127.0.0.1".parse().unwrap();
    let mut session = new_session(&mut stream, &peer, &mut req, &mut rsp)
        .unwrap()
        .unwrap();
    RateLimitedService::<()>::stamp_429_h1(&mut session).unwrap();
    drop(session);
    assert_429_framing(&stream.into_inner());
}

#[cfg(all(feature = "net-h2-server", feature = "rt-tokio"))]
#[tokio::test]
async fn async_429_has_correct_content_length() {
    use crate::network::http::h1_session_async::H1SessionAsync;
    use tokio::io::AsyncReadExt;
    let (mut stream, mut client) = tokio::io::duplex(4096);
    let mut session = H1SessionAsync::new(
        "127.0.0.1".parse().unwrap(),
        &mut stream,
        (http::Method::GET, http::Version::HTTP_11),
        "/".parse().unwrap(),
        (http::HeaderMap::new(), bytes::Bytes::new()),
        false,
        false,
    );
    RateLimitedService::<()>::stamp_429_async(&mut session)
        .await
        .unwrap();
    drop(session);
    drop(stream);
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert_429_framing(&wire);
}

#[cfg(feature = "net-h1-server")]
struct Ok200;

#[cfg(feature = "net-h1-server")]
impl crate::network::http::session::HService for Ok200 {
    fn call<S: crate::network::http::session::Session>(
        &self,
        session: &mut S,
    ) -> std::io::Result<()> {
        session
            .status_code(http::StatusCode::OK)
            .header_str("Content-Length", "0")?
            .body(bytes::Bytes::new())
            .eom()
    }
}

#[cfg(feature = "net-h1-server")]
fn rate_limited(user: &Arc<UserLimiter>, ip: &Arc<IpLimiter>) -> RateLimitedService<Ok200> {
    use crate::network::http::ratelimit::RLKey;
    RateLimitedService::new(
        Ok200,
        user.clone(),
        ip.clone(),
        RLKey {
            cookie_name: "rlid",
            trusted_proxies: vec![],
        },
        build_signer(),
    )
}

/// Serve one request through a sync H1 session and return the status code.
#[cfg(feature = "net-h1-server")]
fn serve_once(service: &RateLimitedService<Ok200>, request: &[u8]) -> String {
    serve_raw(service, request)[9..12].to_owned()
}

/// Serve one request through a sync H1 session and return the whole response.
#[cfg(feature = "net-h1-server")]
fn serve_raw(service: &RateLimitedService<Ok200>, request: &[u8]) -> String {
    use crate::network::http::{h1_session::new_session, session::HService};
    let peer = "127.0.0.1".parse().unwrap();
    let mut stream = std::io::Cursor::new(Vec::new());
    let mut req = bytes::BytesMut::from(request);
    let mut rsp = bytes::BytesMut::new();
    let mut session = new_session(&mut stream, &peer, &mut req, &mut rsp)
        .unwrap()
        .unwrap();
    service.call(&mut session).unwrap();
    drop(session);
    String::from_utf8(stream.into_inner()).unwrap()
}

#[cfg(feature = "net-h1-server")]
#[test]
fn forged_rlid_cookie_does_not_mint_a_fresh_user_bucket() {
    let (ip, user) = build_test_limiters();
    let service = rate_limited(&user, &ip);
    let statuses: Vec<_> = (0..4)
        .map(|_| {
            serve_once(
                &service,
                b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: rlid=forged\r\n\r\n",
            )
        })
        .collect();

    assert!(statuses.iter().any(|s| s == "429"), "{statuses:?}");
    assert_eq!(user.len(), 1, "each forged cookie created a new bucket");
}

#[cfg(feature = "net-h1-server")]
#[test]
fn independent_rate_limiters_each_prune_their_stale_keys() {
    use governor::Quota;
    use nonzero_ext::nonzero;

    // Buckets refill within a millisecond, so the keys below go stale quickly.
    let quota = Quota::per_second(nonzero!(1000u32));
    let limiters: Vec<_> = (0..2)
        .map(|_| {
            (
                Arc::new(UserLimiter::keyed(quota)),
                Arc::new(IpLimiter::keyed(quota)),
            )
        })
        .collect();
    for (user, _) in &limiters {
        // Insert through governor directly, so the request below is the first
        // to prune each limiter.
        let raw: &governor::DefaultKeyedRateLimiter<String> = user;
        for i in 0..100 {
            let _ = raw.check_key(&format!("stale{i}"));
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(20));

    for (user, ip) in &limiters {
        let status = serve_once(
            &rate_limited(user, ip),
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status, "200");
    }
    for (user, _) in &limiters {
        // Only the key of the request just served may remain.
        assert_eq!(user.len(), 1, "stale keys were left in a limiter");
    }
}

#[cfg(feature = "net-h1-server")]
#[test]
fn rlid_cookie_is_found_after_a_cookie_whose_name_extends_it() {
    let (ip, user) = build_test_limiters();
    let service = rate_limited(&user, &ip);
    let signer = build_signer();
    let id = signer.verify_or_new(None).unwrap().id;
    let set_cookie = signer.issue_set_cookie(&id, true, None, Some("/")).unwrap();
    let rlid = set_cookie.split(';').next().unwrap();

    let request =
        format!("GET / HTTP/1.1\r\nHost: localhost\r\nCookie: rlid_pref=dark; {rlid}\r\n\r\n");
    let rsp = serve_raw(&service, request.as_bytes());

    assert!(rsp.starts_with("HTTP/1.1 200 "), "{rsp}");
    assert!(!rsp.to_ascii_lowercase().contains("set-cookie"), "{rsp}");
    // The request was charged to the cookie's bucket, which is now empty.
    assert!(user.check_key(&format!("ck:{id}")).is_err());
}

#[test]
fn direct_check_key_prunes_stale_keys() {
    use governor::Quota;
    use nonzero_ext::nonzero;

    let user = UserLimiter::keyed(Quota::per_second(nonzero!(1000u32)));
    for i in 0..100 {
        let _ = user.check_key(&format!("stale{i}"));
    }
    // Past the prune interval and the buckets' refill time.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let _ = user.check_key(&"fresh".to_owned());

    assert_eq!(user.len(), 1, "check_key did not prune");
}

#[test]
fn shared_limiter_prunes_off_the_request_path() {
    use governor::Quota;
    use nonzero_ext::nonzero;
    use std::time::{Duration, Instant};

    let user = UserLimiter::shared(Quota::per_second(nonzero!(1000u32)));
    for i in 0..100 {
        let _ = user.check_key(&format!("stale{i}"));
    }
    assert_eq!(user.len(), 100, "a request paid for the sweep");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !user.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        user.is_empty(),
        "background pruner left {} keys",
        user.len()
    );
}
