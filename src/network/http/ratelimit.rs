use crate::network::http::rlid::RlidSigner;
use bytes::Bytes;
use governor::{Quota, RateLimiter as GovLimiter};
use http::{HeaderName, StatusCode, header};
use std::{
    num::NonZeroU32,
    {net::IpAddr, sync::Arc},
};

pub type IpLimiter = governor::DefaultKeyedRateLimiter<IpAddr>;
pub type UserLimiter = governor::DefaultKeyedRateLimiter<String>;

#[derive(Clone)]
pub struct RLGuards {
    pub accept_ip: Arc<IpLimiter>,
    pub user_req: Arc<UserLimiter>,
}

pub fn build(
    ip_window_sec: NonZeroU32,
    ip_max_burst: NonZeroU32,
    user_window_sec: NonZeroU32,
    user_max_burst: NonZeroU32,
) -> RLGuards {
    let ip_quota = Quota::per_second(ip_window_sec).allow_burst(ip_max_burst);
    let user_quota = Quota::per_second(user_window_sec).allow_burst(user_max_burst);
    RLGuards {
        accept_ip: Arc::new(GovLimiter::keyed(ip_quota)),
        user_req: Arc::new(GovLimiter::keyed(user_quota)),
    }
}

#[derive(Clone)]
pub struct RLKey {
    pub cookie_name: &'static str,
    pub trusted_proxies: Vec<IpAddr>,
}

impl RLKey {
    pub fn make_key<S: super::session::Session>(&self, sess: &S) -> String {
        // Get Bearer or API Key
        if let Some(h) = sess
            .req_header(&http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
        {
            if let Some(b) = h.strip_prefix("Bearer ") {
                return format!("jwt:{b}");
            }
            if let Some(k) = h.strip_prefix("ApiKey ") {
                return format!("key:{k}");
            }
        }
        // try for X-API-Key header
        if let Some(h) = sess
            .req_header(&HeaderName::from_static("x-api-key"))
            .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
        {
            return format!("key:{h}");
        }

        // Signed cookie
        if let Some(c) = sess
            .req_header(&http::header::COOKIE)
            .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
        {
            if let Some(v) = c
                .split(';')
                .map(str::trim)
                .find_map(|p| p.strip_prefix(&format!("{}=", self.cookie_name)))
            {
                return format!("ck:{v}");
            }
        }

        // If behind a trusted proxy, trust first X-Forwarded-For hop
        let peer = *sess.peer_addr();
        if self.trusted_proxies.iter().any(|ip| *ip == peer) {
            if let Some(xff) = sess
                .req_header(&HeaderName::from_static("x-forwarded-for"))
                .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
            {
                if let Some(first) = xff.split(',').next().map(str::trim) {
                    return format!("ip:{first}");
                }
            }
        }

        // Fallback to peer IP
        format!("ip:{peer}")
    }
}

pub struct RateLimitedService<Svc> {
    inner: Svc,
    user_rl: Arc<UserLimiter>,
    ip_rl: Arc<IpLimiter>,
    key_policy: RLKey,
    rlid_signer: Arc<RlidSigner>,
}

impl<Svc> RateLimitedService<Svc> {
    pub fn new(
        inner: Svc,
        user_rl: Arc<UserLimiter>,
        ip_rl: Arc<IpLimiter>,
        key_policy: RLKey,
        rlid_signer: Arc<RlidSigner>,
    ) -> Self {
        Self {
            inner,
            user_rl,
            ip_rl,
            key_policy,
            rlid_signer,
        }
    }

    #[cfg(feature = "net-h1-server")]
    fn stamp_429<S: super::session::Session>(sess: &mut S) -> std::io::Result<()> {
        let body = Bytes::from_static(b"Too Many Requests");
        sess.status_code(StatusCode::TOO_MANY_REQUESTS)
            .header(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/plain"),
            )?
            .header(
                header::CONTENT_LENGTH,
                header::HeaderValue::from_static("18"),
            )?
            .body(body)
            .eom()
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    async fn stamp_429<S: super::session::Session>(sess: &mut S) -> std::io::Result<()> {
        let body = Bytes::from_static(b"Too Many Requests");
        sess.status_code(StatusCode::TOO_MANY_REQUESTS)
            .header(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/plain"),
            )?
            .header(
                header::CONTENT_LENGTH,
                header::HeaderValue::from_static("18"),
            )?
            .body(body)
            .eom_async()
            .await
    }

    fn user_key_and_cookie<S: super::session::Session>(
        &self,
        sess: &S,
    ) -> (String, Option<String>) {
        let cookie_header = sess
            .req_header(&header::COOKIE)
            .and_then(|v| v.to_str().ok().map(|s| s.to_owned()));
        let rlid_val = cookie_header.and_then(|c| {
            c.split(';').map(str::trim).find_map(|p| {
                p.strip_prefix(self.rlid_signer.cookie_name)
                    .map(|s| s.to_owned())
            })
        });
        let rlid_val = rlid_val.and_then(|v| v.strip_prefix("=").map(|s| s.to_owned()));

        let chk = self.rlid_signer.verify_or_new(rlid_val.as_deref());
        let user_key = format!("ck:{}", chk.id);

        let set_cookie = if chk.must_issue {
            Some(self.rlid_signer.issue_set_cookie(
                &chk.id,
                /*secure=*/ true,
                /*domain=*/ None,
                /*path=*/ Some("/"),
            ))
        } else {
            None
        };

        (user_key, set_cookie)
    }
}

#[cfg(feature = "net-h1-server")]
impl<Svc> super::session::HService for RateLimitedService<Svc>
where
    Svc: super::session::HService,
{
    fn call<SE: super::session::Session>(&mut self, sess: &mut SE) -> std::io::Result<()> {
        let (anon_user_key, set_cookie) = self.user_key_and_cookie(sess);
        let cascaded_key = {
            let k = self.key_policy.make_key(sess);
            if k.starts_with("ck:") {
                anon_user_key
            } else {
                k
            }
        };

        let ip_key = *sess.peer_addr();
        let user_ok = self.user_rl.check_key(&cascaded_key).is_ok();
        let ip_ok = self.ip_rl.check_key(&ip_key).is_ok();

        if let Some(sc) = set_cookie.as_ref() {
            let _ = sess.header_str("Set-Cookie", sc);
        }

        if !(user_ok && ip_ok) {
            return Self::stamp_429(sess);
        }
        self.inner.call(sess)
    }
}

#[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
#[async_trait::async_trait(?Send)]
impl<Svc> super::session::HAsyncService for RateLimitedService<Svc>
where
    Svc: super::session::HAsyncService,
{
    async fn call<SE: super::session::Session>(&mut self, sess: &mut SE) -> std::io::Result<()> {
        let (anon_user_key, set_cookie) = self.user_key_and_cookie(sess);
        let cascaded_key = {
            let k = self.key_policy.make_key(sess);
            if k.starts_with("ck:") {
                anon_user_key
            } else {
                k
            }
        };

        let ip_key = *sess.peer_addr();
        let user_ok = self.user_rl.check_key(&cascaded_key).is_ok();
        let ip_ok = self.ip_rl.check_key(&ip_key).is_ok();

        if let Some(sc) = set_cookie.as_ref() {
            let _ = sess.header_str("Set-Cookie", sc);
        }

        if !(user_ok && ip_ok) {
            return Self::stamp_429(sess).await;
        }
        self.inner.call(sess).await
    }
}

#[cfg(test)]
mod tests {
    use crate::network::http::ratelimit::RateLimitedService;
    use crate::network::http::server::tests::EchoServer;
    use crate::network::http::{
        ratelimit::{IpLimiter, UserLimiter},
        rlid::RlidSigner,
        server::HFactory,
    };
    use nonzero_ext::nonzero;
    use reqwest::blocking::Client;
    use reqwest::header::{COOKIE, HeaderMap, HeaderValue, SET_COOKIE};
    use std::sync::Arc;

    fn do_req(client: &Client, url: &str, cookie: Option<&str>) -> (u16, HeaderMap, String) {
        let mut req = client.get(url);
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

    struct RlEchoFactory {
        user_rl: Arc<UserLimiter>,
        ip_rl: Arc<IpLimiter>,
        signer: Arc<RlidSigner>,
    }

    impl HFactory for RlEchoFactory {
        #[cfg(feature = "net-h1-server")]
        type Service = RateLimitedService<EchoServer>;

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
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

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
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
            super::EchoServer
        }
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_ratelimit_h1_server() {
        use crate::network::http::server::{H1Config, HFactory};
        use std::time::Duration;

        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 1 * 1024 * 1024);

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

        // 1) First request (no cookie): expect 200 and Set-Cookie: rlid=...
        let (s1, h1, _b1) = do_req(&client, &url, None);
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

        // Extract "rlid=..." pair to echo back
        let cookie_pair = {
            let first_seg = set_cookie_line.split(';').next().unwrap().trim();
            first_seg.to_string() // "rlid=...."
        };

        // 2) Second request with same cookie => still under per-user budget => 200
        let (s2, _h2, _b2) = do_req(&client, &url, Some(&cookie_pair));
        assert_eq!(s2, 200, "second request should be 200 OK, got: {s2}");

        // 3) Third request with same cookie => exceed per-user budget => 429
        let (s3, _h3, _b3) = do_req(&client, &url, Some(&cookie_pair));
        assert_eq!(s3, 429, "third request should be 429, got: {s3}");

        // cleanup
        may::coroutine::sleep(Duration::from_millis(100));
        unsafe { server_handle.coroutine().cancel() };
    }

    #[cfg(all(
        feature = "net-h2-server",
        any(feature = "rt-tokio", feature = "rt-glommio")
    ))]
    #[test]
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

        let (cert_pem, key_pem) =
            crate::network::http::server::tests::create_self_signed_tls_pems();
        let _server_thread = std::thread::spawn(move || {
            factory
                .start_h2_tls(
                    addr,
                    (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                    H2Config::default(),
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

        // 1) First request (no cookie): expect 200 + Set-Cookie: rlid=...
        let (s1, h1, _b1) = do_req(&client, &url, None);
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
        // Extract "rlid=..." pair
        let cookie_pair = set_cookie_line
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_string();

        // 2) Second request with same cookie => 200
        let (s2, _h2, _b2) = do_req(&client, &url, Some(&cookie_pair));
        assert_eq!(s2, 200, "second request should be 200 OK, got: {s2}");

        // 3) Third request with same cookie within same second => 429
        let (s3, _h3, _b3) = do_req(&client, &url, Some(&cookie_pair));
        assert_eq!(s3, 429, "third request should be 429, got: {s3}");
    }
}
