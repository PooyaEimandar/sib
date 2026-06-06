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
            && let Some(v) = c
                .split(';')
                .map(str::trim)
                .find_map(|p| p.strip_prefix(&format!("{}=", self.cookie_name)))
        {
            return format!("ck:{v}");
        }

        // If behind a trusted proxy, trust first X-Forwarded-For hop
        let peer = *sess.peer_addr();
        if self.trusted_proxies.contains(&peer)
            && let Some(xff) = sess
                .req_header(&HeaderName::from_static("x-forwarded-for"))
                .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
            && let Some(first) = xff.split(',').next().map(str::trim)
        {
            return format!("ip:{first}");
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
    fn stamp_429_h1<S: super::session::Session>(sess: &mut S) -> std::io::Result<()> {
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

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    async fn stamp_429_async<S: super::session::Session>(sess: &mut S) -> std::io::Result<()> {
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
    fn call<SE: super::session::Session>(&self, sess: &mut SE) -> std::io::Result<()> {
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
            return Self::stamp_429_h1(sess);
        }
        self.inner.call(sess)
    }
}

#[cfg(any(
    feature = "net-h2-server",
    all(feature = "net-h3-server", target_os = "linux")
))]
#[async_trait::async_trait(?Send)]
impl<Svc> super::session::HAsyncService for RateLimitedService<Svc>
where
    Svc: super::session::HAsyncService,
{
    async fn call<SE: super::session::Session>(&self, sess: &mut SE) -> std::io::Result<()> {
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
            return Self::stamp_429_async(sess).await;
        }
        self.inner.call(sess).await
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/network/http/ratelimit_tests.rs"]
mod tests;
