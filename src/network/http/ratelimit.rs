use crate::network::http::rlid::RlidSigner;
use bytes::Bytes;
use governor::{Quota, RateLimiter as GovLimiter, clock::Clock};
use http::{HeaderName, StatusCode, header};
use std::{
    hash::Hash,
    num::NonZeroU32,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
    {net::IpAddr, sync::Arc},
};

// Keyed limiters keep every key they see until pruned.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);
// `next_prune_ms` value that turns inline pruning off.
const NEVER: u64 = u64::MAX;

pub type IpLimiter = KeyedLimiter<IpAddr>;
pub type UserLimiter = KeyedLimiter<String>;
pub type NotUntil = governor::NotUntil<<governor::clock::DefaultClock as Clock>::Instant>;

/// A keyed rate limiter with its own pruning schedule. Services that share the
/// limiter through an `Arc` share its schedule; independent limiters never
/// delay each other's cleanup.
pub struct KeyedLimiter<K: Hash + Eq + Clone> {
    limiter: governor::DefaultKeyedRateLimiter<K>,
    // Monotonic, so a wall-clock step cannot stall pruning.
    epoch: Instant,
    next_prune_ms: AtomicU64,
}

impl<K: Hash + Eq + Clone> KeyedLimiter<K> {
    /// A limiter that prunes inline, on the first check of each interval.
    pub fn keyed(quota: Quota) -> Self {
        GovLimiter::keyed(quota).into()
    }

    /// A limiter pruned by a background thread, so no request pays for a sweep
    /// of the whole key map. The thread exits once the limiter is dropped.
    pub fn shared(quota: Quota) -> Arc<Self>
    where
        K: Send + Sync + 'static,
    {
        let limiter = Arc::new(Self::keyed(quota));
        let weak = Arc::downgrade(&limiter);
        let pruner = std::thread::Builder::new()
            .name("sib-rl-prune".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(PRUNE_INTERVAL);
                    let Some(limiter) = weak.upgrade() else {
                        break;
                    };
                    limiter.limiter.retain_recent();
                }
            });
        // Without a thread, keep pruning inline.
        if pruner.is_ok() {
            limiter.next_prune_ms.store(NEVER, Ordering::Relaxed);
        }
        limiter
    }

    /// Check `key`, pruning first when due.
    pub fn check_key(&self, key: &K) -> Result<(), NotUntil> {
        self.prune_if_due();
        self.limiter.check_key(key)
    }

    /// Check `n` cells for `key`, pruning first when due.
    pub fn check_key_n(
        &self,
        key: &K,
        n: NonZeroU32,
    ) -> Result<Result<(), NotUntil>, governor::InsufficientCapacity> {
        self.prune_if_due();
        self.limiter.check_key_n(key, n)
    }

    /// Drop keys whose buckets have fully refilled, at most once per interval,
    /// so unverified credentials cannot grow memory forever.
    pub fn prune_if_due(&self) {
        let now = self.epoch.elapsed().as_millis() as u64;
        let next = self.next_prune_ms.load(Ordering::Relaxed);
        if now < next
            || self
                .next_prune_ms
                .compare_exchange(
                    next,
                    now + PRUNE_INTERVAL.as_millis() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        self.limiter.retain_recent();
    }
}

impl<K: Hash + Eq + Clone> From<governor::DefaultKeyedRateLimiter<K>> for KeyedLimiter<K> {
    fn from(limiter: governor::DefaultKeyedRateLimiter<K>) -> Self {
        Self {
            limiter,
            epoch: Instant::now(),
            next_prune_ms: AtomicU64::new(0),
        }
    }
}

// Read-only access to the governor limiter; `check_key` and `check_key_n` above
// shadow its methods so direct callers prune too.
impl<K: Hash + Eq + Clone> std::ops::Deref for KeyedLimiter<K> {
    type Target = governor::DefaultKeyedRateLimiter<K>;

    fn deref(&self) -> &Self::Target {
        &self.limiter
    }
}

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
        accept_ip: IpLimiter::shared(ip_quota),
        user_req: UserLimiter::shared(user_quota),
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

        self.ip_key(sess)
    }

    /// Key for the client address. The first X-Forwarded-For hop is trusted only
    /// when the peer is a trusted proxy.
    pub fn ip_key<S: super::session::Session>(&self, sess: &S) -> String {
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
                header::HeaderValue::from_str(&body.len().to_string())
                    .map_err(std::io::Error::other)?,
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
                header::HeaderValue::from_str(&body.len().to_string())
                    .map_err(std::io::Error::other)?,
            )?
            .body(body)
            .eom_async()
            .await
    }

    /// Charge the request to its user and IP buckets. Returns whether it is
    /// allowed and the rlid `Set-Cookie` value to send, if any.
    fn check<S: super::session::Session>(&self, sess: &S) -> (bool, Option<String>) {
        let (verified_user_key, set_cookie) = self.user_key_and_cookie(sess);
        let cascaded_key = {
            let k = self.key_policy.make_key(sess);
            if k.starts_with("ck:") {
                // A forged or expired cookie must not buy a fresh bucket per request.
                verified_user_key.unwrap_or_else(|| self.key_policy.ip_key(sess))
            } else {
                k
            }
        };

        let ip_key = *sess.peer_addr();
        let user_ok = self.user_rl.check_key(&cascaded_key).is_ok();
        let ip_ok = self.ip_rl.check_key(&ip_key).is_ok();
        (user_ok && ip_ok, set_cookie)
    }

    /// Returns the user key of a verified rlid cookie, plus a `Set-Cookie` value
    /// when a new or refreshed cookie must be issued.
    fn user_key_and_cookie<S: super::session::Session>(
        &self,
        sess: &S,
    ) -> (Option<String>, Option<String>) {
        let cookie_header = sess
            .req_header(&header::COOKIE)
            .and_then(|v| v.to_str().ok().map(|s| s.to_owned()));
        // Match the whole cookie name: `rlid_pref=...` is not `rlid=...`.
        let rlid_val = cookie_header.and_then(|c| {
            c.split(';').map(str::trim).find_map(|p| {
                p.split_once('=')
                    .filter(|(name, _)| *name == self.rlid_signer.cookie_name)
                    .map(|(_, v)| v.to_owned())
            })
        });

        let verified = rlid_val.as_deref().and_then(|v| self.rlid_signer.verify(v));
        let user_key = verified.as_ref().map(|chk| format!("ck:{}", chk.id));
        let chk = verified.unwrap_or_else(|| self.rlid_signer.verify_or_new(None));

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
        let (allowed, set_cookie) = self.check(sess);

        if let Some(sc) = set_cookie.as_ref() {
            let _ = sess.header_str("Set-Cookie", sc);
        }

        if !allowed {
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
        let (allowed, set_cookie) = self.check(sess);

        if let Some(sc) = set_cookie.as_ref() {
            let _ = sess.header_str("Set-Cookie", sc);
        }

        if !allowed {
            return Self::stamp_429_async(sess).await;
        }
        self.inner.call(sess).await
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/network/http/ratelimit_tests.rs"]
mod tests;
