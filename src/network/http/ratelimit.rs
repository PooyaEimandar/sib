use dashmap::DashMap;
use heapless::Deque;
use std::borrow::Cow;
use std::time::{Duration, Instant}; // Use heapless for fixed-capacity Deque

const MAX_QUEUE_LEN: usize = 2048; // Prevent abuse during DDoS

pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub limit: u32,
    pub retry_after_secs: Option<u64>,
    pub reset_after_secs: Option<u64>,
}

pub trait RateLimiter {
    fn check(&self, key: Cow<str>) -> RateLimitResult;
}

pub struct FixedWindowLimiter {
    window: Duration,
    limit: u32,
    state: DashMap<Cow<'static, str>, (Instant, u32)>, // (window_start, count)
}

impl FixedWindowLimiter {
    pub fn new(window: Duration, limit: u32) -> Self {
        Self {
            window,
            limit,
            state: DashMap::new(),
        }
    }
}

impl RateLimiter for FixedWindowLimiter {
    fn check(&self, key: Cow<str>) -> RateLimitResult {
        let now = Instant::now();
        let key: Cow<'static, str> = Cow::Owned(key.into_owned());

        let mut entry = self.state.entry(key.clone()).or_insert((now, 0));
        let (start, count) = *entry;

        let elapsed = now.duration_since(start);
        if elapsed > self.window {
            *entry = (now, 1);
            return RateLimitResult {
                allowed: true,
                remaining: self.limit - 1,
                limit: self.limit,
                retry_after_secs: None,
                reset_after_secs: Some(self.window.as_secs()),
            };
        }

        if count < self.limit {
            entry.1 += 1;
            RateLimitResult {
                allowed: true,
                remaining: self.limit - entry.1,
                limit: self.limit,
                retry_after_secs: None,
                reset_after_secs: Some((self.window - elapsed).as_secs()),
            }
        } else {
            RateLimitResult {
                allowed: false,
                remaining: 0,
                limit: self.limit,
                retry_after_secs: Some((self.window - elapsed).as_secs()),
                reset_after_secs: Some((self.window - elapsed).as_secs()),
            }
        }
    }
}

pub struct SlidingWindowLimiter {
    window: Duration,
    limit: usize,
    state: DashMap<Cow<'static, str>, Deque<Instant, MAX_QUEUE_LEN>>, // bounded queue
}

impl SlidingWindowLimiter {
    pub fn new(window: Duration, limit: usize) -> Self {
        Self {
            window,
            limit,
            state: DashMap::new(),
        }
    }
}

impl RateLimiter for SlidingWindowLimiter {
    fn check(&self, key: Cow<str>) -> RateLimitResult {
        let now = Instant::now();
        let key: Cow<'static, str> = Cow::Owned(key.into_owned());
        let mut queue = self.state.entry(key.clone()).or_insert_with(Deque::new);

        while let Some(&front) = queue.front() {
            if now.duration_since(front) > self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.is_empty() {
            self.state.remove(&key);
        }

        if queue.len() < self.limit {
            if queue.len() < MAX_QUEUE_LEN {
                queue.push_back(now).ok(); // discard if full
            }
            RateLimitResult {
                allowed: true,
                remaining: (self.limit.saturating_sub(queue.len().min(self.limit))) as u32,
                limit: self.limit as u32,
                retry_after_secs: None,
                reset_after_secs: queue
                    .front()
                    .map(|&t| self.window.as_secs() - now.duration_since(t).as_secs()),
            }
        } else {
            let retry_after = queue
                .front()
                .map(|&t| self.window.as_secs() - now.duration_since(t).as_secs());
            RateLimitResult {
                allowed: false,
                remaining: 0,
                limit: self.limit as u32,
                retry_after_secs: retry_after,
                reset_after_secs: retry_after,
            }
        }
    }
}

pub enum RateLimiterKind {
    Fixed(FixedWindowLimiter),
    Sliding(SlidingWindowLimiter),
}

impl RateLimiter for RateLimiterKind {
    fn check(&self, key: Cow<str>) -> RateLimitResult {
        match self {
            RateLimiterKind::Fixed(f) => f.check(key),
            RateLimiterKind::Sliding(s) => s.check(key),
        }
    }
}
