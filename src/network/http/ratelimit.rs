use dashmap::DashMap;
use std::collections::VecDeque;
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static CLEANUP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Result of a rate limit check
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub limit: u32,
    pub retry_after_secs: Option<u64>,
    pub reset_after_secs: Option<u64>,
}

/// Rate limiter trait for pluggable strategies
pub trait RateLimiter {
    fn check(&self, key: Cow<str>) -> RateLimitResult;
}

/// Fixed window rate limiter
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

/// Sliding window rate limiter with queue pruning and global cleanup
pub struct SlidingWindowLimiter {
    window: Duration,
    limit: usize,
    max_queue_len: usize,
    state: DashMap<Cow<'static, str>, VecDeque<Instant>>,
}

impl SlidingWindowLimiter {
    pub fn new(window: Duration, limit: usize, max_queue_len: usize) -> Self {
        assert!(
            max_queue_len >= limit,
            "max_queue_len must be >= limit"
        );
        Self {
            window,
            limit,
            max_queue_len,
            state: DashMap::new(),
        }
    }
}

impl RateLimiter for SlidingWindowLimiter {
    fn check(&self, key: Cow<str>) -> RateLimitResult {
        let now = Instant::now();
        let key: Cow<'static, str> = Cow::Owned(key.into_owned());

        // Occasionally perform global cleanup
        if CLEANUP_COUNTER.fetch_add(1, Ordering::Relaxed) % 100 == 0 {
            let window = self.window;
            self.state.retain(|_, queue| {
                queue.back().is_some_and(|&t| now.duration_since(t) <= window)
            });
        }

        // Access or insert queue
        let mut entry = self.state.entry(key.clone()).or_default();
        let queue = entry.value_mut();

        // Prune expired timestamps
        while let Some(&front) = queue.front() {
            if now.duration_since(front) > self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        // Remove empty queues to save memory
        if queue.is_empty() {
            self.state.remove(&key);
        }

        // Allow request if under limit
        if queue.len() < self.limit {
            if queue.len() < self.max_queue_len {
                queue.push_back(now);
            }
            RateLimitResult {
                allowed: true,
                remaining: (self.limit - queue.len()) as u32,
                limit: self.limit as u32,
                retry_after_secs: None,
                reset_after_secs: queue
                    .front()
                    .map(|&t| self.window.as_secs().saturating_sub(now.duration_since(t).as_secs())),
            }
        } else {
            let retry_after = queue
                .front()
                .map(|&t| self.window.as_secs().saturating_sub(now.duration_since(t).as_secs()));
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

/// Enum wrapper for dynamic strategy switching
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
