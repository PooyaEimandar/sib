use dashmap::DashMap;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

pub struct RateLimit {
    map: DashMap<IpAddr, (Instant, u32)>,
    max_burst: u32,
    window: Duration,
    last_gc_time_in_nano: AtomicU64,
    gc_interval: Duration,
    start_time: Instant, // Reference start time for calculating "monotonic time"
}

impl RateLimit {
    pub fn new(max_burst: u32, window: Duration, gc_interval: Duration) -> Self {
        Self {
            map: DashMap::new(),
            max_burst,
            window,
            last_gc_time_in_nano: AtomicU64::new(0),
            gc_interval,
            start_time: Instant::now(),
        }
    }

    #[inline]
    fn now_nanos(&self) -> u64 {
        self.start_time.elapsed().as_nanos() as u64
    }

    #[inline]
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now_instant = Instant::now();
        let now_nanos = self.now_nanos();

        let last_gc = self.last_gc_time_in_nano.load(Ordering::Relaxed);

        if now_nanos.saturating_sub(last_gc) > self.gc_interval.as_nanos() as u64 {
            if self
                .last_gc_time_in_nano
                .compare_exchange(last_gc, now_nanos, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                self.map
                    .retain(|_, (ts, _)| now_instant.duration_since(*ts) < self.gc_interval);
            }
        }

        let mut entry = self.map.entry(ip).or_insert((now_instant, 0));

        if now_instant.duration_since(entry.0) > self.window {
            *entry = (now_instant, 1);
            return true;
        }

        if entry.1 >= self.max_burst {
            return false;
        }

        entry.1 += 1;
        true
    }
}
