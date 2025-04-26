// use dashmap::DashMap;
// use std::{
//     net::IpAddr,
//     sync::atomic::{AtomicU64, Ordering},
//     time::{Duration, Instant},
// };

// #[derive(Default)]
// pub struct RateLimit {
//     map: DashMap<IpAddr, (Instant, u32)>,
//     max_burst: u32,
//     window: Duration,
//     last_gc_time: AtomicU64,
//     gc_interval: Duration,
// }

// impl RateLimit {
//     pub fn new(max_burst: u32, window: Duration, gc_interval: Duration) -> Self {
//         RateLimit {
//             map: DashMap::new(),
//             max_burst,
//             window,
//             last_gc_time: AtomicU64::new(0),
//             gc_interval,
//         }
//     }

//     #[inline]
//     pub fn allow(self: &RateLimit, ip: IpAddr) -> bool {
//         let now_nanos = Instant::now()
//             .duration_since(Instant::now() - Duration::from_secs(86400))
//             .as_nanos() as u64; // nanoseconds since epoch
//         let last_gc = self.last_gc_time.load(Ordering::Relaxed);

//         if now_nanos.saturating_sub(last_gc) > self.gc_interval.as_nanos() as u64
//             && self
//                 .last_gc_time
//                 .compare_exchange(last_gc, now_nanos, Ordering::SeqCst, Ordering::Relaxed)
//                 .is_ok()
//         {
//             let now = Instant::now();
//             self.map
//                 .retain(|_, (ts, _)| now.duration_since(*ts) < self.gc_interval);
//         }

//         // Rate limiting logic
//         let now = Instant::now();
//         let mut entry = self.map.entry(ip).or_insert((now, 0));

//         if now.duration_since(entry.0) > self.window {
//             *entry = (now, 1);
//             return true;
//         }

//         if entry.1 >= self.max_burst {
//             return false;
//         }

//         entry.1 += 1;
//         true
//     }
// }
