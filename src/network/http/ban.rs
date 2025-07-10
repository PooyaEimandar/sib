use std::{net::IpAddr, time::{Duration, Instant}};
use dashmap::DashMap;

pub(crate) static STRIKE_CACHE: once_cell::sync::Lazy<DashMap<IpAddr, (u8, Instant)>> =
    once_cell::sync::Lazy::new(DashMap::new);

pub(crate) static BAN_CACHE: once_cell::sync::Lazy<DashMap<IpAddr, Instant>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[derive(Clone)]
pub struct BanConfig {
    pub max_strikes: u8,
    pub strike_window: Duration,
    pub ban_duration: Duration,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            max_strikes: 5, // Maximum strikes before banning 
            strike_window: Duration::from_secs(30), // 30 seconds
            ban_duration: Duration::from_secs(120), // 120 seconds
        }
    }
}

#[inline]
pub(crate) fn record_strike(ip: IpAddr, reason: &'static str, config: &BanConfig) {
    let now = Instant::now();
    let mut entry = STRIKE_CACHE.entry(ip).or_insert((0, now));
    if now.duration_since(entry.1) > config.strike_window {
        *entry = (1, now);
    } else {
        entry.0 += 1;
        if entry.0 >= config.max_strikes {
            eprintln!("Banning IP {ip} due to repeated {reason} (within {:?})", config.strike_window);
            BAN_CACHE.insert(ip, now + config.ban_duration);
            STRIKE_CACHE.remove(&ip);
        }
    }
}