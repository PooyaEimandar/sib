//! Layout:
//!   /cache/{ns}/data/{key}                -> [expiry_be(8) | value...]
//!   /cache/{ns}/ttl/{bucket_be(8)}/{key}  -> ""
//!   /cache/{ns}/gc/last_bucket            -> bucket_be(8)

use crate::database::fdb::pool::FDBPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[inline]
fn now_ms() -> u64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()) as u64
}

const ROOT_PFX: &[u8] = b"/cache/";
const DATA_SEG: &[u8] = b"/data/";
const TTL_SEG: &[u8] = b"/ttl/";
const GC_LAST: &[u8] = b"/gc/last_bucket";

#[derive(Clone)]
pub struct BucketTtlCache {
    pool: FDBPool,
    ns: Vec<u8>,
    /// GC granularity (default 60s)
    pub bucket_ms: u64,
    /// Safety cushion to avoid edge deletes (default 2 buckets)
    pub lazy_expiration_ms: u64,
    /// Max ttl-keys deleted per GC txn
    pub gc_batch: usize,
}

impl BucketTtlCache {
    pub fn new(pool: FDBPool, ns: impl AsRef<[u8]>) -> Self {
        Self {
            pool,
            ns: ns.as_ref().to_vec(),
            bucket_ms: 60_000,
            lazy_expiration_ms: 120_000,
            gc_batch: 2_000,
        }
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn bucket_of(&self, ts_ms: u64) -> u64 {
        (ts_ms / self.bucket_ms) * self.bucket_ms
    }

    #[inline]
    fn k_data(&self, key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(ROOT_PFX.len() + self.ns.len() + DATA_SEG.len() + key.len());
        k.extend_from_slice(ROOT_PFX);
        k.extend_from_slice(&self.ns);
        k.extend_from_slice(DATA_SEG);
        k.extend_from_slice(key);
        k
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn k_ttl(&self, bucket: u64, key: &[u8]) -> Vec<u8> {
        let mut k =
            Vec::with_capacity(ROOT_PFX.len() + self.ns.len() + TTL_SEG.len() + 8 + 1 + key.len());
        k.extend_from_slice(ROOT_PFX);
        k.extend_from_slice(&self.ns);
        k.extend_from_slice(TTL_SEG);
        k.extend_from_slice(&bucket.to_be_bytes());
        k.push(b'/');
        k.extend_from_slice(key);
        k
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn pfx_bucket(&self, bucket: u64) -> (Vec<u8>, Vec<u8>) {
        // [start, end) range covering a bucket's ttl entries
        let mut start = Vec::with_capacity(ROOT_PFX.len() + self.ns.len() + TTL_SEG.len() + 8 + 1);
        start.extend_from_slice(ROOT_PFX);
        start.extend_from_slice(&self.ns);
        start.extend_from_slice(TTL_SEG);
        start.extend_from_slice(&bucket.to_be_bytes());
        start.push(b'/');
        let mut end = start.clone();
        end.push(0xFF); // simple next-prefix sentinel
        (start, end)
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn k_gc_checkpoint(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(ROOT_PFX.len() + self.ns.len() + GC_LAST.len());
        k.extend_from_slice(ROOT_PFX);
        k.extend_from_slice(&self.ns);
        k.extend_from_slice(GC_LAST);
        k
    }

    #[cfg(feature = "rt-tokio")]
    pub async fn set(&self, key: &[u8], value: &[u8], ttl: Duration) -> std::io::Result<()> {
        let pool = self.pool.clone();
        let ns = self.ns.clone();
        let bucket_ms = self.bucket_ms;
        let key = key.to_vec();
        let value = value.to_vec();

        tokio::task::spawn_blocking(move || {
            use crate::database::fdb::trans::FDBTransaction;

            let loan = pool
                .try_loan()
                .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
            let exp_ms = now_ms().saturating_add(ttl.as_millis() as u64);
            let bucket = (exp_ms / bucket_ms) * bucket_ms;

            let kd = {
                let mut k =
                    Vec::with_capacity(ROOT_PFX.len() + ns.len() + DATA_SEG.len() + key.len());
                k.extend_from_slice(ROOT_PFX);
                k.extend_from_slice(&ns);
                k.extend_from_slice(DATA_SEG);
                k.extend_from_slice(&key);
                k
            };
            let kt = {
                let mut k = Vec::with_capacity(
                    ROOT_PFX.len() + ns.len() + TTL_SEG.len() + 8 + 1 + key.len(),
                );
                k.extend_from_slice(ROOT_PFX);
                k.extend_from_slice(&ns);
                k.extend_from_slice(TTL_SEG);
                k.extend_from_slice(&bucket.to_be_bytes());
                k.push(b'/');
                k.extend_from_slice(&key);
                k
            };

            let mut payload = Vec::with_capacity(8 + value.len());
            payload.extend_from_slice(&exp_ms.to_be_bytes());
            payload.extend_from_slice(&value);

            let trx = FDBTransaction::new(&*loan)?;
            trx.set(&kd, &payload);
            trx.set(&kt, b"");
            trx.commit_blocking()
        })
        .await
        .map_err(std::io::Error::from)?
    }

    #[cfg(feature = "rt-may")]
    pub fn set(&self, key: &[u8], value: &[u8], ttl: Duration) -> std::io::Result<()> {
        use crate::database::fdb::trans::FDBTransaction;

        let loan = self
            .pool
            .try_loan()
            .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
        let exp_ms = now_ms().saturating_add(ttl.as_millis() as u64);
        let bucket = self.bucket_of(exp_ms);

        let kd = self.k_data(key);
        let kt = self.k_ttl(bucket, key);

        let mut payload = Vec::with_capacity(8 + value.len());
        payload.extend_from_slice(&exp_ms.to_be_bytes());
        payload.extend_from_slice(value);

        let trx = FDBTransaction::new(&*loan)?;
        trx.set(&kd, &payload);
        trx.set(&kt, b"");
        trx.commit_blocking()
    }

    #[cfg(feature = "rt-may")]
    pub fn get(&self, key: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        use crate::database::fdb::trans::FDBTransaction;

        let loan = self
            .pool
            .try_loan()
            .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
        let kd = self.k_data(key);
        let trx = FDBTransaction::new(&*loan)?;

        let val = trx.get_blocking_value_optional(&kd, true)?;
        if let Some(raw) = val {
            if raw.len() < 8 {
                return Ok(None);
            }
            let mut be = [0u8; 8];
            be.copy_from_slice(&raw[..8]);
            let exp = u64::from_be_bytes(be);
            if now_ms() >= exp {
                // best-effort scrub
                trx.clear(&kd);
                let _ = trx.commit_blocking();
                return Ok(None);
            }
            return Ok(Some(raw[8..].to_vec()));
        }
        Ok(None)
    }

    #[cfg(feature = "rt-tokio")]
    pub async fn get(&self, key: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let kd = self.k_data(key);

        tokio::task::spawn_blocking(move || {
            use crate::database::fdb::trans::FDBTransaction;

            let loan = pool
                .try_loan()
                .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
            let trx = FDBTransaction::new(&*loan)?;

            let val = trx.get_blocking_value_optional(&kd, true)?;
            if let Some(raw) = val {
                if raw.len() < 8 {
                    return Ok(None);
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(&raw[..8]);
                let exp = u64::from_be_bytes(be);
                if now_ms() >= exp {
                    // best-effort scrub; ttl index will be removed by GC
                    trx.clear(&kd);
                    let _ = trx.commit_blocking();
                    return Ok(None);
                }
                return Ok(Some(raw[8..].to_vec()));
            }
            Ok(None)
        })
        .await
        .map_err(std::io::Error::from)?
    }

    #[cfg(feature = "rt-may")]
    pub fn delete(&self, key: &[u8]) -> std::io::Result<()> {
        use crate::database::fdb::trans::FDBTransaction;

        let loan = self
            .pool
            .try_loan()
            .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
        let kd = self.k_data(key);
        let trx = FDBTransaction::new(&*loan)?;
        trx.clear(&kd);
        trx.commit_blocking()
    }

    #[cfg(feature = "rt-tokio")]
    pub async fn delete(&self, key: &[u8]) -> std::io::Result<()> {
        let pool = self.pool.clone();
        let kd = self.k_data(key);

        tokio::task::spawn_blocking(move || {
            use crate::database::fdb::trans::FDBTransaction;

            let loan = pool
                .try_loan()
                .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
            let trx = FDBTransaction::new(&*loan)?;
            trx.clear(&kd);
            trx.commit_blocking()
        })
        .await
        .map_err(std::io::Error::from)?
    }

    #[cfg(feature = "rt-may")]
    pub fn gc_once(&self) -> std::io::Result<bool> {
        use crate::database::fdb::trans::FDBTransaction;

        let loan = self
            .pool
            .try_loan()
            .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
        let now = now_ms();
        let limit = self.bucket_of(now.saturating_sub(self.lazy_expiration_ms));

        let k_gc = self.k_gc_checkpoint();
        let trx = FDBTransaction::new(&*loan)?;
        let last = trx.get_blocking_value_optional(&k_gc, true)?;
        drop(trx);

        let start_bucket = match last {
            Some(b) if b.len() == 8 => {
                u64::from_be_bytes(b.as_slice().try_into().unwrap()).saturating_add(self.bucket_ms)
            }
            _ => 0,
        };
        let candidate = if start_bucket == 0 {
            self.bucket_of(now.saturating_sub(self.lazy_expiration_ms + self.bucket_ms))
        } else {
            start_bucket
        };

        if candidate == 0 || candidate >= limit {
            return Ok(false);
        }

        let (start, end) = self.pfx_bucket(candidate);
        loop {
            use crate::database::fdb::trans::{FDBRange, FDBStreamingMode};

            let trx = FDBTransaction::new(&*loan)?;
            let range = FDBRange {
                begin_key: &start,
                begin_or_equal: true,
                begin_offset: 0,
                end_key: &end,
                end_or_equal: false,
                end_offset: 0,
                limit: self.gc_batch as i32,
                target_bytes: 1 << 20, // NEW: 1 MiB hint
                mode: FDBStreamingMode::WantAll,
                iteration: 0,
                snapshot: true,
                reverse: false,
            };
            let (batch, _more) = trx.get_range_blocking(&range)?;
            drop(trx);

            if batch.is_empty() {
                break;
            }

            let trx = FDBTransaction::new(&*loan)?;
            for (k_ttl, _) in &batch {
                if let Some(pos) = k_ttl.iter().rposition(|&b| b == b'/') {
                    let key = &k_ttl[pos + 1..];
                    let kd = self.k_data(key);
                    trx.clear(&kd);
                }
                trx.clear(k_ttl);
            }
            trx.commit_blocking()?;
        }

        let trx = FDBTransaction::new(&*loan)?;
        trx.clear_range(&start, &end);
        trx.set(&k_gc, &candidate.to_be_bytes());
        trx.commit_blocking()?;
        Ok(true)
    }

    #[cfg(feature = "rt-tokio")]
    pub async fn gc_once(&self) -> std::io::Result<bool> {
        let pool = self.pool.clone();
        let ns = self.ns.clone();
        let bucket_ms = self.bucket_ms;
        let lazy_expiration_ms = self.lazy_expiration_ms;
        let gc_batch = self.gc_batch;

        tokio::task::spawn_blocking(move || {
            use crate::database::fdb::trans::FDBTransaction;

            let loan = pool
                .try_loan()
                .ok_or_else(|| std::io::Error::other("no FDB handle in pool"))?;
            let now = now_ms();
            let limit = (now.saturating_sub(lazy_expiration_ms) / bucket_ms) * bucket_ms;

            // load checkpoint
            let k_gc = {
                let mut k = Vec::with_capacity(ROOT_PFX.len() + ns.len() + GC_LAST.len());
                k.extend_from_slice(ROOT_PFX);
                k.extend_from_slice(&ns);
                k.extend_from_slice(GC_LAST);
                k
            };
            let trx = FDBTransaction::new(&*loan)?;
            let last = trx.get_blocking_value_optional(&k_gc, true)?; // retry-safe
            drop(trx);

            let start_bucket = match last {
                Some(b) if b.len() == 8 => {
                    u64::from_be_bytes(b.as_slice().try_into().unwrap()).saturating_add(bucket_ms)
                }
                _ => 0,
            };
            let candidate = if start_bucket == 0 {
                (now.saturating_sub(lazy_expiration_ms + bucket_ms) / bucket_ms) * bucket_ms
            } else {
                start_bucket
            };

            if candidate == 0 || candidate >= limit {
                return Ok(false);
            }

            // stream-delete bucket in batches
            let (start, end) = {
                let mut s = Vec::with_capacity(ROOT_PFX.len() + ns.len() + TTL_SEG.len() + 8 + 1);
                s.extend_from_slice(ROOT_PFX);
                s.extend_from_slice(&ns);
                s.extend_from_slice(TTL_SEG);
                s.extend_from_slice(&candidate.to_be_bytes());
                s.push(b'/');
                let mut e = s.clone();
                e.push(0xFF);
                (s, e)
            };

            loop {
                use crate::database::fdb::trans::{FDBRange, FDBStreamingMode};
                let trx = FDBTransaction::new(&*loan)?;
                let range = FDBRange {
                    begin_key: &start,
                    begin_or_equal: true,
                    begin_offset: 0,
                    end_key: &end,
                    end_or_equal: false,
                    end_offset: 0,
                    limit: gc_batch as i32,
                    target_bytes: 1 << 20, // NEW: 1 MiB hint
                    mode: FDBStreamingMode::WantAll,
                    iteration: 0,
                    snapshot: true,
                    reverse: false,
                };
                let (batch, _more) = trx.get_range_blocking(&range)?;
                // Drop before write txn
                drop(trx);

                if batch.is_empty() {
                    break;
                }

                let trx = FDBTransaction::new(&*loan)?;
                for (k_ttl, _) in &batch {
                    if let Some(pos) = k_ttl.iter().rposition(|&b| b == b'/') {
                        let key = &k_ttl[pos + 1..];
                        let mut kd = Vec::with_capacity(
                            ROOT_PFX.len() + ns.len() + DATA_SEG.len() + key.len(),
                        );
                        kd.extend_from_slice(ROOT_PFX);
                        kd.extend_from_slice(&ns);
                        kd.extend_from_slice(DATA_SEG);
                        kd.extend_from_slice(key);
                        trx.clear(&kd);
                    }
                    trx.clear(k_ttl);
                }
                trx.commit_blocking()?;
            }

            // tidy + checkpoint
            let trx = FDBTransaction::new(&*loan)?;
            trx.clear_range(&start, &end);
            trx.set(&k_gc, &candidate.to_be_bytes());
            trx.commit_blocking()?;
            Ok(true)
        })
        .await
        .map_err(std::io::Error::from)?
    }

    #[cfg(feature = "rt-may")]
    pub fn run_gc_loop(&self, interval: Duration) -> std::io::Result<()> {
        loop {
            let _ = self.gc_once()?;
            may::coroutine::sleep(interval);
        }
    }

    #[cfg(feature = "rt-tokio")]
    pub async fn run_gc_loop(&self, interval: Duration) -> std::io::Result<()> {
        loop {
            let _ = self.gc_once().await?;
            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::fdb::network::FDBNetwork;
    use crate::database::fdb::pool::FDBPool;
    use std::{num::NonZeroU64, thread, time::Duration};

    /// Start the FDB network.
    fn start_network_and_pool() -> Option<(thread::JoinHandle<()>, FDBNetwork, FDBPool)> {
        let net = FDBNetwork::new(None).expect("Failed to create FDB network");

        // Spawn run() in background (blocking call)
        let net_clone = net.clone();
        let handle = thread::spawn(move || {
            net_clone.run().expect("Failed to run FDB network");
        });

        // Give network a moment to start
        thread::sleep(Duration::from_millis(200));

        #[cfg(target_os = "macos")]
        let cluster = "/usr/local/etc/foundationdb/fdb.cluster";

        #[cfg(target_os = "linux")]
        let cluster = "/etc/foundationdb/fdb.cluster";

        let pool = FDBPool::new(cluster.to_owned(), NonZeroU64::new(4).unwrap())
            .expect("Failed to create FDBPool");

        Some((handle, net, pool))
    }

    /// Stop the network to unblock run() and join the thread.
    fn stop_and_join(mut net: FDBNetwork, handle: thread::JoinHandle<()>) {
        let _ = net.stop();
        let _ = handle.join();
    }

    #[cfg(feature = "rt-tokio")]
    #[tokio::test]
    async fn cache_set_get_lazy_expire_and_gc() {
        let Some((handle, net, pool)) = start_network_and_pool() else {
            return;
        };
        let cache = BucketTtlCache::new(pool.clone(), "test_cache");
        let mut cache = cache.clone();
        cache.bucket_ms = 200;
        cache.lazy_expiration_ms = 400;
        cache.gc_batch = 512;

        cache
            .set(b"k1", b"v1", Duration::from_millis(150))
            .await
            .expect("set");

        let v = cache.get(b"k1").await.expect("get");
        assert_eq!(v.as_deref(), Some(&b"v1"[..]));

        tokio::time::sleep(Duration::from_millis(260)).await;
        let v = cache.get(b"k1").await.expect("get after expire");
        assert!(v.is_none(), "lazy TTL should miss after expiry");

        for i in 0..8u8 {
            let k = [b't', i];
            let val = [b'v', i];
            cache
                .set(&k, &val, Duration::from_millis(150))
                .await
                .expect("set batch");
        }

        tokio::time::sleep(Duration::from_millis(700)).await;

        let cleaned = cache.gc_once().await.expect("gc_once");
        assert!(cleaned, "expected to clean one expired bucket");

        for i in 0..8u8 {
            let k = [b't', i];
            let v = cache.get(&k).await.expect("get after gc");
            assert!(v.is_none(), "post-GC value should be None for key {:?}", k);
        }

        stop_and_join(net, handle);
    }

    #[cfg(feature = "rt-tokio")]
    #[tokio::test]
    async fn cache_delete_removes_row() {
        let Some((handle, net, pool)) = start_network_and_pool() else {
            return;
        };
        let cache = BucketTtlCache::new(pool.clone(), "test_delete");

        cache
            .set(b"delkey", b"val", Duration::from_secs(5))
            .await
            .expect("set");
        assert!(cache.get(b"delkey").await.unwrap().is_some());

        cache.delete(b"delkey").await.expect("delete");
        assert!(cache.get(b"delkey").await.unwrap().is_none());

        stop_and_join(net, handle);
    }

    #[cfg(feature = "rt-may")]
    #[test]
    fn cache_set_get_lazy_expire_and_gc() {
        let Some((handle, net, pool)) = start_network_and_pool() else {
            return;
        };
        let cache = BucketTtlCache::new(pool.clone(), "test_cache");
        let mut cache = cache.clone();
        cache.bucket_ms = 200;
        cache.lazy_expiration_ms = 400;
        cache.gc_batch = 512;

        cache
            .set(b"k1", b"v1", Duration::from_millis(150))
            .expect("set");

        let v = cache.get(b"k1").expect("get");
        assert_eq!(v.as_deref(), Some(&b"v1"[..]));

        may::coroutine::sleep(Duration::from_millis(260));
        let v = cache.get(b"k1").expect("get after expire");
        assert!(v.is_none());

        for i in 0..8u8 {
            let k = [b'm', i];
            let val = [b'v', i];
            cache
                .set(&k, &val, Duration::from_millis(150))
                .expect("set batch");
        }

        may::coroutine::sleep(Duration::from_millis(700));

        let cleaned = cache.gc_once().expect("gc_once");
        assert!(cleaned, "expected to clean one expired bucket");

        for i in 0..8u8 {
            let k = [b'm', i];
            let v = cache.get(&k).expect("get after gc");
            assert!(v.is_none(), "post-GC value should be None for key {:?}", k);
        }

        stop_and_join(net, handle);
    }

    #[cfg(feature = "rt-may")]
    #[test]
    fn cache_delete_removes_row() {
        let Some((handle, net, pool)) = start_network_and_pool() else {
            return;
        };
        let cache = BucketTtlCache::new(pool.clone(), "test_delete");

        cache
            .set(b"delkey", b"val", Duration::from_secs(5))
            .expect("set");
        assert!(cache.get(b"delkey").expect("get").is_some());

        cache.delete(b"delkey").expect("delete");
        assert!(cache.get(b"delkey").expect("get after delete").is_none());

        stop_and_join(net, handle);
    }
}
