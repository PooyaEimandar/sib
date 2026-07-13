//! Layout:
//!   /cache/{ns}/data/{key}                -> [expiry_be(8) | value...]
//!   /cache/{ns}/ttl/{bucket_be(8)}{key_len_be(4)}{key} -> ""
//!   /cache/{ns}/gc/last_bucket            -> bucket_be(8)

use crate::database::fdb::pool::FDBPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[inline]
fn now_ms() -> u64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()) as u64
}

const ROOT_PFX: &[u8] = b"/cache/";
const DATA_SEG: &[u8] = b"/data/";
const TTL_SEG: &[u8] = b"/ttl/";
const GC_LAST: &[u8] = b"/gc/last_bucket";

#[inline]
fn bucket_of(ts_ms: u64, bucket_ms: u64) -> u64 {
    (ts_ms / bucket_ms) * bucket_ms
}

#[inline]
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.last_mut() {
        if *last != 0xFF {
            *last += 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

#[inline]
fn k_data_for(ns: &[u8], key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(ROOT_PFX.len() + ns.len() + DATA_SEG.len() + key.len());
    k.extend_from_slice(ROOT_PFX);
    k.extend_from_slice(ns);
    k.extend_from_slice(DATA_SEG);
    k.extend_from_slice(key);
    k
}

#[inline]
fn ttl_bucket_prefix(ns: &[u8], bucket: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(ROOT_PFX.len() + ns.len() + TTL_SEG.len() + 8);
    k.extend_from_slice(ROOT_PFX);
    k.extend_from_slice(ns);
    k.extend_from_slice(TTL_SEG);
    k.extend_from_slice(&bucket.to_be_bytes());
    k
}

#[inline]
fn k_ttl_for(ns: &[u8], bucket: u64, key: &[u8]) -> Vec<u8> {
    let mut k = ttl_bucket_prefix(ns, bucket);
    k.extend_from_slice(&(key.len() as u32).to_be_bytes());
    k.extend_from_slice(key);
    k
}

#[inline]
fn pfx_bucket_for(ns: &[u8], bucket: u64) -> Option<(Vec<u8>, Vec<u8>)> {
    let start = ttl_bucket_prefix(ns, bucket);
    let end = prefix_end(&start)?;
    Some((start, end))
}

#[inline]
fn k_gc_checkpoint_for(ns: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(ROOT_PFX.len() + ns.len() + GC_LAST.len());
    k.extend_from_slice(ROOT_PFX);
    k.extend_from_slice(ns);
    k.extend_from_slice(GC_LAST);
    k
}

#[inline]
fn data_key_from_ttl_key(ns: &[u8], bucket: u64, ttl_key: &[u8]) -> Option<Vec<u8>> {
    let prefix = ttl_bucket_prefix(ns, bucket);
    let rest = ttl_key.strip_prefix(prefix.as_slice())?;
    let len_bytes: [u8; 4] = rest.get(..4)?.try_into().ok()?;
    let key_len = u32::from_be_bytes(len_bytes) as usize;
    let key = rest.get(4..4 + key_len)?;
    if rest.len() != 4 + key_len {
        return None;
    }
    Some(k_data_for(ns, key))
}

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
        bucket_of(ts_ms, self.bucket_ms)
    }

    #[inline]
    fn k_data(&self, key: &[u8]) -> Vec<u8> {
        k_data_for(&self.ns, key)
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn k_ttl(&self, bucket: u64, key: &[u8]) -> Vec<u8> {
        k_ttl_for(&self.ns, bucket, key)
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn pfx_bucket(&self, bucket: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        pfx_bucket_for(&self.ns, bucket)
    }

    #[cfg(feature = "rt-may")]
    #[inline]
    fn k_gc_checkpoint(&self) -> Vec<u8> {
        k_gc_checkpoint_for(&self.ns)
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
            let bucket = bucket_of(exp_ms, bucket_ms);
            let kd = k_data_for(&ns, &key);
            let kt = k_ttl_for(&ns, bucket, &key);

            let mut payload = Vec::with_capacity(8 + value.len());
            payload.extend_from_slice(&exp_ms.to_be_bytes());
            payload.extend_from_slice(&value);

            let trx = FDBTransaction::new(&loan)?;
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

        let trx = FDBTransaction::new(&loan)?;
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
        let trx = FDBTransaction::new(&loan)?;

        // Non-snapshot read: for a live key the txn is dropped read-only
        let val = trx.get_blocking_value_optional(&kd, false)?;
        if let Some(raw) = val {
            if raw.len() < 8 {
                return Ok(None);
            }
            let mut be = [0u8; 8];
            be.copy_from_slice(&raw[..8]);
            let exp = u64::from_be_bytes(be);
            if now_ms() >= exp {
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
            let trx = FDBTransaction::new(&loan)?;

            let val = trx.get_blocking_value_optional(&kd, false)?;
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
        let trx = FDBTransaction::new(&loan)?;
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
            let trx = FDBTransaction::new(&loan)?;
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
        let trx = FDBTransaction::new(&loan)?;
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

        let Some((start, end)) = self.pfx_bucket(candidate) else {
            return Ok(false);
        };
        loop {
            use crate::database::fdb::trans::FDBRange;

            let trx = FDBTransaction::new(&loan)?;
            let range = FDBRange::exact_prefix(&start, &end, self.gc_batch as i32);
            let (batch, _more) = trx.get_range_blocking(&range)?;
            drop(trx);

            if batch.is_empty() {
                break;
            }

            let trx = FDBTransaction::new(&loan)?;
            for (k_ttl, _) in &batch {
                if let Some(kd) = data_key_from_ttl_key(&self.ns, candidate, k_ttl) {
                    // Only delete the data record if it is genuinely expired.
                    match trx.get_blocking_value_optional(&kd, false)? {
                        Some(raw) if raw.len() >= 8 => {
                            let mut be = [0u8; 8];
                            be.copy_from_slice(&raw[..8]);
                            if now >= u64::from_be_bytes(be) {
                                trx.clear(&kd);
                            }
                        }
                        // Malformed record ,too short to carry an expiry, reclaim it.
                        Some(_) => {
                            trx.clear(&kd);
                        }
                        None => {}
                    }
                }
                trx.clear(k_ttl);
            }
            trx.commit_blocking()?;
        }

        let trx = FDBTransaction::new(&loan)?;
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
            let limit = bucket_of(now.saturating_sub(lazy_expiration_ms), bucket_ms);

            // load checkpoint
            let k_gc = k_gc_checkpoint_for(&ns);
            let trx = FDBTransaction::new(&loan)?;
            let last = trx.get_blocking_value_optional(&k_gc, true)?; // retry-safe
            drop(trx);

            let start_bucket = match last {
                Some(b) if b.len() == 8 => {
                    u64::from_be_bytes(b.as_slice().try_into().unwrap()).saturating_add(bucket_ms)
                }
                _ => 0,
            };
            let candidate = if start_bucket == 0 {
                bucket_of(
                    now.saturating_sub(lazy_expiration_ms + bucket_ms),
                    bucket_ms,
                )
            } else {
                start_bucket
            };

            if candidate == 0 || candidate >= limit {
                return Ok(false);
            }

            // stream-delete bucket in batches
            let Some((start, end)) = pfx_bucket_for(&ns, candidate) else {
                return Ok(false);
            };

            loop {
                use crate::database::fdb::trans::FDBRange;
                let trx = FDBTransaction::new(&loan)?;
                let range = FDBRange::exact_prefix(&start, &end, gc_batch as i32);
                let (batch, _more) = trx.get_range_blocking(&range)?;
                // Drop before write txn
                drop(trx);

                if batch.is_empty() {
                    break;
                }

                let trx = FDBTransaction::new(&loan)?;
                for (k_ttl, _) in &batch {
                    if let Some(kd) = data_key_from_ttl_key(&ns, candidate, k_ttl) {
                        // Only delete the data record if it is genuinely expired.
                        match trx.get_blocking_value_optional(&kd, false)? {
                            Some(raw) if raw.len() >= 8 => {
                                let mut be = [0u8; 8];
                                be.copy_from_slice(&raw[..8]);
                                if now >= u64::from_be_bytes(be) {
                                    trx.clear(&kd);
                                }
                            }
                            // Malformed record, too short to carry an expiry, reclaim it.
                            Some(_) => {
                                trx.clear(&kd);
                            }
                            None => {}
                        }
                    }
                    trx.clear(k_ttl);
                }
                trx.commit_blocking()?;
            }

            // tidy + checkpoint
            let trx = FDBTransaction::new(&loan)?;
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
#[path = "../../../tests/unit/database/fdb/cache_tests.rs"]
mod tests;
