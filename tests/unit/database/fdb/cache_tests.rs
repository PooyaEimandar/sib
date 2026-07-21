use super::*;
use crate::database::fdb::pool::FDBPool;
use std::{num::NonZeroU64, time::Duration};

/// Start the FDB network.
fn start_network_and_pool() -> Option<FDBPool> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return None;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let cluster = std::env::var("SIB_FDB_CLUSTER_FILE").unwrap_or_else(|_| {
            #[cfg(target_os = "macos")]
            {
                "/usr/local/etc/foundationdb/fdb.cluster".to_owned()
            }
            #[cfg(target_os = "linux")]
            {
                "/etc/foundationdb/fdb.cluster".to_owned()
            }
        });

        if !std::path::Path::new(&cluster).exists() {
            return None;
        }

        crate::database::fdb::test_shared::fdb_test_network_start().ok()?;

        let pool = FDBPool::new(cluster, NonZeroU64::new(4).unwrap()).ok()?;

        Some(pool)
    }
}

#[test]
fn ttl_key_round_trips_keys_with_slashes() {
    let ns = b"test_ns";
    let key = b"a/b/c";
    let bucket = 123_000;

    let ttl_key = k_ttl_for(ns, bucket, key);
    let data_key = data_key_from_ttl_key(ns, bucket, &ttl_key).expect("valid ttl key");

    assert_eq!(data_key, k_data_for(ns, key));
}

#[test]
fn ttl_key_round_trips_keys_starting_with_ff() {
    let ns = b"test_ns";
    let key = [0xFF, b'a', b'/', b'z'];
    let bucket = 456_000;

    let ttl_key = k_ttl_for(ns, bucket, &key);
    let data_key = data_key_from_ttl_key(ns, bucket, &ttl_key).expect("valid ttl key");

    assert_eq!(data_key, k_data_for(ns, &key));
}

#[test]
fn bucket_prefix_range_covers_ff_prefixed_user_keys() {
    let ns = b"test_ns";
    let bucket = 789_000;
    let key = [0xFF, b'a'];

    let (start, end) = pfx_bucket_for(ns, bucket).expect("finite prefix end");
    let ttl_key = k_ttl_for(ns, bucket, &key);

    assert!(ttl_key.as_slice() >= start.as_slice());
    assert!(ttl_key.as_slice() < end.as_slice());
}

#[test]
fn ttl_key_parser_rejects_wrong_bucket_and_malformed_lengths() {
    let ns = b"test_ns";
    let bucket = 123_000;
    let ttl_key = k_ttl_for(ns, bucket, b"key");

    assert!(data_key_from_ttl_key(ns, bucket + 1, &ttl_key).is_none());

    let mut malformed = ttl_key;
    malformed.truncate(malformed.len() - 1);
    assert!(data_key_from_ttl_key(ns, bucket, &malformed).is_none());
}

#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn cache_set_get_lazy_expire_and_gc() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
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
}

#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn cache_delete_removes_row() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
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
}

#[cfg(feature = "rt-may")]
#[test]
fn cache_set_get_lazy_expire_and_gc() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
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
}

#[cfg(feature = "rt-may")]
#[test]
fn cache_delete_removes_row() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
        return;
    };
    let cache = BucketTtlCache::new(pool.clone(), "test_delete");

    cache
        .set(b"delkey", b"val", Duration::from_secs(5))
        .expect("set");
    assert!(cache.get(b"delkey").expect("get").is_some());

    cache.delete(b"delkey").expect("delete");
    assert!(cache.get(b"delkey").expect("get after delete").is_none());
}

// --- Native-async coverage (tokio) ----------------------------------------------
//
// These exercise the callback-driven `FDBFuture` path (no spawn_blocking): many
// in-flight futures at once, and futures dropped mid-flight.

/// Many concurrent set/get on a shared cache. The FDB completion callbacks fire on
/// the FDB network thread and must wake many tokio tasks in parallel — this is what
/// native async buys over the old one-thread-per-op `spawn_blocking`.
#[cfg(feature = "rt-tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_concurrent_async_ops() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
        return;
    };
    let cache = BucketTtlCache::new(pool, "test_concurrent");

    let mut writers = Vec::new();
    for i in 0..64u32 {
        let c = cache.clone();
        writers.push(tokio::spawn(async move {
            let k = format!("ck{i}");
            let v = format!("cv{i}");
            c.set(k.as_bytes(), v.as_bytes(), Duration::from_secs(30))
                .await
                .expect("concurrent set");
        }));
    }
    for w in writers {
        w.await.expect("writer task");
    }

    let mut readers = Vec::new();
    for i in 0..64u32 {
        let c = cache.clone();
        readers.push(tokio::spawn(async move {
            let k = format!("ck{i}");
            let want = format!("cv{i}");
            let got = c.get(k.as_bytes()).await.expect("concurrent get");
            assert_eq!(got.as_deref(), Some(want.as_bytes()));
        }));
    }
    for r in readers {
        r.await.expect("reader task");
    }

    for i in 0..64u32 {
        let k = format!("ck{i}");
        cache.delete(k.as_bytes()).await.expect("cleanup delete");
    }
}

/// Drop `get` futures while they are still pending, then keep using the cache. This
/// stresses the drop-while-pending path: the FDB callback may fire after the `Ready`
/// future and its `FDBFuture` have been dropped. It must never crash or corrupt state.
#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn cache_async_op_is_cancel_safe() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
        return;
    };
    let cache = BucketTtlCache::new(pool, "test_cancel");
    cache
        .set(b"cx", b"cy", Duration::from_secs(30))
        .await
        .expect("set");

    // A 1ns timeout almost always fires before the FDB round-trip completes, so the
    // `get` future is dropped mid-flight.
    for _ in 0..256 {
        let fut = cache.get(b"cx");
        let _ = tokio::time::timeout(Duration::from_nanos(1), fut).await;
    }

    // The cache must still be fully usable.
    let v = cache.get(b"cx").await.expect("get after cancels");
    assert_eq!(v.as_deref(), Some(&b"cy"[..]));
    cache.delete(b"cx").await.expect("cleanup");
}

// --- Native-async coverage (glommio) --------------------------------------------
//
// Runs the same async cache ops on glommio's thread-per-core reactor, validating
// that FDB callbacks waking a glommio task from the FDB network thread work.

#[cfg(feature = "rt-glommio")]
#[test]
fn cache_async_roundtrip_glommio() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
        return;
    };
    glommio::LocalExecutor::default().run(async move {
        let cache = BucketTtlCache::new(pool, "test_glommio");
        cache
            .set(b"gk", b"gv", Duration::from_secs(30))
            .await
            .expect("set");
        let v = cache.get(b"gk").await.expect("get");
        assert_eq!(v.as_deref(), Some(&b"gv"[..]));
        cache.delete(b"gk").await.expect("delete");
        assert!(cache.get(b"gk").await.expect("get after delete").is_none());
    });
}

#[cfg(feature = "rt-glommio")]
#[test]
fn cache_gc_glommio() {
    let Some(pool) = start_network_and_pool() else {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but no usable cluster was found");
        }
        return;
    };
    glommio::LocalExecutor::default().run(async move {
        let mut cache = BucketTtlCache::new(pool, "test_glommio_gc");
        cache.bucket_ms = 200;
        cache.lazy_expiration_ms = 400;
        cache.gc_batch = 512;

        for i in 0..8u8 {
            let k = [b'g', i];
            let val = [b'v', i];
            cache
                .set(&k, &val, Duration::from_millis(150))
                .await
                .expect("set batch");
        }

        glommio::timer::sleep(Duration::from_millis(700)).await;

        let cleaned = cache.gc_once().await.expect("gc_once");
        assert!(cleaned, "expected to clean one expired bucket");

        for i in 0..8u8 {
            let k = [b'g', i];
            let v = cache.get(&k).await.expect("get after gc");
            assert!(v.is_none(), "post-GC value should be None for key {:?}", k);
        }
    });
}
