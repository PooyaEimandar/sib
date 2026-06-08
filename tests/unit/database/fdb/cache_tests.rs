use super::*;
use crate::database::fdb::network::FDBNetwork;
use crate::database::fdb::pool::FDBPool;
use std::{num::NonZeroU64, thread, time::Duration};

/// Start the FDB network.
fn start_network_and_pool() -> Option<(thread::JoinHandle<()>, FDBNetwork, FDBPool)> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return None;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        let cluster = "/usr/local/etc/foundationdb/fdb.cluster";

        #[cfg(target_os = "linux")]
        let cluster = "/etc/foundationdb/fdb.cluster";

        if !std::path::Path::new(cluster).exists() {
            return None;
        }

        let net = FDBNetwork::new(None).ok()?;

        // Spawn run() in background (blocking call)
        let net_clone = net.clone();
        let handle = thread::spawn(move || {
            let _ = net_clone.run();
        });

        // Give network a moment to start
        thread::sleep(Duration::from_millis(200));

        let pool = FDBPool::new(cluster.to_owned(), NonZeroU64::new(4).unwrap()).ok()?;

        Some((handle, net, pool))
    }
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
