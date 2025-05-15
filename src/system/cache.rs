use arc_swap::ArcSwap;
use dashmap::DashSet;
use moka::future::Cache;
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::s_info;

pub struct SCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    keys: DashSet<K>,
    hits: AtomicU64,
    misses: AtomicU64,
    cache: ArcSwap<Cache<K, V>>,
    size: u64,
}

impl<K, V> SCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(size: u64) -> Self {
        let cache = Cache::builder().max_capacity(size).build();
        Self {
            keys: DashSet::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            cache: ArcSwap::from(Arc::new(cache)),
            size,
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub async fn get<F, Fut>(&self, key: &K, factory: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = V>,
    {
        let cache = self.cache.load();

        if let Some(data) = cache.get(key).await {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return data;
        }

        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let data = factory().await;
        self.set(key.clone(), data.clone()).await;
        data
    }

    pub async fn try_get(&self, key: &K) -> Option<V> {
        let cache = self.cache.load();

        if let Some(data) = cache.get(key).await {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(data);
        }

        None
    }

    pub async fn set(&self, key: K, value: V) {
        self.keys.insert(key.clone());
        self.cache.load().insert(key, value).await;
    }

    pub async fn remove(&self, key: &K) {
        self.keys.remove(key);
        self.cache.load().remove(key).await;
    }

    pub async fn contains(&self, key: &K) -> bool {
        self.keys.contains(key)
    }

    /// Atomically resize the cache while preserving existing entries
    async fn resize_cache(&mut self, new_capacity: u64) {
        let current_cache = self.cache.load();

        // Snapshot existing entries
        let mut snapshot = HashMap::new();
        for key in self.keys.iter() {
            if let Some(value) = current_cache.get(&key).await {
                snapshot.insert((*key).clone(), value.clone());
            }
        }

        // Build a new cache from the snapshot
        let new_cache = Arc::new(Cache::builder().max_capacity(new_capacity).build());
        for (key, value) in snapshot {
            new_cache.insert(key, value).await;
        }

        // atomically swap the cache
        self.size = new_capacity;
        self.cache.store(new_cache);
    }

    /// Check if the cache needs to be resized based on hit/miss ratio
    pub async fn check_for_resize(&mut self) {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;

        let hit_rate = if total == 0 {
            1.0
        } else {
            hits as f64 / total as f64
        };

        if hit_rate < 0.8 && misses > 100 {
            // resize the cache if the hit rate is low
            let current_cap = self.cache.load().entry_count();
            let new_cap = (current_cap as f64 * 1.5).ceil() as u64;

            s_info!(
                "Low cache hit ratio: {:.2}, resizing to {}",
                hit_rate,
                new_cap
            );

            self.resize_cache(new_cap).await;

            // Reset counters if you want fresh measurements
            self.hits.store(0, Ordering::Relaxed);
            self.misses.store(0, Ordering::Relaxed);
        }
    }
}

#[tokio::test]
async fn test_cache_insert_and_get() {
    let cache = SCache::<String, u32>::new(10);

    // Initially missing
    let key = "a".to_string();
    let value = cache.get(&key, || async { 42 }).await;
    assert_eq!(value, 42);

    // Should hit the cache now
    let value = cache.try_get(&key).await;
    assert_eq!(value, Some(42));

    // Should hit the cache now
    let value = cache.get(&key, || async { 99 }).await;
    assert_eq!(value, 42);
}

#[tokio::test]
async fn test_cache_hit_and_miss_tracking() {
    let cache = SCache::<String, u32>::new(5);

    let key = "a".to_string();

    // Miss
    cache.get(&key, || async { 1 }).await;

    // Hit
    cache.get(&key, || async { 2 }).await;

    assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
    assert_eq!(cache.misses.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_cache_resize_logic() {
    let mut cache = SCache::<String, u32>::new(2);

    // Trigger enough misses to force resize
    for i in 0..110 {
        let key = format!("k{}", i);
        cache.get(&key, || async { i }).await;
    }

    cache.check_for_resize().await;

    // after resize, new capacity should be larger than initial
    assert!(cache.size() > 2);
}

#[tokio::test]
async fn test_cache_removal() {
    let key = "delete-me".to_string();
    let cache = SCache::<String, u32>::new(10);
    cache.get(&key, || async { 10 }).await;
    assert!(cache.contains(&key).await);
    cache.remove(&key).await;
    assert!(!cache.contains(&key).await);
}

#[tokio::test]
async fn test_parallel_gets() {
    let cache = Arc::new(SCache::<String, u32>::new(100));

    let mut tasks = Vec::new();
    for i in 0..20 {
        let cache = Arc::clone(&cache);
        tasks.push(tokio::spawn(async move {
            let key = format!("user:{}", i % 5); // intentionally cause overlap
            let val = cache.get(&key, || async { i as u32 }).await;
            val
        }));
    }

    let results = futures::future::join_all(tasks).await;
    for r in results {
        assert!(r.is_ok());
    }

    let hit_count = cache.hits.load(Ordering::Relaxed);
    assert!(hit_count > 0); // At least some overlap
}
