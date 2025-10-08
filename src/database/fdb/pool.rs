use crossbeam::queue::ArrayQueue;
use std::{cell::UnsafeCell, fmt, num::NonZeroU64, sync::Arc, time::Duration};

#[cfg(feature = "rt-tokio")]
use tokio::{sync::Notify, time};

#[cfg(feature = "rt-may")]
use may::coroutine;

/// Your FDB handle type (adapt the path to your project)
use crate::database::fdb::db::FDB;

/// Internal storage: fixed slots + free-list of indices
struct PoolInner<T> {
    slots: Box<[UnsafeCell<T>]>,
    freelist: ArrayQueue<usize>,
    #[cfg(feature = "rt-tokio")]
    notify: Notify, // wake async waiters
}

unsafe impl<T: Send> Send for PoolInner<T> {}
unsafe impl<T: Send> Sync for PoolInner<T> {}

/// Zero-copy guard
pub struct Loan<'a, T> {
    inner: &'a PoolInner<T>,
    idx: usize,
}

impl<'a, T> Loan<'a, T> {
    #[inline]
    fn get_mut(&mut self) -> &mut T {
        // SAFETY: unique access guaranteed by free-list protocol
        unsafe { &mut *self.inner.slots[self.idx].get() }
    }
}
impl<'a, T> std::ops::Deref for Loan<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: unique access while loan is alive, but here shared ref is fine
        unsafe { &*self.inner.slots[self.idx].get() }
    }
}
impl<'a, T> std::ops::DerefMut for Loan<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}
impl<'a, T> Drop for Loan<'a, T> {
    fn drop(&mut self) {
        // Return index to freelist and notify any waiters.
        // This should never fail (queue capacity == slots.len()).
        let pushed = self.inner.freelist.push(self.idx).is_ok();
        debug_assert!(pushed, "freelist push should never fail");

        #[cfg(feature = "rt-tokio")]
        self.inner.notify.notify_one();
    }
}

impl<'a, T> fmt::Debug for Loan<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loan").field("idx", &self.idx).finish()
    }
}

/// The pool itself (generic)
#[derive(Clone)]
pub struct Pool<T> {
    inner: Arc<PoolInner<T>>,
}

impl<T> Pool<T> {
    /// Build a pool with size
    pub fn new_with<F>(size: NonZeroU64, mut init: F) -> std::io::Result<Self>
    where
        F: FnMut(usize) -> std::io::Result<T>,
    {
        let n = size.get() as usize;
        // init slots
        let mut vec = Vec::with_capacity(n);
        for i in 0..n {
            vec.push(UnsafeCell::new(init(i)?));
        }
        let slots = vec.into_boxed_slice();

        // free-list initially contains all indices
        let freelist = ArrayQueue::new(n);
        for i in 0..n {
            // capacity is exactly n; this cannot fail
            freelist.push(i).unwrap();
        }

        Ok(Self {
            inner: Arc::new(PoolInner {
                slots,
                freelist,
                #[cfg(feature = "rt-tokio")]
                notify: Notify::new(),
            }),
        })
    }

    /// Try to acquire immediately (non-blocking). Returns `None` if empty.
    #[inline]
    pub fn try_acquire(&self) -> Option<Loan<'_, T>> {
        self.inner.freelist.pop().map(|idx| Loan {
            inner: &self.inner,
            idx,
        })
    }

    /// Blocking acquire with timeout
    #[cfg(feature = "rt-may")]
    pub fn acquire_blocking(&self, timeout: Duration) -> std::io::Result<Loan<'_, T>> {
        if let Some(loan) = self.try_acquire() {
            return Ok(loan);
        }
        let start = std::time::Instant::now();
        // exponential backoff in microseconds
        let mut backoff = 10u64; // μs
        loop {
            if let Some(loan) = self.try_acquire() {
                return Ok(loan);
            }
            if start.elapsed() >= timeout {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "FDB pool acquire (may) got timed out",
                ));
            }
            // yield/sleep cooperatively
            coroutine::yield_now();
            // short sleep after a few spins
            if backoff < 2000 {
                coroutine::sleep(Duration::from_micros(backoff));
                backoff = (backoff * 2).min(2000);
            }
        }
    }

    /// Async acquire with timeout (using Notify)
    #[cfg(feature = "rt-tokio")]
    pub async fn acquire(&self, timeout: Duration) -> std::io::Result<Loan<'_, T>> {
        // Fast path
        if let Some(loan) = self.try_acquire() {
            return Ok(loan);
        }

        // Wait loop with Notify
        let fut = async {
            loop {
                // wait until someone returns an index
                self.inner.notify.notified().await;
                if let Some(loan) = self.try_acquire() {
                    return Ok(loan);
                }
                // spurious wake or contention: loop again
            }
        };

        match time::timeout(timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "FDB pool acquire (may) got timed out",
            )),
        }
    }
}

/// FDB pool wrapper
#[derive(Clone)]
pub struct FDBPool {
    pool: Pool<FDB>,
}

impl FDBPool {
    /// Build an FDB pool by opening `pool_size` FDB handles up-front.
    pub fn new(cluster_path: String, pool_size: NonZeroU64) -> std::io::Result<Self> {
        let pool = Pool::new_with(pool_size, |_i| {
            // Open one FDB handle per slot
            FDB::new(&cluster_path)
        })?;
        Ok(Self { pool })
    }

    /// Non-blocking try-acquire. Returns None if pool is empty.
    pub fn try_loan(&self) -> Option<Loan<'_, FDB>> {
        self.pool.try_acquire()
    }

    /// blocking loan with timeout
    #[cfg(feature = "rt-may")]
    pub fn loan_blocking(&self, timeout: Duration) -> std::io::Result<Loan<'_, FDB>> {
        self.pool.acquire_blocking(timeout)
    }

    /// async loan with timeout
    #[cfg(feature = "rt-tokio")]
    pub async fn loan(&self, timeout: Duration) -> std::io::Result<Loan<'_, FDB>> {
        self.pool.acquire(timeout).await
    }

    /// loan fdb connection (immutable)
    #[cfg(feature = "rt-may")]
    pub fn with_loan<R, F: FnOnce(&FDB) -> R>(
        &self,
        timeout: Duration,
        f: F,
    ) -> std::io::Result<R> {
        let loan = self.loan_blocking(timeout)?;
        Ok(f(&*loan))
    }

    /// loan fdb connection (mutable)
    #[cfg(feature = "rt-may")]
    pub fn with_loan_mut<R, F: FnOnce(&mut FDB) -> R>(
        &self,
        timeout: Duration,
        f: F,
    ) -> std::io::Result<R> {
        let mut loan = self.loan_blocking(timeout)?;
        Ok(f(&mut *loan))
    }

    /// Async loan with timeout (immutable)
    #[cfg(feature = "rt-tokio")]
    pub async fn with_loan_async<R, Fut, F>(&self, timeout: Duration, f: F) -> std::io::Result<R>
    where
        F: for<'a> FnOnce(&'a FDB) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let loan = self.loan(timeout).await?;
        Ok(f(&*loan).await)
    }

    /// Async loan with timeout (mutable)
    #[cfg(feature = "rt-tokio")]
    pub async fn with_loan_mut_async<R, Fut, F>(
        &self,
        timeout: Duration,
        f: F,
    ) -> std::io::Result<R>
    where
        F: for<'a> FnOnce(&'a mut FDB) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let mut loan = self.loan(timeout).await?;
        Ok(f(&mut *loan).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    #[test]
    fn test_fdb_pool_acquire_and_release() {
        // pool of 3 integers initialized to 10, 20, 30
        let pool =
            Pool::new_with(NonZeroU64::new(3).unwrap(), |i| Ok((i as u32 + 1) * 10)).unwrap();

        // take all three
        let l1 = pool.try_acquire().expect("slot 1");
        let l2 = pool.try_acquire().expect("slot 2");
        let l3 = pool.try_acquire().expect("slot 3");

        // now empty
        assert!(pool.try_acquire().is_none(), "pool should be empty");

        // drop one, should be able to acquire again
        drop(l2);
        let l4 = pool.try_acquire().expect("slot after release");
        // value must be one of the initial values
        let v = *l4;
        assert!([10, 20, 30].contains(&v));
        drop(l1);
        drop(l3);
        drop(l4);

        // After returning all, we can acquire 3 again
        let _a = pool.try_acquire().unwrap();
        let _b = pool.try_acquire().unwrap();
        let _c = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn test_zero_copy_mutation() {
        #[derive(Debug, Clone, Copy)]
        struct Item(u64);

        let pool = Pool::new_with(NonZeroU64::new(2).unwrap(), |_i| Ok(Item(0))).unwrap();

        // Acquire both, mutate through &mut Loan to ensure zero-copy uniqueness works.
        let mut a = pool.try_acquire().expect("a");
        let mut b = pool.try_acquire().expect("b");

        a.0 += 5;
        b.0 += 7;
        assert_eq!(a.0, 5);
        assert_eq!(b.0, 7);

        // Release both and reacquire to verify persisted mutation in-place.
        drop(a);
        drop(b);

        // Drain pool and sum values regardless of order.
        let x = pool.try_acquire().unwrap().0;
        let y = pool.try_acquire().unwrap().0;
        assert_eq!(x + y, 12, "mutations must persist in the same slots");
    }

    #[cfg(feature = "rt-may")]
    #[test]
    fn test_fdb_pool_concurrent_acquire_and_increment() {
        #[derive(Default)]
        struct Counter {
            hits: u64,
        }

        let pool = std::sync::Arc::new(
            Pool::new_with(NonZeroU64::new(3).unwrap(), |_i| Ok(Counter::default())).unwrap(),
        );

        // Spawn 30 coroutines; each increments once.
        let jobs = 30usize;
        let mut hs = Vec::new();
        for _ in 0..jobs {
            let pool = pool.clone();
            hs.push(unsafe {
                may::coroutine::spawn(move || {
                    // SAFETY: The pool's free-list protocol guarantees unique access.
                    let mut loan = pool
                        .acquire_blocking(Duration::from_millis(200))
                        .expect("acquire");
                    loan.hits += 1;
                    // drop -> return to freelist
                })
            });
        }
        for h in hs {
            h.join().unwrap();
        }

        // Drain and sum
        let mut total = 0u64;
        for _ in 0..3 {
            let l = pool.try_acquire().expect("slot back after tasks");
            total += l.hits;
        }
        assert_eq!(total, jobs as u64);
    }

    #[cfg(feature = "rt-tokio")]
    #[tokio::test]
    async fn test_fdb_pool_concurrent_acquire_and_increment() {
        // Each slot holds a small counter struct.
        #[derive(Default)]
        struct Counter {
            hits: u64,
        }

        let pool = std::sync::Arc::new(
            Pool::new_with(NonZeroU64::new(4).unwrap(), |_i| Ok(Counter::default())).unwrap(),
        );

        // 64 tasks, each acquires a slot, increments the counter once, and releases.
        let tasks = 64usize;
        let mut joins = Vec::new();
        for _ in 0..tasks {
            let p = pool.clone();
            joins.push(tokio::spawn(async move {
                let mut loan = p
                    .acquire(Duration::from_millis(200))
                    .await
                    .expect("acquire should succeed");
                loan.hits += 1;
            }));
        }
        for j in joins {
            j.await.unwrap();
        }

        // Drain all 4 slots and sum their hits; should equal 64.
        let mut total = 0u64;
        for _ in 0..4 {
            let l = pool.try_acquire().expect("slot back after tasks");
            total += l.hits;
        }
        assert_eq!(total, 64);
    }

    #[cfg(feature = "rt-may")]
    #[test]
    fn test_fdb_pool_timeout_when_all_held() {
        let pool = Pool::new_with(NonZeroU64::new(1).unwrap(), |_| Ok(123u32)).unwrap();

        let _ = pool.try_acquire().expect("first acquire");
        let start = std::time::Instant::now();
        let res = pool.acquire_blocking(Duration::from_millis(50));
        assert!(res.is_err(), "expected timeout");
        assert!(start.elapsed() >= Duration::from_millis(45));
    }

    #[cfg(feature = "rt-tokio")]
    #[tokio::test]
    async fn test_fdb_pool_timeout_when_all_held() {
        use std::time::Instant;
        // Pool of size 1; hold it and try to acquire with a short timeout.
        let pool = Pool::new_with(NonZeroU64::new(1).unwrap(), |_| Ok(())).unwrap();

        let loan = pool.try_acquire().expect("first acquire");
        let start = Instant::now();

        let res = pool.acquire(Duration::from_millis(50)).await;
        assert!(res.is_err(), "should time out");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(45),
            "timeout should approximate requested duration"
        );

        drop(loan);
    }
}
