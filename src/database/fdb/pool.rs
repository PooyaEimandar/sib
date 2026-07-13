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

// SAFETY: sending the pool to another thread moves the owned `T`s, so `T: Send`.
unsafe impl<T: Send> Send for PoolInner<T> {}
// SAFETY: sharing `&PoolInner` lets threads concurrently acquire distinct loans
unsafe impl<T: Send + Sync> Sync for PoolInner<T> {}

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
struct Pool<T> {
    inner: Arc<PoolInner<T>>,
}

// Manual `Clone`: the pool is just a shared handle (`Arc`), so cloning bumps the
// refcount and does not require `T: Clone`.
impl<T> Clone for Pool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Pool<T> {
    /// Build a pool with size
    fn new_with<F>(size: NonZeroU64, mut init: F) -> std::io::Result<Self>
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
    fn try_acquire(&self) -> Option<Loan<'_, T>> {
        self.inner.freelist.pop().map(|idx| Loan {
            inner: &self.inner,
            idx,
        })
    }

    /// Blocking acquire with timeout
    #[cfg(feature = "rt-may")]
    fn acquire_blocking(&self, timeout: Duration) -> std::io::Result<Loan<'_, T>> {
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
    async fn acquire(&self, timeout: Duration) -> std::io::Result<Loan<'_, T>> {
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
                "FDB pool acquire (tokio) got timed out",
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
        Ok(f(&loan))
    }

    /// loan fdb connection (mutable)
    #[cfg(feature = "rt-may")]
    pub fn with_loan_mut<R, F: FnOnce(&mut FDB) -> R>(
        &self,
        timeout: Duration,
        f: F,
    ) -> std::io::Result<R> {
        let mut loan = self.loan_blocking(timeout)?;
        Ok(f(&mut loan))
    }

    /// Async loan with timeout (immutable)
    #[cfg(feature = "rt-tokio")]
    pub async fn with_loan_async<R, Fut, F>(&self, timeout: Duration, f: F) -> std::io::Result<R>
    where
        F: for<'a> FnOnce(&'a FDB) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let loan = self.loan(timeout).await?;
        Ok(f(&loan).await)
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
        Ok(f(&mut loan).await)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/database/fdb/pool_tests.rs"]
mod tests;
