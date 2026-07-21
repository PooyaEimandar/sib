use foundationdb_sys::{
    FDB_future, fdb_future_block_until_ready, fdb_future_cancel, fdb_future_get_error,
    fdb_future_get_value, fdb_future_is_ready, fdb_future_release_memory,
};
use std::os::raw::c_int;
use std::ptr;

pub struct FDBFuture {
    pub fut: *mut FDB_future,
}

// SAFETY: FoundationDB futures are reference-counted client objects whose C API
// supports waiting, cancellation, and destruction from arbitrary client threads.
// The wrapper owns exactly one future pointer and only exposes operations that
// delegate to the FoundationDB C API.
unsafe impl Send for FDBFuture {}
// SAFETY: Shared references only allow C API operations that FoundationDB
// documents as safe on a future handle; mutation-like operations require
// `&mut self`.
unsafe impl Sync for FDBFuture {}

impl FDBFuture {
    pub fn new(fut: *mut FDB_future) -> std::io::Result<Self> {
        if fut.is_null() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Failed to create FDBFuture: null pointer",
            ))
        } else {
            Ok(Self { fut })
        }
    }

    pub fn from_raw(fut: *mut FDB_future) -> Self {
        Self { fut }
    }

    pub fn is_ready(&self) -> bool {
        if self.fut.is_null() {
            return false;
        }
        unsafe { fdb_future_is_ready(self.fut) != 0 }
    }

    pub fn block_until_ready(&self) {
        if !self.fut.is_null() {
            unsafe {
                fdb_future_block_until_ready(self.fut);
            }
        }
    }

    pub fn get_error_code(&self) -> i32 {
        unsafe { fdb_future_get_error(self.fut) }
    }

    pub fn get_value(&self) -> std::io::Result<&[u8]> {
        if self.fut.is_null() {
            return Err(std::io::Error::other("null future"));
        }

        let mut present = 0;
        let mut val_ptr: *const u8 = ptr::null();
        let mut len: c_int = 0;

        let err = unsafe { fdb_future_get_value(self.fut, &mut present, &mut val_ptr, &mut len) };
        if err != 0 {
            return Err(std::io::Error::from_raw_os_error(err));
        }

        if present == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Value not present",
            ));
        }

        Ok(unsafe { std::slice::from_raw_parts(val_ptr, len as usize) })
    }

    pub fn cancel(&mut self) {
        if !self.fut.is_null() {
            unsafe {
                fdb_future_cancel(self.fut);
            }
        }
    }

    pub fn release_memory(&mut self) {
        if !self.fut.is_null() {
            unsafe {
                fdb_future_release_memory(self.fut);
            }
        }
    }
}

impl Drop for FDBFuture {
    fn drop(&mut self) {
        if self.fut.is_null() {
            return;
        }
        unsafe {
            foundationdb_sys::fdb_future_destroy(self.fut);
        }
    }
}

// --- Native async readiness (tokio + glommio) -----------------------------------
//
// Instead of parking a thread in `block_until_ready`, register a completion callback
// with FoundationDB (`fdb_future_set_callback`) and wake the async task when the
// future resolves. This drives both the tokio and glommio executors because it only
// relies on the standard `Waker` contract. The `may` (coroutine) runtime keeps using
// the blocking path above.
#[cfg(any(feature = "rt-tokio", feature = "rt-glommio"))]
mod ready {
    use super::FDBFuture;
    use foundationdb_sys::{FDBFuture as FDBFutureRaw, fdb_future_set_callback};
    use std::future::Future;
    use std::os::raw::c_void;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    /// The slot the C callback wakes. Held behind an `Arc`: one strong ref lives in
    /// the `Ready` future and one is handed to the C side, reclaimed exactly once when
    /// the callback fires. Because the callback only touches this cell (never the FDB
    /// future pointer), it is memory-safe regardless of whether the `Ready` future or
    /// the underlying `FDBFuture` was already dropped.
    struct WakerCell(Mutex<Option<Waker>>);

    impl WakerCell {
        fn register(&self, w: &Waker) {
            let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
            match &*slot {
                Some(existing) if existing.will_wake(w) => {}
                _ => *slot = Some(w.clone()),
            }
        }

        fn wake(&self) {
            let waker = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(w) = waker {
                w.wake();
            }
        }
    }

    /// Future that resolves once the underlying `FDBFuture` is ready. It borrows the
    /// future, so the handle always outlives this waiter.
    pub struct Ready<'a> {
        fut: &'a FDBFuture,
        cell: Option<Arc<WakerCell>>,
    }

    impl FDBFuture {
        /// Await readiness without blocking a thread. Use on the tokio/glommio paths;
        /// `may` uses `block_until_ready`.
        #[inline]
        pub fn ready(&self) -> Ready<'_> {
            Ready {
                fut: self,
                cell: None,
            }
        }
    }

    impl<'a> Future for Ready<'a> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            if this.fut.is_ready() {
                return Poll::Ready(());
            }

            match &this.cell {
                // Callback already registered — just refresh the stored waker, then
                // re-check readiness to close the register/wake race.
                Some(cell) => {
                    cell.register(cx.waker());
                    if this.fut.is_ready() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }
                None => {
                    let cell = Arc::new(WakerCell(Mutex::new(Some(cx.waker().clone()))));
                    // Hand one strong ref to FDB; `on_ready` reclaims it when it fires.
                    let raw = Arc::into_raw(Arc::clone(&cell));
                    let rc = unsafe {
                        fdb_future_set_callback(this.fut.fut, Some(on_ready), raw as *mut c_void)
                    };
                    if rc != 0 {
                        // Registration failed: reclaim our ref and report ready so the
                        // caller observes the error via `get_error_code()`.
                        drop(unsafe { Arc::from_raw(raw) });
                        return Poll::Ready(());
                    }
                    this.cell = Some(cell);
                    // The callback may have fired between set_callback and here.
                    if this.fut.is_ready() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }
            }
        }
    }

    /// FoundationDB guarantees this fires exactly once for a registered callback.
    /// Reclaim the strong ref handed to C in `poll` and wake the task. Never unwind
    /// across the FFI boundary.
    unsafe extern "C" fn on_ready(_f: *mut FDBFutureRaw, param: *mut c_void) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: `param` is the pointer produced by `Arc::into_raw` in `poll`,
            // handed to exactly this callback, which runs exactly once.
            let cell = unsafe { Arc::from_raw(param as *const WakerCell) };
            cell.wake();
        }));
    }
}
