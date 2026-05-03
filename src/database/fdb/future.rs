use foundationdb_sys::{
    FDB_future, fdb_future_block_until_ready, fdb_future_cancel, fdb_future_get_error,
    fdb_future_get_value, fdb_future_is_ready, fdb_future_release_memory,
};
use std::os::raw::c_int;
use std::ptr;

pub struct FDBFuture {
    pub fut: *mut FDB_future,
}

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

    pub async fn await_until_ready(&self) -> std::io::Result<()> {
        FDBFutureAwaitUntilReady::new(self).await
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

struct FDBFutureAwaitUntilReady<'a> {
    fut: &'a FDBFuture,
    waker: Option<Arc<AtomicWaker>>,
}

impl<'a> FDBFutureAwaitUntilReady<'a> {
    fn new(fut: &'a FDBFuture) -> Self {
        Self { fut, waker: None }
    }
}

impl<'a> std::future::Future for FDBFutureAwaitUntilReady<'a> {
    type Output = std::io::Result<()>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let ready = unsafe { foundationdb_sys::fdb_future_is_ready(self.fut.fut) };
        if ready == 0 {
            let mut register = false;
            let waker = self.waker.get_or_insert_with(|| {
                register = true;
                Arc::new(AtomicWaker::new())
            });
            waker.register(cx.waker());
            if register {
                let waker = waker.clone();
                let waker_ptr = Arc::into_raw(waker);

                extern "C" fn fdb_future_callback(
                    _: *mut foundationdb_sys::FDBFuture,
                    callback_parameter: *mut ::std::os::raw::c_void,
                ) {
                    let waker: Arc<AtomicWaker> =
                        unsafe { Arc::from_raw(callback_parameter as *const _) };
                    waker.wake();
                }

                unsafe {
                    foundationdb_sys::fdb_future_set_callback(
                        self.fut.fut,
                        Some(fdb_future_callback),
                        waker_ptr as *mut _,
                    );
                }
            }
            std::task::Poll::Pending
        } else {
            let fdb_err = unsafe { foundationdb_sys::fdb_future_get_error(self.fut.fut) };
            if fdb_err != 0 {
                std::task::Poll::Ready(Err(fdb_error(fdb_err)))
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        }
    }
}
