use std::cell::RefCell;

thread_local! {
    static TL_DATE: RefCell<(u64, String)> = RefCell::new((0, String::with_capacity(64)));
}

use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

/// Current UNIX time in seconds, updated once per second.
/// Read by every request, written by exactly one coroutine.
static NOW_SEC: Lazy<AtomicU64> = Lazy::new(|| {
    AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
});

/// Start the background ticker that updates NOW_SEC.
/// MUST be called exactly once at program startup.
pub(crate) fn start_date_ticker() {
    // spawn a single coroutine
    may::go!(|| {
        loop {
            // align to next second boundary
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            let sleep_ms = 1_000u64.saturating_sub(now.subsec_millis() as u64);
            may::coroutine::sleep(std::time::Duration::from_millis(sleep_ms));

            let sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Relaxed is correct: we only need monotonic-ish visibility
            NOW_SEC.store(sec, Ordering::Relaxed);
        }
    });
}

#[inline]
pub fn current_date_str() -> &'static str {
    // Return a &'static str by leaking a pointer to thread-local storage.
    TL_DATE.with(|cell| {
        let now = NOW_SEC.load(std::sync::atomic::Ordering::Relaxed);

        let mut slot = cell.borrow_mut();
        if slot.0 != now {
            slot.0 = now;

            // Format RFC 7231 HTTP-date using the httpdate crate, which is optimized for this purpose.
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(now);
            slot.1.clear();
            slot.1.push_str(&httpdate::HttpDate::from(t).to_string());
        }

        // SAFETY: The returned reference points into thread-local storage that will not
        // be moved while the thread is alive, and callers must not store it across threads.
        let s: &str = &slot.1;
        unsafe { std::mem::transmute::<&str, &'static str>(s) }
    })
}
