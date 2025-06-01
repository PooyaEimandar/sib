use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use std::sync::Arc;

// "Sun, 06 Nov 1994 08:49:37 GMT".len() == 29
pub const DATE_VALUE_LENGTH: usize = 29;

pub static CURRENT_DATE: Lazy<Arc<ArcSwap<Arc<str>>>> = Lazy::new(|| {
    let now = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
    let swap = Arc::new(ArcSwap::from_pointee(Arc::from(now.into_boxed_str())));

    let swap_clone = Arc::clone(&swap);
    may::go!(move || loop {
        let now = std::time::SystemTime::now();
        let subsec = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_millis();
        let delay = 1_000u64.saturating_sub(subsec as u64);
        may::coroutine::sleep(std::time::Duration::from_millis(delay));

        let new_date = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
        swap_clone.store(Arc::<str>::from(new_date.into_boxed_str()).into());
    });

    swap
});
