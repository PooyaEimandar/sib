use arc_swap::ArcSwap;
use bytes::BytesMut;
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

pub fn append_date(dst: &mut BytesMut) {
    let date = CURRENT_DATE.load();
    dst.extend_from_slice(date.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str;

    #[test]
    fn test_append_date_to_buffer_is_correct_and_utf8() {
        let mut buf = BytesMut::with_capacity(DATE_VALUE_LENGTH);

        // Call the function under test
        append_date(&mut buf);

        let date_str = str::from_utf8(buf.as_ref()).expect("Buffer is not valid UTF-8");

        // Basic length and formatting checks
        assert_eq!(
            buf.len(),
            DATE_VALUE_LENGTH,
            "Expected exact length of {}, got {}",
            DATE_VALUE_LENGTH,
            buf.len()
        );

        assert!(
            date_str.ends_with("GMT"),
            "Expected date to end with 'GMT', got '{}'",
            date_str
        );

        // Check that it parses back into a SystemTime
        let parsed = httpdate::parse_http_date(date_str)
            .expect("Parsed date string should be a valid HTTP date");
        let _ = parsed.duration_since(std::time::UNIX_EPOCH).unwrap(); // ensure it's a valid time
    }
}
