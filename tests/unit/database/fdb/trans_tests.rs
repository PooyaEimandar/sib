use super::*;

#[test]
fn prefix_end_builds_lexicographic_successor() {
    assert_eq!(prefix_end(b"abc").as_deref(), Some(&b"abd"[..]));
    assert_eq!(prefix_end(&[b'a', 0xFF]).as_deref(), Some(&b"b"[..]));
    assert!(prefix_end(&[0xFF]).is_none());
}

#[test]
fn owned_prefix_range_covers_keys_with_ff_suffix() {
    let range = FDBOwnedRange::prefix(&[b'a', 0xFF], 100).expect("finite prefix");
    let inside = [b'a', 0xFF, 0xFF];

    assert!(inside.as_slice() >= range.begin_key.as_slice());
    assert!(inside.as_slice() < range.end_key.as_slice());
    assert_eq!(range.limit, 100);
    assert!(range.snapshot);
}

#[test]
fn owned_range_can_advance_to_next_page() {
    let range = FDBOwnedRange::between(b"a".to_vec(), b"z".to_vec(), 50).after_key(b"mid");
    let borrowed = range.as_range();

    assert_eq!(borrowed.begin_key, b"mid");
    assert!(!borrowed.begin_or_equal);
    assert_eq!(borrowed.begin_offset, 1);
    assert_eq!(borrowed.end_key, b"z");
    assert_eq!(borrowed.limit, 50);
    assert_eq!(borrowed.iteration, 1);
}

#[test]
fn owned_range_builder_preserves_tuning_options() {
    let range = FDBOwnedRange::between(b"a".to_vec(), b"z".to_vec(), 10)
        .with_limit(20)
        .with_target_bytes(4096)
        .with_streaming_mode(FDBStreamingMode::Iterator)
        .snapshot(false);
    let borrowed = range.as_range();

    assert_eq!(borrowed.limit, 20);
    assert_eq!(borrowed.target_bytes, 4096);
    assert_eq!(borrowed.mode, FDBStreamingMode::Iterator);
    assert!(!borrowed.snapshot);
}
