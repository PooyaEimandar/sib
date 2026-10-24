use super::*;

fn live_db() -> FDB {
    crate::database::fdb::test_shared::fdb_test_network_start().expect("FDB network");
    let cluster = std::env::var("SIB_FDB_CLUSTER_FILE").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "/usr/local/etc/foundationdb/fdb.cluster".into()
        } else {
            "/etc/foundationdb/fdb.cluster".into()
        }
    });
    FDB::new(&cluster).expect("test database")
}

#[test]
fn run_replays_writes_after_a_read_error() {
    let db = live_db();
    let key = b"sib-tests/retry-whole-transaction";
    let mut attempts = 0;
    run(&db, |trx| {
        attempts += 1;
        trx.set_option(FDBTransactionOption::Timeout, &5000_i64.to_le_bytes());
        if attempts == 1 {
            // An old read version deterministically triggers transaction_too_old.
            unsafe { foundationdb_sys::fdb_transaction_set_read_version(trx.trs, 1) };
        }
        trx.set(key, b"preserved");
        trx.get_blocking_value_optional(b"sib-tests/unrelated-read", false)?;
        Ok(FDBTransactionOutcome::Ok(()))
    })
    .expect("replay entire transaction");
    assert!(attempts >= 2);
    let trx = FDBTransaction::new(&db).unwrap();
    assert_eq!(
        trx.get_blocking_value_optional(key, false)
            .unwrap()
            .as_deref(),
        Some(&b"preserved"[..])
    );
    trx.clear(key).commit_blocking().unwrap();
}

#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn async_read_failure_does_not_silently_reset_transaction() {
    let db = live_db();
    let trx = FDBTransaction::new(&db).unwrap();
    trx.set_option(FDBTransactionOption::Timeout, &5000_i64.to_le_bytes());
    unsafe { foundationdb_sys::fdb_transaction_set_read_version(trx.trs, 1) };
    trx.set(b"sib-tests/failed-read-write", b"must-not-partially-commit");
    let error = trx
        .get_async_value_optional(b"sib-tests/unrelated-read", false)
        .await
        .unwrap_err();
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<FDBError>()
            .is_some()
    );
    assert!(trx.commit_async().await.is_err());
}

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
    // after_key => FIRST_GREATER_THAN(mid) = (or_equal=true, offset=1), so the
    // next page starts strictly after "mid" rather than re-reading it.
    assert!(borrowed.begin_or_equal);
    assert_eq!(borrowed.begin_offset, 1);
    assert_eq!(borrowed.end_key, b"z");
    // end selector is FIRST_GREATER_OR_EQUAL(end) = (or_equal=false, offset=1).
    assert!(!borrowed.end_or_equal);
    assert_eq!(borrowed.end_offset, 1);
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
