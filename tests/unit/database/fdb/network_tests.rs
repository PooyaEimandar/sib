#[test]
fn test_fdb_network_start_and_stop() {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return;

    let _guard = crate::database::fdb::test_shared::fdb_test_lock();
    if let Err(err) = crate::database::fdb::test_shared::fdb_test_network_start() {
        if cfg!(feature = "db-fdb") {
            panic!("live FoundationDB test requested, but network setup failed: {err}");
        }
    }
}
