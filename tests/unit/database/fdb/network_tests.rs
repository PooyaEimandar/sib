use super::*;
use std::thread;
use std::time::Duration;

#[test]
fn test_fdb_network_start_and_stop() {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return;

    let network = match FDBNetwork::new(None) {
        Ok(network) => network,
        Err(_) => return,
    };
    let mut network_for_stop = network.clone();

    let handle = thread::spawn(move || {
        let _ = network.run();
    });

    // Give it time to start
    thread::sleep(Duration::from_secs(1));

    // Now stop it (separate lock)
    let result = network_for_stop.stop();
    assert!(result.is_ok(), "Failed to stop network");

    // Wait for background thread
    handle.join().unwrap();
}
