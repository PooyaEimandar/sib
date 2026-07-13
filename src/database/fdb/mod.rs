pub mod cache;
pub mod db;
pub mod future;
pub mod network;
pub mod pool;
pub mod trans;

#[cfg(test)]
#[path = "../../../tests/unit/database/fdb/shared.rs"]
pub(crate) mod test_shared;

#[macro_export]
macro_rules! fdb_network_start {
    () => {{
        use std::sync::Arc;
        use $crate::database::fdb::network::FDBNetwork;

        // Share one instance across the run/stop threads with an `Arc`.
        let network: Arc<FDBNetwork> =
            Arc::new(FDBNetwork::new(None).expect("Failed to create FDB network"));
        let network_for_run: Arc<FDBNetwork> = Arc::clone(&network);

        let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
            network_for_run.run().expect("Failed to run FDB network");
        });

        (network, handle)
    }};
}

#[macro_export]
macro_rules! fdb_network_stop {
    ($guard:expr) => {{
        // Type annotate
        let (network_for_stop, handle): (
            std::sync::Arc<$crate::database::fdb::network::FDBNetwork>,
            std::thread::JoinHandle<()>,
        ) = $guard;

        if let Err(e) = network_for_stop.stop() {
            tracing::error!("Failed to stop FDB network: {:?}", e);
        }

        handle.join().expect("Failed to join FDB network thread");
    }};
}
