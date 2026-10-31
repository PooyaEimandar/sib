pub mod cache;
pub mod db;
pub mod future;
pub mod network;
pub mod pool;
pub mod trans;

#[cfg(test)]
#[path = "../../../tests/unit/database/fdb/shared.rs"]
pub(crate) mod test_shared;

/// Create the FDB network and run it on a new thread.
///
/// Evaluates to `std::io::Result<(Arc<FDBNetwork>, JoinHandle<()>)>`; pass the
/// pair to `fdb_network_stop!`. A failure of the network thread is logged.
#[macro_export]
macro_rules! fdb_network_start {
    () => {{
        use std::sync::Arc;
        use $crate::database::fdb::network::FDBNetwork;

        // Share one instance across the run/stop threads with an `Arc`.
        FDBNetwork::new(None).map(|network| {
            let network: Arc<FDBNetwork> = Arc::new(network);
            let network_for_run: Arc<FDBNetwork> = Arc::clone(&network);

            let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
                if let Err(e) = network_for_run.run() {
                    tracing::error!("Failed to run FDB network: {:?}", e);
                }
            });

            (network, handle)
        })
    }};
}

/// Stop the FDB network started by `fdb_network_start!` and join its thread.
///
/// Evaluates to `std::io::Result<()>`. If the network cannot be stopped, its
/// thread is left running rather than joined.
#[macro_export]
macro_rules! fdb_network_stop {
    ($guard:expr) => {{
        // Type annotate
        let (network_for_stop, handle): (
            std::sync::Arc<$crate::database::fdb::network::FDBNetwork>,
            std::thread::JoinHandle<()>,
        ) = $guard;

        network_for_stop.stop().and_then(|()| {
            handle
                .join()
                .map_err(|_| std::io::Error::other("FDB network thread panicked"))
        })
    }};
}
