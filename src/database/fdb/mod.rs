pub mod cache;
pub mod db;
pub mod future;
pub mod network;
pub mod pool;
pub mod trans;

#[macro_export]
macro_rules! fdb_network_start {
    () => {{
        use $crate::database::fdb::network::FDBNetwork;

        let network: FDBNetwork = FDBNetwork::new(None).expect("Failed to create FDB network");
        let network_for_stop: FDBNetwork = network.clone();

        let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
            network.run().expect("Failed to run FDB network");
        });

        (network_for_stop, handle)
    }};
}

#[macro_export]
macro_rules! fdb_network_stop {
    ($guard:expr) => {{
        // Type annotate
        let (mut network_for_stop, handle): (
            $crate::database::fdb::network::FDBNetwork,
            std::thread::JoinHandle<()>,
        ) = $guard;

        if let Err(e) = network_for_stop.stop() {
            tracing::error!("Failed to stop FDB network: {:?}", e);
        }

        handle.join().expect("Failed to join FDB network thread");
    }};
}
