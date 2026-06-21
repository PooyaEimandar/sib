pub fn fdb_test_network_start() -> Result<(), String> {
    static NETWORK: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    NETWORK
        .get_or_init(|| {
            let network = crate::database::fdb::network::FDBNetwork::new(None)
                .map_err(|err| err.to_string())?;
            let runner = network.clone();
            Box::leak(Box::new(network));
            std::thread::spawn(move || {
                let _ = runner.run();
            });
            std::thread::sleep(std::time::Duration::from_millis(500));
            Ok(())
        })
        .clone()
}
