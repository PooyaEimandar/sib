use super::*;

#[test]
fn test_receiver() {
    let config: Config = Config {
        host: "127.0.0.1".to_string(),
        port: 5004,
        codec: Codec::H264,
        protocol: Protocol::UDP,
        latency_ms: 50,
    };

    let stop_flag = Arc::new(Mutex::new(false));
    let stop_flag_thread = Arc::clone(&stop_flag);
    std::thread::spawn(move || {
        let receiver = Receiver::new(config).unwrap();
        receiver
            .run(stop_flag_thread, move |data, width, height| {
                info!(
                    "Received frame of size: {}x{} with len:{}",
                    width,
                    height,
                    data.len()
                );
            })
            .unwrap();
    });

    std::thread::sleep(std::time::Duration::from_secs(10));
    {
        let mut flag = stop_flag.lock().unwrap();
        *flag = true; // Trigger graceful shutdown
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
}
