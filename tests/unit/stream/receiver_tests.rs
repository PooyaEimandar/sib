use super::*;

#[test]
#[ignore = "requires an external video sender"]
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

#[test]
fn stop_flag_wakes_a_receiver_with_an_idle_bus() {
    gst::init().unwrap();
    let bus = gst::Bus::new();
    let stop = Arc::new(Mutex::new(false));
    let worker_stop = stop.clone();
    let worker_bus = bus.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(wait_for_shutdown(&worker_bus, &worker_stop))
            .unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    *stop.lock().unwrap() = true;
    let result = rx.recv_timeout(std::time::Duration::from_secs(1));
    // Also clean up the worker if the regression returns.
    bus.post(gst::message::Eos::new()).unwrap();
    worker.join().unwrap();
    result
        .expect("idle receiver must observe stop flag")
        .unwrap();
}
