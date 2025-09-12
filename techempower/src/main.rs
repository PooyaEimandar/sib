use bytes::Bytes;
use sib::network::http::{
    server::{H1Config, HFactory},
    session::{HService, Session},
};
use std::fs;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(serde::Serialize)]
struct JsonMessage<'a> {
    message: &'a str,
}

impl Default for JsonMessage<'_> {
    fn default() -> Self {
        JsonMessage {
            message: "Hello, World!",
        }
    }
}

struct Server;

impl HService for Server {
    fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
        if session.req_path() == "/json" {
            // Respond with JSON
            let json = serde_json::to_vec(&JsonMessage::default())?;
            return session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Type", "application/json")?
                .header_str("Content-Length", &json.len().to_string())?
                .body(Bytes::from(json))
                .eom();
        }
        session
            .status_code(http::StatusCode::OK)
            .header_str("Content-Type", "text/plain")?
            .header_str("Content-Length", "13")?
            .body(Bytes::from_static(b"Hello, World!"))
            .eom()
    }
}

impl HFactory for Server {
    type Service = Server;

    fn service(&self, _id: usize) -> Server {
        Server
    }
}

fn main() {
    // Print number of CPU cores
    let stack_size = 256 * 1024; // 256 KB stack
    let cpus = num_cpus::get();
    println!("CPU cores: {cpus}");

    sib::init_global_poller(cpus, stack_size);

    // Print total RAM in MB
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        let mb = kb / 1024;
                        println!("Total RAM: {mb} MB");
                    }
                }
                break;
            }
        }
    }

    // Pick a port and start the server
    let addr = "0.0.0.0:8080";
    let mut threads = Vec::with_capacity(cpus);

    for _ in 0..cpus {
        let handle = std::thread::spawn(move || {
            let id = std::thread::current().id();
            println!("Listening {addr} on thread: {id:?}");
            Server
                .start_h1(
                    addr,
                    H1Config {
                        io_timeout: std::time::Duration::from_secs(15),
                        stack_size,
                    },
                )
                .unwrap_or_else(|_| panic!("h1 server failed to start for thread {id:?}"))
                .join()
                .unwrap_or_else(|_| panic!("h1 server failed to joining thread {id:?}"));
        });
        threads.push(handle);
    }

    // Wait for all threads to complete (they won’t unless crashed)
    for handle in threads {
        handle.join().expect("Thread panicked");
    }
}
