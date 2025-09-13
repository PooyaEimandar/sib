use bytes::Bytes;
use sib::network::http::{
    server::{H1Config, HFactory},
    session::{HService, Session},
};

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
    let stack_size = 4 * 1024; // 4 KB stack
    let cpus = num_cpus::get();

    sib::init_global_poller(cpus, stack_size);

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
                .unwrap_or_else(|_| panic!("H1 server failed to start for thread {id:?}"))
                .join()
                .unwrap_or_else(|_| panic!("H1 server failed to join thread {id:?}"));
        });
        threads.push(handle);
    }

    // Wait for all threads to complete
    for handle in threads {
        handle.join().expect("Thread panicked");
    }
}
