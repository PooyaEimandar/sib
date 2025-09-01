use futures_util::{FutureExt, future::LocalBoxFuture};
use sib::network::http::server::{HFactory, HService};
use std::{fs, sync::Arc};

// --------- Fast global allocator ---------
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// --------- Date header cache (updated 1/s) ---------
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;

static DATE_CACHE: Lazy<Arc<ArcSwap<Arc<[u8]>>>> = Lazy::new(|| {
    let initial = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
    Arc::new(ArcSwap::from_pointee(Arc::<[u8]>::from(
        initial.into_bytes().into_boxed_slice(),
    )))
});

fn start_date_updater_once() {
    static STARTED: Lazy<()> = Lazy::new(|| {
        let swap = Arc::clone(&DATE_CACHE);
        std::thread::spawn(move || {
            loop {
                let now = std::time::SystemTime::now();
                let sub = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_millis();
                std::thread::sleep(std::time::Duration::from_millis(1_000u64 - sub as u64));

                let s = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
                swap.store(Arc::<[u8]>::from(s.into_bytes().into_boxed_slice()).into());
            }
        });
    });
    Lazy::force(&STARTED);
}

// RFC1123 date is always 29 bytes, e.g. "Mon, 02 Jan 2006 15:04:05 GMT"
const DATE_LEN: usize = 29;

const PART1: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 12\r\n\
Connection: keep-alive\r\n\
Server: Sib\r\n\
Date: ";
const PART2: &[u8] = b"\r\n\r\nHello World!";

const BUF_LEN: usize = PART1.len() + DATE_LEN + PART2.len();
const DATE_OFF: usize = PART1.len();

// One buffer per shard/thread (no contention, no alloc).
thread_local! {
    static RESP_BUF: std::cell::RefCell<[u8; BUF_LEN]> = {
        let mut buf = [0u8; BUF_LEN];
        // Pre-fill static parts once
        buf[..PART1.len()].copy_from_slice(PART1);
        buf[DATE_OFF + DATE_LEN .. ].copy_from_slice(PART2);
        std::cell::RefCell::new(buf)
    };
}

// --------- Service/Factory ---------
struct HelloService;

impl HService for HelloService {
    type F<'a>
        = LocalBoxFuture<'a, ()>
    where
        Self: 'a;

    fn call<'a>(self, mut stream: glommio::net::TcpStream) -> Self::F<'a> {
        async move {
            use futures_lite::io::AsyncWriteExt;

            // Get current Date (Arc<[u8]> -> &[u8])
            let date = DATE_CACHE.load();

            RESP_BUF.with(|cell| {
                let mut buf = cell.borrow_mut();
                // Patch the date into the prebuilt buffer (29-byte memcpy).
                // This is already optimal; compilers typically vectorize it.
                buf[DATE_OFF..DATE_OFF + DATE_LEN].copy_from_slice(&date);

                // Single syscall on the hot path
                // (glommio/futures-lite write_all() is fine; no flush needed)
                futures_lite::future::block_on(async {
                    let _ = stream.write_all(&*buf).await;
                });
            });
        }
        .boxed_local()
    }
}

struct HelloFactory;
impl HFactory for HelloFactory {
    type Service = HelloService;
    fn service(&self, _shard_id: usize) -> Self::Service {
        HelloService
    }
}

// --------- Main (not on hot path) ---------
fn main() {
    start_date_updater_once();

    let cpus = num_cpus::get();
    println!("CPU cores: {cpus}");

    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                println!("Total RAM: {} MB", kb / 1024);
                break;
            }
        }
    }

    HelloFactory::start_h1(Arc::new(HelloFactory), "0.0.0.0:8080", cpus, 4096)
        .expect("server failed");
}
