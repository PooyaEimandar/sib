use futures_util::{FutureExt, future::LocalBoxFuture};
use nix::sys::uio::writev;
use sib::network::http::server::{HFactory, HService};
use std::{
    fs,
    io::IoSlice,
    os::fd::{AsRawFd, BorrowedFd},
    sync::Arc,
};

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

const PART1: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 13\r\n\
Connection: keep-alive\r\n\
Server: Sib\r\n\
Date: ";
const PART2: &[u8] = b"\r\n\r\nHello, World!";

// --------- Service/Factory ---------
struct HelloService;

impl HService for HelloService {
    type F<'a>
        = LocalBoxFuture<'a, ()>
    where
        Self: 'a;

    fn call<'a>(self, stream: glommio::net::TcpStream) -> Self::F<'a> {
        async move {
            // Arc<[u8]> with 29-byte RFC1123 date
            let date = DATE_CACHE.load();

            // Convert raw fd -> BorrowedFd (what nix::writev expects)
            let fd_raw = stream.as_raw_fd();
            let fd = unsafe { BorrowedFd::borrow_raw(fd_raw) };

            // Single gather write: [PART1][date][PART2]
            let bufs = [
                IoSlice::new(PART1),
                IoSlice::new(&date), // Arc<[u8]> derefs to [u8]
                IoSlice::new(PART2),
            ];

            // One writev(2) syscall, no extra copies/allocations
            let _ = writev(fd, &bufs);
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

    HelloFactory::start_h1(
        Arc::new(HelloFactory),
        "0.0.0.0:8080",
        cpus,
        1024,
        4096,
        std::time::Duration::from_micros(200),
        std::time::Duration::from_micros(50),
    )
    .expect("server failed");
}
