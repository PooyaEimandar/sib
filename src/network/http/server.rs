use core::future::Future;

pub trait HService {
    type F<'a>: Future<Output = ()> + 'a
    where
        Self: 'a;

    fn call<'a>(self, stream: glommio::net::TcpStream) -> Self::F<'a>;
}

pub trait HFactory: Send + Sync + Sized + 'static {
    type Service: HService + 'static;

    /// Create a fresh service for each connection (can hold per-conn buffers/config).
    fn service(&self, shard_id: usize) -> Self::Service;

    /// Start the HTTP/1 server (no TLS here; same idea applies to TLS start).
    #[cfg(feature = "net-h1-server")]
    fn start_h1<L>(
        self: std::sync::Arc<Self>,
        addr: L,
        num_shards: usize,
        backlog: i32,
    ) -> std::io::Result<()>
    where
        L: std::net::ToSocketAddrs,
    {
        // Resolve once before entering the pool.
        let s_addr = addr
            .to_socket_addrs()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address found")
            })?;

        glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
            num_shards,
            glommio::CpuSet::online().ok(),
        ))
        .name("sib")
        .on_all_shards(move || {
            let factory = std::sync::Arc::clone(&self);
            let s_addr = s_addr;

            async move {
                use std::rc::Rc;

                let shard_id = glommio::executor().id();

                #[cfg(unix)]
                let listener = make_listener(s_addr, backlog).expect("bind reuseport backlog");
                #[cfg(not(unix))]
                let listener = glommio::net::TcpListener::bind(s_addr).expect("bind");

                // Concurrency budget
                let sem = Rc::new(glommio::sync::Semaphore::new(
                    (backlog as u64).saturating_mul(2),
                ));

                eprintln!("Shard {shard_id} listening on {s_addr}");

                loop {
                    // Accept first
                    let stream = match listener.accept().await {
                        Ok(stream) => stream,
                        Err(_) => continue, // transient accept error; just keep looping
                    };

                    // Quick per-conn tuning
                    let _ = stream.set_nodelay(true);

                    // Try to reserve a concurrency slot without waiting
                    match std::rc::Rc::clone(&sem).try_acquire(1) {
                        Ok(permit) => {
                            // Build a fresh service for this connection.
                            let srv = factory.service(shard_id);

                            glommio::spawn_local(async move {
                                // hold the semaphore slot for the lifetime of this task
                                let _permit = permit;
                                // run service code
                                srv.call(stream).await;
                            })
                            .detach();
                        }
                        Err(_) => {
                            // drop immediately
                            drop(stream);
                        }
                    }
                }
            }
        })?
        .join_all();

        Ok(())
    }
}

#[cfg(unix)]
fn make_listener(
    addr: std::net::SocketAddr,
    backlog: i32,
) -> std::io::Result<glommio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::{FromRawFd, IntoRawFd};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let sock = Socket::new(domain, Type::STREAM.nonblocking(), Some(Protocol::TCP))?;

    // Basic options
    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    sock.set_reuse_port(true)?;

    // Linux-only optional low-latency options (best-effort)
    #[cfg(target_os = "linux")]
    {
        use libc::{setsockopt, socklen_t};
        use std::os::fd::AsRawFd;

        // TCP_FASTOPEN: allow sending data in SYN; use a reasonable queue length
        const TCP_FASTOPEN: i32 = 23; // Linux value
        let qlen: i32 = 4096;
        unsafe {
            let _ = setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                &qlen as *const _ as *const _,
                std::mem::size_of_val(&qlen) as socklen_t,
            );
        }

        // TCP_DEFER_ACCEPT: wake accept() only when data arrives (seconds)
        const TCP_DEFER_ACCEPT: i32 = 9; // Linux value
        let seconds: i32 = 1;
        unsafe {
            let _ = setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_DEFER_ACCEPT,
                &seconds as *const _ as *const _,
                std::mem::size_of_val(&seconds) as socklen_t,
            );
        }
    }

    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    let listener = unsafe { glommio::net::TcpListener::from_raw_fd(sock.into_raw_fd()) };
    Ok(listener)
}

#[cfg(not(unix))]
fn make_listener(
    addr: std::net::SocketAddr,
    _backlog: i32,
) -> std::io::Result<glommio::net::TcpListener> {
    glommio::net::TcpListener::bind(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use futures_util::future::LocalBoxFuture;
    use std::sync::Arc;

    struct HelloService;

    impl HService for HelloService {
        type F<'a>
            = LocalBoxFuture<'a, ()>
        where
            Self: 'a;

        fn call<'a>(self, mut stream: glommio::net::TcpStream) -> Self::F<'a> {
            async move {
                use futures_lite::io::AsyncWriteExt;
                // Minimal HTTP/1.1 response
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
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

    // Requires Linux for glommio and "net-h1-server" feature
    #[test]
    #[cfg(all(feature = "net-h1-server", target_os = "linux"))]
    fn test_http1() {
        let factory = Arc::new(HelloFactory);

        const PORT: u16 = 8080;
        // Start server in a background thread
        std::thread::spawn({
            let factory = Arc::clone(&factory);
            move || {
                factory
                    .start_h1(format!("127.0.0.1:{PORT}"), 1, 1024)
                    .expect("server failed");
            }
        });

        // Give the shard a moment to initialize
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Create a blocking client
        let client = reqwest::blocking::Client::new();
        let url = format!("http://127.0.0.1:{PORT}/");

        // Retry until server is ready
        let mut resp_text = None;
        for _ in 0..10 {
            match client.get(&url).send() {
                Ok(resp) => {
                    resp_text = Some(resp.text().unwrap());
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }

        let body = resp_text.expect("server never responded");
        assert!(body.contains("Hello World!"), "unexpected body: {body:?}");
    }
}
