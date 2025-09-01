use crate::network::http::session::HService;

fn make_listener(addr: std::net::SocketAddr, backlog: i32) -> std::io::Result<glommio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::{IntoRawFd, FromRawFd};

    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };

    let sock = Socket::new(domain, Type::STREAM.nonblocking(), Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    sock.set_reuse_port(true)?;

    sock.bind(&addr.into())?;
    sock.listen(backlog)?;

    let listener = unsafe { glommio::net::TcpListener::from_raw_fd(sock.into_raw_fd()) };
    Ok(listener)
}

pub trait HFactory: Sized + 'static {
    type Service: HService + Send;
 
    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

    /// Start the http service
    #[cfg(feature = "net-h1-server")]
    fn start_h1<L>(
        self,
        addr: L,
        num_shards: usize,
    ) -> std::io::Result<()>
    where
        L: std::net::ToSocketAddrs + Clone + std::fmt::Display,
    {
        // Resolve once before entering the pool
        let s_addr = addr
            .to_socket_addrs()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .next().map_or_else(|| Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address found")), Ok)?;

        glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
            num_shards,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(move || {
            async move {
                use std::rc::Rc;

                let id = glommio::executor().id();

                #[cfg(unix)]
                let listener = make_listener(s_addr, 65_535).expect("bind reuseport backlog");
                #[cfg(not(unix))]
                let listener = glommio::net::TcpListener::bind(s_addr).expect("bind");

                // Concurrency budget
                let sem = Rc::new(glommio::sync::Semaphore::new(131_072));

                println!("Shard {id} listening on {}", s_addr);

                loop {
                    let permit = Rc::clone(&sem).acquire(1).await;

                    let stream = match listener.accept().await {
                        Ok(tcp_stream) => {
                            // accept and returns TcpStream
                            tcp_stream.set_nodelay(true);
                            tcp_stream
                        }, 
                        Err(_) => {
                            drop(permit);
                            continue;
                        }
                    };

                    glommio::spawn_local(async move {
                        // keep the semaphore permit for this connection
                        let _permit = permit;

                        // run service
                        let res = self.service(id).call();
                        // if let Err(e) = handle_conn(tls_stream, &ok_resp, &nf_resp).await {
                        //     eprintln!("conn error: {e}");
                        // }
                        drop(stream);
                    })
                    .detach();
                }
            }
        })?
        .join_all();

        Ok(())
    }

    // #[cfg(all(feature = "net-h1-server", feature = "tls"))]
    // fn start_h1_tls<L>(
    //     self,
    //     addr: L,
    //     ssl: Tls,
    //     num_shards: usize,
    // ) -> std::io::Result<()>
    // where
    //     L: std::net::ToSocketAddrs + Clone + std::fmt::Display,
    // {
    //     use crate::network::http::tls::{Tls, make_tls_acceptor};

    //     // Create TLS (HTTP/1.1, so h2 disabled here)
    //     let tls_acceptor = make_tls_acceptor(&ssl, false)?;

    //     // Resolve once before entering the pool
    //     let s_addr = addr
    //         .to_socket_addrs()
    //         .expect("resolve address")
    //         .next()
    //         .expect("no address found");

    //     glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
    //         num_shards,
    //         glommio::CpuSet::online().ok(),
    //     ))
    //     .on_all_shards(move || {
    //         let tls_acceptor = tls_acceptor.clone();

    //         async move {
    //             use std::rc::Rc;

    //             let id = glommio::executor().id();

    //             #[cfg(unix)]
    //             let listener = make_listener(s_addr, 65_535).expect("bind reuseport backlog");
    //             #[cfg(not(unix))]
    //             let listener = glommio::net::TcpListener::bind(s_addr).expect("bind");

    //             // Concurrency budget
    //             let sem = Rc::new(glommio::sync::Semaphore::new(131_072));

    //             println!("Shard {id} listening on {}", s_addr);

    //             loop {
    //                 let permit = Rc::clone(&sem).acquire(1).await;

    //                 let stream = match listener.accept().await {
    //                     Ok(s) => s, // accept returns TcpStream
    //                     Err(_) => {
    //                         drop(permit);
    //                         continue;
    //                     }
    //                 };

    //                 let _ = stream.set_nodelay(true);

    //                 let tls_acceptor = tls_acceptor.clone();
    //                 glommio::spawn_local(async move {
    //                     // keep the semaphore permit for this connection
    //                     let _permit = permit;

    //                     let tls_stream = match tls_acceptor.accept(stream).await {
    //                         Ok(s) => s,
    //                         Err(e) => {
    //                             eprintln!("TLS handshake error: {e}");
    //                             return;
    //                         }
    //                     };

    //                     // Handle the connection (your handler goes here)
    //                     // if let Err(e) = handle_conn(tls_stream, &ok_resp, &nf_resp).await {
    //                     //     eprintln!("conn error: {e}");
    //                     // }
    //                     drop(tls_stream);
    //                 })
    //                 .detach();
    //             }
    //         }
    //     })?
    //     .join_all();

    //     Ok(())
    // }

}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {

    }
}