#[cfg(feature = "net-h1-server")]
macro_rules! mc {
    ($exp: expr) => {
        match $exp {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Accept error: {e}");
                continue;
            }
        }
    };
}

#[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
macro_rules! resolve_addr {
    ($addr:expr) => {
        $addr.to_socket_addrs()?.next().map_or_else(
            || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Could not resolve to any address",
                ))
            },
            |x| Ok(x),
        )
    };
}

#[cfg(feature = "net-h1-server")]
#[derive(Debug, Clone)]
pub struct H1Config {
    pub io_timeout: std::time::Duration,
    pub stack_size: usize,
    pub sni: bool,
}

#[cfg(feature = "net-h1-server")]
impl Default for H1Config {
    fn default() -> Self {
        Self {
            io_timeout: std::time::Duration::from_secs(60),
            sni: false,
            stack_size: 1024 * 1024,
        }
    }
}

#[cfg(feature = "net-h2-server")]
#[derive(Debug, Clone)]
pub struct H2Config {
    pub alpn_protocols: Vec<Vec<u8>>,
    pub backlog: usize,
    pub enable_connect_protocol: bool,
    pub initial_connection_window_size: u32,
    pub initial_window_size: u32,
    pub io_timeout: std::time::Duration,
    pub keep_alive: bool, // for h1 over h2 compatibility
    pub max_concurrent_streams: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub max_sessions: u64,
    pub num_of_shards: usize,
}

#[cfg(feature = "net-h2-server")]
impl Default for H2Config {
    fn default() -> Self {
        Self {
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            backlog: 512,
            enable_connect_protocol: false,
            initial_connection_window_size: 64 * 1024,
            initial_window_size: 256 * 1024,
            io_timeout: std::time::Duration::from_secs(60),
            keep_alive: true,
            max_concurrent_streams: 4096,
            max_frame_size: 32 * 1024,
            max_header_list_size: 32 * 1024,
            max_sessions: 1024,
            num_of_shards: 2,
        }
    }
}

#[cfg(feature = "net-h3-server")]
#[derive(Debug, Clone)]
pub struct H3Config {
    pub backlog: usize,
    pub enable_connect_protocol: bool,
    pub io_timeout: std::time::Duration,
    pub keep_alive_interval: std::time::Duration,
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub max_idle_timeout: std::time::Duration,
    pub max_sessions: u64,
    pub num_of_shards: usize,
    pub receive_window: u32,
    pub send_window: u64,
}

#[cfg(feature = "net-h3-server")]
impl Default for H3Config {
    fn default() -> Self {
        Self {
            backlog: 512,
            enable_connect_protocol: false,
            io_timeout: std::time::Duration::from_secs(60),
            keep_alive_interval: std::time::Duration::from_secs(10),
            max_concurrent_bidi_streams: 1024,
            max_concurrent_uni_streams: 256,
            max_idle_timeout: std::time::Duration::from_secs(20),
            max_sessions: 1024,
            num_of_shards: 2,
            receive_window: 8 * 1024 * 1024,
            send_window: 8 * 1024 * 1024,
        }
    }
}

#[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
fn make_socket(
    addr: std::net::SocketAddr,
    protocol: socket2::Protocol,
    backlog: usize,
) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Socket, Type};

    let domain = Domain::for_address(addr);
    let sock = if protocol == socket2::Protocol::TCP {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let socket_type = Type::STREAM.nonblocking();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let socket_type = Type::STREAM;

        Socket::new(domain, socket_type, Some(protocol))?
    } else {
        Socket::new(domain, Type::DGRAM, Some(protocol))?
    };

    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos",))]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    const DEFAULT_BACKLOG: i32 = 512;
    let backlog: i32 = if backlog == 0 {
        DEFAULT_BACKLOG
    } else {
        match i32::try_from(backlog) {
            Ok(y) => y,
            Err(_) => {
                eprintln!("backlog too large, using {}", DEFAULT_BACKLOG);
                DEFAULT_BACKLOG
            }
        }
    };

    if protocol == socket2::Protocol::TCP {
        sock.listen(backlog)?;
    }

    Ok(sock)
}

#[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
fn make_rustls_config(
    chain_cert_key: &(Option<&[u8]>, &[u8], &[u8]),
    alpn_protocols: Vec<Vec<u8>>,
) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, pkcs8_private_keys};

    // Load certs & key
    let certs: Vec<CertificateDer<'static>> = {
        let mut reader = std::io::Cursor::new(chain_cert_key.1);
        certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect()
    };

    let key: PrivateKeyDer<'static> = {
        let mut reader = std::io::Cursor::new(chain_cert_key.2);
        let keys: Result<Vec<_>, std::io::Error> = pkcs8_private_keys(&mut reader)
            .map(|res| {
                res.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Server got a bad private key: {e}"),
                    )
                })
            })
            .collect();
        let keys = keys?;
        if let Some(key) = keys.into_iter().next() {
            PrivateKeyDer::from(key)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Server could not find a private key",
            ));
        }
    };

    // TLS config
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Server could not load cert/key: {e}"),
            )
        })?;

    // set ALPN
    cfg.alpn_protocols = alpn_protocols;

    Ok(cfg)
}

#[cfg(feature = "net-h3-server")]
fn make_quinn_server(
    chain_cert_key: &(Option<&[u8]>, &[u8], &[u8]),
    h3_cfg: &H3Config,
) -> std::io::Result<quinn::ServerConfig> {
    // create server config
    let alpn_protocols = vec![b"h3".to_vec()];
    let cfg = make_rustls_config(chain_cert_key, alpn_protocols)?;

    // create transport config
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(h3_cfg.max_idle_timeout.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "H3 could not set idle timeout",
        )
    })?));
    transport.keep_alive_interval(Some(h3_cfg.keep_alive_interval));
    transport.send_window(h3_cfg.send_window);
    transport.receive_window(quinn::VarInt::from_u32(h3_cfg.receive_window));
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(h3_cfg.max_concurrent_bidi_streams));
    transport
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(h3_cfg.max_concurrent_uni_streams));

    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(cfg).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("H3 could not create quic TLS config: {e}"),
        )
    })?;
    let mut server = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_tls));
    server.transport = std::sync::Arc::new(transport);

    Ok(server)
}

pub trait HFactory: Send + Sync + Sized + 'static {
    #[cfg(feature = "net-h1-server")]
    type Service: crate::network::http::session::HService + Send;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    type HAsyncService: crate::network::http::session::HAsyncService + Send;

    #[cfg(feature = "net-wt-server")]
    type WtService: crate::network::http::wt::WtService + Send;

    // create a new http service for each connection
    #[cfg(feature = "net-h1-server")]
    fn service(&self, id: usize) -> Self::Service;

    // create a new http async service for each connection
    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    fn async_service(&self, id: usize) -> Self::HAsyncService;

    // create a new webtransport service for each connection
    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, id: usize) -> Self::WtService;

    /// Start the http service
    #[cfg(feature = "net-h1-server")]
    fn start_h1<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        cfg: H1Config,
    ) -> std::io::Result<may::coroutine::JoinHandle<()>> {
        let stacksize = if cfg.stack_size > 0 {
            cfg.stack_size
        } else {
            eprintln!("stacksize can not be zero, using default stack size (512 KB) for H1 server");
            512 * 1024
        };
        let listener = may::net::TcpListener::bind(addr)?;
        may::go!(
            may::coroutine::Builder::new()
                .name("Sib_H1_Factory".to_owned())
                .stack_size(stacksize),
            move || {
                use crate::network::http::h1_server::serve;

                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream in listener.incoming() {
                    let mut stream = mc!(stream);

                    // get the client IP address
                    let peer_addr = stream.peer_addr().unwrap_or(std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    ));

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;

                    mc!(stream.set_nodelay(true));
                    let service = self.service(id);
                    let builder = may::coroutine::Builder::new().id(id);
                    let _ = may::go!(builder, move || if let Err(_e) =
                        serve(&mut stream, &peer_addr.ip(), service)
                    {
                        //s_error!("service err = {e:?}");
                        stream.shutdown(std::net::Shutdown::Both).ok();
                    });
                }
            }
        )
    }

    #[cfg(feature = "net-h1-server")]
    fn start_h1_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        cfg: H1Config,
    ) -> std::io::Result<may::coroutine::JoinHandle<()>> {
        use std::net::Shutdown;

        let cert = boring::x509::X509::from_pem(chain_cert_key.1).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Cert error: {e}"))
        })?;
        let pkey = boring::pkey::PKey::private_key_from_pem(chain_cert_key.2).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Key error: {e}"))
        })?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| std::io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = chain_cert_key.0 {
            // add chain
            for extra in boring::x509::X509::stack_from_pem(chain).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Chain error: {e}"),
                )
            })? {
                tls_builder.add_extra_chain_cert(extra)?;
            }
        }
        tls_builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
        tls_builder.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
        tls_builder.set_options(boring::ssl::SslOptions::NO_TICKET);
        tls_builder.set_session_id_context(b"sib\0")?;
        tls_builder.set_alpn_protos(b"\x08http/1.1")?;

        if cfg.sni {
            tls_builder.set_servername_callback(|ssl_ref, _| {
                if ssl_ref
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .is_none()
                {
                    eprintln!("SNI not provided, rejecting connection");
                    return Err(boring::ssl::SniError::ALERT_FATAL);
                }
                Ok(())
            });
        }

        let stacksize = if cfg.stack_size > 0 {
            cfg.stack_size
        } else {
            eprintln!(
                "stacksize can not be zero, using default stack size (512 KB) for H1 TLS server"
            );
            512 * 1024
        };
        let tls_acceptor = std::sync::Arc::new(tls_builder.build());
        let listener = may::net::TcpListener::bind(addr)?;

        may::go!(
            may::coroutine::Builder::new()
                .name("Sib_H1_TLS_Factory".to_owned())
                .stack_size(stacksize),
            move || {
                use crate::network::http::h1_server::serve_tls;

                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream_incoming in listener.incoming() {
                    let stream = mc!(stream_incoming);
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_write_timeout(Some(cfg.io_timeout));
                    let _ = stream.set_read_timeout(Some(cfg.io_timeout));

                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            0,
                        )
                    });

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;

                    let builder = may::coroutine::Builder::new().id(id);
                    let service = self.service(id);
                    let stream_cloned = stream.try_clone();
                    let tls_acceptor_cloned = tls_acceptor.clone();

                    let _ = may::go!(builder, move || {
                        match tls_acceptor_cloned.accept(stream) {
                            Ok(mut tls_stream) => {
                                if let Err(e) = serve_tls(&mut tls_stream, &peer_addr.ip(), service)
                                {
                                    tls_stream.get_mut().shutdown(Shutdown::Both).ok();
                                    eprintln!("serve_tls failed with error: {e} from {peer_addr}");
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS handshake failed {e} from {peer_addr}");
                                match stream_cloned {
                                    Ok(stream_owned) => {
                                        stream_owned.shutdown(Shutdown::Both).ok();
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to shut down the stream after TLS handshake failure: {e} from {peer_addr}"
                                        );
                                    }
                                };
                            }
                        }
                    });
                }
            }
        )
    }

    /// Start the h2 service with TLS based on glommio on linux
    #[cfg(all(
        feature = "net-h2-server",
        feature = "rt-glommio",
        not(feature = "rt-tokio"),
        target_os = "linux",
    ))]
    fn start_h2_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        h2_cfg: H2Config,
    ) -> std::io::Result<()> {
        // get socket address
        let socket_addr = resolve_addr!(addr)?;

        // create tls acceptor
        let tls_acceptor = futures_rustls::TlsAcceptor::from(std::sync::Arc::new(
            make_rustls_config(&chain_cert_key, h2_cfg.alpn_protocols.clone())?,
        ));

        let factory = std::sync::Arc::new(self);

        glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
            h2_cfg.num_of_shards,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(move || {
            // Per-shard clones
            let tls_acceptor = tls_acceptor.clone();
            let factory = factory.clone();
            let h2_cfg = h2_cfg.clone();

            async move {
                let shard_id = glommio::executor().id();

                // Listener per shard with SO_REUSEPORT
                let listener =
                    match make_socket(socket_addr, socket2::Protocol::TCP, h2_cfg.backlog) {
                        Ok(socket) => {
                            use std::os::fd::{FromRawFd, IntoRawFd};
                            unsafe { glommio::net::TcpListener::from_raw_fd(socket.into_raw_fd()) }
                        }
                        Err(e) => {
                            eprintln!("Failed to create h2 listener on {socket_addr}: {e}");
                            return;
                        }
                    };

                println!("Shard {shard_id} listening for H2/TLS on {socket_addr}");

                // Per-shard session limiter
                let sem = std::rc::Rc::new(glommio::sync::Semaphore::new(h2_cfg.max_sessions));

                loop {
                    // Accept from listener
                    let stream = match listener.accept().await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("H2 accept got an error on shard {shard_id}: {e}");
                            continue;
                        }
                    };

                    // Try-acquire a session slot now; if none, close fast to drain the listen queue.
                    let sess_token = match std::rc::Rc::clone(&sem).try_acquire_static_permit(1) {
                        Ok(p) => p,
                        Err(_) => {
                            let _ = stream.shutdown(std::net::Shutdown::Both).await;
                            continue;
                        }
                    };

                    // Set no delay
                    let _ = stream.set_nodelay(true);

                    let peer_ip = stream
                        .peer_addr()
                        .unwrap_or_else(|_| {
                            std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                0,
                            )
                        })
                        .ip();

                    // TLS handshake
                    let tls_stream = match tls_acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("H2 TLS handshake error (shard {shard_id}): {e}");
                            // sess_token is dropped here, freeing the slot
                            continue;
                        }
                    };

                    let factory_cloned = std::sync::Arc::clone(&factory);
                    let h2_cfg_cloned = h2_cfg.clone();

                    glommio::spawn_local({
                        async move {
                            // Hold for the lifetime of the session
                            let _permit = sess_token;

                            // check negotiated ALPN
                            let negotiated = tls_stream
                                .get_ref()
                                .1
                                .alpn_protocol()
                                .map(|v| String::from_utf8_lossy(v).to_string());

                            match negotiated.as_deref() {
                                Some("h2") => {
                                    use crate::network::http::h2_server::serve_h2;
                                    let service = factory_cloned.async_service(shard_id);
                                    if let Err(e) =
                                        serve_h2(tls_stream, service, &h2_cfg_cloned, peer_ip).await
                                    {
                                        eprintln!("h2 serve error (shard {shard_id}): {e}");
                                    }
                                }
                                _ => {
                                    use crate::network::http::h2_server::serve_h1;
                                    let service = factory_cloned.async_service(shard_id);
                                    if let Err(e) =
                                        serve_h1(tls_stream, service, &h2_cfg_cloned, peer_ip).await
                                    {
                                        eprintln!(
                                            "h1 fallback serve error (shard {shard_id}): {e}"
                                        );
                                    }
                                }
                            };
                        }
                    })
                    .detach();
                }
            }
        })
        .map_err(|e| {
            std::io::Error::other(format!("Failed to create H2 Glommio executor pool: {e}"))
        })?
        .join_all();

        Ok(())
    }

    /// Start the h2 service with TLS based on tokio on non-linux OS
    #[cfg(all(
        feature = "net-h2-server",
        feature = "rt-tokio",
        not(feature = "rt-glommio")
    ))]
    fn start_h2_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        h2_cfg: H2Config,
    ) -> std::io::Result<()> {
        use std::sync::Arc;
        use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Semaphore};

        // Resolve bind address once
        let socket_addr = resolve_addr!(addr)?;

        // Shared TLS acceptor
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(make_rustls_config(
            &chain_cert_key,
            h2_cfg.alpn_protocols.clone(),
        )?));

        let factory = Arc::new(self);
        let h2_cfg_arc = Arc::new(h2_cfg);

        // Prepare listeners (use your make_socket for each shard)
        let requested_shards = h2_cfg_arc.num_of_shards.max(1);
        let mut std_listeners: Vec<std::net::TcpListener> = Vec::new();

        for shard_id in 0..requested_shards {
            match make_socket(socket_addr, socket2::Protocol::TCP, h2_cfg_arc.backlog) {
                Ok(sock) => {
                    let std_listener: std::net::TcpListener = sock.into();
                    std_listeners.push(std_listener);
                }
                Err(e) => {
                    // If additional binds fail (likely no SO_REUSEPORT), fall back to first listener.
                    if shard_id > 0 && e.kind() == std::io::ErrorKind::AddrInUse {
                        eprintln!(
                            "SO_REUSEPORT unavailable; falling back to a single shard ({} -> 1)",
                            requested_shards
                        );
                        // keep only the first listener
                        std_listeners.truncate(1);
                        break;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // One OS thread per shard, each with a current-thread Tokio runtime + LocalSet
        let mut handles = Vec::with_capacity(std_listeners.len());
        for (shard_id, std_listener) in std_listeners.into_iter().enumerate() {
            let tls_acceptor = tls_acceptor.clone();
            let factory = factory.clone();
            let h2_cfg = h2_cfg_arc.clone();

            handles.push(
            std::thread::Builder::new()
                .name(format!("h2-shard-{shard_id}"))
                .spawn(move || -> std::io::Result<()> {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(async move {
                        let listener = TcpListener::from_std(std_listener)
                            .map_err(|e| std::io::Error::other(format!("tokio from_std: {e}")))?;

                        eprintln!(
                            "Tokio H2/TLS shard {shard_id} listening on {}",
                            listener
                                .local_addr()
                                .map_err(|e| {
                                    std::io::Error::other(format!("local_addr: {e}"))
                                })?,
                        );

                        // Per-shard concurrency guard
                        let sem = Arc::new(Semaphore::new(h2_cfg.max_sessions as usize));
                        let local = tokio::task::LocalSet::new();

                        local
                            .run_until(async move {
                                loop {
                                    let (mut stream, peer_addr) = match listener.accept().await {
                                        Ok(x) => x,
                                        Err(e) => {
                                            eprintln!("accept error (shard {shard_id}): {e}");
                                            continue;
                                        }
                                    };

                                    let _ = stream.set_nodelay(true);
                                    let peer_ip = peer_addr.ip();

                                    // Try-acquire a session slot
                                    let permit = match sem.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            let _ = stream.shutdown().await;
                                            continue;
                                        }
                                    };

                                    let tls_acceptor = tls_acceptor.clone();
                                    let factory = factory.clone();
                                    let h2_cfg_cloned = h2_cfg.clone();

                                    tokio::task::spawn_local(async move {
                                        let _permit = permit;

                                        // TLS handshake
                                        let tls_stream = match tls_acceptor.accept(stream).await {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!(
                                                    "TLS handshake error (shard {shard_id}) from {peer_addr}: {e}"
                                                );
                                                return;
                                            }
                                        };

                                        // check negotiated ALPN
                                        let negotiated = tls_stream
                                            .get_ref()
                                            .1
                                            .alpn_protocol()
                                            .map(|v| String::from_utf8_lossy(v).to_string());

                                        match negotiated.as_deref() {
                                            Some("h2") => {
                                                use crate::network::http::h2_server::serve_h2;

                                                let service = factory.async_service(shard_id);

                                                if let Err(e) = serve_h2(tls_stream, service, &h2_cfg_cloned, peer_ip).await 
                                                    && !is_tls_eof_no_close_notify(&e) {
                                                        eprintln!("h2 serve error (shard {shard_id}) from {peer_addr}: {e}");
                                                }
                                            }
                                            _ => {
                                                use crate::network::http::h2_server::serve_h1;
                                                let service = factory.async_service(shard_id);
                                                if let Err(e) = serve_h1(tls_stream, service, &h2_cfg_cloned, peer_ip).await 
                                                    && !is_tls_eof_no_close_notify(&e) {
                                                        eprintln!(
                                                            "h1 fallback serve error (shard {shard_id}) from {peer_addr}: {e}"
                                                        );
                                                }
                                            }
                                        };
                                    });
                                }
                                #[allow(unreachable_code)]
                                Ok::<(), std::io::Error>(())
                            })
                            .await
                    })?;

                Ok(())
            })?,
        );
        }

        // Typical server behavior: block by joining the shard threads
        for h in handles {
            h.join()
                .map_err(|_| std::io::Error::other("A shard thread panicked in start_h2_tls"))??;
        }

        Ok(())
    }

    /// Start the h3 service with TLS based on glommio on linux
    #[cfg(all(
        feature = "net-h3-server",
        feature = "rt-glommio",
        not(feature = "rt-tokio"),
        target_os = "linux",
    ))]
    fn start_h3_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        h3_cfg: H3Config,
    ) -> std::io::Result<()> {
        let server = make_quinn_server(&chain_cert_key, &h3_cfg)?;
        let socket_addr = resolve_addr!(addr)?;
        let factory = std::sync::Arc::new(self);

        glommio::LocalExecutorPoolBuilder::new(glommio::PoolPlacement::MaxSpread(
            h3_cfg.num_of_shards,
            glommio::CpuSet::online().ok(),
        ))
        .on_all_shards(move || {
            // Per-shard clones
            let factory = factory.clone();
            let h3_cfg = h3_cfg.clone();

            async move {
                let shard_id = glommio::executor().id();

                // Runtime per shard with SO_REUSEPORT
                let endpoint_res =
                    match make_socket(socket_addr, socket2::Protocol::UDP, h3_cfg.backlog) {
                        Ok(socket) => {
                            let std_sock: std::net::UdpSocket = socket.into();
                            let ep_cfg = quinn::EndpointConfig::default();
                            let runtime = std::sync::Arc::new(quinn::AsyncStdRuntime);
                            quinn::Endpoint::new(ep_cfg, Some(server), std_sock, runtime)
                        }
                        Err(e) => {
                            eprintln!("Failed to create h3 listener on {socket_addr}: {e}");
                            return;
                        }
                    };
                let endpoint = match &endpoint_res {
                    Ok(ep) => ep,
                    Err(e) => {
                        eprintln!("H3 endpoint creation error on shard {shard_id}: {e}");
                        return;
                    }
                };

                // Per-shard concurrency budget
                println!("Shard {shard_id} listening for H3/TLS on {socket_addr}");

                let sem = std::rc::Rc::new(glommio::sync::Semaphore::new(h3_cfg.max_sessions));
                while let Some(incoming) = endpoint.accept().await {
                    // Rate-limit check
                    let peer_ip = incoming.remote_address().ip();

                    // Acquire a session slot (or skip if none available)
                    let permit = match std::rc::Rc::clone(&sem).try_acquire_static_permit(1) {
                        Ok(p) => p,
                        Err(_) => {
                            // Tell the peer immediately; don't just drop.
                            incoming.refuse();
                            continue;
                        }
                    };

                    let factory_cloned = std::sync::Arc::clone(&factory);

                    // accept connection
                    glommio::spawn_local(async move {
                        // Hold for the lifetime of the session
                        let _permit = permit;

                        match incoming.await {
                            Ok(connection) => {
                                use crate::network::http::h3_server::serve;
                                let service = factory_cloned.async_service(shard_id);

                                if let Err(e) = serve(connection, service, peer_ip).await {
                                    eprintln!("h3 serve error (shard {shard_id}): {e}");
                                }
                            }
                            Err(e) => {
                                eprintln!("h3 handshake error (shard {shard_id}): {e}");
                            }
                        };
                    })
                    .detach();
                }
            }
        })
        .map_err(|e| {
            std::io::Error::other(format!("Failed to create H3 Glommio executor pool: {e}"))
        })?
        .join_all();

        Ok(())
    }

    /// Start the h3 service with TLS based on tokio (multi-shard using num_of_shards + make_socket)
    #[cfg(all(
        feature = "net-h3-server",
        feature = "rt-tokio",
        not(feature = "rt-glommio")
    ))]
    fn start_h3_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (Option<&[u8]>, &[u8], &[u8]),
        h3_cfg: H3Config,
    ) -> std::io::Result<()> {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let server = make_quinn_server(&chain_cert_key, &h3_cfg)?;
        let socket_addr = resolve_addr!(addr)?;

        let factory = Arc::new(self);
        let h3_cfg_arc = Arc::new(h3_cfg);

        // Bind one UDP socket per shard using your helper (SO_REUSEPORT when available)
        let requested_shards = h3_cfg_arc.num_of_shards.max(1);
        let mut udp_sockets: Vec<std::net::UdpSocket> = Vec::new();
        for shard_id in 0..requested_shards {
            match make_socket(socket_addr, socket2::Protocol::UDP, h3_cfg_arc.backlog) {
                Ok(sock) => udp_sockets.push(sock.into()),
                Err(e) => {
                    if shard_id > 0 && e.kind() == std::io::ErrorKind::AddrInUse {
                        eprintln!(
                            "H3: SO_REUSEPORT unavailable; falling back to a single shard ({} -> 1)",
                            requested_shards
                        );
                        udp_sockets.truncate(1);
                        break;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // One OS thread per shard; each has a current-thread runtime + LocalSet for !Send tasks
        let mut handles = Vec::with_capacity(udp_sockets.len());
        for (shard_id, std_sock) in udp_sockets.into_iter().enumerate() {
            let server = server.clone();
            let factory = factory.clone();
            let h3_cfg = h3_cfg_arc.clone();

            handles.push(
                std::thread::Builder::new()
                    .name(format!("h3-shard-{shard_id}"))
                    .spawn(move || -> std::io::Result<()> {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;

                        rt.block_on(async move {
                            // Create endpoint on this shard’s UDP socket
                            let ep_cfg = quinn::EndpointConfig::default();
                            let runtime = std::sync::Arc::new(quinn::TokioRuntime);
                            let endpoint =
                                match quinn::Endpoint::new(ep_cfg, Some(server), std_sock, runtime)
                                {
                                    Ok(ep) => ep,
                                    Err(e) => {
                                        eprintln!(
                                            "H3 endpoint creation error (shard {shard_id}): {e}"
                                        );
                                        return Err(std::io::Error::other(e));
                                    }
                                };

                            println!("Tokio H3/TLS shard {shard_id} listening on {}", socket_addr);

                            let sem = Arc::new(Semaphore::new(h3_cfg.max_sessions as usize));
                            let local = tokio::task::LocalSet::new();

                            local
                                .run_until(async move {
                                    loop {
                                        let Some(incoming) = endpoint.accept().await else {
                                            // Endpoint closed
                                            break;
                                        };

                                        // Get peer ip
                                        let peer_ip = incoming.remote_address().ip();

                                        // Try-acquire a session slot (non-blocking)
                                        let permit = match sem.clone().try_acquire_owned() {
                                            Ok(p) => p,
                                            Err(_) => {
                                                // Prefer refusing so the client learns quickly.
                                                incoming.refuse();
                                                continue;
                                            }
                                        };

                                        let factory_cloned = factory.clone();

                                        // Now it's safe to use spawn_local
                                        tokio::task::spawn_local(async move {
                                            let _permit = permit;
                                            match incoming.await {
                                                Ok(connection) => {
                                                    use crate::network::http::h3_server::serve;
                                                    let service =
                                                        factory_cloned.async_service(shard_id);
                                                    if let Err(e) =
                                                        serve(connection, service, peer_ip).await
                                                    {
                                                        eprintln!(
                                                            "h3 serve error (shard {shard_id}): {e}"
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "h3 handshake error (shard {shard_id}): {e}"
                                                    );
                                                }
                                            }
                                        });
                                    }
                                })
                                .await;

                            Ok(())
                        })?;

                        Ok(())
                    })?,
            );
        }

        // Join shard threads and propagate any error
        for h in handles {
            if let Err(e) = h.join().map_err(|_| {
                std::io::Error::other("A shard thread panicked in start_h3_tls (tokio)")
            })? {
                return Err(e);
            }
        }

        Ok(())
    }

    #[cfg(feature = "net-wt-server")]
    fn start_wt_tls<L: std::net::ToSocketAddrs>(
        self,
        addr: L,
        chain_cert_key: (&[u8], &[u8]),
        wt_cfg: crate::network::http::wt::WTConfig,
    ) -> std::io::Result<()> {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        // Load full certificate chain (PEM or DER)
        fn load_cert_chain_pem(pem: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
            let mut reader = std::io::Cursor::new(pem);
            let mut ders = Vec::new();
            for item in rustls_pemfile::certs(&mut reader) {
                let der =
                    item.map_err(|e| std::io::Error::other(format!("Invalid cert in PEM: {e}")))?;
                ders.push(der.to_vec());
            }
            if ders.is_empty() {
                Err(std::io::Error::other("No certificates found in PEM"))
            } else {
                Ok(ders)
            }
        }

        fn load_cert_chain_der_or_pem(bytes: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
            // Heuristic: if it looks like PEM, parse as PEM; otherwise assume DER (single cert)
            let is_pem = bytes.starts_with(b"-----BEGIN");
            if is_pem {
                load_cert_chain_pem(bytes)
            } else {
                // Single DER cert
                Ok(vec![bytes.to_vec()])
            }
        }

        fn load_private_key_der_or_pem(
            bytes: &[u8],
        ) -> std::io::Result<wtransport::tls::PrivateKey> {
            if bytes.starts_with(b"-----BEGIN") {
                // Try PKCS#8
                {
                    let mut r = std::io::Cursor::new(bytes);
                    let keys = rustls_pemfile::pkcs8_private_keys(&mut r)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| {
                            std::io::Error::other(format!("Invalid PKCS#8 PEM key: {e}"))
                        })?;
                    if let Some(k) = keys.into_iter().next() {
                        return Ok(wtransport::tls::PrivateKey::from_der_pkcs8(
                            k.secret_pkcs8_der().to_vec(),
                        ));
                    }
                }
                Err(std::io::Error::other("No usable private key found in PEM"))
            } else {
                // Assume DER PKCS#8 by default; you can add a toggle if you need PKCS#1 here
                Ok(wtransport::tls::PrivateKey::from_der_pkcs8(bytes.to_vec()))
            }
        }

        let cert_chain_ders = load_cert_chain_der_or_pem(chain_cert_key.0)?;
        // Build wtransport cert chain
        let chain = {
            let mut v = Vec::with_capacity(cert_chain_ders.len());
            for der in cert_chain_ders {
                let c = wtransport::tls::Certificate::from_der(der)
                    .map_err(|e| std::io::Error::other(format!("Certificate DER error: {e}")))?;
                v.push(c);
            }
            wtransport::tls::CertificateChain::new(v)
        };

        let key = load_private_key_der_or_pem(chain_cert_key.1)?;

        // Resolve address coherently
        let bind = match addr.to_socket_addrs()?.next() {
            Some(socket_addr) => socket_addr,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Could not resolve address",
                ));
            }
        };

        let num_shards = wt_cfg.num_of_shards.max(1);
        let factory = Arc::new(self);
        let wt_cfg_arc = Arc::new(wt_cfg);

        let mut handles = Vec::with_capacity(num_shards as usize);
        for shard_id in 0..num_shards {
            let factory = factory.clone();
            let wt_cfg = wt_cfg_arc.clone();
            let chain = chain.clone();
            let key = key.clone_key();

            handles.push(
                std::thread::Builder::new()
                    .name(format!("wt-shard-{shard_id}"))
                    .spawn(move || -> std::io::Result<()> {
                        let identity = wtransport::Identity::new(chain, key);
                        // Clone the identity for each thread
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;

                        rt.block_on(async move {
                            let cfg = wtransport::ServerConfig::builder()
                                .with_bind_address(bind)
                                .with_identity(identity)
                                .keep_alive_interval(Some(wt_cfg.keep_alive_interval))
                                // .with_udp_socket(your_reuseport_socket)? // if the API supports it
                                .build();
                            let endpoint = wtransport::Endpoint::server(cfg).map_err(|e| {
                                std::io::Error::other(format!(
                                    "WT shard {shard_id} failed to create endpoint: {e}"
                                ))
                            })?;

                            eprintln!("WT shard {shard_id} listening on {bind}");

                            let sem = Arc::new(Semaphore::new(wt_cfg.max_sessions));
                            let local = tokio::task::LocalSet::new();

                            local
                                .run_until(async move {
                                    loop {
                                        let incoming = endpoint.accept().await;

                                        // Admission control: cheap non-blocking gate
                                        let Ok(permit) = sem.clone().try_acquire_owned() else {
                                            // No capacity: drop incoming fast; client will see refusal/timeout early
                                            continue;
                                        };

                                        let service = factory.wt_service(shard_id);
                                        tokio::task::spawn_local(async move {
                                            let _permit = permit;

                                            let session_req = match incoming.await {
                                                Ok(s) => s,
                                                Err(e) => {
                                                    eprintln!("WT session request error: {e}");
                                                    return;
                                                }
                                            };

                                            // Accept the WT session (Extended CONNECT)
                                            let conn = match session_req.accept().await {
                                                Ok(c) => c,
                                                Err(e) => {
                                                    eprintln!("WT accept error: {e}");
                                                    return;
                                                }
                                            };

                                            // Hand off to your service
                                            use crate::network::http::wt::{WtService, WtSession};
                                            let mut svc = service;
                                            let mut sess = WtSession::new(conn);
                                            if let Err(e) = svc.call(&mut sess).await {
                                                eprintln!("WT service error: {e}");
                                            }
                                        });
                                    }
                                })
                                .await;
                            Ok(())
                        })
                    })?,
            );
        }

        for h in handles {
            h.join()
                .map_err(|_| std::io::Error::other("WT shard panicked"))??;
        }

        Ok(())
    }
}

#[cfg(any(
    feature = "net-h1-server",
    feature = "net-h2-server",
    feature = "net-h3-server"
))]
/// Parse an authority of the form:
/// - "example.com"
/// - "example.com:8080"
/// - "[::1]"
/// - "[::1]:8443"
pub(crate) fn parse_authority(s: &str) -> Option<(String, Option<u16>)> {
    if s.is_empty() {
        return None;
    }

    let trim = s.trim();
    if trim.is_empty() {
        return None;
    }

    if trim.starts_with('[') {
        let close = trim.find(']')?;
        let host = &trim[1..close];
        let rest = &trim[close + 1..];
        if rest.is_empty() {
            return Some((host.to_string(), None));
        }
        if let Some(port_str) = rest.strip_prefix(':')
            && let Ok(p) = port_str.parse::<u16>()
        {
            return Some((host.to_string(), Some(p)));
        }
        return None;
    }

    if let Some(colon) = trim.rfind(':') {
        let (h, p) = trim.split_at(colon);
        let p = &p[1..];
        if !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && let Ok(port) = p.parse::<u16>()
        {
            return Some((h.to_string(), Some(port)));
        }
    }
    Some((trim.to_string(), None))
}

fn is_tls_eof_no_close_notify(e: &std::io::Error) -> bool {
    let msg = e.to_string();
    msg.contains("peer closed connection without sending TLS close_notify")
        || msg.contains("unexpected eof")
        || msg.contains("UnexpectedEof")
}

#[cfg(test)]
pub mod tests {
    use crate::network::http::server::HFactory;

    #[cfg(feature = "net-h1-server")]
    use crate::network::http::session::HService;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    use crate::network::http::session::HAsyncService;
    cfg_if::cfg_if! {
        if #[cfg(any(
            feature = "net-h1-server",
            feature = "net-h2-server",
            feature = "net-h3-server",
            feature = "net-ws-server"))]
        {
            use crate::network::http::session::Session;
            use std::sync::Once;

            static INIT: Once = Once::new();
        }
    }

    pub struct EchoServer;

    #[cfg(feature = "net-h1-server")]
    impl HService for EchoServer {
        fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            // WebSocket upgrade path
            #[cfg(feature = "net-ws-server")]
            if session.is_ws() {
                if let Err(e) = session.ws_accept() {
                    session
                        .status_code(http::StatusCode::BAD_REQUEST)
                        .header_str("Connection", "close")?
                        .eom()?;
                    return Err(e);
                }

                use crate::network::http::ws::OpCode;
                use bytes::{Bytes, BytesMut};

                let mut frag_buf = BytesMut::new();
                let mut expecting_cont = false;
                let mut initial_is_text = false;

                // Pre-allocate small static replies as Bytes to satisfy &Bytes params
                let reply_text = Bytes::from_static(b"hello ws client!");
                let err_protocol = Bytes::from_static(b"protocol error");
                let err_unexpected = Bytes::from_static(b"unexpected continuation");
                let err_utf8 = Bytes::from_static(b"invalid utf8");

                loop {
                    let (code, payload, fin) = session.ws_read()?; // payload: Bytes

                    match code {
                        OpCode::Ping => {
                            // Echo same payload
                            session.ws_write(OpCode::Pong, &payload, true)?;
                        }
                        OpCode::Pong => {
                            // ignore
                        }
                        OpCode::Close => {
                            // Echo client's Close payload back
                            session.ws_write(OpCode::Close, &payload, true)?;
                            break;
                        }
                        OpCode::Text | OpCode::Binary => {
                            if expecting_cont {
                                // Protocol error: new data frame while fragmented message pending
                                session.ws_close(Some(&err_protocol))?;
                                break;
                            }

                            if !fin {
                                // Start fragmented message; accumulate only if needed
                                frag_buf.clear();
                                frag_buf.extend_from_slice(payload.as_ref());
                                expecting_cont = true;
                                initial_is_text = matches!(code, OpCode::Text);
                                continue;
                            }

                            // Single-frame message
                            if matches!(code, OpCode::Text) {
                                if let Ok(msg) = std::str::from_utf8(payload.as_ref()) {
                                    println!(
                                        "WS server got: Text ({} bytes): {msg}",
                                        payload.len()
                                    );
                                    session.ws_write(OpCode::Text, &reply_text, true)?;
                                } else {
                                    session.ws_close(Some(&err_utf8))?;
                                    break;
                                }
                            } else {
                                println!("WS server got Binary ({} bytes)", payload.len());
                                session.ws_write(OpCode::Binary, &payload, true)?;
                            }
                        }
                        OpCode::Continue => {
                            if !expecting_cont {
                                session.ws_close(Some(&err_unexpected))?;
                                break;
                            }

                            frag_buf.extend_from_slice(payload.as_ref());

                            if fin {
                                // Complete fragmented message
                                let whole = frag_buf.as_ref();
                                if initial_is_text {
                                    if let Ok(msg) = std::str::from_utf8(whole) {
                                        println!("WS server got (fragmented text): {msg}");
                                        session.ws_write(OpCode::Text, &reply_text, true)?;
                                    } else {
                                        session.ws_close(Some(&err_utf8))?;
                                        break;
                                    }
                                } else {
                                    println!(
                                        "WS server got (fragmented binary): {} bytes",
                                        whole.len()
                                    );
                                    let whole_bytes = Bytes::copy_from_slice(whole);
                                    session.ws_write(OpCode::Binary, &whole_bytes, true)?;
                                }
                                frag_buf.clear();
                                expecting_cont = false;
                            }
                        }
                    }
                }

                // Tell the outer loop to stop using this socket
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "ws done",
                ));
            }

            // Normal HTTP echo path
            let req_host = session.req_host();
            let req_method = session.req_method();
            let req_path = session.req_path();
            let http_version = session.req_http_version();
            let req_body = session.req_body(std::time::Duration::from_secs(5))?;

            let body = bytes::Bytes::from(format!(
                "Http version: {http_version:?}, Echo: {req_method:?} {req_host:?} {req_path:?}\r\nBody: {req_body:?}"
            ));

            session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Type", "text/plain")?
                .header_str("Content-Length", &body.len().to_string())?
                .body(body)
                .eom()?;

            if req_method == http::Method::POST {
                // Preserve your existing test behavior
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "H1 POST should return WouldBlock",
                ));
            }

            Ok(())
        }
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[async_trait::async_trait(?Send)]
    impl HAsyncService for EchoServer {
        async fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
            let req_host = session.req_host();
            let req_method = session.req_method();
            let req_path = session.req_path().to_owned();
            let http_version = session.req_http_version();
            let req_body = session
                .req_body_async(std::time::Duration::from_secs(5))
                .await;
            let body = bytes::Bytes::from(format!(
                "Http version: {http_version:?}, Echo: {req_method:?} {req_host:?} {req_path:?}\r\nBody: {req_body:?}"
            ));

            let content_len = body.len().to_string();
            session
                .status_code(http::StatusCode::OK)
                .header(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/plain"),
                )?
                .header(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_str(&content_len).expect("content_len"),
                )?
                .body(body)
                .eom_async()
                .await?;
            Ok(())
        }
    }

    impl HFactory for EchoServer {
        #[cfg(feature = "net-h1-server")]
        type Service = Self;

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
        type HAsyncService = Self;

        #[cfg(feature = "net-wt-server")]
        type WtService = Self;

        #[cfg(feature = "net-h1-server")]
        fn service(&self, _id: usize) -> Self::Service {
            EchoServer
        }

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
        fn async_service(&self, _id: usize) -> Self::HAsyncService {
            EchoServer
        }

        #[cfg(feature = "net-wt-server")]
        fn wt_service(&self, _id: usize) -> Self::WtService {
            EchoServer
        }
    }

    #[cfg(feature = "net-wt-server")]
    use crate::network::http::wt::{WtService, WtSession};

    #[cfg(feature = "net-wt-server")]
    #[async_trait::async_trait(?Send)]
    impl WtService for EchoServer {
        async fn call(&mut self, _session: &mut WtSession) -> std::io::Result<()> {
            // keep-alive window for manual testing via the browser
            use tokio::time::Duration;
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    #[cfg(any(
        feature = "net-h1-server",
        feature = "net-h2-server",
        feature = "net-h3-server",
        feature = "net-ws-server"
    ))]
    pub fn create_self_signed_tls_pems() -> (String, String) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        use sha2::{Digest, Sha256};

        let mut params: CertificateParams = Default::default();
        params.not_before = date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        // Get PEM strings
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Convert PEM -> DER by stripping header/footer and base64-decoding
        let mut der_b64 = String::with_capacity(cert_pem.len());
        for line in cert_pem.lines() {
            if !line.starts_with("-----") {
                der_b64.push_str(line.trim());
            }
        }
        let cert_der = b64.decode(der_b64).expect("PEM base64 decode");

        // SHA-256 over DER, base64 encode result
        let hash = Sha256::digest(&cert_der);
        let base64_hash = b64.encode(hash);

        println!("BASE64_SHA256_OF_DER_CERT: {}", base64_hash);

        INIT.call_once(|| {
            rustls::crypto::CryptoProvider::install_default(
                rustls::crypto::aws_lc_rs::default_provider(),
            )
            .expect("install aws-lc-rs");
        });

        (cert_pem, key_pem)
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_tls_server_gracefull_shutdown() {
        use std::time::Duration;

        use crate::network::http::server::H1Config;
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 0);

        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1_tls(
                addr,
                (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                H1Config::default(),
            )
            .expect("H1 TLS server failed to start");

        let handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        handler.join().expect("shutdown signaler failed");
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_get() {
        use crate::network::http::server::H1Config;
        use may::net::TcpStream;
        use std::{
            io::{Read, Write},
            time::Duration,
        };

        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // Pick a port and start the server
        let addr = "127.0.0.1:8081";
        let server_handle = EchoServer
            .start_h1(addr, H1Config::default())
            .expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(500));

            // Client sends HTTP request
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();

            eprintln!("H1 GET Response: {response}");
            assert!(response.contains("/test"));
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(1));
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_post() {
        use crate::network::http::server::H1Config;
        use may::net::TcpStream;
        use std::time::Duration;
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8082";
        let server_handle = EchoServer
            .start_h1(addr, H1Config::default())
            .expect("h1 start server");

        let client_handler = may::go!(move || {
            use std::io::{Read, Write};
            may::coroutine::sleep(Duration::from_millis(500));

            let mut stream = TcpStream::connect(addr).expect("connect");

            let body = b"hello=world";
            let req = format!(
                "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );

            stream.write_all(req.as_bytes()).unwrap();
            stream.write_all(body).unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();
            eprintln!("H1 POST Response: {response}");

            // Should include method, path, and echoed body contents
            assert!(response.contains("POST"));
            assert!(response.contains("/submit"));
        });

        may::join!(server_handle, client_handler);
        std::thread::sleep(Duration::from_secs(1));
    }

    #[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
    #[test]
    fn test_h1_ws_server() {
        use crate::network::http::server::H1Config;
        use std::time::Duration;

        let addr = "127.0.0.1:8081";
        let server_handler = std::thread::spawn(move || {
            const NUMBER_OF_WORKERS: usize = 1;
            crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

            // Pick a port and start the server
            EchoServer
                .start_h1(addr, H1Config::default())
                .expect("h1 start server")
        });

        std::thread::sleep(Duration::from_millis(500));
        // Connect to websocket server
        let (mut socket, response) = tungstenite::client::connect(format!("ws://{}", addr))
            .expect("websocket handshake failed");

        eprintln!("WS GET Response: {response:?}");

        if socket.can_write() {
            socket
                .write(tungstenite::Message::Text("hello ws server".into()))
                .expect("ws write");
            socket.flush().expect("ws flush");
        }
        if socket.can_read() {
            let msg = socket.read().expect("ws read");
            eprintln!("WS client got: {msg:?}");
        }
        socket.close(None).expect("close failed");

        may::join!(server_handler);

        std::thread::sleep(Duration::from_secs(1));
    }

    #[cfg(feature = "net-h2-server")]
    #[test]
    fn test_h2_tls_server_get() {
        let addr = "127.0.0.1:8083";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H2Config;
            // Pick a port and start the server
            EchoServer
                .start_h2_tls(
                    addr,
                    (None, cert.as_bytes(), key.as_bytes()),
                    H2Config::default(),
                )
                .expect("start_h2_tls");
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        // test http1 get
        {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .http1_only()
                .build()
                .expect("reqwest client");

            let resp = client
                .get(format!("https://{}", addr))
                .version(reqwest::Version::HTTP_11)
                .body("Hello, World!")
                .timeout(std::time::Duration::from_millis(300))
                .send()
                .expect("reqwest send");
            eprintln!("H1 Response: {resp:?}");
            assert!(resp.status().is_success());

            let body = resp.text().expect("resp text");
            eprintln!("H1 Response: {body:?}");
            assert!(body.contains("Echo:"));
            assert!(body.contains("Hello, World!"));
        }

        // test http2 get
        {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .http2_adaptive_window(true)
                .build()
                .expect("reqwest client");

            let resp = client
                .get(format!("https://{}", addr))
                .version(reqwest::Version::HTTP_2)
                .body("Hello, World!")
                .timeout(std::time::Duration::from_millis(300))
                .send()
                .expect("reqwest send");
            eprintln!("H2 Response: {resp:?}");
            assert!(resp.status().is_success());

            let body = resp.text().expect("resp text");
            eprintln!("H2 Response: {body:?}");
            assert!(body.contains("Echo:"));
            assert!(body.contains("Hello, World!"));
        }
    }

    #[cfg(feature = "net-h2-server")]
    #[test]
    fn test_h2_tls_server_post() {
        let addr = "127.0.0.1:8084";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H2Config;
            // Pick a port and start the server
            EchoServer
                .start_h2_tls(
                    addr,
                    (None, cert.as_bytes(), key.as_bytes()),
                    H2Config::default(),
                )
                .expect("start_h2_tls");
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        // test http1 post
        {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .http1_only()
                .build()
                .expect("reqwest client");

            let resp = client
                .post(format!("https://{}", addr))
                .version(reqwest::Version::HTTP_11)
                .body("Hello, World!")
                .timeout(std::time::Duration::from_millis(300))
                .send()
                .expect("reqwest send");
            eprintln!("H1 Response: {resp:?}");
            assert!(resp.status().is_success());

            let body = resp.text().expect("resp text");
            eprintln!("H1 Response: {body:?}");
            assert!(body.contains("Echo:"));
            assert!(body.contains("Hello, World!"));
        }
        // test http2 post
        {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .http2_adaptive_window(true)
                .build()
                .expect("reqwest client");

            let resp = client
                .post(format!("https://{}", addr))
                .version(reqwest::Version::HTTP_2)
                .body("Hello, World!")
                .timeout(std::time::Duration::from_millis(300))
                .send()
                .expect("reqwest send");
            eprintln!("H2 Response: {resp:?}");
            assert!(resp.status().is_success());

            let body = resp.text().expect("resp text");
            eprintln!("H2 Response: {body:?}");
            assert!(body.contains("Echo:"));
            assert!(body.contains("Hello, World!"));
        }
    }

    #[cfg(feature = "net-h3-server")]
    #[test]
    fn test_h3_tls_server_get() {
        let addr = "127.0.0.1:8085";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H3Config;
            let h3_cfg = H3Config::default();
            // Pick a port and start the server
            EchoServer
                .start_h3_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h3_cfg)
                .expect("start_h3_tls");
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http3_prior_knowledge()
            .build()
            .expect("reqwest client");

        let resp = client
            .get(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_3)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        eprintln!("Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        eprintln!("Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }

    #[cfg(feature = "net-h3-server")]
    #[test]
    fn test_h3_tls_server_post() {
        let addr = "127.0.0.1:8086";
        let _ = std::thread::spawn(move || {
            let (cert, key) = create_self_signed_tls_pems();

            use crate::network::http::server::H3Config;
            let h3_cfg = H3Config::default();
            // Pick a port and start the server
            EchoServer
                .start_h3_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h3_cfg)
                .expect("start_h3_tls");
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http3_prior_knowledge()
            .build()
            .expect("reqwest client");

        let resp = client
            .post(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_3)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        eprintln!("Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        eprintln!("Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }
}
