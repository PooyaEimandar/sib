use super::handler::HandlerFn;
use crate::{network::http::handler, s_error};
use crate::{s_info, s_trace, s_warn};
use core::time::Duration;
use dashmap::DashMap;
use futures::StreamExt;
use pingora::{listeners::TcpSocketOptions, protocols::TcpKeepalive, services::Service};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_quiche::http3::driver::{H3Event, IncomingH3Headers, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};

pub struct RateLimit {
    map: DashMap<IpAddr, (Instant, u32)>,
    max_burst: u32,
    window: Duration,
    last_gc_time: AtomicU64,
    gc_interval: Duration,
}

#[inline]
pub fn is_rate_limited(rate_limit: &RateLimit, ip: IpAddr) -> bool {
    let now_nanos = Instant::now()
        .duration_since(Instant::now() - Duration::from_secs(86400))
        .as_nanos() as u64; // nanoseconds since epoch
    let last_gc = rate_limit.last_gc_time.load(Ordering::Relaxed);

    if now_nanos.saturating_sub(last_gc) > rate_limit.gc_interval.as_nanos() as u64
        && rate_limit
            .last_gc_time
            .compare_exchange(last_gc, now_nanos, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    {
        let now = Instant::now();
        rate_limit
            .map
            .retain(|_, (ts, _)| now.duration_since(*ts) < rate_limit.gc_interval);
    }

    // Rate limiting logic
    let now = Instant::now();
    let mut entry = rate_limit.map.entry(ip).or_insert((now, 0));

    if now.duration_since(entry.0) > rate_limit.window {
        *entry = (now, 1);
        return false;
    }

    if entry.1 >= rate_limit.max_burst {
        return true;
    }

    entry.1 += 1;
    false
}

pub struct Server {
    address: String,
    h2_port: u16,
    h3_port: u16,
    h2: bool,
    h3: bool,
    cert_path: String,
    key_path: String,
    tcp_fast_open_backlog_size: usize,
    max_idle_timeout: Duration,
    tcp_keep_alive_interval: Duration,
    tcp_keep_alive_count: usize,
    rate_limiter: Option<Arc<RateLimit>>,
    handler: Option<HandlerFn>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            h2_port: 8443,
            h3_port: 8443,
            h2: true,
            h3: true,
            cert_path: "".to_string(),
            key_path: "".to_string(),
            tcp_fast_open_backlog_size: 128,
            max_idle_timeout: Duration::from_secs(15),
            tcp_keep_alive_interval: Duration::from_secs(5),
            tcp_keep_alive_count: 3,
            rate_limiter: None,
            handler: None,
        }
    }
}

impl Server {
    pub fn new(
        address: String,
        h2_port: u16,
        h3_port: u16,
        rate_limit_max_burst_period: Option<(Duration, NonZeroU32, Duration)>,
        handler: Option<HandlerFn>,
    ) -> Self {
        let rate_limiter =
            if let Some((period, max_burst, gc_interval)) = rate_limit_max_burst_period {
                Some(Arc::new(RateLimit {
                    map: DashMap::new(),
                    max_burst: max_burst.get(),
                    window: period,
                    last_gc_time: AtomicU64::new(0),
                    gc_interval,
                }))
            } else {
                None
            };

        Self {
            address,
            h2_port,
            h3_port,
            rate_limiter,
            handler,
            ..Default::default()
        }
    }

    pub fn set_cert_path(&mut self, p_cert_path: String) -> &mut Self {
        self.cert_path = p_cert_path;
        self
    }

    pub fn set_key_path(&mut self, p_key_path: String) -> &mut Self {
        self.key_path = p_key_path;
        self
    }

    pub fn set_tcp_fast_open_backlog_size(
        &mut self,
        p_tcp_fast_open_backlog_size: usize,
    ) -> &mut Self {
        self.tcp_fast_open_backlog_size = p_tcp_fast_open_backlog_size;
        self
    }

    pub fn set_max_idle_timeout(&mut self, max_idle_timeout: Duration) -> &mut Self {
        self.max_idle_timeout = max_idle_timeout;
        self
    }

    pub fn set_tcp_keep_alive_interval(
        &mut self,
        p_tcp_keep_alive_interval: Duration,
    ) -> &mut Self {
        self.tcp_keep_alive_interval = p_tcp_keep_alive_interval;
        self
    }

    pub fn set_tcp_keep_alive_count(&mut self, p_tcp_keep_alive_count: usize) -> &mut Self {
        self.tcp_keep_alive_count = p_tcp_keep_alive_count;
        self
    }

    pub fn set_enable_h2(&mut self, p_enable: bool) -> &mut Self {
        self.h2 = p_enable;
        self
    }

    pub fn set_enable_h3(&mut self, p_enable: bool) -> &mut Self {
        self.h3 = p_enable;
        self
    }

    pub async fn run_forever(&self) -> anyhow::Result<()> {
        let h2_address_port = format!("{}:{}", self.address, self.h2_port);
        let h3_address_port = format!("{}:{}", self.address, self.h3_port);

        let mut tasks = vec![];

        if self.h3 {
            let h3_server = Self::run_h3_forever(
                h3_address_port,
                self.cert_path.clone(),
                self.key_path.clone(),
                self.max_idle_timeout,
                self.rate_limiter.clone(),
                self.handler.clone(),
            );
            tasks.push(tokio::spawn(async move {
                if let Err(e) = h3_server.await {
                    s_error!("H3 server failed: {:?}", e);
                }
            }));
        }

        if self.h2 {
            let h2_server = self.create_h2_server(h2_address_port)?;
            // Run Pingora H2 on separate blocking thread
            let h2_thread = std::thread::spawn(move || {
                h2_server.run_forever();
            });

            tasks.push(tokio::spawn(async move {
                h2_thread.join().expect("H2 thread panicked on join");
            }));
        }

        if tasks.is_empty() {
            anyhow::bail!("Neither H2 nor H3 enabled.");
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                s_info!("SIGINT received.");
            },
            res = futures::future::select_all(tasks) => {
                if let (Err(e), _, _) = res {
                    s_error!("Sib exited with error: {:?}", e);
                }
            }
        }

        Ok(())
    }

    fn create_h2_server(&self, p_address_port: String) -> anyhow::Result<pingora::server::Server> {
        // Validate certificate and key paths
        if !std::path::Path::new(&self.cert_path).exists() {
            anyhow::bail!("Certificate file does not exist: {}", self.cert_path);
        }
        if !std::path::Path::new(&self.key_path).exists() {
            anyhow::bail!("Private key file does not exist: {}", self.key_path);
        }

        let opt = None;
        let mut h2_server = pingora::server::Server::new(opt)?;
        h2_server.bootstrap();

        let mut sock_options = TcpSocketOptions::default();
        sock_options.tcp_fastopen = Some(self.tcp_fast_open_backlog_size);
        sock_options.tcp_keepalive = Some(TcpKeepalive {
            idle: self.max_idle_timeout,
            interval: self.tcp_keep_alive_interval,
            count: self.tcp_keep_alive_count,
        });

        let mut tls_settings =
            pingora::listeners::tls::TlsSettings::intermediate(&self.cert_path, &self.key_path)?;
        tls_settings.set_min_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))?;
        tls_settings.set_alpn(pingora::protocols::ALPN::H2H1);
        tls_settings.enable_h2();

        let mut service = handler::service(self.rate_limiter.clone(), self.handler.clone());
        service.add_tls_with_settings(&p_address_port, Some(sock_options), tls_settings);

        let services: Vec<Box<dyn Service>> = vec![Box::new(service)];
        h2_server.add_services(services);

        s_info!("Sib's H2 started on TCP port:{p_address_port}");

        Ok(h2_server)
    }

    async fn run_h3_forever(
        address_port: String,
        cert: String,
        private_key: String,
        max_idle_timeout: Duration,
        rate_limiter: Option<Arc<RateLimit>>,
        handler: Option<HandlerFn>,
    ) -> anyhow::Result<()> {
        let socket = tokio::net::UdpSocket::bind(&address_port).await?;
        let settings = tokio_quiche::settings::QuicSettings {
            max_idle_timeout: Some(max_idle_timeout),
            ..Default::default()
        };
        let mut listeners = listen(
            [socket],
            ConnectionParams::new_server(
                settings,
                tokio_quiche::settings::TlsCertificatePaths {
                    cert: &cert,
                    private_key: &private_key,
                    kind: tokio_quiche::settings::CertificateKind::X509,
                },
                Default::default(),
            ),
            SimpleConnectionIdGenerator,
            DefaultMetrics,
        )?;

        if listeners.is_empty() {
            anyhow::bail!("Expected one listener at least");
        }

        let accept_stream = &mut listeners[0];

        s_info!("Sib's H3 started on UDP port: {address_port}");

        while let Some(conn_result) = accept_stream.next().await {
            match conn_result {
                Ok(conn) => {
                    let peer_addr = conn.peer_addr();

                    // check rate limit
                    if let Some(ref limiter) = rate_limiter {
                        let ip = peer_addr.ip();
                        if is_rate_limited(limiter, ip) {
                            s_warn!("H3 Rate limit exceeded for {ip}");
                            continue;
                        }
                    }

                    let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
                    conn.start(driver);

                    let handler_cloned = handler.clone();
                    tokio::spawn(async move {
                        Self::handle_h3_connection(controller, handler_cloned).await;
                    });
                }
                Err(e) => {
                    s_error!("Sib QUIC failed on accepting: {e}");
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn handle_h3_connection(mut controller: ServerH3Controller, handler: Option<HandlerFn>) {
        while let Some(ServerH3Event::Core(event)) = controller.event_receiver_mut().recv().await {
            match event {
                H3Event::IncomingHeaders(IncomingH3Headers {
                    stream_id,
                    headers,
                    send,
                    recv,
                    read_fin,
                    h3_audit_stats,
                }) => {
                    if let Some(p_handler) = &handler {
                        let session = super::session::Session::new_h3(
                            stream_id,
                            headers,
                            send,
                            recv,
                            read_fin,
                            h3_audit_stats,
                        );
                        if let Err(e) = p_handler(session).await {
                            s_error!("Handler error: {:?}", e);
                        }
                    }
                }
                event => {
                    s_trace!("event: {event:?}");
                }
            }
        }
    }
}
