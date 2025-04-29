use super::handler::HandlerFn;
use crate::network::ratelimit::RateLimit;
use crate::{network::http::handler, s_error};
use crate::{s_info, s_trace, s_warn};
use core::time::Duration;
use futures::StreamExt;
use pingora::{listeners::TcpSocketOptions, protocols::TcpKeepalive, services::Service};
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio_quiche::datagram_socket::ShutdownConnectionExt;
use tokio_quiche::http3::driver::{H3Event, IncomingH3Headers, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};

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
                Some(Arc::new(RateLimit::new(
                    max_burst.get(),
                    period,
                    gc_interval,
                )))
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

        let mut h2_server = pingora::server::Server::new(None)?;
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
        service.threads = Some(num_cpus::get());

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
        use socket2::{Domain, Socket, Type};
        use tokio::net::UdpSocket;

        let cpu_count = num_cpus::get();
        let mut listeners = Vec::new();

        // Bind multiple UDP sockets with SO_REUSEPORT
        for _ in 0..cpu_count {
            let addr = address_port.parse::<std::net::SocketAddr>()?;
            let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;
            socket.set_nonblocking(true)?;
            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            socket.bind(&addr.into())?;

            let socket = UdpSocket::from_std(socket.into())?;
            listeners.push(socket);
        }

        let mut servers = listen(
            listeners,
            ConnectionParams::new_server(
                tokio_quiche::settings::QuicSettings {
                    max_idle_timeout: Some(max_idle_timeout),
                    ..Default::default()
                },
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

        if servers.is_empty() {
            anyhow::bail!("Expected at least one listener for H3.");
        }

        s_info!("Sib's H3 started on UDP port: {address_port}");

        let mut tasks = vec![];

        for mut accept_stream in servers.drain(..) {
            let rate_limiter = rate_limiter.clone();
            let handler = handler.clone();

            let task = tokio::spawn(async move {
                while let Some(conn_result) = accept_stream.next().await {
                    match conn_result {
                        Ok(mut conn) => {
                            let peer_addr = conn.peer_addr();

                            // Check rate limit
                            if let Some(ref limiter) = rate_limiter {
                                let ip = peer_addr.ip();
                                if !limiter.allow(ip) {
                                    s_warn!("H3 Rate limit exceeded for {ip}");
                                    let _ = conn.shutdown_connection().await;
                                    continue;
                                }
                            }

                            let (driver, controller) =
                                ServerH3Driver::new(Http3Settings::default());
                            conn.start(driver);

                            let handler_cloned = handler.clone();
                            tokio::spawn(async move {
                                Self::handle_h3_connection(controller, handler_cloned).await;
                            });
                        }
                        Err(e) => {
                            s_error!("H3 accept error: {e}");
                            continue;
                        }
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all H3 listener tasks
        futures::future::try_join_all(tasks).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::http::session::Session;
    use crate::system::log::{LogFileConfig, LogFilterLevel, LogRolling, init_log};
    use bytes::Bytes;
    use std::path::PathBuf;

    fn generate_self_signed_cert() -> (String, String) {
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        let name = vec!["localhost".to_string()];

        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(name).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[tokio::test]
    async fn test_server() -> anyhow::Result<()> {
        let log_file = LogFileConfig {
            roller: LogRolling::DAILY,
            dir: "log".to_owned(),
            file_name: "app.log".to_owned(),
            ansi: false,
        };
        let _log_system = init_log(LogFilterLevel::TRACE, Some(log_file), None).await;

        let (cert_pem, key_pem) = generate_self_signed_cert();
        // save the cert and key to files
        let cert_path = PathBuf::from("test_cert.pem");
        let key_path = PathBuf::from("test_key.pem");
        std::fs::write(&cert_path, cert_pem).expect("Unable to write cert file");
        std::fs::write(&key_path, key_pem).expect("Unable to write key file");

        let port = portpicker::pick_unused_port().expect("No ports free");
        let url = format!("https://127.0.0.1:{}/", port);
        let body_bytes = Bytes::from(&b"Hello World"[..]);
        let body_cloned = std::sync::Arc::new(body_bytes.clone());
        let server_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                Server::new(
                    "127.0.0.1".to_string(),
                    port,
                    port,
                    Some((
                        Duration::from_secs(1),
                        NonZeroU32::new(10).unwrap(),
                        Duration::from_secs(1),
                    )),
                    Some(Arc::new(move |mut session: Session| {
                        let body = body_cloned.clone();
                        Box::pin({
                            async move {
                                session.send_status(http::StatusCode::OK).await?;
                                session.insert_header(
                                    &http::header::CONTENT_TYPE,
                                    http::HeaderValue::from_static("text/plain"),
                                );
                                session.send_body((*body).clone(), true).await?;
                                session.send_eom().await
                            }
                        })
                    })),
                )
                .set_cert_path(cert_path.to_string_lossy().to_string())
                .set_key_path(key_path.to_string_lossy().to_string())
                .set_enable_h2(true)
                .set_enable_h3(true)
                .set_tcp_fast_open_backlog_size(1024)
                .set_max_idle_timeout(Duration::from_secs(5))
                .run_forever()
                .await
                .expect("Failed to run test server");
            });
        });

        // wait a little bit to let server boot up
        tokio::time::sleep(Duration::from_secs(1)).await;

        let h2_client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()?;

        let res = h2_client.get(&url).send().await?;

        assert_eq!(res.status(), reqwest::StatusCode::OK);
        let body = res.bytes().await?;
        assert_eq!(body, body_bytes);

        server_thread.thread().unpark();

        Ok(())
    }
}
