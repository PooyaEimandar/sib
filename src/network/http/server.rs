use super::handler::HandlerFn;
use crate::{network::http::handler, s_error};
use crate::{s_info, s_trace};
use core::time::Duration;
use futures::StreamExt;
use pingora::{listeners::TcpSocketOptions, protocols::TcpKeepalive, services::Service};
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
    tcp_keep_alive_idle: Duration,
    tcp_keep_alive_interval: Duration,
    tcp_keep_alive_count: usize,
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
            tcp_fast_open_backlog_size: 10,
            tcp_keep_alive_idle: Duration::from_secs(60),
            tcp_keep_alive_interval: Duration::from_secs(5),
            tcp_keep_alive_count: 5,
            handler: None,
        }
    }
}

impl Server {
    pub fn new(address: String, h2_port: u16, h3_port: u16, handler: Option<HandlerFn>) -> Self {
        Self {
            address,
            h2_port,
            h3_port,
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

    pub fn set_tcp_keep_alive_idle(&mut self, p_tcp_keep_alive_idle: Duration) -> &mut Self {
        self.tcp_keep_alive_idle = p_tcp_keep_alive_idle;
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
            idle: self.tcp_keep_alive_idle,
            interval: self.tcp_keep_alive_interval,
            count: self.tcp_keep_alive_count,
        });

        let mut tls_settings =
            pingora::listeners::tls::TlsSettings::intermediate(&self.cert_path, &self.key_path)?;

        tls_settings.set_alpn(pingora::protocols::ALPN::H2H1);
        tls_settings.enable_h2();

        let mut service = handler::service(self.handler.clone());
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
        handler: Option<HandlerFn>,
    ) -> anyhow::Result<()> {
        let socket = tokio::net::UdpSocket::bind(&address_port).await?;
        let mut listeners = listen(
            [socket],
            ConnectionParams::new_server(
                Default::default(),
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
                    let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
                    let peer_addr = conn.peer_addr();
                    conn.start(driver);

                    s_info!("Incoming QUIC con from: {peer_addr:?}");

                    let handler_cloned = handler.clone();
                    tokio::spawn(async move {
                        s_info!("Handling QUIC connection from: {peer_addr:?}");
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
