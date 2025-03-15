use core::time::Duration;
use futures::{SinkExt, StreamExt};
use pingora::{listeners::TcpSocketOptions, protocols::TcpKeepalive, services::Service};
use std::collections::HashMap;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::{H3Event, IncomingH3Headers, OutboundFrame, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3::{self, NameValue};
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};
use wasmer::{Engine, Module};

use crate::network::http::handler;

use super::param::Param;

pub struct Server {
    address: String,
    port: u16,
    h2: bool,
    h3: bool,
    routes_wasms: HashMap<String, String>,
    cert_path: String,
    key_path: String,
    tcp_fast_open_backlog_size: usize,
    tcp_keep_alive_idle: Duration,
    tcp_keep_alive_interval: Duration,
    tcp_keep_alive_count: usize,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 8443,
            h2: true,
            h3: true,
            routes_wasms: HashMap::new(),
            cert_path: "".to_string(),
            key_path: "".to_string(),
            tcp_fast_open_backlog_size: 10,
            tcp_keep_alive_idle: Duration::from_secs(60),
            tcp_keep_alive_interval: Duration::from_secs(5),
            tcp_keep_alive_count: 5,
        }
    }
}

impl Server {
    pub fn new(p_address: String, p_port: u16) -> Self {
        Self {
            address: p_address,
            port: p_port,
            ..Default::default()
        }
    }

    pub fn add_route(&mut self, route: String, wasm: String) {
        self.routes_wasms.insert(route, wasm);
    }

    pub fn remove_route(&mut self, route: &str) {
        self.routes_wasms.remove(route);
    }

    pub fn clear_routes(&mut self) {
        self.routes_wasms.clear();
    }

    pub fn get_address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    pub fn get_cert_path(&self) -> &str {
        &self.cert_path
    }

    pub fn get_key_path(&self) -> &str {
        &self.key_path
    }

    pub fn get_tcp_fast_open_backlog_size(&self) -> usize {
        self.tcp_fast_open_backlog_size
    }

    pub fn get_tcp_keep_alive_idle(&self) -> Duration {
        self.tcp_keep_alive_idle
    }

    pub fn get_tcp_keep_alive_interval(&self) -> Duration {
        self.tcp_keep_alive_interval
    }

    pub fn get_tcp_keep_alive_count(&self) -> usize {
        self.tcp_keep_alive_count
    }

    pub fn set_cert_path(&mut self, p_cert_path: String) {
        self.cert_path = p_cert_path;
    }

    pub fn set_key_path(&mut self, p_key_path: String) {
        self.key_path = p_key_path;
    }

    pub fn set_tcp_fast_open_backlog_size(&mut self, p_tcp_fast_open_backlog_size: usize) {
        self.tcp_fast_open_backlog_size = p_tcp_fast_open_backlog_size;
    }

    pub fn set_tcp_keep_alive_idle(&mut self, p_tcp_keep_alive_idle: Duration) {
        self.tcp_keep_alive_idle = p_tcp_keep_alive_idle;
    }

    pub fn set_tcp_keep_alive_interval(&mut self, p_tcp_keep_alive_interval: Duration) {
        self.tcp_keep_alive_interval = p_tcp_keep_alive_interval;
    }

    pub fn set_tcp_keep_alive_count(&mut self, p_tcp_keep_alive_count: usize) {
        self.tcp_keep_alive_count = p_tcp_keep_alive_count;
    }

    pub fn set_enable_h2(&mut self, p_enable: bool) {
        self.h2 = p_enable;
    }

    pub fn set_enable_h3(&mut self, p_enable: bool) {
        self.h3 = p_enable;
    }

    pub fn run_forever(&self) -> anyhow::Result<()> {
        let wasm_engine = Engine::default();
        if let Ok(mut wasms) = handler::WASMS.write() {
            // load all WASM
            for (route, wasm_path) in self.routes_wasms.iter() {
                // Load the WebAssembly binary
                let wasm_bytes = std::fs::read(wasm_path)?;
                // create a new WASM module
                let module = Module::new(&wasm_engine, &wasm_bytes)?;
                // insert the module into the WASMS
                wasms.insert(route.to_string(), module);
            }
        } else {
            anyhow::bail!("Failed to acquire write lock on WASMS");
        }

        let address_port = format!("{}:{}", self.address, self.port);

        if self.h2 && self.h3 {
            // Run H3 on another thread
            let h3_server = Self::run_h3_forever(
                address_port.clone(),
                self.cert_path.clone(),
                self.key_path.clone(),
            );
            std::thread::spawn(move || -> anyhow::Result<()> {
                tokio::runtime::Runtime::new()?.block_on(h3_server)?;
                Ok(())
            });

            // Run H2 on the main thread
            let h2_server = self.create_h2_server(address_port)?;
            h2_server.run_forever();
        } else if self.h2 {
            // Only H2 is enabled, run it on the main thread
            let h2_server = self.create_h2_server(address_port)?;
            h2_server.run_forever();
        } else if self.h3 {
            // Only H3 is enabled, run it on the main thread
            let h3_server =
                Self::run_h3_forever(address_port, self.cert_path.clone(), self.key_path.clone());
            tokio::runtime::Runtime::new()?.block_on(h3_server)?;
        }

        anyhow::bail!("either H2 or H3 must be enabled");
    }

    fn create_h2_server(&self, p_address_port: String) -> anyhow::Result<pingora::server::Server> {
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

        let mut tls_settings = pingora::listeners::tls::TlsSettings::intermediate(
            self.cert_path.as_str(),
            self.key_path.as_str(),
        )
        .expect("Failed to load TLS certificate or key");
        tls_settings.enable_h2();

        let mut service = handler::service();
        service.add_tls_with_settings(&p_address_port, Some(sock_options), tls_settings);

        let services: Vec<Box<dyn Service>> = vec![Box::new(service)];
        h2_server.add_services(services);

        Ok(h2_server)
    }

    async fn run_h3_forever(
        address_port: String,
        cert: String,
        private_key: String,
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

        while let Some(conn) = accept_stream.next().await {
            let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
            conn?.start(driver);
            tokio::spawn(Self::handle_h3_connection(controller));
        }
        Ok(())
    }

    async fn handle_h3_connection(mut controller: ServerH3Controller) {
        while let Some(ServerH3Event::Core(event)) = controller.event_receiver_mut().recv().await {
            match event {
                H3Event::IncomingHeaders(IncomingH3Headers {
                    stream_id: _,
                    headers,
                    mut send,
                    mut recv,
                    read_fin,
                    h3_audit_stats: _,
                }) => {
                    // body.extend_from_slice(&data);

                    let mut method: String = "".to_owned();
                    let mut path: String = "".to_owned();
                    let mut host: String = "".to_owned();
                    let mut parsed_headers = Vec::new();

                    let got: [bool; 3] = [false, false, false];

                    for header in &headers {
                        let name = String::from_utf8_lossy(header.name()).to_string();
                        let value = String::from_utf8_lossy(header.value()).to_string();
                        parsed_headers.push((name, value.clone()));

                        match header.name() {
                            b":method" => method = value,
                            b":path" => path = value,
                            b"host" => host = value,
                            b":authority" if host.is_empty() => host = value,
                            _ => (), // Collect other headers
                        }

                        // Exit early once all required headers are found
                        if got[0] && got[1] && got[2] {
                            break;
                        }
                    }

                    let param = Param::new(method, path, host);

                    // Properly read the body in a non-blocking manner
                    let mut body = bytes::BytesMut::new();

                    if !read_fin {
                        while let Some(chunk) = recv.recv().await {
                            match chunk {
                                tokio_quiche::http3::driver::InboundFrame::Body(data, fin) => {
                                    body.extend_from_slice(&data);
                                    if fin {
                                        break; // End of stream
                                    }
                                }
                                _ => break, // Stop on unexpected frame
                            }
                        }
                    }

                    let body = if body.is_empty() {
                        None
                    } else {
                        Some(body.freeze())
                    }; // Freeze only after fully reading

                    // Call the shared handler
                    let (_status_code, response_headers, response_body) =
                        handler::shared_handler(param, parsed_headers, body, true).await;

                    // Send response headers
                    // TODO: remove unwrap and use log
                    send.send(OutboundFrame::Headers(
                        response_headers
                            .into_iter()
                            .map(|(k, v)| h3::Header::new(k.as_bytes(), v.as_bytes()))
                            .collect(),
                    ))
                    .await
                    .unwrap();

                    // Send response body
                    // TODO: remove unwrap and use log
                    send.send(OutboundFrame::body(
                        BufFactory::buf_from_slice(&response_body),
                        true,
                    ))
                    .await
                    .unwrap();
                }
                _event => {
                    //log::info!("event: {event:?}");
                }
            }
        }
    }
}
