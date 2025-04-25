use std::{net::SocketAddr, str::FromStr, time::Duration};
use wtransport::{
    Endpoint, Identity, ServerConfig,
    endpoint::IncomingSession,
    tls::{CertificateChain, PrivateKey},
};

pub struct WTransportServer {
    address: String,
    port: u16,
    cert_path: String,
    key_path: String,
    max_idle_timeout: Duration,
}

impl WTransportServer {
    pub async fn run_forever(&self) -> anyhow::Result<()> {
        let socket_addr = SocketAddr::from_str(&format!("{}:{}", self.address, self.port))?;
        let (cert_chain, private_key) = tokio::join!(
            CertificateChain::load_pemfile(self.cert_path.clone()),
            PrivateKey::load_pemfile(self.key_path.clone())
        );
        let identity = Identity::new(cert_chain?, private_key?);
        let config = ServerConfig::builder()
            .with_bind_address(socket_addr)
            .with_identity(identity)
            .keep_alive_interval(Some(self.max_idle_timeout))
            .build();

        let server = Endpoint::server(config)?;

        for id in 0.. {
            let incoming_session = server.accept().await;
            tokio::spawn(Self::handle_connection(id, incoming_session));
        }

        Ok(())
    }

    async fn handle_connection(_id: u64, _incoming_session: IncomingSession) {
        crate::s_debug!("New WebTransport");

        //let session_request = incoming_session.await?;
    }
}
