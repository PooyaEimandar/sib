#[derive(Debug, Clone)]
pub struct WTConfig {
    pub keep_alive_interval: std::time::Duration,
    /// Total time allowed for the QUIC handshake, CONNECT request and admission response.
    pub request_timeout: std::time::Duration,
    pub num_of_shards: usize,
    pub max_sessions: usize,
}

impl Default for WTConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: std::time::Duration::from_secs(3),
            request_timeout: std::time::Duration::from_secs(10),
            num_of_shards: 1,
            max_sessions: 1024,
        }
    }
}

/// Read-only metadata for a WebTransport CONNECT request, before it is accepted.
///
/// Headers and origin are client-supplied; they do not establish identity on their own.
/// Validate application credentials in [`WtService::admit`] and retain any resulting
/// identity on the service instance for use in [`WtService::call`].
pub struct WtRequest<'a> {
    request: &'a wtransport::endpoint::SessionRequest,
}

impl<'a> WtRequest<'a> {
    pub(crate) fn new(request: &'a wtransport::endpoint::SessionRequest) -> Self {
        Self { request }
    }

    /// Peer UDP address at the time of the call; QUIC migration can change it.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.request.remote_address()
    }

    /// The request's `:authority` field, including its port if present.
    pub fn authority(&self) -> &str {
        self.request.authority()
    }

    /// The request's `:path` field, including its query string if present.
    pub fn path(&self) -> &str {
        self.request.path()
    }

    pub fn origin(&self) -> Option<&str> {
        self.request.origin()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.request.user_agent()
    }

    /// All request fields, including pseudo-headers. HTTP/3 header names are lowercase.
    pub fn headers(&self) -> &std::collections::HashMap<String, String> {
        self.request.headers()
    }
}

/// Response to a request that has not yet been accepted as a WebTransport session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WtAdmission {
    Accept,
    Forbidden,
    NotFound,
    TooManyRequests,
}

pub struct WtSession {
    conn: wtransport::connection::Connection,
}

pub struct WtReadStream {
    recv: wtransport::RecvStream,
}

impl WtReadStream {
    /// Read data from the stream.
    pub async fn read(&mut self, buf: &mut bytes::BytesMut) -> std::io::Result<usize> {
        match self.recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0), // EOF reached, return 0 bytes read
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("wt recv read: {e}"),
            )),
        }
    }
}

pub struct WtWriteStream {
    send: wtransport::SendStream,
}

impl WtWriteStream {
    /// Write data to the stream.
    pub async fn write(&mut self, buf: &bytes::Bytes) -> std::io::Result<usize> {
        self.send.write(buf).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("wt send write: {e}"))
        })
    }

    /// Gracefully finish the stream.
    pub async fn finish(&mut self) -> std::io::Result<()> {
        self.send.finish().await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("wt send finish: {e}"))
        })
    }
}

impl WtSession {
    pub fn new(conn: wtransport::connection::Connection) -> Self {
        Self { conn }
    }

    /// Accept a bidi stream
    pub async fn accept_bi(&self) -> std::io::Result<(WtWriteStream, WtReadStream)> {
        self.conn
            .accept_bi()
            .await
            .map(|(send, recv)| (WtWriteStream { send }, WtReadStream { recv }))
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("wt accept_bi: {e}"))
            })
    }

    /// Accept a unidirectional stream (from client).
    pub async fn accept_uni(&self) -> std::io::Result<WtReadStream> {
        self.conn
            .accept_uni()
            .await
            .map(|recv| WtReadStream { recv })
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("wt accept_uni: {e}"))
            })
    }

    /// Receive a datagram.
    pub async fn recv_dgram(&self) -> std::io::Result<bytes::Bytes> {
        let datagram = self.conn.receive_datagram().await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("wt recv_dgram: {e}"))
        })?;
        Ok(bytes::Bytes::from(datagram.to_vec()))
    }

    /// Open a server->client unidirectional stream.
    pub async fn open_uni(&self) -> std::io::Result<WtWriteStream> {
        let opening = self.conn.open_uni().await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("wt open_uni: {e}"))
        })?;
        opening
            .await
            .map(|send| WtWriteStream { send })
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("wt open_uni (send stream): {e}"),
                )
            })
    }

    /// Send a datagram.
    pub fn send_dgram(&self, bytes: &bytes::Bytes) -> std::io::Result<()> {
        self.conn.send_datagram(bytes).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("wt send_dgram: {e}"))
        })
    }
}

#[cfg(feature = "net-wt-server")]
#[async_trait::async_trait(?Send)]
pub trait WtService: Send {
    /// Decide whether to accept a CONNECT request before `call` can exchange data.
    ///
    /// Override this to validate routes, browser origins and application credentials.
    /// The default accepts requests for compatibility with existing services; it does
    /// not authenticate them. Rejections send HTTP 403, 404 or 429. An error fails
    /// closed with 403, without logging the error text or request credentials.
    ///
    /// The same mutable service instance is used for admission and `call`, so it can
    /// retain the authenticated identity. `WTConfig::request_timeout` bounds the
    /// entire handshake/admission phase; timeout or server shutdown drops this future.
    /// Keep work asynchronous and ensure cancellation releases application resources.
    async fn admit(&mut self, _request: &WtRequest<'_>) -> std::io::Result<WtAdmission> {
        Ok(WtAdmission::Accept)
    }

    async fn call(&mut self, session: &mut WtSession) -> std::io::Result<()>;
}

#[cfg(all(test, feature = "mtls"))]
#[path = "../../../tests/unit/network/http/wt_tests.rs"]
mod tests;
