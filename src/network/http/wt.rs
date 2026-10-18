/// Why a WebTransport connection ended, including a peer's close code and reason.
pub use wtransport::error::ConnectionError as WtConnectionError;

#[derive(Debug, Clone)]
pub struct WTConfig {
    pub keep_alive_interval: std::time::Duration,
    /// Total time allowed for the QUIC handshake, CONNECT request and admission response.
    pub request_timeout: std::time::Duration,
    pub num_of_shards: usize,
    pub max_sessions: usize,
    /// Per-connection incoming datagram queue bytes. None keeps Quinn's default.
    /// Old datagrams are dropped on overflow; use a nonzero value large enough
    /// for the largest datagram, including the WebTransport header.
    pub datagram_receive_buffer_bytes: Option<usize>,
    /// Per-connection outgoing datagram queue bytes. None keeps Quinn's default.
    /// A full queue drops old datagrams instead of building a reliable backlog.
    pub datagram_send_buffer_bytes: Option<usize>,
}

impl Default for WTConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: std::time::Duration::from_secs(3),
            request_timeout: std::time::Duration::from_secs(10),
            num_of_shards: 1,
            max_sessions: 1024,
            datagram_receive_buffer_bytes: None,
            datagram_send_buffer_bytes: None,
        }
    }
}

impl WTConfig {
    pub(crate) fn transport_config(&self) -> std::io::Result<wtransport::quinn::TransportConfig> {
        if self.datagram_receive_buffer_bytes == Some(0)
            || self.datagram_send_buffer_bytes == Some(0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "WebTransport datagram queue limits must be nonzero",
            ));
        }
        let mut transport = wtransport::quinn::TransportConfig::default();
        if let Some(bytes) = self.datagram_receive_buffer_bytes {
            transport.datagram_receive_buffer_size(Some(bytes));
        }
        if let Some(bytes) = self.datagram_send_buffer_bytes {
            transport.datagram_send_buffer_size(bytes);
        }
        Ok(transport)
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
            Err(e) => Err(std::io::Error::other(format!("wt recv read: {e}"))),
        }
    }
}

pub struct WtWriteStream {
    send: wtransport::SendStream,
}

impl WtWriteStream {
    /// Write data to the stream.
    pub async fn write(&mut self, buf: &bytes::Bytes) -> std::io::Result<usize> {
        self.send
            .write(buf)
            .await
            .map_err(|e| std::io::Error::other(format!("wt send write: {e}")))
    }

    /// Gracefully finish the stream.
    pub async fn finish(&mut self) -> std::io::Result<()> {
        self.send
            .finish()
            .await
            .map_err(|e| std::io::Error::other(format!("wt send finish: {e}")))
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
            .map_err(|e| std::io::Error::other(format!("wt accept_bi: {e}")))
    }

    /// Accept a unidirectional stream (from client).
    pub async fn accept_uni(&self) -> std::io::Result<WtReadStream> {
        self.conn
            .accept_uni()
            .await
            .map(|recv| WtReadStream { recv })
            .map_err(|e| std::io::Error::other(format!("wt accept_uni: {e}")))
    }

    /// Receive a datagram.
    pub async fn recv_dgram(&self) -> std::io::Result<bytes::Bytes> {
        let datagram = self
            .conn
            .receive_datagram()
            .await
            .map_err(|e| std::io::Error::other(format!("wt recv_dgram: {e}")))?;
        Ok(bytes::Bytes::from(datagram.to_vec()))
    }

    /// Open a server->client unidirectional stream.
    pub async fn open_uni(&self) -> std::io::Result<WtWriteStream> {
        let opening = self
            .conn
            .open_uni()
            .await
            .map_err(|e| std::io::Error::other(format!("wt open_uni: {e}")))?;
        opening
            .await
            .map(|send| WtWriteStream { send })
            .map_err(|e| std::io::Error::other(format!("wt open_uni (send stream): {e}")))
    }

    /// Current maximum outgoing application datagram payload, in bytes.
    ///
    /// Excludes the WebTransport header. Returns `None` if the peer does not support
    /// datagrams or its limit cannot fit that header; `Some(0)` allows only an empty
    /// payload. This limit can change with the path MTU and does not describe incoming
    /// datagrams or guarantee delivery. Sending can still fail after querying it.
    pub fn max_datagram_size(&self) -> Option<usize> {
        use wtransport::proto::{datagram::Datagram, ids::QStreamId};

        let header_size = Datagram::header_size(QStreamId::from_session_id(self.conn.session_id()));
        // wtransport 0.7.2 subtracts unchecked; a peer can advertise less than the header.
        self.conn
            .quic_connection()
            .max_datagram_size()?
            .checked_sub(header_size)
    }

    /// Send one unreliable datagram without fragmentation.
    ///
    /// Errors distinguish an oversized payload (`InvalidInput`), a peer without
    /// datagram support (`Unsupported`) and a closed connection (`NotConnected`).
    /// Success means the transport accepted the payload, not that the peer received it.
    pub fn send_dgram(&self, bytes: &bytes::Bytes) -> std::io::Result<()> {
        self.conn.send_datagram(bytes).map_err(|e| {
            use std::io::ErrorKind;
            use wtransport::error::SendDatagramError;

            let kind = match e {
                SendDatagramError::TooLarge => ErrorKind::InvalidInput,
                SendDatagramError::UnsupportedByPeer => ErrorKind::Unsupported,
                SendDatagramError::NotConnected => ErrorKind::NotConnected,
            };
            std::io::Error::new(kind, e)
        })
    }

    /// Close the underlying QUIC connection immediately, without flushing pending data.
    ///
    /// `error_code` is a QUIC application code in `0..2^62`, not a browser WebTransport
    /// session close code. An out-of-range code returns `InvalidInput` without closing.
    /// The transport may truncate `reason` to fit a packet. Repeated closes are harmless.
    pub fn close(&self, error_code: u64, reason: &[u8]) -> std::io::Result<()> {
        let error_code = wtransport::VarInt::try_from_u64(error_code)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.conn.close(error_code, reason);
        Ok(())
    }

    /// Wait for connection termination and retain its typed reason.
    ///
    /// Returns immediately if already closed. A local `close` yields `LocallyClosed`;
    /// a peer's application close includes its QUIC code and reason bytes.
    /// This does not wait for outstanding data or close notifications to reach the peer.
    pub async fn closed(&self) -> WtConnectionError {
        self.conn.closed().await
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

#[cfg(all(test, feature = "mtls"))]
#[path = "../../../tests/unit/network/http/wt_session_tests.rs"]
mod session_tests;
