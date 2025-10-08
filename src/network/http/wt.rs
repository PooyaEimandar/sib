#[derive(Debug, Clone)]
pub struct WTConfig {
    pub keep_alive_interval: std::time::Duration,
    pub num_of_shards: usize,
    pub max_sessions: usize,
}

impl Default for WTConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: std::time::Duration::from_secs(3),
            num_of_shards: 1,
            max_sessions: 1024,
        }
    }
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
    async fn call<W: WtSession>(&mut self, session: &mut W) -> std::io::Result<()>;
}
