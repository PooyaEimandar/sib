// #![allow(unused_assignments)]
// use super::callback::{OnCloseSocketCallback, OnMessageCallback, OnSocketCallback};
// use crate::system::{
//     buffer::{Buffer, BufferType, MAX_BUFFER_SIZE},
//     socket::timeouts::{timeout_for_read_write, timeout_for_udp_read},
// };
// use anyhow::{Context, Result, anyhow};
// use std::{net::SocketAddr, str::FromStr};
// use tokio::{net::UdpSocket, time::Instant};

// #[repr(C)]
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum UdpConnectionType {
//     Server = 0,
//     Client,
// }

// #[derive(Debug)]
// pub struct UdpClient {
//     pub address: String,
//     pub port: u16,
//     pub connection_type: UdpConnectionType,
//     pub io_number_of_retry: u32,
//     pub io_timeout_in_secs: f64,
// }

// impl UdpClient {
//     #[must_use]
//     pub const fn new(p_address: String, p_port: u16, p_connection_type: UdpConnectionType) -> Self {
//         Self {
//             address: p_address,
//             port: p_port,
//             connection_type: p_connection_type,
//             io_number_of_retry: 5,
//             io_timeout_in_secs: 5.0,
//         }
//     }

//     pub async fn connect(
//         &self,
//         on_bind: OnSocketCallback,
//         on_msg: OnMessageCallback,
//         on_close: OnCloseSocketCallback,
//     ) -> Result<()> {
//         let address = format!("{}:{}", self.address, self.port);
//         let socket_addr: SocketAddr = address.parse().context("Failed to parse socket address")?;

//         let socket = match self.connection_type {
//             UdpConnectionType::Server => UdpSocket::bind(socket_addr)
//                 .await
//                 .context("Failed to bind UDP socket for server")?,
//             UdpConnectionType::Client => {
//                 let sock = UdpSocket::bind("0.0.0.0:0")
//                     .await
//                     .context("Failed to bind local UDP socket for client")?;
//                 sock.connect(socket_addr)
//                     .await
//                     .context("Failed to connect UDP socket to remote")?;
//                 sock
//             }
//         };

//         on_bind.run(&socket_addr)?;

//         let mut msg = Buffer::new(BufferType::BINARY);
//         let start_time = Instant::now();

//         match self.connection_type {
//             UdpConnectionType::Server => loop {
//                 let elapsed = start_time.elapsed().as_secs_f64();

//                 let (msg_size, peer_addr) = self
//                     .try_read(&socket, &mut msg.buf)
//                     .await
//                     .with_context(|| format!("UDP server read from {socket_addr:?} failed"))?;

//                 msg.size = msg_size;

//                 if let Err(err) = on_msg.run(&peer_addr, &mut msg, elapsed) {
//                     return on_close.run(
//                         &socket_addr,
//                         &format!("Message callback requested to close server: {err:?}"),
//                     );
//                 }

//                 if msg_size > 0 {
//                     self.try_send(&socket, &peer_addr, &mut msg.buf)
//                         .await
//                         .with_context(|| {
//                             format!("UDP server send to {peer_addr:?} failed from {socket_addr:?}")
//                         })?;
//                 }
//             },
//             UdpConnectionType::Client => {
//                 let peer_addr = socket
//                     .peer_addr()
//                     .context("Failed to load local address for UDP client")?;

//                 loop {
//                     let elapsed = start_time.elapsed().as_secs_f64();

//                     if let Err(err) = on_msg.run(&peer_addr, &mut msg, elapsed) {
//                         return on_close.run(
//                             &socket_addr,
//                             &format!("Message callback requested to close client: {err:?}"),
//                         );
//                     }

//                     if msg.size > 0 {
//                         self.try_send(&socket, &peer_addr, &mut msg.buf)
//                             .await
//                             .context("UDP client send failed")?;

//                         let (msg_size, _) = self
//                             .try_read(&socket, &mut msg.buf)
//                             .await
//                             .context("UDP client read failed")?;

//                         msg.size = msg_size;
//                     }
//                 }
//             }
//         }
//     }

//     async fn read(
//         socket: &UdpSocket,
//         buffer: &mut [u8; MAX_BUFFER_SIZE],
//         timeout: f64,
//     ) -> Result<(usize, SocketAddr)> {
//         let res = if timeout > 0.0 {
//             tokio::select! {
//                 _ = timeout_for_udp_read(timeout) => Err(anyhow!("UDP read timed out")),
//                 res = socket.recv_from(buffer) => res.context("UDP read failed"),
//             }
//         } else {
//             socket.recv_from(buffer).await.context("UDP read failed")
//         };

//         res
//     }

//     async fn send(
//         socket: &UdpSocket,
//         peer: &SocketAddr,
//         buffer: &mut [u8; MAX_BUFFER_SIZE],
//         timeout: f64,
//     ) -> Result<usize> {
//         let res = if timeout > 0.0 {
//             tokio::select! {
//                 _ = timeout_for_read_write(timeout) => Err(anyhow!("UDP send timed out")),
//                 res = socket.send_to(buffer, peer) => res.context("UDP send failed"),
//             }
//         } else {
//             socket
//                 .send_to(buffer, peer)
//                 .await
//                 .context("UDP send failed")
//         };

//         res
//     }

//     async fn try_send(
//         &self,
//         socket: &UdpSocket,
//         peer: &SocketAddr,
//         buffer: &mut [u8; MAX_BUFFER_SIZE],
//     ) -> Result<usize> {
//         for _ in 0..self.io_number_of_retry {
//             if let Ok(sent) = Self::send(socket, peer, buffer, self.io_timeout_in_secs).await {
//                 return Ok(sent);
//             }
//         }
//         Err(anyhow!("Max retries reached in try_send"))
//     }

//     async fn try_read(
//         &self,
//         socket: &UdpSocket,
//         buffer: &mut [u8; MAX_BUFFER_SIZE],
//     ) -> Result<(usize, SocketAddr)> {
//         for _ in 0..self.io_number_of_retry {
//             if let Ok(res) = Self::read(socket, buffer, self.io_timeout_in_secs).await {
//                 return Ok(res);
//             }
//         }
//         Err(anyhow!("Max retries reached in try_read"))
//     }
// }
