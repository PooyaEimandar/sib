use crate::network::http::session::HService;
use bytes::{BufMut, BytesMut};
use may::{
    net::{TcpListener, TcpStream},
    {coroutine, go},
};
#[cfg(feature = "net-h3-server")]
use std::{
    io::{self, Read},
    mem::MaybeUninit, os::fd::FromRawFd,
};

#[cfg(unix)]
use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(unix)]
use may::io::WaitIo;

#[cfg(feature = "net-h3-server")]
const MAX_DATAGRAM_SIZE: usize = 1350;
#[cfg(feature = "net-h3-server")]
const H3_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
#[cfg(feature = "net-h3-server")]
const H3_MAX_BYTES_PER_TICK: usize = 512 * 1024; //cap per tick

const MIN_BUF_LEN: usize = 1024;
const MAX_BODY_LEN: usize = 4096;
pub const BUF_LEN: usize = MAX_BODY_LEN * 8;

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

pub trait HFactory: Send + Sync + Sized + 'static {
    cfg_if::cfg_if! {
        if #[cfg(any(feature = "net-h3-server"))] {
            type Service: HService + Send;
        }
        else {
            type Service: HService + Send;
        }
    }
 
    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

    /// Start the http service
    #[cfg(feature = "net-h1-server")]
    fn start_h1<L: ToSocketAddrs>(
        self,
        addr: L,
        stack_size: usize,
    ) -> io::Result<coroutine::JoinHandle<()>> {
        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };
        let listener = TcpListener::bind(addr)?;
        go!(
            coroutine::Builder::new()
                .name("H1Factory".to_owned())
                .stack_size(stacksize),
            move || {
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
                    let _ = go!(builder, move || if let Err(_e) =
                        serve(&mut stream, peer_addr, service)
                    {
                        //s_error!("service err = {e:?}");
                        stream.shutdown(std::net::Shutdown::Both).ok();
                    });
                }
            }
        )
    }

    #[cfg(all(feature = "net-h1-server", feature = "sys-boring-ssl"))]
    fn start_h1_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        ssl: &super::util::SSL,
        stack_size: usize,
        rate_limiter: Option<super::ratelimit::RateLimiterKind>,
    ) -> io::Result<coroutine::JoinHandle<()>> {
        use std::net::Shutdown;

        let cert = boring::x509::X509::from_pem(ssl.cert_pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Cert error: {e}")))?;
        let pkey = boring::pkey::PKey::private_key_from_pem(ssl.key_pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Key error: {e}")))?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = ssl.chain_pem {
            // add chain
            for extra in boring::x509::X509::stack_from_pem(chain).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("Chain error: {e}"))
            })? {
                tls_builder.add_extra_chain_cert(extra)?;
            }
        }
        tls_builder.set_min_proto_version(ssl.min_version.to_boring())?;
        tls_builder.set_max_proto_version(ssl.max_version.to_boring())?;
        tls_builder.set_options(boring::ssl::SslOptions::NO_TICKET);
        tls_builder.set_session_id_context(b"sib\0")?;
        tls_builder.set_alpn_protos(b"\x08http/1.1")?;

        #[cfg(not(debug_assertions))]
        {
            tls_builder.set_servername_callback(|ssl_ref, _| {
                if ssl_ref.servername(boring::ssl::NameType::HOST_NAME).is_none() {
                    eprintln!("SNI not provided, rejecting connection");
                    return Err(boring::ssl::SniError::ALERT_FATAL);
                }
                Ok(())
            });
        }

        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024
        };
        let io_timeout = ssl.io_timeout;
        let tls_acceptor = std::sync::Arc::new(tls_builder.build());
        let listener = TcpListener::bind(addr)?;

        go!(
            coroutine::Builder::new()
                .name("H1TLSFactory".to_owned())
                .stack_size(stacksize),
            move || {
                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream_incoming in listener.incoming() {
                    let stream = mc!(stream_incoming);
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_write_timeout(Some(io_timeout));
                    let _ = stream.set_read_timeout(Some(io_timeout));

                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    });
                    let ip = peer_addr.ip();

                    if let Some(rl) = &rate_limiter {
                        if !ip.is_unspecified() {
                            use super::ratelimit::RateLimiter;
                            let result = rl.check(ip.to_string().into());
                            if !result.allowed {
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                        }
                    }

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;

                    let builder = may::coroutine::Builder::new().id(id);
                    let service = self.service(id);
                    let stream_cloned = stream.try_clone();
                    let tls_acceptor_cloned = tls_acceptor.clone();

                    let _ = go!(builder, move || {
                        match tls_acceptor_cloned.accept(stream) {
                            Ok(mut tls_stream) => {
                                if let Err(e) = serve_tls(&mut tls_stream, peer_addr, service) {
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

    #[cfg(feature = "net-h3-server")]
    fn start_h3_tls<L: ToSocketAddrs>(
        self,
        addr: L,
        (cert_pem_file_path, key_pem_file_path): (&str, &str),
        io_timeout: std::time::Duration,
        verify_peer: bool,
        (stack_size, num_of_workers): (usize, usize),
        extend_connect: bool
    ) -> std::io::Result<()> {
        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };

        // share a service factory safely across dispatchers
        let factory: std::sync::Arc<dyn Fn(usize) -> Self::Service + Send + Sync> =
            std::sync::Arc::new(move |id| self.service(id));

        let address = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("Failed to get address info"))?;
        let sockets = bind_udp_sockets(address, io_timeout, num_of_workers)?;
        for socket in sockets {

            let local_addr = socket
            .local_addr()
            .map_err(|e| std::io::Error::other(format!("Failed to get local address: {e:?}")))?;

            let cfg = build_quiche_config(
                cert_pem_file_path,
                key_pem_file_path,
                io_timeout,
                verify_peer,
                extend_connect,
            )?;

            let factory_cloned = factory.clone();
            let _ = may::go!(
                may::coroutine::Builder::new()
                    .name("H3ServiceFactory".to_owned())
                    .stack_size(stacksize),
                move || {
                    quic_dispatcher(socket, cfg, local_addr, extend_connect, factory_cloned);
                }
            );
        }
        Ok(())
    }
}

#[cfg(feature = "net-h1-server")]
#[inline]
pub(crate) fn reserve_buf(buf: &mut BytesMut) {
    let rem = buf.capacity() - buf.len();
    if rem < MIN_BUF_LEN {
        buf.reserve(BUF_LEN - rem);
    }
}

#[cfg(all(unix, feature = "net-h1-server"))]
#[inline]
fn read(stream: &mut impl Read, buf: &mut BytesMut) -> io::Result<bool> {
    reserve_buf(buf);
    let chunk = buf.chunk_mut();
    let len = chunk.len();

    // SAFETY: We ensure exclusive access and will commit the right amount
    let read_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), len) };

    let mut io_slice = [std::io::IoSliceMut::new(read_buf)];
    let n = match stream.read_vectored(&mut io_slice) {
        Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "read closed")),
        Ok(n) => n,
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e),
    };

    unsafe {
        buf.advance_mut(n);
    }
    Ok(n < len)
}

#[cfg(all(unix, feature = "net-h1-server"))]
#[inline]
fn write(stream: &mut impl std::io::Write, rsp_buf: &mut BytesMut) -> io::Result<(usize, bool)> {
    use bytes::Buf;
    use std::io::IoSlice;

    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    let mut write_cnt = 0;
    let mut blocked = false;

    while write_cnt < len {
        let slice = IoSlice::new(unsafe { write_buf.get_unchecked(write_cnt..) });
        match stream.write_vectored(std::slice::from_ref(&slice)) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed")),
            Ok(n) => write_cnt += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => { blocked = true; break;},
            Err(e) => return Err(e),
        }
    }
    rsp_buf.advance(write_cnt);
    Ok((write_cnt, blocked))
}

#[cfg(all(unix, feature = "net-h1-server"))]
fn read_write<S, T>(
    stream: &mut S,
    peer_addr: &SocketAddr,
    req_buf: &mut BytesMut,
    rsp_buf: &mut BytesMut,
    service: &mut T,
) -> io::Result<bool>
where
    S: Read + io::Write,
    T: HService,
{
    // Prioritize draining any pending response bytes
    let mut blocked = false;
    if !rsp_buf.is_empty() {
        let (_, wblocked) = write(stream, rsp_buf)?;
        blocked |= wblocked;
        if !rsp_buf.is_empty() {
            return Ok(true); // will call wait_io()
        }
    }

    // Now read a fresh request
    let rblocked = read(stream, req_buf)?;
    blocked |= rblocked;

    // Serve as many requests as are fully buffered
    loop {
        use crate::network::http::h1_session;
        let mut headers = [MaybeUninit::uninit(); h1_session::MAX_HEADERS];
        let mut sess = match h1_session::new_session(stream, peer_addr, &mut headers, req_buf, rsp_buf)? {
            Some(sess) => sess,
            None => break,
        };

        if let Err(e) = service.call(&mut sess) {
            if e.kind() == std::io::ErrorKind::ConnectionAborted {
                // only abort if the service explicitly wants hard close
                return Err(e);
            }
            // Any other error just break
            break;
        }
    }
    
    // final flush
    let (_, wblocked2) = write(stream, rsp_buf)?;
    blocked |= wblocked2;

    Ok(blocked)
}

#[cfg(all(unix, feature = "net-h1-server"))]
fn serve<T: HService>(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    mut service: T,
) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, &peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.wait_io();
        }
    }
}

#[cfg(all(unix, feature = "net-h1-server", feature = "sys-boring-ssl"))]
fn serve_tls<T: HService>(
    stream: &mut boring::ssl::SslStream<may::net::TcpStream>,
    peer_addr: SocketAddr,
    mut service: T,
) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, &peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.get_mut().wait_io();
        }
    }
}

#[cfg(not(unix))]
fn serve<T: HService>(stream: &mut TcpStream, mut service: T) -> io::Result<()> {
    use std::io::Write;
    use bytes::Buf;

    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        // read
        reserve_buf(&mut req_buf);
        let read_buf: &mut [u8] = unsafe { std::mem::transmute(&mut *req_buf.chunk_mut()) };
        let read_cnt = stream.read(read_buf)?;
        if read_cnt == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        unsafe { req_buf.advance_mut(read_cnt) };

        // parse & serve
        if read_cnt > 0 {
            loop {
                use crate::network::http::h1_session; // <-- fix module path
                let mut headers = [MaybeUninit::uninit(); h1_session::MAX_HEADERS];
                let mut sess = match h1_session::new_session(stream, &mut headers, &mut req_buf, &mut rsp_buf)? {
                    Some(sess) => sess,
                    None => break,
                };
                if let Err(e) = service.call(&mut sess) {
                    if e.kind() == std::io::ErrorKind::ConnectionAborted {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        // write (drain)
        while !rsp_buf.is_empty() {
            let n = stream.write(rsp_buf.chunk())?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed"));
            }
            rsp_buf.advance(n);
        }
    }
}


#[cfg(feature = "net-h3-server")]
type ConnKey = [u8; quiche::MAX_CONN_ID_LEN];

#[cfg(feature = "net-h3-server")]
enum H3CtrlMsg {
    AddCid(ConnKey, may::sync::mpsc::Sender<Datagram>),
    RemoveCid(ConnKey),
}
#[cfg(feature = "net-h3-server")]
#[derive(Debug)]
struct Datagram {
    buf: Vec<u8>,
    from: SocketAddr,
    to: SocketAddr,
}

#[cfg(feature = "net-h3-server")]
#[inline]
fn key_from_cid(cid: &quiche::ConnectionId<'_>) -> ConnKey {
    let mut k = [0u8; quiche::MAX_CONN_ID_LEN];
    let s = cid.len().min(quiche::MAX_CONN_ID_LEN);
    k[..s].copy_from_slice(cid.as_ref());
    k
}

#[cfg(feature = "net-h3-server")]
fn bind_udp_sockets(addr: SocketAddr, io_timeout: std::time::Duration, n: usize) -> io::Result<Vec<std::sync::Arc<may::net::UdpSocket>>> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::{IntoRawFd};

    // Only fan out on Linux (REUSEPORT). On others, make a single socket.
    let fanout = if cfg!(any(target_os = "linux", target_os = "android")) { n } else { 1 };

    let mut v = Vec::with_capacity(fanout);
    for _ in 0..fanout {
        let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.set_read_timeout(Some(io_timeout))?;
        s.set_write_timeout(Some(io_timeout))?;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        s.set_reuse_port(true)?; // enable only on Linux/Android

        s.bind(&addr.into())?;
        s.set_recv_buffer_size(32 * 1024 * 1024)?;
        s.set_send_buffer_size(32 * 1024 * 1024)?;
        s.set_nonblocking(true)?;

        // Transfer ownership of the FD to may::net::UdpSocket (no double close).
        let fd = s.into_raw_fd();
        let may_udp = unsafe { may::net::UdpSocket::from_raw_fd(fd) };
        v.push(std::sync::Arc::new(may_udp));
    }
    Ok(v)
}

#[cfg(feature = "net-h3-server")]
fn build_quiche_config(
    cert_pem_file_path: &str,
    key_pem_file_path: &str,
    io_timeout: std::time::Duration,
    verify_peer: bool,
    extend_connect: bool,
) -> io::Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| io::Error::other(format!("Quiche builder got an error: {e}")))?;

    config
        .load_cert_chain_from_pem_file(cert_pem_file_path)
        .map_err(|e| io::Error::other(format!("Failed to load cert chain: {e:?}")))?;
    config
        .load_priv_key_from_pem_file(key_pem_file_path)
        .map_err(|e| io::Error::other(format!("Failed to load private key: {e:?}")))?;

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| io::Error::other(format!("Failed to set application protos: {e:?}")))?;

    config.set_max_idle_timeout(io_timeout.as_millis() as u64);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(256 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(64 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(64 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024 * 1024);
    config.set_initial_max_streams_bidi(1024);
    config.set_initial_max_streams_uni(1024);
    config.set_disable_active_migration(true);
    config.verify_peer(verify_peer);
    config.enable_early_data();
    if extend_connect {
        config.enable_dgram(true, MAX_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE);
    }
    Ok(config)
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
#[cfg(feature = "net-h3-server")]
fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
#[cfg(feature = "net-h3-server")]
fn validate_token<'a>(
    src: &std::net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles newly writable streams.
#[cfg(feature = "net-h3-server")]
fn handle_writable(session: &mut super::h3_session::H3Session, stream_id: u64) {
    let conn = &mut session.conn;
    let http3_conn = match session.http3_conn.as_mut() {
        Some(h3) => h3,
        None => { eprintln!("{} handle_writable with no h3_conn", conn.trace_id()); return; }
    };

    let Some(resp) = session.partial_responses.get_mut(&stream_id) else { return; };

    // Flush headers if still pending
    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => {}
            Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => return,
            Err(quiche::h3::Error::RequestCancelled)
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
                session.partial_responses.remove(&stream_id);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
                return;
            }
            Err(e) => {
                session.partial_responses.remove(&stream_id);
                eprintln!("{} send_response failed on {}: {:?}", conn.trace_id(), stream_id, e);
                return;
            }
        }
        resp.headers = None;
    }

    // Stream body in bounded chunks while we have credit.
    let mut budget = H3_MAX_BYTES_PER_TICK.min(resp.body.len().saturating_sub(resp.written));

    while resp.written < resp.body.len() && budget > 0 {
        let cap = quic_conn_stream_capacity(conn, stream_id);
        if cap == 0 { return; } // we’ll be called again when writable

        let want = H3_CHUNK_SIZE.min(budget).min(cap);
        let chunk = resp.body.chunk_at(resp.written, want);
        if chunk.is_empty() { return; }

        match http3_conn.send_body(conn, stream_id, chunk, false) {
            Ok(n) if n > 0 => {
                resp.written += n;
                budget = budget.saturating_sub(n);
            }
            Ok(_) | Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                return;
            }
            Err(quiche::h3::Error::RequestCancelled)
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
                session.partial_responses.remove(&stream_id);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
                return;
            }
            Err(e) => {
                session.partial_responses.remove(&stream_id);
                eprintln!("{} send_body failed on {}: {:?}", conn.trace_id(), stream_id, e);
                return;
            }
        }
    }

    // If fully written, send FIN and clean up
    if resp.written >= resp.body.len() {
        match http3_conn.send_body(conn, stream_id, &[], true) {
            Ok(_) | Err(quiche::h3::Error::Done) => {}
            Err(quiche::h3::Error::StreamBlocked) => return, // FIN will be retried later
            Err(e) => eprintln!("{} send FIN failed on {}: {:?}", conn.trace_id(), stream_id, e),
        }
        session.partial_responses.remove(&stream_id);
    }
}

#[cfg(feature = "net-h3-server")]
fn handle_h3_request<S: HService>(
    stream_id: u64,
    session: &mut super::h3_session::H3Session,
    service: &mut S,
) {
    use super::h3_session::{self, PartialResponse};

    // Decide response on headers only; stop reading request body.
    if let Err(e) = session.conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0) {
        if !matches!(e, quiche::Error::Done) {
            eprintln!("{} sid={} stream_shutdown(Read) non-fatal: {:?}", session.conn.trace_id(), stream_id, e);
        }
    }

    // Prepare the session & run the service to fill rsp_headers / rsp_body.
    h3_session::init_session(session);
    if let Err(e) = service.call(session) {
        if e.kind() == std::io::ErrorKind::ConnectionAborted {
            session.partial_responses.remove(&stream_id);
            let _ = session.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
            return;
        }
    }

    let http3_conn = match session.http3_conn.as_mut() {
        Some(v) => v,
        None => { eprintln!("{} HTTP/3 connection not initialized", session.conn.trace_id()); return; }
    };

    // Send headers first (or defer if blocked)
    match http3_conn.send_response(&mut session.conn, stream_id, &session.rsp_headers, false) {
        Ok(_) => {}
        Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
            use std::mem::take;
            session.partial_responses.insert(stream_id, PartialResponse {
                headers: Some(take(&mut session.rsp_headers)),
                body: take(&mut session.rsp_body),
                written: 0,
            });
            return;
        }
        Err(quiche::h3::Error::RequestCancelled)
        | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
        | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
            session.partial_responses.remove(&stream_id);
            let _ = session.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
            return;
        }
        Err(e) => {
            session.partial_responses.remove(&stream_id);
            eprintln!("{} send_response failed: {:?}", session.conn.trace_id(), e);
            return;
        }
    }

    // Send body in bounded chunks
    let total = session.rsp_body.len();
    let mut written = 0usize;
    let mut budget = H3_MAX_BYTES_PER_TICK.min(total);

    while written < total && budget > 0 {
        let cap = quic_conn_stream_capacity(&session.conn, stream_id);
        if cap == 0 { break; } // wait for writable()
        let want  = H3_CHUNK_SIZE.min(budget).min(cap);
        let chunk = session.rsp_body.chunk_at(written, want);

        match http3_conn.send_body(&mut session.conn, stream_id, chunk, false) {
            Ok(n) if n > 0 => { written += n; budget = budget.saturating_sub(n); }
            Ok(_) | Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => { break; }
            Err(quiche::h3::Error::RequestCancelled)
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
                let _ = session.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
                return;
            }
            Err(e) => { eprintln!("{} send_body failed: {:?}", session.conn.trace_id(), e); return; }
        }
    }

    if written < total {
        use std::mem::take;
        let body_src = take(&mut session.rsp_body);
        session.partial_responses.insert(stream_id, PartialResponse {
            headers: None,
            body: body_src,
            written,
        });
    } else {
        let cap = quic_conn_stream_capacity(&session.conn, stream_id);
        if cap == 0 {
            // Enqueue a FIN-only write so handle_writable() will finish it.
            session.partial_responses.insert(stream_id, PartialResponse {
                headers: None,
                body: h3_session::BodySource::Empty,
                written: 0,
            });
            return;
        }
        match http3_conn.send_body(&mut session.conn, stream_id, &[], true) {
            Ok(_) | Err(quiche::h3::Error::Done) => {}
            Err(quiche::h3::Error::StreamBlocked) => {
                session.partial_responses.insert(stream_id, PartialResponse {
                    headers: None,
                    body: h3_session::BodySource::Empty,
                    written: 0,
                });
            }
            Err(e) => eprintln!("{} send FIN failed: {:?}", session.conn.trace_id(), e),
        }
    }
}

#[cfg(feature = "net-h3-server")]
fn quic_dispatcher<S: HService + Send + 'static>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    mut config: quiche::Config,
    local_addr: SocketAddr,
    extend_connect: bool,
    call_service: std::sync::Arc<dyn Fn(usize) -> S + Send + Sync>,
) {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    type WorkerTx = may::sync::mpsc::Sender<Datagram>;
    let mut by_cid:  HashMap<ConnKey, WorkerTx> = HashMap::new();

    // NEW: short-lived addr map to cover CID switch race
    struct AddrEntry { tx: WorkerTx, expires: Instant }
    let mut by_addr: HashMap<SocketAddr, AddrEntry> = HashMap::new();
    const BY_ADDR_TTL: Duration = Duration::from_secs(5);

    let (ctrl_tx, ctrl_rx) = may::sync::mpsc::channel::<H3CtrlMsg>();
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        // drain control messages
        while let Ok(msg) = ctrl_rx.try_recv() {
            match msg {
                H3CtrlMsg::AddCid(cid, tx) => { by_cid.insert(cid, tx); }
                H3CtrlMsg::RemoveCid(cid)  => { by_cid.remove(&cid); }
            }
        }
        // expire old addr bindings
        let now = Instant::now();
        by_addr.retain(|_, e| e.expires > now);

        // recv one datagram
        let mut scratch = [0u8; 65535];
        let (n, from) = match socket.recv_from(&mut scratch) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {may::coroutine::yield_now(); continue;},
            Err(e) => { eprintln!("recv_from error: {e:?}"); continue; }
        };

        // parse header using n
        let hdr = match quiche::Header::from_slice(&mut scratch[..n], quiche::MAX_CONN_ID_LEN) {
            Ok(h) => h,
            Err(e) => { eprintln!("Header parse failed: {e:?}"); continue; }
        };
        let dcid_key = key_from_cid(&hdr.dcid);

        // fast path: known DCID
        if let Some(tx) = by_cid.get(&dcid_key) {
            let mut v = Vec::with_capacity(n);
            v.extend_from_slice(&scratch[..n]);
            let _ = tx.send(Datagram { buf: v, from, to: local_addr });
            continue;
        }

        // fallback by remote address; also "learn" the new DCID
        if let Some(entry) = by_addr.get_mut(&from) {
            entry.expires = Instant::now() + BY_ADDR_TTL;
            let tx = &entry.tx;
            let mut v = Vec::with_capacity(n);
            v.extend_from_slice(&scratch[..n]);
            let _ = tx.send(Datagram { buf: v, from, to: local_addr });
            by_cid.insert(dcid_key, tx.clone());
            continue;
        }

        // unknown DCID and no addr binding → handle Initial / VN
        if hdr.ty != quiche::Type::Initial {
            if !quiche::version_is_supported(hdr.version) {
                if let Ok(len) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                    let _ = socket.send_to(&out[..len], from);
                }
            }
            continue;
        }

        if !quiche::version_is_supported(hdr.version) {
            if let Ok(len) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                let _ = socket.send_to(&out[..len], from);
            }
            continue;
        }

        // retry if needed
        let token = hdr.token.as_deref().unwrap_or(&[]);
        let odcid_opt = if token.is_empty() { None } else { validate_token(&from, token) };
        if odcid_opt.is_none() {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let cid_len = hdr.dcid.len().min(quiche::MAX_CONN_ID_LEN);
            let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut scid_bytes[..cid_len]).expect("rng");
            let scid = quiche::ConnectionId::from_ref(&scid_bytes[..cid_len]);
            let new_token = mint_token(&hdr, &from);
            if let Ok(len) = quiche::retry(&hdr.scid, &hdr.dcid, &scid, &new_token, hdr.version, &mut out) {
                let _ = socket.send_to(&out[..len], from);
            }
            continue;
        }

        // accept new connection
        let conn = match quiche::accept(&hdr.dcid, odcid_opt.as_ref(), local_addr, from, &mut config) {
            Ok(c) => c,
            Err(e) => { eprintln!("accept failed: {e:?}"); continue; }
        };

        // create channel, spawn worker, then seed
        let (tx, rx) = may::sync::mpsc::channel::<Datagram>();
        let tx_cloned = tx.clone();
        let socket_cloned = socket.clone();
        let ctrl_tx_cloned = ctrl_tx.clone();
        let service = call_service(dcid_key[0] as usize);
        may::go!(move || {
            handle_quic_connection(
                socket_cloned,
                conn,
                from,
                (rx, tx),
                ctrl_tx_cloned,
                (dcid_key, extend_connect),
                service,
            );
        });
        
        by_addr.insert(from, AddrEntry { tx: tx_cloned.clone(), expires: Instant::now() + BY_ADDR_TTL });
        by_cid.insert(dcid_key, tx_cloned.clone());
        let mut v = Vec::with_capacity(n);
        v.extend_from_slice(&scratch[..n]);
        let _ = tx_cloned.send(Datagram { buf: v, from, to: local_addr });
    }
}


#[cfg(feature = "net-h3-server")]
fn handle_quic_connection<S: HService + 'static>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    conn: quiche::Connection,
    from: SocketAddr,
    (rx, tx): (may::sync::mpsc::Receiver<Datagram>, may::sync::mpsc::Sender<Datagram>),
    ctrl_tx: may::sync::mpsc::Sender<H3CtrlMsg>,
    (initial_dcid, extend_connect): (ConnKey, bool),
    mut service: S,
) {
    use std::collections::{HashSet};
    use crate::network::http::h3_session;

    let mut dcids: HashSet<ConnKey> = HashSet::new();
    let mut session = h3_session::new_session(from, conn);

    // Register the initial DCID as the primary key for routing
    if dcids.insert(initial_dcid) {
        let _ = ctrl_tx.send(H3CtrlMsg::AddCid(initial_dcid, tx.clone()));
    }
    // register all server source CIDs
    register_scids(&session.conn, &mut dcids, &ctrl_tx, &tx);

    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut h3_config = match quiche::h3::Config::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("h3 Config new: {e}");
            return;
        }
    };

    h3_config.set_qpack_max_table_capacity(4 * 1024);
    h3_config.set_qpack_blocked_streams(100);
    h3_config.set_max_field_section_size(256 * 1024);
    if extend_connect {
        h3_config.enable_extended_connect(true);
    }

    let mut pending: Option<(std::net::SocketAddr, Vec<u8>)> = None;
    let mut next_deadline = std::time::Instant::now() + 
        session.conn.timeout().unwrap_or(std::time::Duration::from_millis(5));
    loop {
        // Fire QUIC timers if due
        if std::time::Instant::now() >= next_deadline {
            session.conn.on_timeout();
            next_deadline = std::time::Instant::now() + 
                session.conn.timeout().unwrap_or(std::time::Duration::from_millis(5));
        }
        let timeout = next_deadline.saturating_duration_since(std::time::Instant::now());
        let wait = std::cmp::min(timeout, std::time::Duration::from_millis(5));

        // try to nonblocking-drain any backlog quickly
        let mut got_packet = false;
        let mut drained = 0usize;
        while drained < 64 {
            match rx.try_recv() {
                Ok(mut data) => {
                    let recv_info = quiche::RecvInfo { to: data.to, from: data.from };
                    if session.conn.recv(&mut data.buf, recv_info).is_ok() {
                        got_packet = true;
                    }
                    drained += 1;
                }
                Err(_) => break,
            }
        }

        // if we still didn’t get anything, block up to the QUIC timeout for ONE packet
        if !got_packet {
            let _ = may::select! {
                pkt = rx.recv() => {
                    if let Ok(mut data) = pkt {
                        let recv_info = quiche::RecvInfo { to: data.to, from: data.from };
                        if session.conn.recv(&mut data.buf, recv_info).is_ok() {
                            got_packet = true;
                        }
                    }
                },
                _ = may::coroutine::sleep(wait) => { session.conn.on_timeout(); }
            };
        }

        if (session.conn.is_in_early_data() || session.conn.is_established())
            && session.http3_conn.is_none()
        {
            for sc in session.conn.source_ids() {
                let k = key_from_cid(sc);
                if dcids.insert(k) {
                    let _ = ctrl_tx.send(H3CtrlMsg::AddCid(k, tx.clone()));
                }
            }
            match quiche::h3::Connection::with_transport(&mut session.conn, &h3_config) {
                Ok(h3) => session.http3_conn = Some(h3),
                Err(e) => eprintln!("with_transport: {e}"),
            }
        }

        if session.http3_conn.is_some() {
            for stream_id in session.conn.writable() {
                handle_writable(&mut session, stream_id);
            }

            loop {
                // Poll once with a short-lived borrow of h3_conn.
                let polled = {
                    let Some(h3) = session.http3_conn.as_mut() else { break };
                    h3.poll(&mut session.conn)
                };

                match polled {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        session.req_headers = Some(list);
                        session.current_stream_id = Some(sid);
                        // respond immediately
                        handle_h3_request(sid, &mut session, &mut service);
                        session.current_stream_id = None;
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        // For normal HTTP: we already stream_shutdown(Read), just drain & drop.
                        let mut tmp = [0u8; 4096];
                        loop {
                            let res = {
                                let Some(h3) = session.http3_conn.as_mut() else { break };
                                h3.recv_body(&mut session.conn, sid, &mut tmp)
                            };
                            match res {
                                Ok(_n) => {} // drop
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => { eprintln!("recv_body(drop): {e:?}"); break; }
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) => {
                        session.req_body_map.remove(&sid);
                        if session.current_stream_id == Some(sid) {
                            // If you keep current_stream_id for another reason, clear it.
                            session.current_stream_id = None;
                        }
                    }
                    Ok((sid, quiche::h3::Event::Reset { .. })) => {
                        // also drop any pending HTTP response state for that stream
                        session.partial_responses.remove(&sid);
                    }
                    Ok((_id, quiche::h3::Event::PriorityUpdate)) => { /* ignore */ }
                    Ok((_id, quiche::h3::Event::GoAway)) => { /* ignore */ }
                    Err(quiche::h3::Error::Done) => break, // no more events this tick
                    Err(quiche::h3::Error::RequestCancelled) | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_))) |
                    Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
                        // per-stream transport issues, don't kill the whole connection worker
                        continue;
                    }
                    Err(e) => {
                        let _ = session.conn.close(true, 0x1, b"h3 fatal");
                        eprintln!("{} h3 error: {e:?}", session.conn.trace_id());
                        break;
                    }
                }
            }
        }

        // drain sends (flush pending first)
        loop {
            if let Some((to, pkt)) = pending.take() {
                match socket.send_to(&pkt, to) {
                    Ok(_) => { /* sent */ }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        pending = Some((to, pkt));  // keep for next tick
                        break;
                    }
                    Err(e) => {
                        eprintln!("send failed (pending): {e:?}");
                        session.conn.close(false, 0x1, b"send-pending-fail").ok();
                        break;
                    }
                }
                continue; // maybe more to send this tick
            }

            match session.conn.send(&mut out) {
                Ok((n, send_info)) => {
                    match socket.send_to(&out[..n], send_info.to) {
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // keep a copy and retry next tick
                            pending = Some((send_info.to, out[..n].to_vec()));
                            break;
                        }
                        Err(e) => {
                            eprintln!("send failed: {e:?}");
                            session.conn.close(false, 0x1, b"send-fail").ok();
                            break;
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("{} send error: {e:?}", session.conn.trace_id());
                    session.conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            }
        }

        register_scids(&session.conn, &mut dcids, &ctrl_tx, &tx);

        // close handling
        if session.conn.is_closed() {
            // cleanup
            for cid in dcids.drain() {
                let _ = ctrl_tx.send(H3CtrlMsg::RemoveCid(cid));
            }
            break;
        }

        if !got_packet {
            may::coroutine::yield_now();
        }
    }
}

#[cfg(feature = "net-h3-server")]
#[inline]
fn register_scids(
    conn: &quiche::Connection,
    dcids: &mut std::collections::HashSet<ConnKey>,
    ctrl_tx: &may::sync::mpsc::Sender<H3CtrlMsg>,
    tx: &may::sync::mpsc::Sender<Datagram>,
) {
    for sc in conn.source_ids() {
        let k = key_from_cid(sc);
        if dcids.insert(k) {
            let _ = ctrl_tx.send(H3CtrlMsg::AddCid(k, tx.clone()));
        }
    }
}

#[cfg(feature = "net-h3-server")]
#[inline]
fn quic_conn_stream_capacity(conn: &quiche::Connection, sid: u64) -> usize {
    conn.stream_capacity(sid).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use crate::network::http::{
        server::{HFactory, HService},
        session::Session,
        util::{Status, SSLVersion},
    };
    use may::net::TcpStream;
    use std::{
        io::{Read, Write},
        time::Duration,
    };

    struct EchoServer;

    impl HService for EchoServer {
        fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            let req_method = session.req_method().unwrap_or_default().to_owned();
            let req_path = session.req_path().unwrap_or_default().to_owned();
            let req_body = session.req_body(std::time::Duration::from_secs(5))?;
            let body = bytes::Bytes::from(format!(
                "Echo: {req_method:?} {req_path:?}\r\nBody: {req_body:?}"
            ));
            let mut body_len = itoa::Buffer::new();
            let body_len_str = body_len.format(body.len());

            session
                .status_code(Status::Ok)
                .header_str("Content-Type", "text/plain")?
                .header_str("Content-Length", body_len_str)?
                .body(&body)
                .eom();

            if !session.is_h3() && req_method == "POST" {
                return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "H1 POST should return WouldBlock"));
            }
            Ok(())
        }
    }

    impl HFactory for EchoServer {
        type Service = EchoServer;

        fn service(&self, _id: usize) -> EchoServer {
            EchoServer
        }
    }

    // #[cfg(feature = "sys-boring-ssl")]
    // fn create_self_signed_tls_pems() -> (String, String) {
    //     use rcgen::{
    //         CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
    //     };
    //     let mut params: CertificateParams = Default::default();
    //     params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    //     params.not_after = date_time_ymd(4096, 1, 1);
    //     params.distinguished_name = DistinguishedName::new();
    //     params
    //         .distinguished_name
    //         .push(DnType::OrganizationName, "Sib");
    //     params.distinguished_name.push(DnType::CommonName, "Sib");
    //     params.subject_alt_names = vec![
    //         SanType::DnsName("localhost".try_into().unwrap()),
    //         SanType::IpAddress("127.0.0.1".parse().unwrap()),
    //         SanType::IpAddress("::1".parse().unwrap()),
    //     ];
    //     let key_pair = KeyPair::generate().unwrap();
    //     let cert = params.self_signed(&key_pair).unwrap();
    //     (cert.pem(), key_pair.serialize_pem())
    // }

    #[cfg(feature = "sys-boring-ssl")]
    fn create_self_signed_tls_pems() -> (String, String) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        use sha2::{Digest, Sha256};
        use base64::{engine::general_purpose::STANDARD as b64, Engine as _};

        let mut params: CertificateParams = Default::default();
        params.not_before = date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::OrganizationName, "Sib");
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

        (cert_pem, key_pem)
    }


    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_get_response() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));

            // Client sends HTTP request
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();

            assert!(response.contains("/test"));
            eprintln!("\r\nH1 GET Response: {response}");
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(feature = "net-h1-server")]
    #[test]
    fn test_h1_server_post_response() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer.start_h1(addr, 0).expect("h1 start server");

        let client_handler = may::go!(move || {
            use std::io::{Read, Write};
            may::coroutine::sleep(Duration::from_millis(100));

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

            // Should include method, path, and echoed body contents
            assert!(response.contains("POST"));
            assert!(response.contains("/submit"));
            eprintln!("\r\nH1 POST Response: {response}");
        });

        may::join!(server_handle, client_handler);
        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(all(feature = "sys-boring-ssl", feature = "net-h1-server"))]
    #[test]
    fn test_tls_h1_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let ssl = crate::network::http::util::SSL {
            cert_pem: cert_pem.as_bytes(),
            key_pem: key_pem.as_bytes(),
            chain_pem: None,
            min_version: SSLVersion::TLS1_2,
            max_version: SSLVersion::TLS1_3,
            io_timeout: std::time::Duration::from_secs(10),
        };
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1_tls(addr, &ssl, 0, None)
            .expect("h1 TLS start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    #[cfg(all(feature = "sys-boring-ssl", feature = "net-h1-server"))]
    #[test]
    fn test_tls_h1_server_response() {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);
        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let ssl = crate::network::http::util::SSL {
            cert_pem: cert_pem.as_bytes(),
            key_pem: key_pem.as_bytes(),
            chain_pem: None,
            min_version: SSLVersion::TLS1_2,
            max_version: SSLVersion::TLS1_3,
            io_timeout: std::time::Duration::from_secs(10),
        };
        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1_tls(addr, &ssl, 0, None)
            .expect("h1 start server");

        may::join!(server_handle);

        std::thread::sleep(Duration::from_secs(3));
    }

    #[cfg(feature = "net-h3-server")]
    #[tokio::test]
    async fn test_quiche_server_response() -> Result<(), Box<dyn std::error::Error>> {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        std::fs::write("/tmp/cert.pem", certs.0)?;
        std::fs::write("/tmp/key.pem", certs.1)?;

        // Start the server in a background thread
        std::thread::spawn(|| {
            println!("Starting H3 server...");
            EchoServer
                .start_h3_tls("0.0.0.0:8080", ("/tmp/cert.pem", "/tmp/key.pem"), std::time::Duration::from_secs(10), true, (0, NUMBER_OF_WORKERS), false)
                .expect("h3 start server");
        });

        // Wait for the server to be ready
        std::thread::sleep(std::time::Duration::from_millis(1000));

        let client = reqwest::Client::builder()
            .http3_prior_knowledge()
            .danger_accept_invalid_certs(true)
            .build()?;
        let url = "https://127.0.0.1:8080/";
        let res = client
            .get(url)
            .version(reqwest::Version::HTTP_3)
            .send()
            .await?;

        println!("Response: {:?} {}", res.version(), res.status());
        println!("Headers: {:#?}\n", res.headers());
        let body = res.text().await?;
        println!("{body}");

        Ok(())
    }
}