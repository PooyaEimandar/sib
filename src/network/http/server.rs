#[cfg(feature = "net-h3-server")]
use crate::network::http::session::HServiceWebTransport;

use crate::network::http::session::HService;
use bytes::{BufMut, BytesMut};
use may::{
    net::{TcpListener, TcpStream},
    {coroutine, go},
};
use std::{
    io::{self, Read},
    mem::MaybeUninit,
};

#[cfg(unix)]
use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(unix)]
use may::io::WaitIo;

#[cfg(feature = "net-h3-server")]
const MAX_DATAGRAM_SIZE: usize = 1200;

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

pub trait HFactory: Send + Sized + 'static {

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "net-h3-server"))] {
            type Service: HService + HServiceWebTransport + Send;
        }
        else {
            type Service: HService + Send;
        }
    }
 
    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

    /// Start the http service
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

    #[cfg(feature = "sys-boring-ssl")]
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
        cert_pem_file_path: &str,
        key_pem_file_path: &str,
        verify_peer: bool,
        stack_size: usize,
        dgram_size: Option<(usize, usize)>
    ) -> std::io::Result<()> {
        // create the UDP listening socket.
        let socket = std::sync::Arc::new(may::net::UdpSocket::bind(addr)?);
        let local_addr = socket
            .local_addr()
            .map_err(|e| std::io::Error::other(format!("Failed to get local address: {e:?}")))?;

        // create QUIC config
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| std::io::Error::other(format!("Quiche builder got an error: {e}")))?;

        config
            .load_cert_chain_from_pem_file(cert_pem_file_path)
            .map_err(|e| std::io::Error::other(format!("Failed to load cert chain: {e:?}")))?;

        config
            .load_priv_key_from_pem_file(key_pem_file_path)
            .map_err(|e| std::io::Error::other(format!("Failed to load private key: {e:?}")))?;

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|e| {
                std::io::Error::other(format!("Failed to set application protos: {e:?}"))
            })?;

        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.verify_peer(verify_peer);
        config.enable_early_data();

        let extend_connect = if let Some((r_len, s_len)) = dgram_size{
            config.enable_dgram(true, r_len, s_len);
            true
        } else {
            false
        };

        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };

        let _ = may::go!(
            may::coroutine::Builder::new()
                .name("H3ServiceFactory".to_owned())
                .stack_size(stacksize),
            move || {
                quic_dispatcher(socket, config, local_addr, extend_connect, move |id| self.service(id));
            }
        );
        Ok(())
    }
}

#[inline]
pub(crate) fn reserve_buf(buf: &mut BytesMut) {
    let rem = buf.capacity() - buf.len();
    if rem < MIN_BUF_LEN {
        buf.reserve(BUF_LEN - rem);
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(all(unix, feature = "sys-boring-ssl"))]
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

    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);
    loop {
        // read the socket for requests
        reserve_buf(&mut req_buf);
        let read_buf: &mut [u8] = unsafe { std::mem::transmute(&mut *req_buf.chunk_mut()) };
        let read_cnt = stream.read(read_buf)?;
        if read_cnt == 0 {
            //connection was closed
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        unsafe { req_buf.advance_mut(read_cnt) };

        // prepare the requests
        if read_cnt > 0 {
            loop {
                let mut headers = [MaybeUninit::uninit(); h1session::MAX_HEADERS];
                let mut sess =
                    match h1session::new_session(stream, &mut headers, &mut req_buf, &mut rsp_buf)?
                    {
                        Some(sess) => sess,
                        None => break,
                    };

                if let Err(e) = service.call(&mut sess) {
                    if e.kind() == std::io::ErrorKind::ConnectionAborted {
                        // abort the connection immediately
                        return Err(e);
                    }
                }
            }
        }

        // send the result back to client
        stream.write_all(&rsp_buf)?;
    }
}

#[cfg(feature = "net-h3-server")]
type ConnKey = [u8; quiche::MAX_CONN_ID_LEN];

#[cfg(feature = "net-h3-server")]
enum H3CtrlMsg {
    BindAddr(std::net::SocketAddr, may::sync::mpsc::Sender<Datagram>),
    UnbindAddr(std::net::SocketAddr),
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
    let http3_conn = &mut match session.http3_conn.as_mut() {
        Some(v) => v,
        None => {
            eprintln!(
                "{} HTTP/3 connection is not initialized while checking handle_writable",
                conn.trace_id()
            );
            return;
        }
    };

    //s_debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !session.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = match session.partial_responses.get_mut(&stream_id) {
        Some(v) => v,
        None => {
            eprintln!(
                "{} no partial response for stream id {}",
                conn.trace_id(),
                stream_id
            );
            return;
        }
    };

    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => (),
            Err(quiche::h3::Error::StreamBlocked) => {
                return;
            }
            Err(e) => {
                eprintln!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        }
    }

    resp.headers = None;

    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            session.partial_responses.remove(&stream_id);
            eprintln!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        session.partial_responses.remove(&stream_id);
    }
}

#[cfg(feature = "net-h3-server")]
fn handle_h3_request<S: HService>(
    stream_id: u64,
    session: &mut super::h3_session::H3Session,
    service: &mut S,
) {
    use super::h3_session::PartialResponse;

    // We decide the response based on headers alone, so stop reading the
    // request stream so that any body is ignored and pointless Data events
    // are not generated.
    match session
        .conn
        .stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
    {
        Ok(_) => (),
        Err(e) => {
            eprintln!(
                "{} stream shutdown failed: {:?}",
                session.conn.trace_id(),
                e
            );
            return;
        }
    }

    let _ = service.call(session);

    let http3_conn = match session.http3_conn.as_mut() {
        Some(v) => v,
        None => {
            eprintln!(
                "{} HTTP/3 connection is not initialized while handling request",
                session.conn.trace_id()
            );
            return;
        }
    };

    match http3_conn.send_response(&mut session.conn, stream_id, &session.rsp_headers, false) {
        Ok(v) => v,

        Err(quiche::h3::Error::StreamBlocked) => {
            let response = PartialResponse {
                headers: Some(session.rsp_headers.clone()),
                body: session.rsp_body.clone(),
                written: 0,
            };

            session.partial_responses.insert(stream_id, response);
            return;
        }

        Err(e) => {
            eprintln!("{} stream send failed {:?}", session.conn.trace_id(), e);
            return;
        }
    }

    let written = match http3_conn.send_body(&mut session.conn, stream_id, &session.rsp_body, true)
    {
        Ok(v) => v,
        Err(quiche::h3::Error::Done) => 0,
        Err(e) => {
            eprintln!("{} stream send failed {:?}", session.conn.trace_id(), e);
            return;
        }
    };

    if written < session.rsp_body.len() {
        let response = PartialResponse {
            headers: None,
            body: session.rsp_body.clone(),
            written,
        };

        session.partial_responses.insert(stream_id, response);
    }
}
#[cfg(feature = "net-h3-server")]
fn quic_dispatcher<S, F>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    mut config: quiche::Config,
    local_addr: SocketAddr,
    extend_connect: bool,
    mut call_service: F,
) where
    S: HService + HServiceWebTransport + Send + 'static,
    F: FnMut(usize) -> S + Send + 'static,
{
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    type WorkerTx = may::sync::mpsc::Sender<Datagram>;
    struct AddrEntry { tx: WorkerTx, expires: Instant }

    let mut by_cid: HashMap<ConnKey, WorkerTx> = HashMap::new();
    let mut by_addr: HashMap<SocketAddr, AddrEntry> = HashMap::new();
    const BY_ADDR_TTL: Duration = Duration::from_secs(10);

    // control channel
    let (ctrl_tx, ctrl_rx) = may::sync::mpsc::channel::<H3CtrlMsg>();

    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        // drain control messages
        while let Ok(msg) = ctrl_rx.try_recv() {
            match msg {
                H3CtrlMsg::BindAddr(addr, tx) => {
                    by_addr.insert(addr, AddrEntry { tx, expires: Instant::now() + BY_ADDR_TTL });
                }
                H3CtrlMsg::UnbindAddr(addr) => {
                    by_addr.remove(&addr);
                },
                H3CtrlMsg::AddCid(cid, tx) => { 
                    by_cid.insert(cid, tx); 
                }
                H3CtrlMsg::RemoveCid(cid) => { 
                    by_cid.remove(&cid); 
                }
            }
        }

        let now = Instant::now();
        by_addr.retain(|_, v| v.expires > now);

        // read a UDP datagram
        let mut buf = BytesMut::with_capacity(65535);
        buf.resize(65535, 0);
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                may::coroutine::yield_now();
                continue;
            }
            Err(e) => {
                eprintln!("recv_from error: {e:?}");
                continue;
            }
        };
        buf.truncate(n);

        // parse QUIC header
        let hdr = match quiche::Header::from_slice(&mut buf[..], quiche::MAX_CONN_ID_LEN) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Header parse failed: {e:?}");
                continue;
            }
        };

        let dcid_key = key_from_cid(&hdr.dcid);

        // fast path: known DCID → route to worker
        if let Some(tx) = by_cid.get(&dcid_key) {
            let _ = tx.send(Datagram {
                buf: buf.to_vec(),
                from,
                to: local_addr,
            });
            continue;
        }

        // fallback path: known address → route and learn new DCID
        if let Some(entry) = by_addr.get_mut(&from) {
            entry.expires = Instant::now() + BY_ADDR_TTL; // refresh the ttl
            let tx = &entry.tx;
            let _ = tx.send(Datagram { buf: buf.to_vec(), from, to: local_addr });
            by_cid.insert(dcid_key, tx.clone());
            continue;
        }

        // new connection handling
        if hdr.ty != quiche::Type::Initial {
            // version negotiation if needed
            if !quiche::version_is_supported(hdr.version) {
                if let Ok(len) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                    let _ = socket.send_to(&out[..len], from);
                }
            }
            continue;
        }

        // VN again for robustness
        if !quiche::version_is_supported(hdr.version) {
            if let Ok(len) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                let _ = socket.send_to(&out[..len], from);
            }
            continue;
        }

        // stateless retry if no/invalid token
        let token = hdr.token.as_deref().unwrap_or(&[]);
        let odcid_opt = if token.is_empty() {
            Some(quiche::ConnectionId::from_ref(&hdr.dcid))
        } else {
            validate_token(&from, token)
        };
        if odcid_opt.is_none() {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();

            // make a server CID (any random bytes up to MAX_CONN_ID_LEN)
            let cid_len = hdr.dcid.len().min(quiche::MAX_CONN_ID_LEN);
            let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut scid_bytes[..cid_len]).expect("rng");
            let scid = quiche::ConnectionId::from_ref(&scid_bytes[..cid_len]);

            let new_token = mint_token(&hdr, &from);
            if let Ok(len) = quiche::retry(
                &hdr.scid,
                &hdr.dcid,
                &scid,
                &new_token,
                hdr.version,
                &mut out,
            ) {
                let _ = socket.send_to(&out[..len], from);
            }
            continue;
        }

        // accept
        let conn =
            match quiche::accept(&hdr.dcid, odcid_opt.as_ref(), local_addr, from, &mut config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("accept failed: {e:?}");
                    continue;
                }
            };

        // spawn worker
        let (tx, rx) = may::sync::mpsc::channel::<Datagram>();
        // We bind by address immediately; the worker will also AddCid as needed.
        by_addr.insert(from, AddrEntry { tx: tx.clone(), expires: Instant::now() + BY_ADDR_TTL });

        // Bind the current DCID too (client is using hdr.dcid now)
        by_cid.insert(dcid_key, tx.clone());

        // seed worker with the first datagram
        let _ = tx.send(Datagram {
            buf: buf.to_vec(),
            from,
            to: local_addr,
        });

        let socket_cloned = socket.clone();
        let ctrl_tx_cloned = ctrl_tx.clone();
        let service = call_service(dcid_key[0] as usize);
        may::go!(move || {
            handle_quic_connection(
                socket_cloned,
                conn,
                from,
                (rx, tx.clone()),
                ctrl_tx_cloned,
                (dcid_key, extend_connect),
                service,
            );
        });
    }
}

#[cfg(feature = "net-h3-server")]
fn handle_quic_connection<S: HService + HServiceWebTransport + 'static>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    conn: quiche::Connection,
    from: SocketAddr,
    (rx, tx): (may::sync::mpsc::Receiver<Datagram>, may::sync::mpsc::Sender<Datagram>),
    ctrl_tx: may::sync::mpsc::Sender<H3CtrlMsg>,
    (initial_dcid, extend_connect): (ConnKey, bool),
    mut service: S,
) {
    use std::collections::{HashSet, HashMap};
    use crate::network::http::h3_session;

    let mut dcids: HashSet<ConnKey> = HashSet::new();
    let mut wt_connect_streams: HashSet<u64> = HashSet::new();
    let mut wt_quarter_to_connect: HashMap<u64, u64> = HashMap::new();
    let mut wt_stream_owner: HashMap<u64, u64> = HashMap::new();
    let mut wt_assoc_hdr_buf: HashMap<u64, Vec<u8>> = HashMap::new();

    let mut session = h3_session::new_session(from, conn);

    // Tell dispatcher we own this addr
    let _ = ctrl_tx.send(H3CtrlMsg::BindAddr(from, tx.clone()));

    // Register the initial DCID as the primary key for routing
    if dcids.insert(initial_dcid)
    {
        let _ = ctrl_tx.send(H3CtrlMsg::AddCid(initial_dcid, tx.clone()));
    }

    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut h3_config = match quiche::h3::Config::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("h3 Config new: {e}");
            return;
        }
    };

    if extend_connect {
        h3_config.set_qpack_max_table_capacity(64 * 1024);
        h3_config.set_qpack_blocked_streams(100);
        h3_config.set_max_field_section_size(64 * 1024);
        h3_config.enable_extended_connect(true);
    }

    loop {
        let timeout = session
            .conn
            .timeout()
            .unwrap_or_else(|| std::time::Duration::from_secs(5));
        let mut got_packet = false;

        let _ = may::select! {
            pkt = rx.recv() => {
                match pkt {
                    Ok(mut data) => {
                        let recv_info = quiche::RecvInfo { to: data.to, from: data.from };
                        if let Err(e) = session.conn.recv(&mut data.buf, recv_info) {
                            if e != quiche::Error::Done {
                                eprintln!("{} recv failed: {e:?}", session.conn.trace_id());
                            }
                        } else {
                            got_packet = true;
                        }
                    }
                    Err(_) => return, // channel closed
                }
            },
            _ = may::coroutine::sleep(timeout) => {
                session.conn.on_timeout();
            }
        };

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
                        
                        if extend_connect {
                            use quiche::h3::NameValue;

                            let has_connect = list
                                .iter()
                                .find(|h| h.name() == b":method")
                                .map(|h| h.value().eq_ignore_ascii_case(b"CONNECT"))
                                .unwrap_or(false);

                            let has_webtransport = list
                                .iter()
                                .find(|h| h.name() == b":protocol")
                                .map(|h| h.value().eq_ignore_ascii_case(b"webtransport"))
                                .unwrap_or(false);

                            session.req_headers = Some(list);
                            session.current_stream_id = Some(sid);

                            if has_connect && has_webtransport {
                                let peer_ok = match session.http3_conn.as_mut() {
                                    Some(h3) => h3.extended_connect_enabled_by_peer(),
                                    None => false,
                                };

                                if !peer_ok {
                                    let _ = {
                                        let Some(h3) = session.http3_conn.as_mut() else { continue };
                                        let rsp = [quiche::h3::Header::new(b":status", b"421")];
                                        h3.send_response(&mut session.conn, sid, &rsp, true)
                                    };
                                    continue;
                                }

                                {
                                    let Some(h3) = session.http3_conn.as_mut() else { continue };
                                    let rsp = [quiche::h3::Header::new(b":status", b"200")];
                                    match h3.send_response(&mut session.conn, sid, &rsp, false) {
                                        Ok(_) => {
                                            wt_connect_streams.insert(sid);
                                            service.on_wt_open(&mut session, sid);
                                            wt_quarter_to_connect.insert(wt_quarter_id(sid), sid);
                                        },
                                        Err(e) => {
                                            eprintln!("WT 200 send failed on sid {sid}: {e:?}");
                                        }
                                    }
                                }

                                continue;
                            }
                        }
                        else {
                            session.req_headers = Some(list);
                            session.current_stream_id = Some(sid);
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        // WT CONNECT streams shouldn't carry HTTP DATA frames; if they do, drain & ignore capsules.
                        if extend_connect && wt_connect_streams.contains(&sid) {
                            let mut tmp = [0u8; 4096];
                            loop {
                                let res = {
                                    let Some(h3) = session.http3_conn.as_mut() else { break };
                                    h3.recv_body(&mut session.conn, sid, &mut tmp)
                                };
                                match res {
                                    Ok(_n) => { /* ignore capsules */ }
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(e) => {
                                        eprintln!("WT CONNECT data recv err: {e:?}");
                                        break;
                                    }
                                }
                            }
                            continue;
                        }

                        // For normal streams, read into a local Vec while h3 is borrowed…
                        let mut collected: Vec<u8> = Vec::new();
                        {
                            let mut tmp = [0u8; 4096];
                            loop {
                                let res = {
                                    let Some(h3) = session.http3_conn.as_mut() else { break };
                                    h3.recv_body(&mut session.conn, sid, &mut tmp)
                                };
                                match res {
                                    Ok(n) => collected.extend_from_slice(&tmp[..n]),
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(e) => {
                                        eprintln!("recv_body: {e:?}");
                                        break;
                                    }
                                }
                            }
                        }
                        // …then append to session after the borrow ends.
                        if !collected.is_empty() {
                            session
                                .req_body_map
                                .entry(sid)
                                .or_default()
                                .extend_from_slice(&collected);
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) => {
                        // No h3 borrow needed to handle service & maps.
                        if extend_connect && wt_connect_streams.remove(&sid) {
                            service.on_wt_close(&mut session, sid);
                            wt_quarter_to_connect.remove(&wt_quarter_id(sid));
                            wt_stream_owner.retain(|_, owner| *owner != sid);
                            session.req_body_map.remove(&sid);
                            if session.current_stream_id == Some(sid) {
                                session.current_stream_id = None;
                            }
                            continue;
                        }

                        if session.current_stream_id == Some(sid) {
                            handle_h3_request(sid, &mut session, &mut service);
                            session.current_stream_id = None;
                        }
                        session.req_body_map.remove(&sid);
                    }
                    Ok((sid, quiche::h3::Event::Reset { .. })) => {
                        if extend_connect && wt_connect_streams.remove(&sid) {
                            service.on_wt_close(&mut session, sid);
                            wt_quarter_to_connect.remove(&wt_quarter_id(sid));
                            wt_stream_owner.retain(|_, owner| *owner != sid);
                            if session.current_stream_id == Some(sid) {
                                session.current_stream_id = None;
                            }
                        }
                    }
                    Ok((_id, quiche::h3::Event::PriorityUpdate)) => { /* ignore */ }
                    Ok((_id, quiche::h3::Event::GoAway)) => {
                        if extend_connect {
                            // Close any WT sessions
                            for sid in wt_connect_streams.drain() {
                                service.on_wt_close(&mut session, sid);
                            }
                        }
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        eprintln!("{} h3 error: {e:?}", session.conn.trace_id());
                        break;
                    }
                }
            }
        }

        if extend_connect {
            // WebTransport UNI/BIDI
            if session.http3_conn.is_some() {
                // Iterate QUIC transport streams that are readable this tick
                for sid in session.conn.readable() {
                    // Drain as much as we can this tick. We may not be associated yet.
                    let mut fin_seen = false;
                    let is_uni = (sid & 0x02) != 0;
                    loop {
                        // Reuse a stack buffer for this recv
                        let mut tmp = [0u8; 4096];
                        let (n, fin) = match session.conn.stream_recv(sid, &mut tmp) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => break, // nothing more for now
                            Err(e) => {
                                eprintln!("{} WT stream_recv err on {sid}: {e:?}", session.conn.trace_id());
                                break;
                            }
                        };

                        if n == 0 && !fin {
                            // No bytes and not FIN — nothing else to do now
                            break;
                        }

                        fin_seen |= fin;

                        // Are we already associated to a CONNECT stream?
                        if let Some(&owner) = wt_stream_owner.get(&sid) {
                            // Deliver bytes as data
                            if n > 0 {
                                if is_uni {
                                    service.on_wt_unistream_data(&mut session, owner, sid, &tmp[..n]);
                                } else {
                                    service.on_wt_bistream_data(&mut session, owner, sid, &tmp[..n]);
                                }
                            }
                            continue;
                        }

                        // Not associated yet — accumulate header bytes until we can parse.
                        let buf = wt_assoc_hdr_buf.entry(sid).or_default();
                        if n > 0 {
                            buf.extend_from_slice(&tmp[..n]);
                        }

                        // Try to parse the association header from the accumulated buffer.
                        // parse_wt_stream_assoc expects the header starting at offset 0.
                        if let Some((connect_sid, header_len, is_uni)) = parse_wt_stream_assoc(sid, &buf[..]) {
                            // Only accept association if this CONNECT stream is actually a WT session we opened.
                            if !wt_connect_streams.contains(&connect_sid) {
                                // Not a known WT CONNECT owner — treat as non-WT; drop header buffer.
                                wt_assoc_hdr_buf.remove(&sid);
                                continue;
                            }

                            // Record owner and fire the "open" callback once.
                            wt_stream_owner.insert(sid, connect_sid);
                            if is_uni {
                                service.on_wt_unistream_open(&mut session, connect_sid, sid);
                            } else {
                                service.on_wt_bistream_open(&mut session, connect_sid, sid);
                            }

                            // Deliver any payload bytes that followed the header in the same packets.
                            if buf.len() > header_len {
                                let first_payload = &buf[header_len..];
                                if is_uni {
                                    service.on_wt_unistream_data(&mut session, connect_sid, sid, first_payload);
                                } else {
                                    service.on_wt_bistream_data(&mut session, connect_sid, sid, first_payload);
                                }
                            }

                            // Clear the header buffer now that we’re associated.
                            wt_assoc_hdr_buf.remove(&sid);
                        } else {
                            // Header still incomplete. If FIN arrives before association, we'll drop below.
                        }
                    } // end inner drain loop

                    // Cleanup on stream FIN
                    if fin_seen {
                        wt_stream_owner.remove(&sid);
                        wt_assoc_hdr_buf.remove(&sid);
                    }
                }
            }


            // handle dgram
            if let Some(h3_conn) = session.http3_conn.as_ref() && h3_conn.dgram_enabled_by_peer(&session.conn) {
                // Limit per-tick datagrams
                const MAX_DGRAMS_PER_TICK: usize = 1024;
                let mut drained = 0;
                // scratch buffer for a single QUIC DATAGRAM
                let mut dgram_buf = [0u8; MAX_DATAGRAM_SIZE];
                loop {
                    if drained >= MAX_DGRAMS_PER_TICK { break; }
                    match session.conn.dgram_recv(&mut dgram_buf) {
                        Ok(len) => {
                            let bytes = &dgram_buf[..len];
                            // H3 DATAGRAM format: [quarter-id(varint)][optional ctx(varint)][payload...]
                            if let Some((quarter_id, ctx, payload)) = parse_wt_dgram(bytes) {
                                if let Some(&connect_sid) = wt_quarter_to_connect.get(&quarter_id) {
                                    // Call your service hook
                                    service.on_wt_datagram(&mut session, connect_sid, ctx, payload);
                                } else {
                                    // We haven't seen the CONNECT stream yet
                                    eprintln!("Unknown quarter-id {quarter_id}, len={}", payload.len());
                                }
                            } else {
                                eprintln!("Malformed H3 DATAGRAM");
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            eprintln!("{} QUIC dgram_recv error: {e:?}", session.conn.trace_id());
                            break;
                        }
                    }
                    drained += 1;
                }
            }
        }

        // drain sends
        loop {
            match session.conn.send(&mut out) {
                Ok((n, send_info)) => {
                    if let Err(e) = socket.send_to(&out[..n], send_info.to) {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            eprintln!("send failed: {e:?}");
                        } else {
                            may::coroutine::yield_now();
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

        if session.conn.is_closed() {
            if extend_connect {
                // best-effort close callbacks for any remaining WT sessions
                for sid in wt_connect_streams.drain() {
                    service.on_wt_close(&mut session, sid);
                }
            }
            // cleanup
            let _ = ctrl_tx.send(H3CtrlMsg::UnbindAddr(from));
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

/// Parses a QUIC varint from `buf`
#[cfg(feature = "net-h3-server")]
#[inline]
fn read_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() { return None; }
    let b0 = buf[0];
    // Two most significant bits determine length:
    let (_prefix, len) = match b0 >> 6 {
        0b00 => (0, 1),
        0b01 => (1, 2),
        0b10 => (2, 4),
        0b11 => (3, 8),
        _ => unreachable!(),
    };
    if buf.len() < len { return None; }

    let mut value = (b0 & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | (b as u64);
    }

    Some((value, len))
}

#[cfg(feature = "net-h3-server")]
#[inline]
fn wt_quarter_id(connect_sid: u64) -> u64 { connect_sid / 4 }

#[cfg(feature = "net-h3-server")]
#[inline]
fn parse_wt_dgram(b: &[u8]) -> Option<(u64 /*quarter*/, Option<u64> /*ctx*/, &[u8]/*payload*/)> {
    let (qid, n1) = read_quic_varint(b)?;
    if n1 == b.len() { return Some((qid, None, &[])); }
    // Try read context id; if it fails, treat as no ctx and payload = rest
    if let Some((ctx, n2)) = read_quic_varint(&b[n1..]) {
        Some((qid, Some(ctx), &b[n1 + n2..]))
    } else {
        Some((qid, None, &b[n1..]))
    }
}

#[cfg(feature = "net-h3-server")]
#[inline]
fn parse_wt_stream_assoc(stream_id: u64, buf: &[u8]) -> Option<(u64 /*connect_sid*/, usize /*hdr_len*/, bool /*is_uni*/)> {
    const WT_UNI_STREAM_TYPE: u64 = 0x54; // draft-ietf-webtrans-http3
    if (stream_id & 0x02) != 0 {
        // uni
        let (ty, n1) = read_quic_varint(buf)?;
        if ty != WT_UNI_STREAM_TYPE { return None; }
        let (connect_sid, n2) = read_quic_varint(&buf[n1..])?;
        Some((connect_sid, n1 + n2, true))
    } else {
        // bi
        let (connect_sid, n1) = read_quic_varint(buf)?;
        Some((connect_sid, n1, false))
    }
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

    #[cfg(feature = "net-h3-server")]
    impl crate::network::http::session::HServiceWebTransport for EchoServer {
        fn on_wt_open<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64) {
            eprintln!("Hi Webtransport");
        }
        fn on_wt_close<SE: Session>(&mut self, _session: &mut SE, _connect_sid: u64) {
            eprintln!("Bye Webtransport");
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
                .start_h3_tls("0.0.0.0:8080", "/tmp/cert.pem", "/tmp/key.pem", true, 0, Some((1350, 1350)))
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