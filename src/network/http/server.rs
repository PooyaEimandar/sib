use bytes::{BufMut, BytesMut};
use may::{net::{TcpListener, TcpStream}, {coroutine, go}};
use std::{{io::{self, Read}}, mem::MaybeUninit};
use crate::network::http::session::HService;

#[cfg(unix)]
use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(unix)]
use may::io::WaitIo;

#[cfg(feature = "net-h3-server")]
const MAX_DATAGRAM_SIZE: usize = 1350;

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
    type Service: HService + Send;
    
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
            coroutine::Builder::new().name("H1Factory".to_owned()).stack_size(stacksize),
            move || {
                
                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;

                for stream in listener.incoming() {
                    let mut stream = mc!(stream);

                    // get the client IP address
                    let peer_addr = stream.peer_addr().unwrap_or(
                        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    );

                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;

                    mc!(stream.set_nodelay(true));
                    let service = self.service(id);
                    let builder = may::coroutine::Builder::new().id(id);
                    let _ = go!(
                        builder,
                        move || if let Err(_e) = serve(&mut stream, peer_addr, service) {
                            //s_error!("service err = {e:?}");
                            stream.shutdown(std::net::Shutdown::Both).ok();
                        }
                    );
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

        let cert = boring::x509::X509::from_pem(ssl.cert_pem).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Cert error: {e}"))
        })?;
        let pkey = boring::pkey::PKey::private_key_from_pem(ssl.key_pem).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Key error: {e}"))
        })?;

        let mut tls_builder =
            boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())
                .map_err(|e| io::Error::other(format!("Builder error: {e}")))?;

        tls_builder.set_private_key(&pkey)?;
        tls_builder.set_certificate(&cert)?;
        if let Some(chain) = ssl.chain_pem {
            // add chain
            for extra in boring::x509::X509::stack_from_pem(chain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Chain error: {e}")))? 
            {
                tls_builder.add_extra_chain_cert(extra)?; 
            }
        }
        tls_builder.set_min_proto_version(ssl.min_version.to_boring())?;
        tls_builder.set_max_proto_version(ssl.max_version.to_boring())?;
        tls_builder.set_alpn_protos(b"\x08http/1.1")?;

        // tls_builder.set_servername_callback(|ssl_ref, _| {
        //     if ssl_ref.servername(boring::ssl::NameType::HOST_NAME).is_none() {
        //         eprintln!("SNI not provided, rejecting connection");
        //         return Err(boring::ssl::SniError::ALERT_FATAL);
        //     }
        //     Ok(())
        // });

        let stacksize = if stack_size > 0 { stack_size } else { 2 * 1024 * 1024 };
        let io_timeout = ssl.io_timeout;
        let tls_acceptor = std::sync::Arc::new(tls_builder.build());
        let listener = TcpListener::bind(addr)?;

        go!(coroutine::Builder::new().name("H1TLSFactory".to_owned()).stack_size(stacksize), move || {
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

                let _ = go!(
                    builder, 
                    move || {
                        match tls_acceptor_cloned.accept(stream) {
                            Ok(mut tls_stream) => {
                                if let Err(e) = serve_tls(&mut tls_stream, peer_addr, service) {
                                    tls_stream.get_mut().shutdown(Shutdown::Both).ok();
                                    eprintln!("serve_tls failed with error: {e} from {peer_addr}");
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS handshake failed {e} from {peer_addr}");
                                match stream_cloned
                                {
                                    Ok(stream_owned) => {
                                        stream_owned.shutdown(Shutdown::Both).ok();
                                    },
                                    Err(e) => {
                                        eprintln!("Failed to shut down the stream after TLS handshake failure: {e} from {peer_addr}");
                                    },
                                };
                            }
                        }
                    }
                );            
            }
        })
    }

    #[cfg(feature = "net-h3-server")]
    fn start_h3_tls(
        self,
        addr: &'static str,
        cert_pem_file_path: &'static str,
        key_pem_file_path: &'static str,
        stack_size: usize,
    ) -> std::io::Result<()>
    {
        use std::collections::HashMap;
        use crate::network::http::{h3_session, h3_session::H3Session};
        
        type H3Sessions = HashMap<quiche::ConnectionId<'static>, H3Session>;

        // create the UDP listening socket.
        let socket = may::net::UdpSocket::bind(addr)?;

        // allocate global buffer in heap
        let mut buf = [0; 65535].to_vec();
        // allocate out buffer in stack
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // create h3 config
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| std::io::Error::other(format!("Failed to create h3 Config because: {e}")))?;

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
            .map_err(|e| std::io::Error::other(format!("Failed to set application protos: {e:?}")))?;

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
        config.verify_peer(false);
        config.enable_early_data();

        let rng = ring::rand::SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to create h3 connection id seed because: {e:?}"
            ))
        })?;

        let mut sessions = H3Sessions::new();
        let local_addr = socket
            .local_addr()
            .map_err(|e| std::io::Error::other(format!("Failed to get local address: {e:?}")))?;

        let stacksize = if stack_size > 0 {
            stack_size
        } else {
            2 * 1024 * 1024 // default to 2 MiB
        };

        let _ = may::go!(
            may::coroutine::Builder::new().name("H3ServiceFactory".to_owned()).stack_size(stacksize),
            move || {
                loop {
                    // Read incoming UDP packets from the socket and feed them to quiche,
                    // until there are no more packets to read.
                    'read: loop {
                        let timeout = sessions
                            .values()
                            .filter_map(|s| s.conn.timeout())
                            .min()
                            .unwrap_or_else(|| std::time::Duration::from_secs(5));

                        let mut from = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
                        let mut len = 0;
                        let mut event = 0;

                        may::select! {
                            recv = socket.recv_from(&mut buf) => {
                                match recv {
                                    Ok((n, f)) => {
                                        from = f;
                                        len = n;
                                        eprintln!("Received {len} bytes from {from}");
                                        event = 0; // continue
                                    }
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::WouldBlock {
                                            event = 1; // yield and break
                                        } else {
                                            event = 3; // panic
                                        }
                                    }
                                }
                            },
                            _ = may::coroutine::sleep(timeout) => {
                                eprintln!("timeout");
                                event = 2; // timeout
                            }
                        };

                        match event {
                            0 => {
                                // Proceed with processing `buf[..len]` and `from`
                            }
                            1 => {
                                may::coroutine::yield_now();
                                break 'read;
                            }
                            2 => {
                                sessions.values_mut().for_each(|c| c.conn.on_timeout());
                                break 'read;
                            }
                            _ => {
                                return;
                            }
                        };

                        eprintln!("got {len} bytes");

                        let pkt_buf = &mut buf[..len];

                        // Parse the QUIC packet's header.
                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("Parsing packet header failed: {e:?}");
                                continue 'read;
                            }
                        };

                        eprintln!("got packet {hdr:?}");
                        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                        let conn_id = conn_id.to_vec().into();

                        // Lookup a connection based on the packet's connection ID. If there
                        // is no connection matching, create a new one.
                        let session = if !sessions.contains_key(&hdr.dcid)
                            && !sessions.contains_key(&conn_id)
                        {
                            if hdr.ty != quiche::Type::Initial {
                                eprintln!("Packet is not Initial");
                                continue 'read;
                            }

                            if !quiche::version_is_supported(hdr.version) {
                                eprintln!("Doing version negotiation");

                                let len =
                                    match quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            eprintln!("quiche negotiate version failed: {e:?}");
                                            return;
                                        }
                                    };
                                let out = &out[..len];

                                if let Err(e) = socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        eprintln!("send() would block");
                                        break;
                                    }
                                    eprintln!("send() failed: {e:?}");
                                }
                                continue 'read;
                            }

                            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                            scid.copy_from_slice(&conn_id);

                            let scid = quiche::ConnectionId::from_ref(&scid);

                            // Token is always present in Initial packets.
                            let token = match hdr.token.as_ref() {
                                Some(v) => v,
                                None => {
                                    eprintln!("No token in Initial packet");
                                    return;
                                }
                            };

                            // Do stateless retry if the client didn't send a token.
                            if token.is_empty() {
                                eprintln!("Doing stateless retry");

                                let new_token = mint_token(&hdr, &from);

                                let len = match quiche::retry(
                                    &hdr.scid,
                                    &hdr.dcid,
                                    &scid,
                                    &new_token,
                                    hdr.version,
                                    &mut out,
                                ) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        eprintln!("quiche retry failed: {e:?}");
                                        return;
                                    }
                                };

                                let out = &out[..len];

                                if let Err(e) = socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        eprintln!("send() would block");
                                        break;
                                    }
                                    eprintln!("send() failed: {e:?}");
                                }
                                continue 'read;
                            }

                            let odcid = validate_token(&from, token);

                            // The token was not valid, meaning the retry failed, so
                            // drop the packet.
                            if odcid.is_none() {
                                eprintln!("Invalid address validation token");
                                continue 'read;
                            }

                            if scid.len() != hdr.dcid.len() {
                                eprintln!("Invalid destination connection ID");
                                continue 'read;
                            }

                            // Reuse the source connection ID we sent in the Retry packet,
                            // instead of changing it again.
                            let scid = hdr.dcid.clone();

                            eprintln!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                            let conn = match quiche::accept(
                                &scid,
                                odcid.as_ref(),
                                local_addr,
                                from,
                                &mut config,
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("quiche accept failed: {e:?}");
                                    return;
                                }
                            };

                            let session = h3_session::new_session(from, conn);

                            sessions.insert(scid.clone(), session);
                            match sessions.get_mut(&scid) {
                                Some(v) => v,
                                None => {
                                    eprintln!("Failed to get session with scid={scid:?}");
                                    return;
                                }
                            }
                        } else {
                            match sessions.get_mut(&hdr.dcid) {
                                Some(v) => v,
                                None => match sessions.get_mut(&conn_id) {
                                    Some(v) => v,
                                    None => {
                                        eprintln!(
                                            "Failed to get session with dcid={:?} or conn_id={:?}",
                                            hdr.dcid, conn_id
                                        );
                                        return;
                                    }
                                },
                            }
                        };

                        let to = match socket.local_addr() {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("Failed to get local address: {e:?}");
                                return;
                            }
                        };
                        let recv_info = quiche::RecvInfo { to, from };

                        // Process potentially coalesced packets.
                        let read = match session.conn.recv(pkt_buf, recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("{} recv failed: {:?}", session.conn.trace_id(), e);
                                continue 'read;
                            }
                        };
                        eprintln!("{} processed {} bytes", session.conn.trace_id(), read);

                        // Flush handshake and other early packets
                        loop {
                            match session.conn.send(&mut out) {
                                Ok((write, send_info)) => {
                                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                                        if e.kind() != std::io::ErrorKind::WouldBlock {
                                            eprintln!("send failed: {e:?}");
                                        }
                                    }
                                    eprintln!("{} wrote {} bytes", session.conn.trace_id(), write);
                                }
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    eprintln!("{} send error: {:?}", session.conn.trace_id(), e);
                                    session.conn.close(false, 0x1, b"fail").ok();
                                    break;
                                }
                            }
                        }
                        eprintln!(
                            "{} connection stats: {:?}",
                            session.conn.trace_id(),
                            session.conn.stats()
                        );

                        // Create a new HTTP/3 connection as soon as the QUIC connection
                        // is established.
                        if (session.conn.is_in_early_data() || session.conn.is_established())
                            && session.http3_conn.is_none()
                        {
                            eprintln!(
                                "{} QUIC handshake completed, now trying HTTP/3",
                                session.conn.trace_id()
                            );

                            let h3_conn = match quiche::h3::Connection::with_transport(
                                &mut session.conn,
                                &h3_config,
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("failed to create HTTP/3 connection: {e}");
                                    continue 'read;
                                }
                            };

                            // TODO: sanity check h3 connection before adding to map
                            session.http3_conn = Some(h3_conn);
                        }

                        if session.http3_conn.is_some() {
                            // Handle writable streams.
                            for stream_id in session.conn.writable() {
                                handle_writable(session, stream_id);
                            }

                            // Process HTTP/3 events.
                            loop {
                                let http3_conn = match session.http3_conn.as_mut() {
                                    Some(v) => v,
                                    None => {
                                        eprintln!(
                                            "{} HTTP/3 connection is not initialized",
                                            session.conn.trace_id()
                                        );
                                        return;
                                    }
                                };

                                match http3_conn.poll(&mut session.conn) {
                                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                        session.req_headers = Some(list);

                                        match stream_id.try_into() {
                                            Ok(id) => {
                                                let mut service = self.service(id);
                                                handle_h3_request(stream_id, session, &mut service);
                                            },
                                            Err(_) => {
                                                eprintln!("{} invalid stream id {}", session.conn.trace_id(), stream_id);
                                                return;
                                            }
                                        };
                                    }
                                    Ok((stream_id, quiche::h3::Event::Data)) => {
                                        eprintln!(
                                            "{} got data on stream id {}",
                                            session.conn.trace_id(),
                                            stream_id
                                        );
                                    }
                                    Ok((_stream_id, quiche::h3::Event::Finished)) => (),
                                    Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),
                                    Ok((
                                        _prioritized_element_id,
                                        quiche::h3::Event::PriorityUpdate,
                                    )) => (),
                                    Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),
                                    Err(quiche::h3::Error::Done) => {
                                        break;
                                    }
                                    Err(e) => {
                                        eprintln!("{} HTTP/3 error {:?}", session.conn.trace_id(), e);

                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Generate outgoing QUIC packets for all active connections and send
                    // them on the UDP socket, until quiche reports that there are no more
                    // packets to be sent.
                    for session in sessions.values_mut() {
                        loop {
                            let (write, send_info) = match session.conn.send(&mut out) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => {
                                    eprintln!("{} done writing", session.conn.trace_id());
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("{} send failed: {:?}", session.conn.trace_id(), e);
                                    session.conn.close(false, 0x1, b"fail").ok();
                                    break;
                                }
                            };
                            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    eprintln!("send() would block");
                                    break;
                                }
                                eprintln!("send() failed: {e:?}");
                            }
                            eprintln!("{} written {} bytes", session.conn.trace_id(), write);
                        }
                    }

                    // Garbage collect closed connections.
                    sessions.retain(|_, ref mut s| {
                        eprintln!("Collecting garbage");
                        if s.conn.is_closed() {
                            eprintln!(
                                "{} connection collected {:?}",
                                s.conn.trace_id(),
                                s.conn.stats()
                            );
                        }
                        !s.conn.is_closed()
                    });
                }
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
fn write(stream: &mut impl std::io::Write, rsp_buf: &mut BytesMut) -> io::Result<usize> {
    use bytes::Buf;
    use std::io::IoSlice;

    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    let mut write_cnt = 0;
    while write_cnt < len {
        let slice = IoSlice::new(unsafe { write_buf.get_unchecked(write_cnt..) });
        match stream.write_vectored(std::slice::from_ref(&slice)) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed")),
            Ok(n) => write_cnt += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    rsp_buf.advance(write_cnt);
    Ok(write_cnt)
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
    // read the socket for requests
    let blocked = read(stream, req_buf)?;
    loop {
        // create a new session

        use crate::network::http::h1_session;
        let mut headers = [MaybeUninit::uninit(); h1_session::MAX_HEADERS];
        let mut sess = match h1_session::new_session(stream, peer_addr, &mut headers, req_buf, rsp_buf)? {
            Some(sess) => sess,
            None => break,
        };
        // call the service with the session
        if let Err(e) = service.call(&mut sess) {
            if e.kind() == std::io::ErrorKind::ConnectionAborted {
                return Err(e);
            }
        }
    }
    // send the response back to client
    write(stream, rsp_buf)?;
    Ok(blocked)
}

#[cfg(unix)]
fn serve<T: HService>(stream: &mut TcpStream, peer_addr: SocketAddr,mut service: T) -> io::Result<()> {
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
                    match h1session::new_session(stream, &mut headers, &mut req_buf, &mut rsp_buf)? {
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
fn handle_h3_request<T: HService>(stream_id: u64, session: &mut super::h3_session::H3Session, service: &mut T)
{
    use super::h3_session::PartialResponse;

    // We decide the response based on headers alone, so stop reading the
    // request stream so that any body is ignored and pointless Data events
    // are not generated.
    match session.conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{} stream shutdown failed: {:?}", session.conn.trace_id(), e);
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

    let written = match http3_conn.send_body(&mut session.conn, stream_id, &session.rsp_body, true) {
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


    println!("headers are {:?}", session.rsp_headers);
    println!("body is {:?}", session.rsp_body);
    
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
pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    use quiche::h3::NameValue;

    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use crate::network::http::{
        server::{HService, HFactory}, session::Session, util::Status
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
            let req_body = session.req_body(std::time::Duration::from_secs(1))?;
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
            Ok(())
        }
    }

    impl HFactory for EchoServer {
        type Service = EchoServer;

        fn service(&self, _id: usize) -> EchoServer {
            EchoServer
        }
    }

    #[cfg(feature = "sys-boring-ssl")]
    fn create_self_signed_tls_pems() -> (String, String) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        let mut params: CertificateParams = Default::default();
        params.not_before = rcgen::date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn test_h1_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        may::config()
            .set_workers(NUMBER_OF_WORKERS);

        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1(addr, 0)
            .expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    #[test]
    fn test_h1_server_response() {
        const NUMBER_OF_WORKERS: usize = 1;
        may::config()
            .set_workers(NUMBER_OF_WORKERS);

        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = EchoServer
            .start_h1(addr, 0)
            .expect("h1 start server");

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
            print!("Response: {response}");
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(2));
    }

    #[cfg(feature = "sys-boring-ssl")]
    #[test]
    fn test_tls_h1_gracefull_shutdown() {
        const NUMBER_OF_WORKERS: usize = 1;
        may::config()
            .set_workers(NUMBER_OF_WORKERS);

        let (cert_pem, key_pem) = create_self_signed_tls_pems();
        let ssl = crate::network::http::util::SSL
        {
            cert_pem: cert_pem.as_bytes(),
            key_pem: key_pem.as_bytes(),
            chain_pem: None,
            min_version: crate::network::http::util::SSLVersion::TLS1_2,
            max_version: crate::network::http::util::SSLVersion::TLS1_3,
            io_timeout: std::time::Duration::from_secs(10)
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

    // #[test]
    // fn test_tls_h1_server_response() {
    //     let (cert_pem, key_pem) = create_self_signed_tls_pems();
    //     // Pick a port and start the server
    //     let addr = "127.0.0.1:8080";
    //     let server_handle = H1Server(EchoService)
    //         .start_tls(addr, cert_pem.as_bytes(), key_pem.as_bytes())
    //         .expect("h1 start server");

    //     may::join!(server_handle);

    //     std::thread::sleep(Duration::from_secs(200));
    // }

    #[tokio::test]
    async fn test_quiche_server_response() -> Result<(), Box<dyn std::error::Error>> {
        const NUMBER_OF_WORKERS: usize = 1;
        may::config()
            .set_workers(NUMBER_OF_WORKERS);
        
        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        std::fs::write("/tmp/cert.pem", certs.0)?;
        std::fs::write("/tmp/key.pem", certs.1)?;

        // Start the server in a background thread
        std::thread::spawn(|| {
            println!("Starting H3 server...");
            EchoServer.start_h3_tls("0.0.0.0:8080", "/tmp/cert.pem", "/tmp/key.pem", 0)
            .expect("h3 start server");
        });

        // Wait for the server to be ready
        std::thread::sleep(std::time::Duration::from_millis(300));

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
