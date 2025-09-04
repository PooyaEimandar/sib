use crate::network::http::session::HService;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{self};
use std::net::SocketAddr;

const MAX_DATAGRAM_SIZE: usize = 1200; // RFC-safe default
const TOKEN_TTL_SECS: u64 = 120; // 2 minutes

type ConnKey = [u8; quiche::MAX_CONN_ID_LEN];

enum H3CtrlMsg {
    AddCid(ConnKey, may::sync::mpsc::Sender<Datagram>),
    RemoveCid(ConnKey),
}

#[derive(Clone)]
struct RetryKey {
    secret: [u8; 32],
}

#[derive(Debug)]
struct Datagram {
    buf: Box<[u8; 65535]>,
    len: usize,
    from: SocketAddr,
    to: SocketAddr,
}

// rotate this key periodically (keep previous+current in memory).
fn retry_key_current() -> RetryKey {
    RetryKey {
        secret: *b"0123456789abcdef0123456789abcdef",
    }
}

#[inline]
fn key_from_cid(cid: &quiche::ConnectionId<'_>) -> ConnKey {
    let mut k = [0u8; quiche::MAX_CONN_ID_LEN];
    let s = cid.len().min(quiche::MAX_CONN_ID_LEN);
    k[..s].copy_from_slice(cid.as_ref());
    k
}

pub(crate) fn build_quiche_config(
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
    config.set_initial_max_data(32 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(8 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(16 * 1024 * 1024);
    config.set_initial_max_streams_bidi(256);
    config.set_initial_max_streams_uni(64);
    config.set_disable_active_migration(true);
    config.verify_peer(verify_peer);
    config.enable_early_data();
    if extend_connect {
        config.enable_dgram(true, MAX_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE);
    }
    Ok(config)
}

fn mint_token_secure(key: &RetryKey, odcid: &[u8], client_ip: &std::net::SocketAddr) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ip = match client_ip.ip() {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    let mut payload = Vec::with_capacity(8 + 1 + ip.len() + odcid.len());
    payload.extend_from_slice(&ts.to_be_bytes());
    payload.push(ip.len() as u8);
    payload.extend_from_slice(&ip);
    payload.extend_from_slice(odcid);

    let mut mac = Hmac::<Sha256>::new_from_slice(&key.secret).unwrap();
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();

    // token = payload || tag
    let mut out = payload;
    out.extend_from_slice(&tag);
    out
}

fn validate_token_secure(
    key: &RetryKey,
    token: &[u8],
    client_ip: &std::net::SocketAddr,
) -> Option<Vec<u8>> {
    if token.len() < 8 + 1 + 32 {
        return None;
    } // ts + iplen + tag
    let (head, tag) = token.split_at(token.len() - 32);

    let mut mac = Hmac::<Sha256>::new_from_slice(&key.secret).ok()?;
    mac.update(head);
    mac.verify_slice(tag).ok()?; // constant-time check

    // parse head
    let (tsb, rest) = head.split_at(8);
    let ts = u64::from_be_bytes(tsb.try_into().ok()?);
    let (iplenb, rest) = rest.split_first()?;
    let iplen = *iplenb as usize;
    if rest.len() < iplen {
        return None;
    }
    let (ipb, odcid) = rest.split_at(iplen);

    // check IP match
    let want_ip = match client_ip.ip() {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    if ipb != want_ip.as_slice() {
        return None;
    }

    // check TTL
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now.saturating_sub(ts) > TOKEN_TTL_SECS {
        return None;
    }

    Some(odcid.to_vec())
}

/// Handles newly writable streams.
fn handle_writable(session: &mut super::h3_session::H3Session, stream_id: u64) {
    let conn = &mut session.conn;
    let http3_conn = match session.http3_conn.as_mut() {
        Some(h3) => h3,
        None => {
            eprintln!("{} handle_writable with no h3_conn", conn.trace_id());
            return;
        }
    };

    let Some(resp) = session.partial_responses.get_mut(&stream_id) else {
        return;
    };

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
                eprintln!(
                    "{} send_response failed on {}: {:?}",
                    conn.trace_id(),
                    stream_id,
                    e
                );
                return;
            }
        }
        resp.headers = None;
    }

    // Stream body in bounded chunks while we have credit.
    let mut budget = resp.body.len().saturating_sub(resp.written);

    while resp.written < resp.body.len() && budget > 0 {
        let cap = quic_conn_stream_capacity(conn, stream_id);
        if cap == 0 {
            return;
        }

        let want = cap.min(budget);
        let chunk = resp.body.chunk_at(resp.written, want);
        if chunk.is_empty() {
            return;
        }

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
                eprintln!(
                    "{} send_body failed on {}: {:?}",
                    conn.trace_id(),
                    stream_id,
                    e
                );
                return;
            }
        }
    }

    // If fully written, send FIN and clean up
    if resp.written >= resp.body.len() {
        match http3_conn.send_body(conn, stream_id, &[], true) {
            Ok(_) | Err(quiche::h3::Error::Done) => {}
            Err(quiche::h3::Error::StreamBlocked) => return, // FIN will be retried later
            Err(e) => eprintln!(
                "{} send FIN failed on {}: {:?}",
                conn.trace_id(),
                stream_id,
                e
            ),
        }
        session.partial_responses.remove(&stream_id);
    }
}

fn handle_h3_request<S: HService>(
    stream_id: u64,
    session: &mut super::h3_session::H3Session,
    service: &mut S,
) {
    use super::h3_session::{self, PartialResponse};

    // Decide response on headers only; stop reading request body.
    if let Err(e) = session
        .conn
        .stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
    {
        if !matches!(e, quiche::Error::Done) {
            eprintln!(
                "{} sid={} stream_shutdown(Read) non-fatal: {:?}",
                session.conn.trace_id(),
                stream_id,
                e
            );
        }
    }

    // Prepare the session & run the service to fill rsp_headers / rsp_body.
    h3_session::init_session(session);
    if let Err(e) = service.call(session) {
        if e.kind() == std::io::ErrorKind::ConnectionAborted {
            session.partial_responses.remove(&stream_id);
            let _ = session
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
            return;
        }
    }

    let http3_conn = match session.http3_conn.as_mut() {
        Some(v) => v,
        None => {
            eprintln!(
                "{} HTTP/3 connection not initialized",
                session.conn.trace_id()
            );
            return;
        }
    };

    // Send headers first (or defer if blocked)
    match http3_conn.send_response(&mut session.conn, stream_id, &session.rsp_headers, false) {
        Ok(_) => {}
        Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
            use std::mem::take;
            session.partial_responses.insert(
                stream_id,
                PartialResponse {
                    headers: Some(take(&mut session.rsp_headers)),
                    body: take(&mut session.rsp_body),
                    written: 0,
                },
            );
            return;
        }
        Err(quiche::h3::Error::RequestCancelled)
        | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
        | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
            session.partial_responses.remove(&stream_id);
            let _ = session
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
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
    let mut budget = total;

    while written < total && budget > 0 {
        let cap = quic_conn_stream_capacity(&session.conn, stream_id);
        if cap == 0 {
            break;
        } // wait for writable()

        let want = cap.min(budget);
        let chunk = session.rsp_body.chunk_at(written, want);

        match http3_conn.send_body(&mut session.conn, stream_id, chunk, false) {
            Ok(n) if n > 0 => {
                written += n;
                budget = budget.saturating_sub(n);
            }
            Ok(_) | Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                break;
            }
            Err(quiche::h3::Error::RequestCancelled)
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
                let _ = session
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
                return;
            }
            Err(e) => {
                eprintln!("{} send_body failed: {:?}", session.conn.trace_id(), e);
                return;
            }
        }
    }

    if written < total {
        use std::mem::take;
        let body_src = take(&mut session.rsp_body);
        session.partial_responses.insert(
            stream_id,
            PartialResponse {
                headers: None,
                body: body_src,
                written,
            },
        );
    } else {
        let cap = quic_conn_stream_capacity(&session.conn, stream_id);
        if cap == 0 {
            // Enqueue a FIN-only write so handle_writable() will finish it.
            session.partial_responses.insert(
                stream_id,
                PartialResponse {
                    headers: None,
                    body: h3_session::BodySource::Empty,
                    written: 0,
                },
            );
            return;
        }
        match http3_conn.send_body(&mut session.conn, stream_id, &[], true) {
            Ok(_) | Err(quiche::h3::Error::Done) => {}
            Err(quiche::h3::Error::StreamBlocked) => {
                session.partial_responses.insert(
                    stream_id,
                    PartialResponse {
                        headers: None,
                        body: h3_session::BodySource::Empty,
                        written: 0,
                    },
                );
            }
            Err(e) => eprintln!("{} send FIN failed: {:?}", session.conn.trace_id(), e),
        }
    }
}

pub(crate) fn quic_dispatcher<S: HService + Send + 'static>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    mut config: quiche::Config,
    local_addr: SocketAddr,
    extend_connect: bool,
    call_service: std::sync::Arc<dyn Fn(usize) -> S + Send + Sync>,
) {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    type WorkerTx = may::sync::mpsc::Sender<Datagram>;
    let mut by_cid: HashMap<ConnKey, WorkerTx> = HashMap::new();

    // short-lived addr map to cover CID switch race
    struct AddrEntry {
        tx: WorkerTx,
        expires: Instant,
    }
    let mut by_addr: HashMap<SocketAddr, AddrEntry> = HashMap::new();
    const BY_ADDR_TTL: Duration = Duration::from_secs(5);

    let (ctrl_tx, ctrl_rx) = may::sync::mpsc::channel::<H3CtrlMsg>();
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    let mut scratch = [0u8; 65535];
    loop {
        // drain control messages
        while let Ok(msg) = ctrl_rx.try_recv() {
            match msg {
                H3CtrlMsg::AddCid(cid, tx) => {
                    by_cid.insert(cid, tx);
                }
                H3CtrlMsg::RemoveCid(cid) => {
                    by_cid.remove(&cid);
                }
            }
        }
        // expire old addr bindings
        let now = Instant::now();
        by_addr.retain(|_, e| e.expires > now);

        // recv one datagram
        let (n, from) = match socket.recv_from(&mut scratch) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                may::coroutine::yield_now();
                continue;
            }
            Err(e) => {
                eprintln!("recv_from error: {e:?}");
                continue;
            }
        };

        // parse header using n
        let hdr = match quiche::Header::from_slice(&mut scratch[..n], quiche::MAX_CONN_ID_LEN) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Header parse failed: {e:?}");
                continue;
            }
        };
        let dcid_key = key_from_cid(&hdr.dcid);

        // fast path: known DCID
        if let Some(tx) = by_cid.get(&dcid_key) {
            let _ = tx.send(make_datagram(from, local_addr, &scratch[..n]));

            // pull a few more waiting packets without going around the loop again
            for _ in 0..8 {
                match socket.recv_from(&mut scratch) {
                    Ok((n2, from2)) => {
                        if let Ok(h2) =
                            quiche::Header::from_slice(&mut scratch[..n2], quiche::MAX_CONN_ID_LEN)
                        {
                            let k2 = key_from_cid(&h2.dcid);
                            if let Some(tx2) = by_cid.get(&k2) {
                                let _ = tx2.send(make_datagram(from2, local_addr, &scratch[..n2]));
                            } else if let Some(entry2) = by_addr.get_mut(&from2) {
                                entry2.expires = Instant::now() + BY_ADDR_TTL;
                                let _ = entry2.tx.send(make_datagram(
                                    from2,
                                    local_addr,
                                    &scratch[..n2],
                                ));
                                by_cid.insert(k2, entry2.tx.clone());
                            } else {
                                // Not known yet; fall back to normal path next loop
                                break;
                            }
                        } else {
                            // Can't parse; skip
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }

            continue;
        }

        // fallback by remote address; also "learn" the new DCID
        if let Some(entry) = by_addr.get_mut(&from) {
            entry.expires = Instant::now() + BY_ADDR_TTL;
            let _ = entry
                .tx
                .send(make_datagram(from, local_addr, &scratch[..n]));
            by_cid.insert(dcid_key, entry.tx.clone());
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

        // Retry: only when required by policy. If client provided a valid token, accept.
        let retry_key = retry_key_current();
        let token = hdr.token.as_deref().unwrap_or(&[]);
        let odcid_bytes_opt: Option<Vec<u8>> = if token.is_empty() {
            None
        } else {
            validate_token_secure(&retry_key, token, &from)
        };
        if odcid_bytes_opt.is_none() {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let cid_len = hdr.dcid.len().min(quiche::MAX_CONN_ID_LEN);
            let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut scid_bytes[..cid_len]).expect("rng");

            let scid = quiche::ConnectionId::from_ref(&scid_bytes[..cid_len]);
            let new_token = mint_token_secure(&retry_key, &hdr.dcid, &from);
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

        // We have a valid token: build a ConnectionId that borrows from the odcid bytes.
        // Keep the Vec alive while we pass a &ConnectionId into quiche::accept.
        let odcid_bytes = odcid_bytes_opt.unwrap();
        let odcid_conn_id = quiche::ConnectionId::from_ref(&odcid_bytes);

        // accept new connection
        let conn = match quiche::accept(
            &hdr.dcid,
            Some(&odcid_conn_id),
            local_addr,
            from,
            &mut config,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept failed: {e:?}");
                continue;
            }
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

        by_addr.insert(
            from,
            AddrEntry {
                tx: tx_cloned.clone(),
                expires: Instant::now() + BY_ADDR_TTL,
            },
        );
        by_cid.insert(dcid_key, tx_cloned.clone());
        let _ = tx_cloned.send(make_datagram(from, local_addr, &scratch[..n]));
    }
}

fn handle_quic_connection<S: HService + 'static>(
    socket: std::sync::Arc<may::net::UdpSocket>,
    conn: quiche::Connection,
    from: SocketAddr,
    (rx, tx): (
        may::sync::mpsc::Receiver<Datagram>,
        may::sync::mpsc::Sender<Datagram>,
    ),
    ctrl_tx: may::sync::mpsc::Sender<H3CtrlMsg>,
    (initial_dcid, extend_connect): (ConnKey, bool),
    mut service: S,
) {
    use crate::network::http::h3_session;
    use std::collections::HashSet;

    let mut dcids: HashSet<ConnKey> = HashSet::new();
    let mut session = h3_session::new_session(from, conn);

    if dcids.insert(initial_dcid) {
        let _ = ctrl_tx.send(H3CtrlMsg::AddCid(initial_dcid, tx.clone()));
    }
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
    h3_config.set_qpack_blocked_streams(64);
    h3_config.set_max_field_section_size(64 * 1024);
    if extend_connect {
        h3_config.enable_extended_connect(true);
    }

    // Optimized pending handling
    let mut pending_to: Option<SocketAddr> = None;
    let mut pending_len: usize = 0;
    let mut pending_buf: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM_SIZE);

    loop {
        let deadline = std::time::Instant::now() + session.conn.timeout().unwrap_or_default();
        let wait = deadline.saturating_duration_since(std::time::Instant::now());

        let mut got_packet = false;
        let _ = may::select! {
            pkt = rx.recv() => {
                if let Ok(mut data) = pkt {
                    let recv_info = quiche::RecvInfo { to: data.to, from: data.from };
                    if session.conn.recv(&mut data.buf[..data.len], recv_info).is_ok() {
                        got_packet = true;
                    }
                    // drain whatever else is queued right now
                    for _ in 0..32 {
                        if let Ok(mut more) = rx.try_recv() {
                            let recv_info = quiche::RecvInfo { to: more.to, from: more.from };
                            let _ = session.conn.recv(&mut more.buf[..more.len], recv_info);
                        } else {
                            break;
                        }
                    }
                }
            },
            _ = may::coroutine::sleep(wait) => { session.conn.on_timeout(); }
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
                let polled = {
                    let Some(h3) = session.http3_conn.as_mut() else {
                        break;
                    };
                    h3.poll(&mut session.conn)
                };

                match polled {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        session.req_headers = Some(list);
                        session.current_stream_id = Some(sid);
                        handle_h3_request(sid, &mut session, &mut service);
                        session.current_stream_id = None;
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        let mut tmp = [0u8; 4096];
                        loop {
                            let res = {
                                let Some(h3) = session.http3_conn.as_mut() else {
                                    break;
                                };
                                h3.recv_body(&mut session.conn, sid, &mut tmp)
                            };
                            match res {
                                Ok(_) => {}
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => {
                                    eprintln!("recv_body(drop): {e:?}");
                                    break;
                                }
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) => {
                        session.req_body_map.remove(&sid);
                        if session.current_stream_id == Some(sid) {
                            session.current_stream_id = None;
                        }
                    }
                    Ok((sid, quiche::h3::Event::Reset { .. })) => {
                        session.partial_responses.remove(&sid);
                    }
                    Ok((_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(quiche::h3::Error::RequestCancelled)
                    | Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_)))
                    | Err(quiche::h3::Error::TransportError(quiche::Error::StreamReset(_))) => {
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

        // Optimized pending send
        loop {
            if let Some(to) = pending_to {
                match socket.send_to(&pending_buf[..pending_len], to) {
                    Ok(_) => {
                        pending_to = None;
                        pending_len = 0;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("send failed (pending): {e:?}");
                        session.conn.close(false, 0x1, b"send-pending-fail").ok();
                        break;
                    }
                }
                continue;
            }

            let mut sent_any = false;
            for _ in 0..32 {
                match session.conn.send(&mut out) {
                    Ok((n, send_info)) => match socket.send_to(&out[..n], send_info.to) {
                        Ok(_) => {
                            sent_any = true;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            pending_buf.clear();
                            pending_buf.extend_from_slice(&out[..n]);
                            pending_len = n;
                            pending_to = Some(send_info.to);
                            break;
                        }
                        Err(e) => {
                            eprintln!("send failed: {e:?}");
                            session.conn.close(false, 0x1, b"send-fail").ok();
                            break;
                        }
                    },
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        eprintln!("{} send error: {e:?}", session.conn.trace_id());
                        session.conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                }
            }
            if !sent_any {
                break;
            }
        }

        register_scids(&session.conn, &mut dcids, &ctrl_tx, &tx);

        if session.conn.is_closed() {
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

#[inline]
fn make_datagram(from: SocketAddr, to: SocketAddr, data: &[u8]) -> Datagram {
    let mut buf = Box::new([0u8; 65535]);
    let len = data.len();
    buf[..len].copy_from_slice(data);
    Datagram { buf, len, from, to }
}

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

#[inline]
fn quic_conn_stream_capacity(conn: &quiche::Connection, sid: u64) -> usize {
    conn.stream_capacity(sid).unwrap_or(0)
}
