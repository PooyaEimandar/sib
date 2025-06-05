use quiche::h3::NameValue;
use ring::rand::*;
use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}

struct Client {
    conn: quiche::Connection,
    http3_conn: Option<quiche::h3::Connection>,
    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

pub fn start(
    addr: &'static str,
    cert_pem_file_path: &'static str,
    key_pem_file_path: &'static str,
) -> std::io::Result<()> {
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

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).map_err(|e| {
        std::io::Error::other(format!(
            "Failed to create h3 connection id seed because: {e:?}"
        ))
    })?;

    let mut clients = ClientMap::new();
    let local_addr = socket
        .local_addr()
        .map_err(|e| std::io::Error::other(format!("Failed to get local address: {e:?}")))?;

    let _ = may::go!(
        may::coroutine::Builder::new()
            .stack_size(2 * 1024 * 1024) // 2 MiB stack size
            .name("H3ServiceFactory".to_owned()),
        move || {
            loop {
                // Read incoming UDP packets from the socket and feed them to quiche,
                // until there are no more packets to read.
                'read: loop {
                    let timeout = clients
                        .values()
                        .filter_map(|c| c.conn.timeout())
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
                                    eprintln!("Received {} bytes from {}", len, from);
                                    event = 0; // continue
                                }
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        eprintln!("WouldBlock");
                                        event = 1; // yield and break
                                    } else {
                                        // s_error!("recv_from failed: {:?}", e);
                                        eprintln!("panic");
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
                            clients.values_mut().for_each(|c| c.conn.on_timeout());
                            break 'read;
                        }
                        _ => {
                            return;
                        }
                    };

                    eprintln!("got {} bytes", len);

                    let pkt_buf = &mut buf[..len];

                    // Parse the QUIC packet's header.
                    let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Parsing packet header failed: {:?}", e);
                            continue 'read;
                        }
                    };

                    eprintln!("got packet {:?}", hdr);
                    let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                    let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                    let conn_id = conn_id.to_vec().into();

                    // Lookup a connection based on the packet's connection ID. If there
                    // is no connection matching, create a new one.
                    let client = if !clients.contains_key(&hdr.dcid)
                        && !clients.contains_key(&conn_id)
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
                                        eprintln!("quiche negotiate version failed: {:?}", e);
                                        return;
                                    }
                                };
                            let out = &out[..len];

                            if let Err(e) = socket.send_to(out, from) {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    eprintln!("send() would block");
                                    break;
                                }
                                panic!("send() failed: {:?}", e);
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
                                    eprintln!("quiche retry failed: {:?}", e);
                                    return;
                                }
                            };

                            let out = &out[..len];

                            if let Err(e) = socket.send_to(out, from) {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    eprintln!("send() would block");
                                    break;
                                }

                                panic!("send() failed: {:?}", e);
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
                                eprintln!("quiche accept failed: {:?}", e);
                                return;
                            }
                        };

                        let client = Client {
                            conn,
                            http3_conn: None,
                            partial_responses: HashMap::new(),
                        };

                        clients.insert(scid.clone(), client);
                        match clients.get_mut(&scid) {
                            Some(v) => v,
                            None => {
                                eprintln!("Failed to get client with scid={:?}", scid);
                                return;
                            }
                        }
                    } else {
                        match clients.get_mut(&hdr.dcid) {
                            Some(v) => v,
                            None => match clients.get_mut(&conn_id) {
                                Some(v) => v,
                                None => {
                                    eprintln!(
                                        "Failed to get client with dcid={:?} or conn_id={:?}",
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
                            eprintln!("Failed to get local address: {:?}", e);
                            return;
                        }
                    };
                    let recv_info = quiche::RecvInfo { to, from };

                    // Process potentially coalesced packets.
                    let read = match client.conn.recv(pkt_buf, recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("{} recv failed: {:?}", client.conn.trace_id(), e);
                            continue 'read;
                        }
                    };
                    eprintln!("{} processed {} bytes", client.conn.trace_id(), read);

                    // 🔁 Flush handshake and other early packets
                    loop {
                        match client.conn.send(&mut out) {
                            Ok((write, send_info)) => {
                                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                                    if e.kind() != std::io::ErrorKind::WouldBlock {
                                        panic!("send failed: {:?}", e);
                                    }
                                }
                                eprintln!("{} wrote {} bytes", client.conn.trace_id(), write);
                            }
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                eprintln!("{} send error: {:?}", client.conn.trace_id(), e);
                                client.conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        }
                    }
                    eprintln!(
                        "{} connection stats: {:?}",
                        client.conn.trace_id(),
                        client.conn.stats()
                    );

                    // Create a new HTTP/3 connection as soon as the QUIC connection
                    // is established.
                    if (client.conn.is_in_early_data() || client.conn.is_established())
                        && client.http3_conn.is_none()
                    {
                        eprintln!(
                            "{} QUIC handshake completed, now trying HTTP/3",
                            client.conn.trace_id()
                        );

                        let h3_conn = match quiche::h3::Connection::with_transport(
                            &mut client.conn,
                            &h3_config,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("failed to create HTTP/3 connection: {}", e);
                                continue 'read;
                            }
                        };

                        // TODO: sanity check h3 connection before adding to map
                        client.http3_conn = Some(h3_conn);
                    }

                    if client.http3_conn.is_some() {
                        // Handle writable streams.
                        for stream_id in client.conn.writable() {
                            handle_writable(client, stream_id);
                        }

                        // Process HTTP/3 events.
                        loop {
                            let http3_conn = match client.http3_conn.as_mut() {
                                Some(v) => v,
                                None => {
                                    eprintln!(
                                        "{} HTTP/3 connection is not initialized",
                                        client.conn.trace_id()
                                    );
                                    return;
                                }
                            };

                            match http3_conn.poll(&mut client.conn) {
                                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                    handle_request(client, stream_id, &list, "/");
                                }
                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    eprintln!(
                                        "{} got data on stream id {}",
                                        client.conn.trace_id(),
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
                                    eprintln!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);

                                    break;
                                }
                            }
                        }
                    }
                }

                // Generate outgoing QUIC packets for all active connections and send
                // them on the UDP socket, until quiche reports that there are no more
                // packets to be sent.
                for client in clients.values_mut() {
                    loop {
                        let (write, send_info) = match client.conn.send(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                eprintln!("{} done writing", client.conn.trace_id());
                                break;
                            }
                            Err(e) => {
                                eprintln!("{} send failed: {:?}", client.conn.trace_id(), e);
                                client.conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        };
                        if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                eprintln!("send() would block");
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                        eprintln!("{} written {} bytes", client.conn.trace_id(), write);
                    }
                }

                // Garbage collect closed connections.
                clients.retain(|_, ref mut c| {
                    eprintln!("Collecting garbage");
                    if c.conn.is_closed() {
                        eprintln!(
                            "{} connection collected {:?}",
                            c.conn.trace_id(),
                            c.conn.stats()
                        );
                    }
                    !c.conn.is_closed()
                });
            }
        }
    );
    Ok(())
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
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

/// Handles incoming HTTP/3 requests.
fn handle_request(client: &mut Client, stream_id: u64, headers: &[quiche::h3::Header], root: &str) {
    let conn = &mut client.conn;
    let http3_conn = &mut match client.http3_conn.as_mut() {
        Some(v) => v,
        None => {
            eprintln!(
                "{} HTTP/3 connection is not initialized while checking handle_request",
                conn.trace_id()
            );
            return;
        }
    };

    // info!(
    //     "{} got request {:?} on stream id {}",
    //     conn.trace_id(),
    //     hdrs_to_strings(headers),
    //     stream_id
    // );

    // We decide the response based on headers alone, so stop reading the
    // request stream so that any body is ignored and pointless Data events
    // are not generated.
    match conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{} stream shutdown failed: {:?}", conn.trace_id(), e);
            return;
        }
    }

    let (headers, body) = build_response(root, headers);

    match http3_conn.send_response(conn, stream_id, &headers, false) {
        Ok(v) => v,

        Err(quiche::h3::Error::StreamBlocked) => {
            let response = PartialResponse {
                headers: Some(headers),
                body,
                written: 0,
            };

            client.partial_responses.insert(stream_id, response);
            return;
        }

        Err(_e) => {
            //s_error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    }

    let written = match http3_conn.send_body(conn, stream_id, &body, true) {
        Ok(v) => v,
        Err(quiche::h3::Error::Done) => 0,
        Err(_e) => {
            //s_error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    if written < body.len() {
        let response = PartialResponse {
            headers: None,
            body,
            written,
        };

        client.partial_responses.insert(stream_id, response);
    }
}

/// Builds an HTTP/3 response given a request.
fn build_response(
    root: &str,
    request: &[quiche::h3::Header],
) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    let mut file_path = std::path::PathBuf::from(root);
    let mut path = std::path::Path::new("");
    let mut method = None;

    // Look for the request's path and method.
    for hdr in request {
        match hdr.name() {
            b":path" => {
                path = std::path::Path::new(std::str::from_utf8(hdr.value()).unwrap_or("/"))
            }
            b":method" => method = Some(hdr.value()),
            _ => (),
        }
    }

    let (status, body) = match method {
        Some(b"GET") => {
            for c in path.components() {
                if let std::path::Component::Normal(v) = c {
                    file_path.push(v)
                }
            }

            match std::fs::read(file_path.as_path()) {
                Ok(data) => (200, data),
                Err(_) => (404, b"Not Found!".to_vec()),
            }
        }

        _ => (405, Vec::new()),
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];

    (headers, body)
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;
    let http3_conn = &mut match client.http3_conn.as_mut() {
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

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = match client.partial_responses.get_mut(&stream_id) {
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
            Err(_e) => {
                //s_error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        }
    }

    resp.headers = None;

    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(_e) => {
            client.partial_responses.remove(&stream_id);

            //s_error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::network::http::h3::start;

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

    #[tokio::test]
    async fn test_quiche_server_response() -> Result<(), Box<dyn std::error::Error>> {
        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        std::fs::write("/tmp/cert.pem", certs.0)?;
        std::fs::write("/tmp/key.pem", certs.1)?;

        // Start the server in a background thread
        std::thread::spawn(|| {
            println!("Starting the server...");
            let _ = start("0.0.0.0:8080", "/tmp/cert.pem", "/tmp/key.pem");
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
