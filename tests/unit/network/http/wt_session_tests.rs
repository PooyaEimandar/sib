use super::{WtConnectionError, WtSession};
use bytes::Bytes;
use std::{future::Future, io::ErrorKind, sync::Arc, time::Duration};
use wtransport::quinn::TransportConfig;

async fn with_session_pair<F, Fut>(mut client_transport: TransportConfig, run: F)
where
    F: FnOnce(WtSession, WtSession) -> Fut,
    Fut: Future<Output = ()>,
{
    tokio::time::timeout(Duration::from_secs(15), async {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let identity = wtransport::Identity::new(
            wtransport::tls::CertificateChain::new(vec![
                wtransport::tls::Certificate::from_der(cert.der().to_vec()).unwrap(),
            ]),
            wtransport::tls::PrivateKey::from_der_pkcs8(key.serialize_der()),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        // Keep the path limit stable for the exact-size datagram test.
        let mut server_transport = super::WTConfig {
            datagram_receive_buffer_bytes: Some(4096),
            datagram_send_buffer_bytes: Some(4096),
            ..Default::default()
        }
        .transport_config()
        .unwrap();
        server_transport.mtu_discovery_config(None);
        client_transport.mtu_discovery_config(None);
        let server = wtransport::Endpoint::server(
            wtransport::ServerConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_transport(identity, server_transport)
                .build(),
        )
        .unwrap();
        let client = wtransport::Endpoint::client(
            wtransport::ClientConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_tls_and_transport(tls, client_transport)
                .build(),
        )
        .unwrap();
        let url = format!("https://{}/session", server.local_addr().unwrap());
        let (server_conn, client_conn) = tokio::join!(
            async { server.accept().await.await.unwrap().accept().await.unwrap() },
            client.connect(url),
        );
        run(
            WtSession::new(server_conn),
            WtSession::new(client_conn.unwrap()),
        )
        .await;

        server.close(wtransport::VarInt::from_u32(0), b"test complete");
        client.close(wtransport::VarInt::from_u32(0), b"test complete");
        tokio::join!(server.wait_idle(), client.wait_idle());
    })
    .await
    .expect("WebTransport session test must finish");
}

#[tokio::test(flavor = "current_thread")]
async fn datagram_limit_excludes_header_and_rejects_oversized_payloads() {
    with_session_pair(TransportConfig::default(), |server, client| async move {
        let limit = server.max_datagram_size().unwrap();
        assert!(limit > 0);
        let payload = Bytes::from(vec![0x5a; limit]);
        server.send_dgram(&payload).unwrap();
        assert_eq!(client.recv_dgram().await.unwrap(), payload);

        let oversized = Bytes::from(vec![0; limit + 1]);
        let error = server.send_dgram(&oversized).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error
                .get_ref()
                .unwrap()
                .is::<wtransport::error::SendDatagramError>()
        );
        let payload = Bytes::from_static(b"still connected");
        server.send_dgram(&payload).unwrap();
        assert_eq!(client.recv_dgram().await.unwrap(), payload);
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn peer_limit_smaller_than_webtransport_header_does_not_underflow() {
    let mut transport = TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1));
    with_session_pair(transport, |server, _client| async move {
        assert_eq!(server.max_datagram_size(), None);
        assert_eq!(
            server.send_dgram(&Bytes::new()).unwrap_err().kind(),
            ErrorKind::InvalidInput,
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn peer_without_datagram_support_returns_unsupported() {
    let mut transport = TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    with_session_pair(transport, |server, _client| async move {
        assert_eq!(server.max_datagram_size(), None);
        assert_eq!(
            server
                .send_dgram(&Bytes::from_static(b"packet"))
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported,
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn peer_close_preserves_reason_and_wakes_pending_operations() {
    with_session_pair(TransportConfig::default(), |server, client| async move {
        let (closed, datagram, stream, ()) = tokio::join!(
            server.closed(),
            server.recv_dgram(),
            server.accept_uni(),
            async {
                tokio::task::yield_now().await;
                client.close(42, b"room ended").unwrap();
            },
        );
        match closed {
            WtConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.code().into_inner(), 42);
                assert_eq!(close.reason(), b"room ended");
            }
            other => panic!("expected peer application close, got {other:?}"),
        }
        assert!(datagram.is_err());
        assert!(stream.is_err());
        assert_eq!(
            server
                .send_dgram(&Bytes::from_static(b"late packet"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotConnected,
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_close_code_keeps_session_open_and_local_close_is_repeatable() {
    with_session_pair(TransportConfig::default(), |server, client| async move {
        for code in [1_u64 << 62, u64::MAX] {
            assert_eq!(
                server.close(code, b"invalid").unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
        let payload = Bytes::from_static(b"still open");
        server.send_dgram(&payload).unwrap();
        assert_eq!(client.recv_dgram().await.unwrap(), payload);

        let (closed, datagram, ()) = tokio::join!(server.closed(), server.recv_dgram(), async {
            tokio::task::yield_now().await;
            server.close((1_u64 << 62) - 1, b"done").unwrap();
            server.close(0, b"second close").unwrap();
        },);
        assert_eq!(closed, WtConnectionError::LocallyClosed);
        assert!(datagram.is_err());
        assert_eq!(server.closed().await, WtConnectionError::LocallyClosed);
        match client.closed().await {
            WtConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.code().into_inner(), (1_u64 << 62) - 1);
                assert_eq!(close.reason(), b"done");
            }
            other => panic!("expected peer application close, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_send_queue_drops_old_datagrams_and_keeps_latest() {
    with_session_pair(TransportConfig::default(), |server, client| async move {
        // No yield while filling: the QUIC driver cannot drain the send queue.
        for sequence in 0..128u8 {
            server
                .send_dgram(&Bytes::from(vec![sequence; 1024]))
                .unwrap();
        }
        let first = client.recv_dgram().await.unwrap();
        assert_eq!(first.len(), 1024);
        assert!(
            first[0] >= 124,
            "an old packet survived the 4 KiB queue bound"
        );
        let mut last = first;
        while last[0] != 127 {
            last = client.recv_dgram().await.unwrap();
        }
        assert!(last.iter().all(|byte| *byte == 127));
        client
            .send_dgram(&Bytes::from_static(b"still connected"))
            .unwrap();
        assert_eq!(server.recv_dgram().await.unwrap(), b"still connected"[..]);
    })
    .await;
}
