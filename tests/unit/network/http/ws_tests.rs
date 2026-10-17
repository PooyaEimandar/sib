use super::*;

// RFC 6455 section 5.7: a masked client text frame containing "Hello".
const MASKED_HELLO: &[u8] = &[
    0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
];
const HELLO: &[u8] = b"\x81\x05Hello";

#[test]
fn unmasked_client_frames_are_rejected_for_every_opcode() {
    for op in [
        OpCode::Text,
        OpCode::Binary,
        OpCode::Continue,
        OpCode::Close,
        OpCode::Ping,
        OpCode::Pong,
    ] {
        for payload in [Bytes::new(), Bytes::from_static(b"\x03\xe8")] {
            let bytes = encode_frame(op, &payload, true, None);
            let mut input = BytesMut::from(bytes.as_ref());
            let error = try_parse_frame(&mut input).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{op:?}");
            assert_eq!(input.as_ref(), bytes.as_ref(), "invalid frame was consumed");
        }
    }
}

#[test]
fn unmasked_headers_fail_without_waiting_for_lengths_or_payloads() {
    assert!(
        try_parse_frame(&mut BytesMut::from(&[0x82][..]))
            .unwrap()
            .is_none()
    );
    for length in [0, 1, 125, 126, 127] {
        let mut input = BytesMut::from(&[0x82, length][..]);
        let error = try_parse_frame(&mut input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.len(), 2);
    }
}

#[test]
fn masked_frames_preserve_partial_input_and_frame_boundaries() {
    let mut input = BytesMut::new();
    for byte in &MASKED_HELLO[..MASKED_HELLO.len() - 1] {
        input.extend_from_slice(&[*byte]);
        let before = input.clone();
        assert!(try_parse_frame(&mut input).unwrap().is_none());
        assert_eq!(input, before);
    }
    input.extend_from_slice(&MASKED_HELLO[MASKED_HELLO.len() - 1..]);
    // A masked empty ping with an all-zero key is valid too.
    input.extend_from_slice(&[0x89, 0x80, 0, 0, 0, 0]);
    let hello = try_parse_frame(&mut input).unwrap().unwrap();
    assert_eq!(hello.op, OpCode::Text);
    assert!(hello.fin && hello.masked);
    assert_eq!(hello.payload, &HELLO[2..]);
    let ping = try_parse_frame(&mut input).unwrap().unwrap();
    assert_eq!(ping.op, OpCode::Ping);
    assert!(ping.fin && ping.masked && ping.payload.is_empty());
    assert!(input.is_empty());
}

#[test]
fn masked_extended_lengths_and_continuations_remain_supported() {
    for length in [125, 126, 65535, 65536] {
        let payload = Bytes::from(vec![0xa5; length]);
        let bytes = encode_frame(OpCode::Binary, &payload, false, Some([1, 2, 3, 4]));
        let mut input = BytesMut::from(bytes.as_ref());
        // Final continuation containing '!': zero mask is permitted.
        input.extend_from_slice(&[0x80, 0x81, 0, 0, 0, 0, b'!']);
        let frame = try_parse_frame(&mut input).unwrap().unwrap();
        assert_eq!(frame.op, OpCode::Binary);
        assert!(!frame.fin);
        assert_eq!(frame.payload, payload);
        let continuation = try_parse_frame(&mut input).unwrap().unwrap();
        assert_eq!(continuation.op, OpCode::Continue);
        assert!(continuation.fin);
        assert_eq!(continuation.payload, b"!".as_slice());
        assert!(input.is_empty());
    }
}

#[cfg(any(
    feature = "net-h1-server",
    all(
        feature = "net-h2-server",
        feature = "rt-tokio",
        not(feature = "rt-glommio")
    )
))]
const UPGRADE: &[u8] = b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

#[cfg(feature = "net-h1-server")]
#[test]
fn sync_session_aborts_unmasked_client_frames_after_upgrade() {
    use crate::network::http::{h1_session::new_session, session::Session};
    struct Duplex {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl io::Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl io::Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut input = MASKED_HELLO.to_vec();
    input.extend_from_slice(&[0x82, 127]); // Unmasked, no extended length or body.
    let mut stream = Duplex {
        input: io::Cursor::new(input),
        output: Vec::new(),
    };
    let mut request = BytesMut::from(UPGRADE);
    let mut response = BytesMut::new();
    let peer = "127.0.0.1".parse().unwrap();
    let mut session = new_session(&mut stream, &peer, &mut request, &mut response)
        .unwrap()
        .unwrap();
    assert!(session.is_ws());
    session.ws_accept().unwrap();
    let (op, payload, fin) = session.ws_read().unwrap();
    assert_eq!(
        (op, payload.as_ref(), fin),
        (OpCode::Text, b"Hello".as_slice(), true)
    );
    session.ws_write(op, &payload, fin).unwrap();
    // The sync server treats ConnectionAborted as a hard close, so it cannot
    // try to reuse an upgraded connection as HTTP after the protocol error.
    assert_eq!(
        session.ws_read().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(stream.output.starts_with(b"HTTP/1.1 101 "));
    assert!(
        stream.output.ends_with(HELLO),
        "server replies must remain unmasked"
    );
}

#[cfg(all(
    feature = "net-h2-server",
    feature = "rt-tokio",
    not(feature = "rt-glommio")
))]
#[tokio::test(flavor = "current_thread")]
async fn async_server_closes_unmasked_frames_from_buffered_or_new_input() {
    use crate::network::http::{
        h2_server,
        server::H2Config,
        session::{HAsyncService, Session},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    struct Echo;
    #[async_trait::async_trait(?Send)]
    impl HAsyncService for Echo {
        async fn call<S: Session>(&self, session: &mut S) -> io::Result<()> {
            session.ws_accept_async().await?;
            loop {
                let (op, payload, fin) = session.ws_read_async().await?;
                session.ws_write_async(op, payload, fin).await?;
            }
        }
    }

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for seeded in [true, false] {
            let (server, mut client) = tokio::io::duplex(4096);
            let config = H2Config::default();
            let server = h2_server::serve_h1(
                server,
                Echo,
                &config,
                "127.0.0.1".parse().unwrap(),
                CancellationToken::new(),
            );
            let client = async {
                let mut upgrade = UPGRADE.to_vec();
                if seeded {
                    upgrade.extend_from_slice(&[0x82, 127]);
                }
                client.write_all(&upgrade).await.unwrap();
                let mut response = Vec::new();
                loop {
                    response.push(client.read_u8().await.unwrap());
                    if response.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(response.starts_with(b"HTTP/1.1 101 "));
                if !seeded {
                    client.write_all(MASKED_HELLO).await.unwrap();
                    let mut echo = [0u8; 7];
                    client.read_exact(&mut echo).await.unwrap();
                    assert_eq!(&echo, HELLO);
                    client.write_all(&[0x82, 127]).await.unwrap();
                }
                // Leave the client write half open: the server must close as
                // soon as it sees MASK=0, not wait for any body or client EOF.
                let mut trailing = Vec::new();
                client.read_to_end(&mut trailing).await.unwrap();
                assert!(trailing.is_empty(), "invalid data reached the echo service");
            };
            let (result, ()) = tokio::join!(server, client);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    })
    .await
    .expect("server must close an unmasked WebSocket without waiting for payload");
}
