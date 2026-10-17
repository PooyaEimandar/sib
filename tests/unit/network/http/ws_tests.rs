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
            let error = try_parse_frame(&mut input, usize::MAX).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{op:?}");
            assert_eq!(input.as_ref(), bytes.as_ref(), "invalid frame was consumed");
        }
    }
}

#[test]
fn unmasked_headers_fail_without_waiting_for_lengths_or_payloads() {
    assert!(
        try_parse_frame(&mut BytesMut::from(&[0x82][..]), usize::MAX)
            .unwrap()
            .is_none()
    );
    for length in [0, 1, 125, 126, 127] {
        let mut input = BytesMut::from(&[0x82, length][..]);
        let error = try_parse_frame(&mut input, usize::MAX).unwrap_err();
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
        assert!(try_parse_frame(&mut input, usize::MAX).unwrap().is_none());
        assert_eq!(input, before);
    }
    input.extend_from_slice(&MASKED_HELLO[MASKED_HELLO.len() - 1..]);
    // A masked empty ping with an all-zero key is valid too.
    input.extend_from_slice(&[0x89, 0x80, 0, 0, 0, 0]);
    let hello = try_parse_frame(&mut input, usize::MAX).unwrap().unwrap();
    assert_eq!(hello.op, OpCode::Text);
    assert!(hello.fin && hello.masked);
    assert_eq!(hello.payload, &HELLO[2..]);
    let ping = try_parse_frame(&mut input, usize::MAX).unwrap().unwrap();
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
        let frame = try_parse_frame(&mut input, usize::MAX).unwrap().unwrap();
        assert_eq!(frame.op, OpCode::Binary);
        assert!(!frame.fin);
        assert_eq!(frame.payload, payload);
        let continuation = try_parse_frame(&mut input, usize::MAX).unwrap().unwrap();
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
    let mut messages = MessageAssembler::new(5, 2).unwrap();
    let (op, payload) = messages.read(&mut session).unwrap();
    assert_eq!((op, payload.as_ref()), (OpCode::Text, b"Hello".as_slice()));
    session.ws_write(op, &payload, true).unwrap();
    // The sync server treats ConnectionAborted as a hard close, so it cannot
    // try to reuse an upgraded connection as HTTP after the protocol error.
    assert_eq!(
        messages.read(&mut session).unwrap_err().kind(),
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

#[test]
fn noncanonical_lengths_and_invalid_controls_are_rejected_from_headers() {
    for bytes in [
        vec![0x82, 0xfe, 0, 1], // 16-bit encoding of a one-byte payload
        vec![0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 126], // 64-bit encoding of 126
        vec![0x89, 0xfe],       // control frames cannot use extended lengths
        vec![0x09, 0x80],       // fragmented ping
        vec![0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0], // forbidden high bit
    ] {
        let error = try_parse_frame(&mut BytesMut::from(bytes.as_slice()), usize::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn invalid_close_payloads_and_complete_text_are_rejected() {
    for (op, payload) in [
        (OpCode::Close, b"x".as_slice()),
        (OpCode::Close, &[0x03, 0xed]), // 1005 cannot appear on the wire
        (OpCode::Close, &[0x03, 0xe8, 0xff]), // invalid UTF-8 reason
        (OpCode::Text, &[0xff]),
    ] {
        let bytes = encode_frame(op, &Bytes::copy_from_slice(payload), true, Some([0; 4]));
        let error = try_parse_frame(&mut BytesMut::from(bytes.as_ref()), usize::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn frame_size_limits_are_checked_before_mask_or_payload() {
    for (header, limit) in [
        (vec![0x82, 0x85], 4),
        (vec![0x82, 0xfe, 1, 0], 255),
        (vec![0x82, 0xff, 0, 0, 0, 0, 0, 1, 0, 0], 65535),
    ] {
        let mut input = BytesMut::from(header.as_slice());
        let error = try_parse_frame(&mut input, limit).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.as_ref(), header);
    }
}

#[test]
fn message_assembly_handles_controls_and_utf8_split_between_fragments() {
    let mut messages = MessageAssembler::new(4, 3).unwrap();
    assert!(
        messages
            .push_frame(OpCode::Text, Bytes::from_static(&[0xf0, 0x9f]), false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        messages
            .push_frame(OpCode::Ping, Bytes::from_static(b"ping"), true)
            .unwrap(),
        Some((OpCode::Ping, Bytes::from_static(b"ping")))
    );
    assert!(
        messages
            .push_frame(OpCode::Continue, Bytes::from_static(&[0x98]), false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        messages
            .push_frame(OpCode::Continue, Bytes::from_static(&[0x80]), true)
            .unwrap(),
        Some((OpCode::Text, Bytes::from_static("😀".as_bytes())))
    );
    // The next message gets fresh byte/fragment budgets.
    assert_eq!(
        messages
            .push_frame(OpCode::Binary, Bytes::from_static(b"next"), true)
            .unwrap(),
        Some((OpCode::Binary, Bytes::from_static(b"next")))
    );
}

#[test]
fn message_bounds_and_protocol_errors_are_terminal() {
    for (first, second, size, fragments) in [
        (
            (OpCode::Binary, b"ab".as_slice(), false),
            (OpCode::Continue, b"cd".as_slice(), true),
            3,
            4,
        ),
        (
            (OpCode::Binary, b"".as_slice(), false),
            (OpCode::Continue, b"".as_slice(), true),
            8,
            1,
        ),
        (
            (OpCode::Text, b"a".as_slice(), false),
            (OpCode::Binary, b"b".as_slice(), true),
            8,
            4,
        ),
        (
            (OpCode::Text, &[0xf0], false),
            (OpCode::Continue, b"x".as_slice(), true),
            8,
            4,
        ),
    ] {
        let mut messages = MessageAssembler::new(size, fragments).unwrap();
        assert!(
            messages
                .push_frame(first.0, Bytes::copy_from_slice(first.1), first.2)
                .unwrap()
                .is_none()
        );
        let error = messages
            .push_frame(second.0, Bytes::copy_from_slice(second.1), second.2)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(messages.data.is_empty());
        assert_eq!(
            messages
                .push_frame(OpCode::Binary, Bytes::new(), true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    let mut messages = MessageAssembler::new(4, 4).unwrap();
    assert!(
        messages
            .push_frame(OpCode::Continue, Bytes::new(), true)
            .is_err()
    );
    assert!(MessageAssembler::new(4, 0).is_err());
    let mut empty_only = MessageAssembler::new(0, 1).unwrap();
    assert!(
        empty_only
            .push_frame(OpCode::Binary, Bytes::new(), true)
            .unwrap()
            .is_some()
    );
    assert!(
        empty_only
            .push_frame(OpCode::Binary, Bytes::from_static(b"x"), true)
            .is_err()
    );
}

#[test]
fn close_discards_partial_messages_and_validates_codes_and_reasons() {
    for payload in [
        Bytes::new(),
        Bytes::from_static(&[0x03, 0xe8]),
        Bytes::from_static(&[0x0b, 0xb8, b'o', b'k']),
    ] {
        let mut messages = MessageAssembler::new(16, 4).unwrap();
        messages
            .push_frame(OpCode::Binary, Bytes::from_static(b"partial"), false)
            .unwrap();
        assert_eq!(
            messages
                .push_frame(OpCode::Close, payload.clone(), true)
                .unwrap(),
            Some((OpCode::Close, payload))
        );
        assert!(messages.data.is_empty());
        assert!(
            messages
                .push_frame(OpCode::Continue, Bytes::new(), true)
                .is_err()
        );
    }
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 2000, 5000] {
        let mut messages = MessageAssembler::new(16, 4).unwrap();
        assert!(
            messages
                .push_frame(
                    OpCode::Close,
                    Bytes::copy_from_slice(&code.to_be_bytes()),
                    true
                )
                .is_err()
        );
    }
}

#[cfg(all(
    feature = "net-h2-server",
    feature = "rt-tokio",
    not(feature = "rt-glommio")
))]
#[tokio::test(flavor = "current_thread")]
async fn async_frame_limit_fails_without_reading_the_payload() {
    let mut scratch = BytesMut::from(&[0x82, 0xfe, 0x10, 0][..]);
    // Reading from this stream would yield EOF. The advertised size alone must fail.
    let error = ws_read_from_io(&mut tokio::io::empty(), &mut scratch, 1024)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(scratch.len(), 4);
}
