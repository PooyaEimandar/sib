use super::*;
use crate::network::http::{h1_session_async::H1SessionAsync, session::Session};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct RecordingIo {
    bytes: Vec<u8>,
    largest_write: usize,
    truncate_after_headers: Option<PathBuf>,
    pending: bool,
}

impl RecordingIo {
    fn record(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest_write = self.largest_write.max(bytes.len());
        // Short writes exercise the response writer without buffering in a socket.
        let count = bytes.len().min(997);
        self.bytes.extend_from_slice(&bytes[..count]);
        if self.truncate_after_headers.is_some() && self.bytes.windows(4).any(|w| w == b"\r\n\r\n")
        {
            let path = self.truncate_after_headers.take().unwrap();
            std::fs::File::options()
                .write(true)
                .open(path)?
                .set_len(32)?;
        }
        Ok(count)
    }
}
impl io::Read for RecordingIo {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl io::Write for RecordingIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.record(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl AsyncRead for RecordingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for RecordingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Alternate Pending/Ready so the async path must respect backpressure.
        self.pending = !self.pending;
        if self.pending {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(self.record(bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn serve(
    fixture: &Fixture,
    protocol: Protocol,
    headers: HeaderMap,
    version: Version,
    streaming: (u64, usize),
    io: &mut RecordingIo,
) -> io::Result<()> {
    let path = fixture.root.join("large.pak");
    match protocol {
        #[cfg(feature = "net-h1-server")]
        Protocol::H1Sync => {
            use crate::network::http::h1_session::new_session;
            use bytes::BytesMut;
            let mut request = format!("GET /large.pak {version:?}\r\nHost: localhost\r\n");
            for (key, value) in &headers {
                request.push_str(&format!("{key}: {}\r\n", value.to_str().unwrap()));
            }
            request.push_str("\r\n");
            let mut request = BytesMut::from(request.as_bytes());
            let mut reply = BytesMut::new();
            let peer = "127.0.0.1".parse().unwrap();
            let mut session = new_session(io, &peer, &mut request, &mut reply)?.unwrap();
            super::super::serve_h1(
                &mut session,
                &path,
                &fixture.cache,
                &[EncodingType::None],
                (1, 1024),
                streaming,
                ("inline", true),
            )
        }
        Protocol::H1Async => {
            let mut session = H1SessionAsync::new(
                "127.0.0.1".parse().unwrap(),
                io,
                (Method::GET, version),
                Uri::from_static("/large.pak"),
                (headers, Bytes::new()),
                true,
                false,
            );
            super::super::serve_h1_async(
                &mut session,
                &path,
                &fixture.cache,
                &[EncodingType::None],
                (1, 1024),
                streaming,
                ("inline", true),
            )
            .await
        }
        Protocol::H2 => unreachable!(),
    }
}

fn large_file(fixture: &Fixture) -> Vec<u8> {
    let bytes: Vec<u8> = (0..768 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(fixture.root.join("large.pak"), &bytes).unwrap();
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn large_h1_ranges_use_bounded_writes_and_exact_fixed_length_framing() {
    let fixture = Fixture::new();
    let bytes = large_file(&fixture);
    for &protocol in PROTOCOLS.iter().filter(|p| !matches!(p, Protocol::H2)) {
        for version in [Version::HTTP_11, Version::HTTP_10] {
            for (streaming, maximum) in [((16 * 1024, 4096), 4096), ((0, 0), 64 * 1024)] {
                for (range, start, end) in [
                    (
                        format!("bytes=123-{}", bytes.len() - 58),
                        123,
                        bytes.len() - 57,
                    ),
                    (format!("bytes=-{}", bytes.len() - 79), 79, bytes.len()),
                ] {
                    let mut io = RecordingIo::default();
                    serve(
                        &fixture,
                        protocol,
                        range_headers(&range),
                        version,
                        streaming,
                        &mut io,
                    )
                    .await
                    .unwrap();
                    let response = parse_h1(&io.bytes);
                    assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
                    assert_eq!(
                        response.headers[header::CONTENT_RANGE],
                        format!("bytes {}-{}/{}", start, end - 1, bytes.len())
                    );
                    assert_eq!(
                        response.headers[header::CONTENT_LENGTH],
                        (end - start).to_string()
                    );
                    assert!(!response.headers.contains_key(header::TRANSFER_ENCODING));
                    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
                    assert!(
                        response.body == bytes[start..end],
                        "{protocol:?}: wrong range bytes (received {})",
                        response.body.len()
                    );
                    assert!(
                        io.largest_write <= maximum,
                        "{protocol:?}: wrote {} bytes at once; limit is {maximum}",
                        io.largest_write
                    );
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn streamed_full_files_keep_exact_bytes_and_length() {
    let fixture = Fixture::new();
    let bytes = large_file(&fixture);
    for &protocol in PROTOCOLS.iter().filter(|p| !matches!(p, Protocol::H2)) {
        let mut io = RecordingIo::default();
        serve(
            &fixture,
            protocol,
            HeaderMap::new(),
            Version::HTTP_11,
            (16 * 1024, 4096),
            &mut io,
        )
        .await
        .unwrap();
        let response = parse_h1(&io.bytes);
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers[header::CONTENT_LENGTH],
            bytes.len().to_string()
        );
        assert!(
            response.body == bytes,
            "{protocol:?}: wrong file bytes (received {})",
            response.body.len()
        );
        assert!(io.largest_write <= 4096);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_file_truncated_during_range_streaming_aborts_the_response() {
    for &protocol in PROTOCOLS.iter().filter(|p| !matches!(p, Protocol::H2)) {
        let fixture = Fixture::new();
        large_file(&fixture);
        let mut io = RecordingIo {
            truncate_after_headers: Some(fixture.root.join("large.pak")),
            ..Default::default()
        };
        let result = serve(
            &fixture,
            protocol,
            range_headers("bytes=123-"),
            Version::HTTP_11,
            (16 * 1024, 4096),
            &mut io,
        )
        .await;
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted,
            "{protocol:?}"
        );
        let response = parse_h1(&io.bytes);
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert!(response.body.is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn async_h1_streaming_preserves_length_or_uses_chunked_when_unknown() {
    for length in [None, Some("5")] {
        let mut io = RecordingIo::default();
        let mut session = H1SessionAsync::new(
            "127.0.0.1".parse().unwrap(),
            &mut io,
            (Method::GET, Version::HTTP_11),
            Uri::from_static("/"),
            (HeaderMap::new(), Bytes::new()),
            true,
            false,
        );
        if let Some(length) = length {
            session.header_str("content-length", length).unwrap();
        }
        session.start_h1_streaming_async().await.unwrap();
        session.send_h1_data_async(b"he", false).await.unwrap();
        session.send_h1_data_async(b"llo", true).await.unwrap();
        assert!(session.response_sent());
        drop(session);
        let response = parse_h1(&io.bytes);
        if length.is_some() {
            assert_eq!(response.headers[header::CONTENT_LENGTH], "5");
            assert!(!response.headers.contains_key(header::TRANSFER_ENCODING));
            assert_eq!(response.body, b"hello");
        } else {
            assert_eq!(response.headers[header::TRANSFER_ENCODING], "chunked");
            assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
            assert_eq!(response.body, b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_length_streams_reject_incomplete_or_oversized_final_writes() {
    for bytes in [b"short".as_slice(), b"too many bytes".as_slice()] {
        let mut io = RecordingIo::default();
        let mut session = H1SessionAsync::new(
            "127.0.0.1".parse().unwrap(),
            &mut io,
            (Method::GET, Version::HTTP_11),
            Uri::from_static("/"),
            (HeaderMap::new(), Bytes::new()),
            true,
            false,
        );
        session.header_str("content-length", "10").unwrap();
        session.start_h1_streaming_async().await.unwrap();
        assert!(session.send_h1_data_async(bytes, true).await.is_err());
        assert!(!session.response_sent());
        // A handler cannot append a second HTTP response after partial headers.
        assert!(
            session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Bytes::new())
                .eom_async()
                .await
                .is_err()
        );
        drop(session);
        assert!(parse_h1(&io.bytes).body.is_empty());
    }
}

#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
#[tokio::test(flavor = "current_thread")]
async fn aborted_streams_close_keep_alive_without_an_extra_response() {
    use crate::network::http::{h2_server, server::H2Config, session::HAsyncService};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    struct AbortedFile(Arc<AtomicUsize>);
    #[async_trait::async_trait(?Send)]
    impl HAsyncService for AbortedFile {
        async fn call<S: Session>(&self, session: &mut S) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            session
                .status_code(StatusCode::PARTIAL_CONTENT)
                .header_str("content-length", "100")?;
            session.start_h1_streaming_async().await?;
            session.send_h1_data_async(b"partial", false).await?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "file truncated",
            ))
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let requests = Arc::new(AtomicUsize::new(0));
        let (server, mut client) = tokio::io::duplex(4096);
        let config = H2Config { keep_alive: true, ..Default::default() };
        let server = h2_server::serve_h1(server, AbortedFile(Arc::clone(&requests)), &config, "127.0.0.1".parse().unwrap(), CancellationToken::new());
        let client = async {
            client.write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (result, bytes) = tokio::join!(server, client);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        let response = parse_h1(&bytes);
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers[header::CONTENT_LENGTH], "100");
        assert_eq!(response.body, b"partial");
    }).await.expect("an aborted file stream must close promptly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_session_sync_adapter_preserves_fixed_length_streaming() {
    let mut io = RecordingIo::default();
    let mut session = H1SessionAsync::new(
        "127.0.0.1".parse().unwrap(),
        &mut io,
        (Method::GET, Version::HTTP_11),
        Uri::from_static("/"),
        (HeaderMap::new(), Bytes::new()),
        true,
        false,
    );
    session.header_str("content-length", "5").unwrap();
    session.header_str("transfer-encoding", "chunked").unwrap();
    session.start_h1_streaming().unwrap();
    session.send_h1_data(b"he", false).unwrap();
    session.send_h1_data(b"llo", true).unwrap();
    assert!(session.response_sent());
    drop(session);
    let response = parse_h1(&io.bytes);
    assert_eq!(response.headers[header::CONTENT_LENGTH], "5");
    assert!(!response.headers.contains_key(header::TRANSFER_ENCODING));
    assert_eq!(response.body, b"hello");
}

#[tokio::test(flavor = "current_thread")]
async fn small_h1_responses_survive_truncation_after_headers() {
    for &protocol in PROTOCOLS.iter().filter(|p| !matches!(p, Protocol::H2)) {
        for range in [false, true] {
            let fixture = Fixture::new();
            let bytes: Vec<_> = (0..8192).map(|i| (i % 251) as u8).collect();
            std::fs::write(fixture.root.join("large.pak"), &bytes).unwrap();
            let mut io = RecordingIo {
                truncate_after_headers: Some(fixture.root.join("large.pak")),
                ..Default::default()
            };
            serve(
                &fixture,
                protocol,
                if range {
                    range_headers("bytes=4096-")
                } else {
                    HeaderMap::new()
                },
                Version::HTTP_11,
                (16 * 1024, 4096),
                &mut io,
            )
            .await
            .unwrap();
            let response = parse_h1(&io.bytes);
            let expected = if range { &bytes[4096..] } else { &bytes[..] };
            assert_eq!(
                response.status,
                if range {
                    StatusCode::PARTIAL_CONTENT
                } else {
                    StatusCode::OK
                }
            );
            assert!(
                response.body == expected,
                "{protocol:?}: buffered response changed after headers"
            );
            assert_eq!(
                response.headers[header::CONTENT_LENGTH],
                expected.len().to_string()
            );
            assert!(io.truncate_after_headers.is_none());
        }
    }
}
