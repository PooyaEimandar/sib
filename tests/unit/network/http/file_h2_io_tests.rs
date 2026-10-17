use super::*;
use crate::network::http::{
    h2_server,
    server::H2Config,
    session::{HAsyncService, Session},
};
use std::{io, sync::Arc};
use tokio_util::sync::CancellationToken;

struct FileService {
    fixture: Arc<Fixture>,
    threshold: u64,
    chunk_size: usize,
    finished: tokio::sync::mpsc::UnboundedSender<io::Result<()>>,
}

#[async_trait::async_trait(?Send)]
impl HAsyncService for FileService {
    async fn call<S: Session>(&self, session: &mut S) -> io::Result<()> {
        if session.req_path() == "/ping" {
            return session.body(Bytes::from_static(b"pong")).eom();
        }
        let result = super::super::serve_h2(
            session,
            &self.fixture.root.join("large.pak"),
            &self.fixture.cache,
            &[EncodingType::None],
            (1, 1024),
            (self.threshold, self.chunk_size),
            ("inline", true),
        )
        .await;
        self.finished.send(result).unwrap();
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn h2_ranges_stream_exact_bytes_and_leave_credit_for_other_requests() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let fixture = Arc::new(Fixture::new());
        let contents: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::write(fixture.root.join("large.pak"), &contents).unwrap();
        for (threshold, chunk_size) in [(128 * 1024, 1024), (1024, 128), (1024, 0)] {
            for range in [None, Some("bytes=123-70000")] {
                let (finished, mut results) = tokio::sync::mpsc::unbounded_channel();
                let service = FileService {
                    fixture: Arc::clone(&fixture),
                    threshold,
                    chunk_size,
                    finished,
                };
                let shutdown = CancellationToken::new();
                let (server, client) = tokio::io::duplex(4096);
                let config = H2Config::default();
                let server = h2_server::serve_h2(
                    server,
                    service,
                    &config,
                    "127.0.0.1".parse().unwrap(),
                    shutdown.clone(),
                );
                let client = async {
                    let (mut sender, connection) = h2::client::Builder::new()
                        .initial_window_size(256)
                        .handshake::<_, Bytes>(client)
                        .await
                        .unwrap();
                    let requests = async {
                        let mut request =
                            http::Request::builder().uri("https://localhost/large.pak");
                        if let Some(range) = range {
                            request = request.header(header::RANGE, range);
                        }
                        let (response, _) = sender
                            .send_request(request.body(()).unwrap(), true)
                            .unwrap();
                        let response = response.await.unwrap();
                        let (parts, mut body) = response.into_parts();
                        let (start, end) = if range.is_some() {
                            (123, 70001)
                        } else {
                            (0, contents.len())
                        };
                        assert_eq!(
                            parts.status,
                            if range.is_some() {
                                StatusCode::PARTIAL_CONTENT
                            } else {
                                StatusCode::OK
                            }
                        );
                        if range.is_some() {
                            let ranges: Vec<_> = parts
                                .headers
                                .get_all(header::CONTENT_RANGE)
                                .iter()
                                .collect();
                            assert_eq!(
                                ranges.len(),
                                1,
                                "only one Content-Range may describe a response"
                            );
                            assert_eq!(
                                ranges[0],
                                &format!("bytes {}-{}/{}", start, end - 1, contents.len())
                            );
                        }
                        // Hold the first stream's receive credit while completing another
                        // request. Both handlers and the H2 driver share this one thread.
                        let first = body.data().await.unwrap().unwrap();
                        let (ping, _) = sender
                            .send_request(
                                http::Request::builder()
                                    .uri("https://localhost/ping")
                                    .body(())
                                    .unwrap(),
                                true,
                            )
                            .unwrap();
                        let mut ping = ping.await.unwrap().into_body();
                        assert_eq!(ping.data().await.unwrap().unwrap(), b"pong".as_slice());
                        assert!(ping.data().await.is_none());
                        let mut bytes = first.to_vec();
                        body.flow_control().release_capacity(first.len()).unwrap();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            if threshold < contents.len() as u64 && chunk_size != 0 {
                                assert!(chunk.len() <= chunk_size);
                            }
                            bytes.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                        assert!(
                            bytes == contents[start..end],
                            "incorrect file/range contents"
                        );
                        results.recv().await.unwrap().unwrap();
                        shutdown.cancel();
                    };
                    let (result, ()) = tokio::join!(connection, requests);
                    result.unwrap();
                };
                tokio::task::LocalSet::new()
                    .run_until(async {
                        let (result, ()) = tokio::join!(server, client);
                        result.unwrap();
                    })
                    .await;
            }
        }
    })
    .await
    .expect("HTTP/2 downloads and an independent stream must make progress");
}

#[tokio::test(flavor = "current_thread")]
async fn h2_streaming_rejects_a_file_shorter_than_the_requested_extent() {
    use crate::network::http::h1_session_async::H1SessionAsync;
    let fixture = Fixture::new();
    let (mut io, _client) = tokio::io::duplex(1024);
    // This session cannot start H2: extent validation must fail before headers.
    let mut session = H1SessionAsync::new(
        "127.0.0.1".parse().unwrap(),
        &mut io,
        (Method::GET, Version::HTTP_11),
        Uri::from_static("/"),
        (HeaderMap::new(), Bytes::new()),
        false,
        false,
    );
    let result = super::super::serve_h2_streaming(
        &mut session,
        StatusCode::PARTIAL_CONTENT,
        &fixture.root.join("plain.txt"),
        2,
        100,
        1024,
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn h2_file_open_does_not_block_the_runtime_thread() {
    use crate::network::http::h1_session_async::H1SessionAsync;
    use std::{fs::OpenOptions, sync::mpsc};
    let fixture = Fixture::new();
    let fifo = fixture.root.join("slow-file");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (wake, wake_rx) = mpsc::channel();
    let (done, done_rx) = mpsc::channel();
    let writer_path = fifo.clone();
    // A separate OS thread guarantees the old blocking implementation is
    // released too, so the regression fails instead of hanging the test runner.
    let writer = std::thread::spawn(move || {
        let responsive = wake_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(writer_path)
            .unwrap();
        let _ = done_rx.recv();
        responsive
    });
    let (mut io, _client) = tokio::io::duplex(1024);
    let mut session = H1SessionAsync::new(
        "127.0.0.1".parse().unwrap(),
        &mut io,
        (Method::GET, Version::HTTP_11),
        Uri::from_static("/"),
        (HeaderMap::new(), Bytes::new()),
        false,
        false,
    );
    let transfer = async {
        let result =
            super::super::serve_h2_streaming(&mut session, StatusCode::OK, &fifo, 0, 1, 1024).await;
        let _ = done.send(());
        assert!(result.is_err());
    };
    let other_work = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = wake.send(());
    };
    tokio::join!(transfer, other_work);
    assert!(
        writer.join().unwrap(),
        "opening a slow file blocked unrelated work on the runtime"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn h2_truncation_resets_only_the_incomplete_stream() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let fixture = Arc::new(Fixture::new());
        let path = fixture.root.join("large.pak");
        let contents = vec![b'x'; 96 * 1024];
        std::fs::write(&path, &contents).unwrap();
        let (finished, mut results) = tokio::sync::mpsc::unbounded_channel();
        let service = FileService {
            fixture: Arc::clone(&fixture),
            threshold: 1024,
            chunk_size: 128,
            finished,
        };
        let shutdown = CancellationToken::new();
        let (server, client) = tokio::io::duplex(4096);
        let config = H2Config::default();
        let server = h2_server::serve_h2(
            server,
            service,
            &config,
            "127.0.0.1".parse().unwrap(),
            shutdown.clone(),
        );
        let client = async {
            let (mut sender, connection) = h2::client::Builder::new()
                .initial_window_size(256)
                .handshake::<_, Bytes>(client)
                .await
                .unwrap();
            let requests = async {
                let (response, _) = sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://localhost/large.pak")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let mut body = response.into_body();
                let first = body.data().await.unwrap().unwrap();
                assert!(!first.is_empty());
                // The stream is open, but receive credit prevents the entire
                // file being queued before we truncate it on disk.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
                let mut received = first.len();
                body.flow_control().release_capacity(first.len()).unwrap();
                let error = loop {
                    match body.data().await {
                        Some(Ok(bytes)) => {
                            received += bytes.len();
                            body.flow_control().release_capacity(bytes.len()).unwrap();
                        }
                        Some(Err(error)) => break error,
                        None => panic!("truncated file was reported as a complete response"),
                    }
                };
                assert_eq!(error.reason(), Some(h2::Reason::INTERNAL_ERROR));
                assert!(received < contents.len());
                assert_eq!(
                    results.recv().await.unwrap().unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
                let (ping, _) = sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://localhost/ping")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                let mut ping = ping.await.unwrap().into_body();
                assert_eq!(ping.data().await.unwrap().unwrap(), b"pong".as_slice());
                assert!(ping.data().await.is_none());
                shutdown.cancel();
            };
            let (result, ()) = tokio::join!(connection, requests);
            result.unwrap();
        };
        tokio::task::LocalSet::new()
            .run_until(async {
                let (result, ()) = tokio::join!(server, client);
                result.unwrap();
            })
            .await;
    })
    .await
    .expect("truncation must reset the stream without stalling the connection");
}
