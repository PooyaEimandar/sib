use super::*;
use crate::network::http::session::{HAsyncService, Session};
use bytes::Bytes;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Service {
    live: Arc<AtomicUsize>,
}
struct Guard(Arc<AtomicUsize>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait::async_trait(?Send)]
impl HAsyncService for Service {
    async fn call<S: Session>(&self, session: &mut S) -> io::Result<()> {
        #[cfg(feature = "net-ws-server")]
        if session.is_ws() {
            return session.ws_accept_async().await;
        }
        let body = match session.req_path().as_str() {
            "/hang" => {
                self.live.fetch_add(1, Ordering::SeqCst);
                let _guard = Guard(self.live.clone());
                std::future::pending::<()>().await;
                unreachable!()
            }
            // The same drain loop must terminate for HTTP/1 and HTTP/2 bodies.
            "/echo" => {
                let mut data = Vec::new();
                while let Some(chunk) = session.req_body_async(Duration::from_secs(2)).await {
                    data.extend_from_slice(&chunk?);
                }
                Bytes::from(data)
            }
            "/large" => Bytes::from(vec![b'x'; 100]),
            "/staged-fail" => {
                session.header_str("content-length", "100")?;
                return Err(io::Error::other("handler failed after staging headers"));
            }
            "/cookies" => {
                session.header_str("set-cookie", "a=1")?;
                session.header(
                    http::header::SET_COOKIE,
                    http::HeaderValue::from_static("b=2"),
                )?;
                Bytes::new()
            }
            "/fixed-eom" => {
                session.header_str("content-length", "4")?;
                session.start_h1_streaming()?;
                session.send_h1_data(b"abcd", false)?;
                return session.eom();
            }
            "/retry-head" => {
                // Ignore a failed head write and try to finish the response anyway.
                let _ = session.start_h1_streaming_async().await;
                return session.eom();
            }
            "/partial-stream" => {
                session.header_str("content-length", "10")?;
                session.start_h1_streaming_async().await?;
                session.send_h1_data_async(b"abc", false).await?;
                return Err(io::Error::other("handler failed mid-stream"));
            }
            _ => Bytes::from_static(b"hello"),
        };
        session
            .header_str("content-length", &body.len().to_string())?
            .body(body)
            .eom_async()
            .await
    }
}
fn service() -> Service {
    Service {
        live: Arc::new(AtomicUsize::new(0)),
    }
}
/// Run one HTTP/1 connection over an in-memory pipe and return everything the server wrote.
async fn h1_exchange(cfg: &H2Config, request: &[u8]) -> (String, io::Result<()>) {
    let (mut client, server) = tokio::io::duplex(8192);
    let run = serve_h1(
        server,
        service(),
        cfg,
        "127.0.0.1".parse().unwrap(),
        CancellationToken::new(),
    );
    let verify = async {
        client.write_all(request).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        reply
    };
    let (result, reply) = tokio::join!(run, verify);
    (reply, result)
}

fn config() -> H2Config {
    H2Config {
        io_timeout: Duration::from_millis(250),
        ..Default::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fragmented_h1_body_keeps_pipelined_request_and_head_length() {
    let (mut client, server) = tokio::io::duplex(8192);
    let cfg = config();
    let run = serve_h1(
        server,
        service(),
        &cfg,
        "127.0.0.1".parse().unwrap(),
        CancellationToken::new(),
    );
    let verify = async {
        client
            .write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nab")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        client
            .write_all(
                b"cdefHEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply.matches("HTTP/1.1 200").count(), 2, "{reply}");
        assert!(reply.contains("\r\n\r\nabcdefHTTP/1.1 200"), "{reply}");
        assert!(
            reply.to_lowercase().contains("content-length: 5\r\n"),
            "{reply}"
        );
        assert!(reply.ends_with("\r\n\r\n"), "HEAD returned a body: {reply}");
    };
    let (result, ()) = tokio::join!(run, verify);
    result.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn h1_rejects_oversized_complete_headers_and_signed_lengths() {
    for request in [
        format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "x".repeat(300)),
        "POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\nx".into(),
    ] {
        let (mut client, server) = tokio::io::duplex(8192);
        client.write_all(request.as_bytes()).await.unwrap();
        let cfg = H2Config {
            max_header_list_size: 256,
            ..config()
        };
        assert!(
            serve_h1(
                server,
                service(),
                &cfg,
                "127.0.0.1".parse().unwrap(),
                CancellationToken::new()
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_headers_and_h2_preface_expire() {
    let cfg = config();
    for h2 in [false, true] {
        let (_client, server) = tokio::io::duplex(8192);
        let run = async {
            if h2 {
                serve_h2(
                    server,
                    service(),
                    &cfg,
                    "127.0.0.1".parse().unwrap(),
                    CancellationToken::new(),
                )
                .await
            } else {
                serve_h1(
                    server,
                    service(),
                    &cfg,
                    "127.0.0.1".parse().unwrap(),
                    CancellationToken::new(),
                )
                .await
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(2), run)
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn h2_releases_upload_window_and_cancels_tasks_on_disconnect() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (client, server) = tokio::io::duplex(8192);
            let svc = service();
            let live = svc.live.clone();
            let run = tokio::task::spawn_local(async move {
                serve_h2(
                    server,
                    svc,
                    &H2Config {
                        io_timeout: Duration::from_secs(2),
                        ..config()
                    },
                    "127.0.0.1".parse().unwrap(),
                    CancellationToken::new(),
                )
                .await
            });
            let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
            let connection = tokio::task::spawn_local(connection);
            let (response, mut upload) = sender
                .send_request(
                    http::Request::post("https://localhost/echo")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let data = Bytes::from(vec![42; 512 * 1024]);
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut offset = 0;
                while offset < data.len() {
                    upload.reserve_capacity(data.len() - offset);
                    let cap = std::future::poll_fn(|cx| upload.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    let end = (offset + cap).min(data.len());
                    upload
                        .send_data(data.slice(offset..end), end == data.len())
                        .unwrap();
                    offset = end;
                }
                let mut body = response.await.unwrap().into_body();
                let mut received = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    received.extend_from_slice(&chunk);
                }
                assert_eq!(received, data);
            })
            .await
            .unwrap();
            let (_response, _stream) = sender
                .send_request(
                    http::Request::get("https://localhost/hang")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while live.load(Ordering::SeqCst) != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            connection.abort();
            drop(sender);
            tokio::time::timeout(Duration::from_secs(3), run)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            tokio::task::yield_now().await;
            assert_eq!(live.load(Ordering::SeqCst), 0);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn idle_timeout_measures_inactivity_not_download_duration() {
    let (mut client, server) = tokio::io::duplex(1);
    let mut server = IdleIo::new(server, Duration::from_millis(100));
    let read = async {
        for _ in 0..10 {
            assert_eq!(server.read_u8().await.unwrap(), 9);
        }
    };
    let write = async {
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            client.write_all(&[9]).await.unwrap();
        }
    };
    tokio::join!(read, write);
}

#[tokio::test(flavor = "current_thread")]
async fn h1_error_fallback_drops_staged_headers() {
    let (reply, result) = h1_exchange(
        &config(),
        b"GET /staged-fail HTTP/1.1\r\nHost: localhost\r\n\r\n\
GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    result.unwrap();
    let lower = reply.to_lowercase();
    assert!(reply.starts_with("HTTP/1.1 500 "), "{reply}");
    assert!(lower.contains("content-length: 0\r\n"), "{reply}");
    assert!(!lower.contains("content-length: 100"), "{reply}");
    assert!(
        reply.ends_with("\r\n\r\nhello"),
        "next request was not served: {reply}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn h1_error_after_partial_stream_closes_the_connection() {
    let (reply, result) = h1_exchange(
        &config(),
        b"GET /partial-stream HTTP/1.1\r\nHost: localhost\r\n\r\n\
GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(result.is_err());
    assert!(reply.ends_with("\r\n\r\nabc"), "{reply}");
    assert_eq!(reply.matches("HTTP/1.1 ").count(), 1, "{reply}");
}

// Blocking session writes need a multi-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn h1_sync_eom_keeps_fixed_length_framing() {
    let (reply, result) = h1_exchange(
        &config(),
        b"GET /fixed-eom HTTP/1.1\r\nHost: localhost\r\n\r\n\
GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    result.unwrap();
    assert!(reply.contains("\r\n\r\nabcdHTTP/1.1 200"), "{reply}");
}

#[tokio::test(flavor = "current_thread")]
async fn h1_repeated_response_headers_are_all_sent() {
    let (reply, result) = h1_exchange(
        &config(),
        b"GET /cookies HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    result.unwrap();
    let lower = reply.to_lowercase();
    assert!(lower.contains("set-cookie: a=1\r\n"), "{reply}");
    assert!(lower.contains("set-cookie: b=2\r\n"), "{reply}");
}

#[cfg(feature = "net-ws-server")]
#[tokio::test(flavor = "current_thread")]
async fn ws_close_async_sends_normal_closure_code_with_reason() {
    use crate::network::http::h1_session_async::H1SessionAsync;

    let (mut client, mut server) = tokio::io::duplex(1024);
    let mut session = H1SessionAsync::new(
        "127.0.0.1".parse().unwrap(),
        &mut server,
        (http::Method::GET, http::Version::HTTP_11),
        "/".parse().unwrap(),
        (http::HeaderMap::new(), Bytes::new()),
        true,
        true,
    );
    session
        .ws_close_async(Some(Bytes::from_static(b"going away")))
        .await
        .unwrap();
    assert!(
        session
            .ws_close_async(Some(Bytes::from_static(b"\xff")))
            .await
            .is_err()
    );
    drop(session);

    let mut frame = [0u8; 14];
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame[..4], &[0x88, 12, 0x03, 0xe8]);
    assert_eq!(&frame[4..], b"going away");
}

#[cfg(feature = "net-ws-server")]
#[tokio::test(flavor = "current_thread")]
async fn h1_ws_upgrade_keeps_connection_upgrade_without_keep_alive() {
    let cfg = H2Config {
        keep_alive: false,
        ..config()
    };
    let (reply, result) = h1_exchange(
        &cfg,
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .await;
    result.unwrap();
    let lower = reply.to_lowercase();
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply}");
    assert!(lower.contains("connection: upgrade\r\n"), "{reply}");
    assert!(!lower.contains("connection: close"), "{reply}");
}

/// Transport whose writes fail once after `fail_at` bytes, then succeed again.
struct FlakyWrite<S> {
    inner: S,
    fail_at: usize,
    written: usize,
    failed: bool,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FlakyWrite<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FlakyWrite<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut len = buf.len();
        if !this.failed {
            let room = this.fail_at - this.written;
            if room == 0 {
                this.failed = true;
                return std::task::Poll::Ready(Err(io::Error::other("injected write failure")));
            }
            len = len.min(room);
        }
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, &buf[..len]);
        if let std::task::Poll::Ready(Ok(n)) = result {
            this.written += n;
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn h1_write_failure_mid_body_closes_instead_of_appending_a_500() {
    let (mut client, server) = tokio::io::duplex(8192);
    let server = FlakyWrite {
        inner: server,
        fail_at: 60,
        written: 0,
        failed: false,
    };
    let cfg = config();
    let run = serve_h1(
        server,
        service(),
        &cfg,
        "127.0.0.1".parse().unwrap(),
        CancellationToken::new(),
    );
    let verify = async {
        client
            .write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        reply
    };
    let (result, reply) = tokio::join!(run, verify);
    assert!(result.is_err());
    assert_eq!(reply.matches("HTTP/1.1 ").count(), 1, "{reply}");
    assert!(!reply.contains(" 500 "), "{reply}");
}

#[tokio::test(flavor = "multi_thread")]
async fn h1_eom_after_a_failed_streaming_head_does_not_send_a_terminator() {
    let (mut client, server) = tokio::io::duplex(8192);
    let server = FlakyWrite {
        inner: server,
        fail_at: 10,
        written: 0,
        failed: false,
    };
    let cfg = config();
    let run = serve_h1(
        server,
        service(),
        &cfg,
        "127.0.0.1".parse().unwrap(),
        CancellationToken::new(),
    );
    let verify = async {
        client
            .write_all(b"GET /retry-head HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        reply
    };
    let (result, reply) = tokio::join!(run, verify);
    assert!(result.is_err());
    assert_eq!(reply, "HTTP/1.1 2", "{reply:?}");
}
