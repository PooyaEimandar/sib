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
        let body = match session.req_path().as_str() {
            "/hang" => {
                self.live.fetch_add(1, Ordering::SeqCst);
                let _guard = Guard(self.live.clone());
                std::future::pending::<()>().await;
                unreachable!()
            }
            "/echo" if session.req_http_version() == http::Version::HTTP_2 => {
                let mut data = Vec::new();
                while let Some(chunk) = session.req_body_async(Duration::from_secs(2)).await {
                    data.extend_from_slice(&chunk?);
                }
                Bytes::from(data)
            }
            "/echo" => session
                .req_body_async(Duration::from_secs(2))
                .await
                .unwrap()?,
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
