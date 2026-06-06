use crate::network::http::server::HFactory;

#[allow(unused_imports)]
use tracing::{error, info, warn};

#[cfg(feature = "net-h1-server")]
use crate::network::http::session::HService;

#[cfg(any(
    feature = "net-h2-server",
    all(feature = "net-h3-server", target_os = "linux")
))]
use crate::network::http::session::HAsyncService;
cfg_if::cfg_if! {
    if #[cfg(any(
        feature = "net-h1-server",
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux"),
        feature = "net-ws-server"))]
    {
        use crate::network::http::session::Session;
        use std::sync::Once;

        static INIT: Once = Once::new();
    }
}

pub struct EchoServer;

#[cfg(feature = "net-h1-server")]
impl HService for EchoServer {
    fn call<SE: Session>(&self, session: &mut SE) -> std::io::Result<()> {
        // WebSocket upgrade path
        #[cfg(feature = "net-ws-server")]
        if session.is_ws() {
            if let Err(e) = session.ws_accept() {
                session
                    .status_code(http::StatusCode::BAD_REQUEST)
                    .header_str("Connection", "close")?
                    .eom()?;
                return Err(e);
            }

            use crate::network::http::ws::OpCode;
            use bytes::{Bytes, BytesMut};

            let mut frag_buf = BytesMut::new();
            let mut expecting_cont = false;
            let mut initial_is_text = false;

            // Pre-allocate small static replies as Bytes to satisfy &Bytes params
            let reply_text = Bytes::from_static(b"hello ws client!");
            let err_protocol = Bytes::from_static(b"protocol error");
            let err_unexpected = Bytes::from_static(b"unexpected continue");
            let err_utf8 = Bytes::from_static(b"invalid utf8");

            loop {
                let (code, payload, fin) = session.ws_read()?; // payload: Bytes

                match code {
                    OpCode::Ping => {
                        // Echo same payload
                        session.ws_write(OpCode::Pong, &payload, true)?;
                    }
                    OpCode::Pong => {
                        // ignore
                    }
                    OpCode::Close => {
                        // Echo client's Close payload back
                        session.ws_write(OpCode::Close, &payload, true)?;
                        break;
                    }
                    OpCode::Text | OpCode::Binary => {
                        if expecting_cont {
                            // Protocol error: new data frame while fragmented message pending
                            session.ws_close(Some(&err_protocol))?;
                            break;
                        }

                        if !fin {
                            // Start fragmented message; accumulate only if needed
                            frag_buf.clear();
                            frag_buf.extend_from_slice(payload.as_ref());
                            expecting_cont = true;
                            initial_is_text = matches!(code, OpCode::Text);
                            continue;
                        }

                        // Single-frame message
                        if matches!(code, OpCode::Text) {
                            if let Ok(msg) = std::str::from_utf8(payload.as_ref()) {
                                info!("WS server got: Text ({} bytes): {msg}", payload.len());
                                session.ws_write(OpCode::Text, &reply_text, true)?;
                            } else {
                                session.ws_close(Some(&err_utf8))?;
                                break;
                            }
                        } else {
                            info!("WS server got Binary ({} bytes)", payload.len());
                            session.ws_write(OpCode::Binary, &payload, true)?;
                        }
                    }
                    OpCode::Continue => {
                        if !expecting_cont {
                            session.ws_close(Some(&err_unexpected))?;
                            break;
                        }

                        frag_buf.extend_from_slice(payload.as_ref());

                        if fin {
                            // Complete fragmented message
                            let whole = frag_buf.as_ref();
                            if initial_is_text {
                                if let Ok(msg) = std::str::from_utf8(whole) {
                                    info!("WS server got (fragmented text): {msg}");
                                    session.ws_write(OpCode::Text, &reply_text, true)?;
                                } else {
                                    session.ws_close(Some(&err_utf8))?;
                                    break;
                                }
                            } else {
                                info!("WS server got (fragmented binary): {} bytes", whole.len());
                                let whole_bytes = Bytes::copy_from_slice(whole);
                                session.ws_write(OpCode::Binary, &whole_bytes, true)?;
                            }
                            frag_buf.clear();
                            expecting_cont = false;
                        }
                    }
                }
            }

            // Tell the outer loop to stop using this socket
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "ws done",
            ));
        }

        // Normal HTTP echo path
        let req_host = session.req_host();
        let req_method = session.req_method();
        let req_path = session.req_path();
        let http_version = session.req_http_version();
        let req_body = session.req_body(std::time::Duration::from_secs(5))?;
        let req_body_text = std::str::from_utf8(req_body).unwrap_or("<non-utf8 body>");

        let body = bytes::Bytes::from(format!(
            "Http version: {http_version:?}, Echo: {req_method:?} {req_host:?} {req_path:?}\r\nBody: {req_body_text}"
        ));

        session
            .status_code(http::StatusCode::OK)
            .header_str("Content-Type", "text/plain")?
            .header_str("Content-Length", &body.len().to_string())?
            .body(body)
            .eom()?;

        if req_method == http::Method::POST {
            // Preserve your existing test behavior
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "H1 POST should return WouldBlock",
            ));
        }

        Ok(())
    }
}

#[cfg(any(
    feature = "net-h2-server",
    all(feature = "net-h3-server", target_os = "linux")
))]
#[async_trait::async_trait(?Send)]
impl HAsyncService for EchoServer {
    async fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        // WebSocket upgrade path
        #[cfg(feature = "net-ws-server")]
        if session.is_ws() {
            if let Err(e) = session.ws_accept_async().await {
                session
                    .status_code(http::StatusCode::BAD_REQUEST)
                    .header_str("Connection", "close")?
                    .eom()?;
                return Err(e);
            }

            use crate::network::http::ws::OpCode;
            use bytes::{Bytes, BytesMut};

            let mut frag_buf = BytesMut::new();
            let mut expecting_cont = false;
            let mut initial_is_text = false;

            // Pre-allocate small static replies as Bytes to satisfy &Bytes params
            let err_protocol = Bytes::from_static(b"protocol error");
            let err_unexpected = Bytes::from_static(b"unexpected continue");
            let err_utf8 = Bytes::from_static(b"invalid utf8");

            loop {
                let (code, payload, fin) = session.ws_read_async().await?; // payload: Bytes

                match code {
                    OpCode::Ping => {
                        // Echo same payload
                        session.ws_write_async(OpCode::Pong, payload, true).await?;
                    }
                    OpCode::Pong => {
                        // ignore
                    }
                    OpCode::Close => {
                        // Echo client's Close payload back
                        session.ws_write_async(OpCode::Close, payload, true).await?;
                        break;
                    }
                    OpCode::Text | OpCode::Binary => {
                        if expecting_cont {
                            // Protocol error: new data frame while fragmented message pending
                            session.ws_close_async(Some(err_protocol)).await?;
                            break;
                        }

                        if !fin {
                            // Start fragmented message; accumulate only if needed
                            frag_buf.clear();
                            frag_buf.extend_from_slice(payload.as_ref());
                            expecting_cont = true;
                            initial_is_text = matches!(code, OpCode::Text);
                            continue;
                        }

                        // Single-frame message
                        if matches!(code, OpCode::Text) {
                            if let Ok(msg) = std::str::from_utf8(payload.as_ref()) {
                                let reply_text = Bytes::from_static(b"hello ws client!");
                                info!("WS server got: Text ({} bytes): {msg}", payload.len());
                                session
                                    .ws_write_async(OpCode::Text, reply_text, true)
                                    .await?;
                            } else {
                                session.ws_close_async(Some(err_utf8)).await?;
                                break;
                            }
                        } else {
                            info!("WS server got Binary ({} bytes)", payload.len());
                            session
                                .ws_write_async(OpCode::Binary, payload, true)
                                .await?;
                        }
                    }
                    OpCode::Continue => {
                        if !expecting_cont {
                            session.ws_close_async(Some(err_unexpected)).await?;
                            break;
                        }

                        frag_buf.extend_from_slice(payload.as_ref());

                        if fin {
                            // Complete fragmented message
                            let whole = frag_buf.as_ref();
                            if initial_is_text {
                                if let Ok(msg) = std::str::from_utf8(whole) {
                                    let reply_text = Bytes::from_static(b"hello ws client!");
                                    info!("WS server got (fragmented text): {msg}");
                                    session
                                        .ws_write_async(OpCode::Text, reply_text, true)
                                        .await?;
                                } else {
                                    session.ws_close_async(Some(err_utf8)).await?;
                                    break;
                                }
                            } else {
                                info!("WS server got (fragmented binary): {} bytes", whole.len());
                                let whole_bytes = Bytes::copy_from_slice(whole);
                                session
                                    .ws_write_async(OpCode::Binary, whole_bytes, true)
                                    .await?;
                            }
                            frag_buf.clear();
                            expecting_cont = false;
                        }
                    }
                }
            }

            // Tell the outer loop to stop using this socket
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "ws done",
            ));
        }

        let req_host = session.req_host();
        let req_method = session.req_method();
        let req_path = session.req_path().to_owned();
        let http_version = session.req_http_version();
        let req_body = session
            .req_body_async(std::time::Duration::from_secs(5))
            .await;
        let body = bytes::Bytes::from(format!(
            "Http version: {http_version:?}, Echo: {req_method:?} {req_host:?} {req_path:?}\r\nBody: {req_body:?}"
        ));

        let content_len = body.len().to_string();
        session
            .status_code(http::StatusCode::OK)
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            )?
            .header(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&content_len).expect("content_len"),
            )?
            .body(body)
            .eom_async()
            .await?;
        Ok(())
    }
}

impl HFactory for EchoServer {
    #[cfg(feature = "net-h1-server")]
    type Service = Self;

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    type HAsyncService = Self;

    #[cfg(feature = "net-wt-server")]
    type WtService = Self;

    #[cfg(feature = "net-h1-server")]
    fn service(&self, _id: usize) -> Self::Service {
        EchoServer
    }

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        EchoServer
    }

    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, _id: usize) -> Self::WtService {
        EchoServer
    }
}

#[cfg(feature = "net-wt-server")]
use crate::network::http::wt::{WtService, WtSession};

#[cfg(feature = "net-wt-server")]
#[async_trait::async_trait(?Send)]
impl WtService for EchoServer {
    async fn call(&mut self, _session: &mut WtSession) -> std::io::Result<()> {
        // keep-alive window for manual testing via the browser
        use tokio::time::Duration;
        tokio::time::sleep(Duration::from_secs(10)).await;
        Ok(())
    }
}

#[cfg(feature = "net-h1-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h1_tls_server_gracefull_shutdown() {
    use crate::{MtlsIdentity, network::http::server::H1Config};
    use std::time::Duration;

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 0);

    let tls = MtlsIdentity::generate(&[], &[], false);
    let addr = "127.0.0.1:8080";
    let server_handle = EchoServer
        .start_h1_tls(
            addr,
            (
                None,
                tls.server_cert_pem.as_bytes(),
                tls.server_key_pem.as_bytes(),
            ),
            H1Config::default(),
        )
        .expect("H1 TLS server failed to start");

    let handler = may::go!(move || {
        may::coroutine::sleep(Duration::from_millis(100));
        unsafe { server_handle.coroutine().cancel() };
    });

    handler.join().expect("shutdown signaler failed");
}

#[cfg(feature = "net-h1-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h1_tls_server_get_with_client_auth() {
    use crate::{MtlsIdentity, network::http::server::H1Config};
    use std::time::Duration;

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

    // Pick a port and start the server
    const ADDR: &str = "localhost:8081";
    let tls = MtlsIdentity::generate(&[], &[], true);
    let server_handle = EchoServer
        .start_h1_tls(
            ADDR,
            (
                None,
                tls.server_cert_pem.as_bytes(),
                tls.server_key_pem.as_bytes(),
            ),
            H1Config {
                client_ca_pem: Some(tls.ca_cert_pem.clone().into_bytes()),
                ..Default::default()
            },
        )
        .expect("h1 tls start server");

    let client_handler = may::go!(move || {
        // Give the server a moment to start listening
        may::coroutine::sleep(Duration::from_millis(500));

        let server_ca =
            reqwest::Certificate::from_pem(tls.ca_cert_pem.as_bytes()).expect("parse server cert");
        // Use reqwest blocking in this coroutine.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .add_root_certificate(server_ca)
            .identity(
                reqwest::Identity::from_pem(
                    format!(
                        "{}\n{}",
                        tls.client_cert_pem.unwrap(),
                        tls.client_key_pem.unwrap()
                    )
                    .as_bytes(),
                )
                .expect("build client identity"),
            )
            .build()
            .expect("build reqwest client");

        let url = format!("https://{ADDR}/test");

        let resp = client.get(&url).body("Hello").send().expect("send GET");
        let status = resp.status();
        let body = resp.text().expect("read body");

        info!("H1 GET Status: {status}");
        info!("H1 GET Body: {body}");

        assert!(status.is_success(), "status was {status}");
        assert!(body.contains("/test"), "body did not contain /test");
    });

    may::join!(server_handle, client_handler);

    std::thread::sleep(Duration::from_secs(1));
}

#[cfg(feature = "net-h1-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h1_server_get() {
    use crate::network::http::server::H1Config;
    use std::time::Duration;

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

    // Pick a port and start the server
    let addr = "127.0.0.1:8081";
    let server_handle = EchoServer
        .start_h1(addr, H1Config::default())
        .expect("h1 start server");

    let client_handler = may::go!(move || {
        // Give the server a moment to start listening
        may::coroutine::sleep(Duration::from_millis(500));

        // Use reqwest (blocking) in this coroutine.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");

        let url = format!("http://{addr}/test");

        let resp = client.get(&url).body("Hello").send().expect("send GET");
        let status = resp.status();
        let body = resp.text().expect("read body");

        info!("H1 GET Status: {status}");
        info!("H1 GET Body: {body}");

        assert!(status.is_success(), "status was {status}");
        assert!(body.contains("/test"), "body did not contain /test");
    });

    may::join!(server_handle, client_handler);

    std::thread::sleep(Duration::from_secs(1));
}

#[cfg(feature = "net-h1-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h1_server_post() {
    use crate::network::http::server::H1Config;
    use std::time::Duration;

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

    let addr = "127.0.0.1:8082";
    let server_handle = EchoServer
        .start_h1(addr, H1Config::default())
        .expect("h1 start server");

    let client_handler = may::go!(move || {
        may::coroutine::sleep(Duration::from_millis(500));

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");

        let url = format!("http://{addr}/submit");

        let body = "hello=world";

        let resp = client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .expect("send POST");

        let status = resp.status();
        let text = resp.text().expect("read body");

        info!("H1 POST Status: {status}");
        info!("H1 POST Body: {text}");

        assert!(status.is_success(), "status was {status}");
        assert!(text.contains("POST"));
        assert!(text.contains("/submit"));
        assert!(text.contains("hello=world"));
    });

    may::join!(server_handle, client_handler);
    std::thread::sleep(Duration::from_secs(1));
}

#[cfg(all(feature = "net-ws-server", feature = "net-h1-server"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h1_ws_server() {
    use crate::network::http::server::H1Config;
    use std::time::Duration;

    let addr = "127.0.0.1:8081";
    let server_handler = std::thread::spawn(move || {
        const NUMBER_OF_WORKERS: usize = 1;
        crate::init_global_poller(NUMBER_OF_WORKERS, 2 * 1024 * 1024);

        // Pick a port and start the server
        EchoServer
            .start_h1(addr, H1Config::default())
            .expect("h1 start server")
    });

    std::thread::sleep(Duration::from_millis(500));
    // Connect to websocket server
    let (mut socket, response) =
        tungstenite::client::connect(format!("ws://{}", addr)).expect("websocket handshake failed");

    info!("WS GET Response: {response:?}");

    if socket.can_write() {
        socket
            .write(tungstenite::Message::Text("hello ws server".into()))
            .expect("ws write");
        socket.flush().expect("ws flush");
    }
    if socket.can_read() {
        let msg = socket.read().expect("ws read");
        info!("WS client got: {msg:?}");
    }
    socket.close(None).expect("close failed");

    may::join!(server_handler);

    std::thread::sleep(Duration::from_secs(1));
}

#[cfg(feature = "net-h2-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h2_tls_server_gracefull_shutdown() {
    use crate::{MtlsIdentity, network::http::server::H2Config};
    use std::time::Duration;

    let cancel_token = tokio_util::sync::CancellationToken::new();

    let ct_cloned = cancel_token.clone();
    let handler = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        ct_cloned.cancel();
    });

    let tls = MtlsIdentity::generate(&[], &[], false);
    let addr = "127.0.0.1:8080";
    EchoServer
        .start_h2_tls(
            addr,
            (
                None,
                tls.server_cert_pem.as_bytes(),
                tls.server_key_pem.as_bytes(),
            ),
            H2Config::default(),
            cancel_token,
        )
        .expect("H2 TLS server failed to start");

    handler.join().expect("shutdown signaler failed");
}

#[cfg(feature = "net-h2-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h2_tls_server_get() {
    let addr = "127.0.0.1:8083";
    let _ = std::thread::spawn(move || {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let mtls = crate::MtlsIdentity::generate(&[], &[], false);

        use crate::network::http::server::H2Config;
        // Pick a port and start the server
        EchoServer
            .start_h2_tls(
                addr,
                (
                    None,
                    mtls.server_cert_pem.as_bytes(),
                    mtls.server_key_pem.as_bytes(),
                ),
                H2Config::default(),
                cancel_token.clone(),
            )
            .expect("start_h2_tls");
    });

    std::thread::sleep(std::time::Duration::from_secs(1));

    // test http1 get
    {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http1_only()
            .build()
            .expect("reqwest client");

        let resp = client
            .get(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_11)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        info!("H1 Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        info!("H1 Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }

    // test http2 get
    {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http2_adaptive_window(true)
            .build()
            .expect("reqwest client");

        let resp = client
            .get(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_2)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        info!("H2 Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        info!("H2 Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }
}

#[cfg(feature = "net-h2-server")]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h2_tls_server_post() {
    let addr = "127.0.0.1:8084";
    let _ = std::thread::spawn(move || {
        use crate::network::http::server::H2Config;

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let mtls = crate::MtlsIdentity::generate(&[], &[], false);
        // Pick a port and start the server
        EchoServer
            .start_h2_tls(
                addr,
                (
                    None,
                    mtls.server_cert_pem.as_bytes(),
                    mtls.server_key_pem.as_bytes(),
                ),
                H2Config::default(),
                cancel_token.clone(),
            )
            .expect("start_h2_tls");
    });

    std::thread::sleep(std::time::Duration::from_secs(1));

    // test http1 post
    {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http1_only()
            .build()
            .expect("reqwest client");

        let resp = client
            .post(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_11)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        info!("H1 Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        info!("H1 Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }
    // test http2 post
    {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .http2_adaptive_window(true)
            .build()
            .expect("reqwest client");

        let resp = client
            .post(format!("https://{}", addr))
            .version(reqwest::Version::HTTP_2)
            .body("Hello, World!")
            .timeout(std::time::Duration::from_millis(300))
            .send()
            .expect("reqwest send");
        info!("H2 Response: {resp:?}");
        assert!(resp.status().is_success());

        let body = resp.text().expect("resp text");
        info!("H2 Response: {body:?}");
        assert!(body.contains("Echo:"));
        assert!(body.contains("Hello, World!"));
    }
}

#[cfg(all(feature = "net-h2-server", feature = "net-ws-server"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h2_tls_ws_over_h1_upgrade() {
    use crate::MtlsIdentity;
    use std::{net::TcpStream, time::Duration};

    let addr = "127.0.0.1:8087";

    // Cancellation token
    let cancel_token = tokio_util::sync::CancellationToken::new();

    //Generate ONCE and reuse on both sides
    let mtls = MtlsIdentity::generate(&[], &[], false);

    // Clone into server thread
    let cert_for_server = mtls.server_cert_pem.clone();
    let key_for_server = mtls.server_key_pem.clone();

    // Start H2 TLS server (it will also accept H1 via ALPN fallback path)
    let _ = std::thread::spawn(move || {
        use crate::network::http::server::H2Config;

        EchoServer
            .start_h2_tls(
                addr,
                (None, cert_for_server.as_bytes(), key_for_server.as_bytes()),
                H2Config::default(),
                cancel_token.clone(),
            )
            .expect("start_h2_tls");
    });

    std::thread::sleep(Duration::from_millis(800));

    // Client trusts the SAME cert the server will present
    let ca =
        native_tls::Certificate::from_pem(mtls.server_cert_pem.as_bytes()).expect("parse cert pem");

    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(ca)
        .build()
        .expect("build tls connector");

    // Connect TCP to the bind address
    let tcp = TcpStream::connect(addr).expect("tcp connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(3))).ok();
    tcp.set_nodelay(true).ok();

    // Perform TLS handshake (SNI = "localhost")
    let tls_stream = connector.connect("localhost", tcp).expect("tls handshake");

    // Perform WebSocket handshake
    let (mut ws, resp) =
        tungstenite::client::client(format!("wss://{}", addr), tls_stream).expect("wss handshake");

    info!("WS handshake response: {resp:?}");

    ws.send(tungstenite::Message::Text("hello ws server".into()))
        .expect("ws write");

    let msg = ws.read().expect("ws read");
    info!("WS client got: {msg:?}");

    assert!(
        matches!(&msg, tungstenite::Message::Text(s) if s.contains("hello ws")),
        "unexpected ws response: {msg:?}"
    );

    ws.close(None).ok();
}

#[cfg(all(feature = "net-h2-server", feature = "net-ws-server"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h2_tls_ws_over_h1_upgrade_with_client_auth() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::{net::TcpStream, sync::Arc, time::Duration};
    use tungstenite::Message;

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // helper: parse PEM cert list
    fn parse_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .map(|c| c.expect("cert pem parse").into_owned())
            .collect()
    }

    // helper: parse PEM private key
    fn parse_key(pem: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(pem)
            .expect("key pem parse")
            .clone_key()
    }

    // create mTLS identity for server and client
    let mtls = crate::MtlsIdentity::generate(&[], &[], true);
    let cert_for_server = mtls.server_cert_pem.clone();
    let key_for_server = mtls.server_key_pem.clone();
    let ca = mtls.ca_cert_pem.clone();

    const ADDR: &str = "127.0.0.1:8088";

    // Start server with client auth enabled
    let _ = std::thread::spawn(move || {
        use crate::network::http::server::H2Config;

        let cfg = H2Config {
            client_ca_pem: Some(ca.into_bytes()),
            ..Default::default()
        };

        EchoServer
            .start_h2_tls(
                ADDR,
                (None, cert_for_server.as_bytes(), key_for_server.as_bytes()),
                cfg,
                cancel_token.clone(),
            )
            .expect("start_h2_tls (mtls)");
    });

    std::thread::sleep(Duration::from_millis(800));

    // Trust the server cert (self-signed) by adding it as a root for the test.
    let mut roots = rustls::RootCertStore::empty();
    for c in parse_certs(mtls.ca_cert_pem.as_bytes()) {
        roots.add(c).expect("add CA cert as root");
    }

    // Provide client identity (client cert + key)
    let client_chain = parse_certs(mtls.client_cert_pem.unwrap().as_bytes());
    assert!(!client_chain.is_empty(), "client cert chain empty");
    let client_key = parse_key(mtls.client_key_pem.unwrap().as_bytes());

    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, client_key)
        .expect("build rustls client config with mTLS");

    // TCP connect to server
    let tcp = TcpStream::connect(ADDR).expect("tcp connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(3))).ok();
    tcp.set_nodelay(true).ok();

    // TLS handshake (SNI must match what your server cert covers; for self-signed tests we use localhost)
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = rustls::ClientConnection::new(Arc::new(tls_cfg), server_name).expect("client conn");

    // rustls stream implementing Read+Write
    let tls_stream = rustls::StreamOwned::new(conn, tcp);

    // WebSocket handshake over the established TLS stream
    let (mut ws, resp) =
        tungstenite::client::client(format!("wss://{}", ADDR), tls_stream).expect("wss handshake");
    info!("WS handshake response: {resp:?}");

    ws.send(Message::Text("hello ws server (mtls)".into()))
        .expect("ws write");

    let msg = ws.read().expect("ws read");
    info!("WS client got: {msg:?}");

    assert!(
        matches!(&msg, Message::Text(s) if s.contains("hello ws")),
        "unexpected ws response: {msg:?}"
    );

    ws.close(None).ok();
}

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h3_tls_server_get() {
    let addr = "127.0.0.1:8085";
    let _ = std::thread::spawn(move || {
        let (cert, key) = create_self_signed_tls_pems();

        use crate::network::http::server::H3Config;
        let h3_cfg = H3Config::default();
        // Pick a port and start the server
        EchoServer
            .start_h3_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h3_cfg)
            .expect("start_h3_tls");
    });

    std::thread::sleep(std::time::Duration::from_secs(1));

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .http3_prior_knowledge()
        .build()
        .expect("reqwest client");

    let resp = client
        .get(format!("https://{}", addr))
        .version(reqwest::Version::HTTP_3)
        .body("Hello, World!")
        .timeout(std::time::Duration::from_millis(300))
        .send()
        .expect("reqwest send");
    info!("Response: {resp:?}");
    assert!(resp.status().is_success());

    let body = resp.text().expect("resp text");
    info!("Response: {body:?}");
    assert!(body.contains("Echo:"));
    assert!(body.contains("Hello, World!"));
}

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
#[test]
#[ignore = "legacy network integration test uses fixed ports or long-running servers"]
fn test_h3_tls_server_post() {
    let addr = "127.0.0.1:8086";
    let _ = std::thread::spawn(move || {
        let (cert, key) = create_self_signed_tls_pems();

        use crate::network::http::server::H3Config;
        let h3_cfg = H3Config::default();
        // Pick a port and start the server
        EchoServer
            .start_h3_tls(addr, (None, cert.as_bytes(), key.as_bytes()), h3_cfg)
            .expect("start_h3_tls");
    });

    std::thread::sleep(std::time::Duration::from_secs(1));

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .http3_prior_knowledge()
        .build()
        .expect("reqwest client");

    let resp = client
        .post(format!("https://{}", addr))
        .version(reqwest::Version::HTTP_3)
        .body("Hello, World!")
        .timeout(std::time::Duration::from_millis(300))
        .send()
        .expect("reqwest send");
    info!("Response: {resp:?}");
    assert!(resp.status().is_success());

    let body = resp.text().expect("resp text");
    info!("Response: {body:?}");
    assert!(body.contains("Echo:"));
    assert!(body.contains("Hello, World!"));
}
