#![cfg(feature = "net-h1-server")]

#[cfg(feature = "net-h2-server")]
use sib::network::http::session::HAsyncService;
use sib::network::http::{
    server::{H1Config, HFactory},
    session::{HService, Session},
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Once,
    time::Duration,
};

static INIT: Once = Once::new();

struct EchoService;

impl HService for EchoService {
    fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        let method = session.req_method_str().unwrap_or_default().to_owned();
        let path = session.req_path();
        let body = session.req_body(Duration::from_secs(1))?;
        let body_len = body.len();
        let rsp = bytes::Bytes::from(format!("{method} {path}"));

        session
            .status_code(http::StatusCode::OK)
            .header_str("Content-Length", &rsp.len().to_string())?
            .header_str("X-Req-Body-Len", &body_len.to_string())?
            .body(rsp)
            .eom()
    }
}

#[derive(Clone, Copy)]
#[cfg(feature = "net-h2-server")]
struct UnusedAsyncService;

#[cfg(feature = "net-h2-server")]
#[async_trait::async_trait(?Send)]
impl HAsyncService for UnusedAsyncService {
    async fn call<S: Session>(&self, _session: &mut S) -> std::io::Result<()> {
        Err(std::io::Error::other("unused async service in H1 test"))
    }
}

#[derive(Clone, Copy)]
#[cfg(feature = "net-wt-server")]
struct UnusedWtService;

#[cfg(feature = "net-wt-server")]
#[async_trait::async_trait(?Send)]
impl sib::network::http::wt::WtService for UnusedWtService {
    async fn call(
        &mut self,
        _session: &mut sib::network::http::wt::WtSession,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other("unused wt service in H1 test"))
    }
}

struct EchoFactory;

impl HFactory for EchoFactory {
    type Service = EchoService;

    #[cfg(feature = "net-h2-server")]
    type HAsyncService = UnusedAsyncService;

    #[cfg(feature = "net-wt-server")]
    type WtService = UnusedWtService;

    fn service(&self, _id: usize) -> Self::Service {
        EchoService
    }

    #[cfg(feature = "net-h2-server")]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        UnusedAsyncService
    }

    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, _id: usize) -> Self::WtService {
        UnusedWtService
    }
}

struct ServiceFactory<S>(S);

impl<S: HService + Clone + Send + Sync + 'static> HFactory for ServiceFactory<S> {
    type Service = S;

    #[cfg(feature = "net-h2-server")]
    type HAsyncService = UnusedAsyncService;

    #[cfg(feature = "net-wt-server")]
    type WtService = UnusedWtService;

    fn service(&self, _id: usize) -> Self::Service {
        self.0.clone()
    }

    #[cfg(feature = "net-h2-server")]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        UnusedAsyncService
    }

    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, _id: usize) -> Self::WtService {
        UnusedWtService
    }
}

fn start_service<S: HService + Clone + Send + Sync + 'static>(
    service: S,
    cfg: H1Config,
) -> (String, may::coroutine::JoinHandle<()>) {
    init_runtime();
    let addr = unused_addr();
    let handle = ServiceFactory(service)
        .start_h1(&addr, cfg)
        .expect("start h1 server");
    std::thread::sleep(Duration::from_millis(150));
    (addr, handle)
}

/// Fails POST requests without reading their body; answers anything else with its path.
#[derive(Clone)]
struct FailPostService;

impl HService for FailPostService {
    fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        if session.req_method() == http::Method::POST {
            session.header_str("X-Staged", "before-failure")?;
            return Err(std::io::Error::other("handler failed"));
        }
        let rsp = bytes::Bytes::from(session.req_path());
        session
            .status_code(http::StatusCode::OK)
            .header_str("Content-Length", &rsp.len().to_string())?
            .body(rsp)
            .eom()
    }
}

fn init_runtime() {
    INIT.call_once(|| {
        sib::init_global_poller(1, 2 * 1024 * 1024);
    });
}

fn unused_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").to_string()
}

fn start_server() -> (String, may::coroutine::JoinHandle<()>) {
    init_runtime();
    let addr = unused_addr();
    let handle = EchoFactory
        .start_h1(&addr, H1Config::default())
        .expect("start h1 server");
    std::thread::sleep(Duration::from_millis(150));
    (addr, handle)
}

fn read_available(stream: &mut TcpStream) -> String {
    // A server that closes with unread request bytes resets the connection, and
    // macOS then rejects socket options; reads on such a socket return at once.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(e) => panic!("read response: {e}"),
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn h1_post_body_is_consumed_before_next_keep_alive_request() {
    let (addr, handle) = start_server();
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");
    stream.set_nodelay(true).expect("nodelay");

    stream
        .write_all(
            b"POST /first HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
Connection: keep-alive\r\n\
\r\n\
helloGET /second HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: keep-alive\r\n\
\r\n",
        )
        .expect("write pipelined requests");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        response.contains("POST /first"),
        "first response missing or malformed:\n{response}"
    );
    assert!(
        response.contains("GET /second"),
        "second request was not parsed after POST body:\n{response}"
    );
    assert!(
        !response.contains("helloGET"),
        "body bytes leaked into the next request parse:\n{response}"
    );
}

#[test]
fn h1_ignored_incomplete_body_closes_instead_of_reusing_socket() {
    struct NoBodyService;

    impl HService for NoBodyService {
        fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
            let rsp = bytes::Bytes::from_static(b"ok");
            session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Length", "2")?
                .body(rsp)
                .eom()
        }
    }

    struct NoBodyFactory;

    impl HFactory for NoBodyFactory {
        type Service = NoBodyService;

        #[cfg(feature = "net-h2-server")]
        type HAsyncService = UnusedAsyncService;

        #[cfg(feature = "net-wt-server")]
        type WtService = UnusedWtService;

        fn service(&self, _id: usize) -> Self::Service {
            NoBodyService
        }

        #[cfg(feature = "net-h2-server")]
        fn async_service(&self, _id: usize) -> Self::HAsyncService {
            UnusedAsyncService
        }

        #[cfg(feature = "net-wt-server")]
        fn wt_service(&self, _id: usize) -> Self::WtService {
            UnusedWtService
        }
    }

    init_runtime();
    let addr = unused_addr();
    let handle = NoBodyFactory
        .start_h1(&addr, H1Config::default())
        .expect("start h1 server");
    std::thread::sleep(Duration::from_millis(150));

    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");
    stream
        .write_all(
            b"POST /partial HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 10\r\n\
Connection: keep-alive\r\n\
\r\n\
abcGET /must-not-run HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n",
        )
        .expect("write incomplete body");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        response.contains("200 OK"),
        "first response was not flushed:\n{response}"
    );
    assert!(
        !response.contains("/must-not-run"),
        "server reused a connection with an unread body:\n{response}"
    );
}

#[test]
fn h1_rejects_invalid_content_length() {
    let (addr, handle) = start_server();
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(
            b"POST /bad HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: nope\r\n\
Connection: keep-alive\r\n\
\r\n\
hello",
        )
        .expect("write invalid content-length request");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        !response.contains("POST /bad"),
        "invalid Content-Length request was served:\n{response}"
    );
}

#[test]
fn h1_rejects_conflicting_content_lengths() {
    let (addr, handle) = start_server();
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(
            b"POST /bad HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
Content-Length: 6\r\n\
Connection: keep-alive\r\n\
\r\n\
hello!",
        )
        .expect("write conflicting content-length request");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        !response.contains("POST /bad"),
        "conflicting Content-Length request was served:\n{response}"
    );
}

#[test]
fn h1_failed_handler_with_partial_body_does_not_parse_body_as_request() {
    let (addr, handle) = start_service(FailPostService, H1Config::default());
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 1000\r\n\
\r\n\
GET /smuggled HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n",
        )
        .expect("write partial body");
    // More body bytes make a reused connection parse what it has buffered.
    std::thread::sleep(Duration::from_millis(200));
    let _ = stream.write_all(b"x");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        !response.contains("/smuggled"),
        "body bytes of a failed request were served as a request:\n{response}"
    );
}

#[test]
fn h1_failed_handler_never_flushes_staged_headers() {
    let (addr, handle) = start_service(FailPostService, H1Config::default());
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(
            b"POST /fail HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 0\r\n\
\r\n",
        )
        .expect("write request");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        response.starts_with("HTTP/1.1 500 "),
        "failed request was not answered with a 500:\n{response}"
    );
    assert!(
        !response.contains("X-Staged"),
        "headers of the failed response reached the client:\n{response}"
    );
}

#[test]
fn h1_eom_without_body_terminates_the_header_block() {
    #[derive(Clone)]
    struct NoContentService;

    impl HService for NoContentService {
        fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
            if session.req_path() == "/empty" {
                return session.status_code(http::StatusCode::NO_CONTENT).eom();
            }
            session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Length", "4")?
                .body(bytes::Bytes::from_static(b"next"))
                .eom()
        }
    }

    let (addr, handle) = start_service(NoContentService, H1Config::default());
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(
            b"GET /empty HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n\
GET /next HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n",
        )
        .expect("write pipelined requests");

    let response = read_available(&mut stream);
    stream.shutdown(Shutdown::Both).ok();
    unsafe { handle.coroutine().cancel() };

    assert!(
        response.starts_with("HTTP/1.1 204 "),
        "missing 204 response:\n{response}"
    );
    assert!(
        response.contains("\r\n\r\nHTTP/1.1 200 OK"),
        "204 headers were not terminated before the next response:\n{response}"
    );
}

#[test]
fn h1_idle_keep_alive_connection_honors_io_timeout() {
    let cfg = H1Config {
        io_timeout: Duration::from_millis(300),
        ..H1Config::default()
    };
    let (addr, handle) = start_service(FailPostService, cfg);
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    stream
        .write_all(b"GET /once HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");

    // Read the response, then wait for the server to close the idle connection.
    let started = std::time::Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    let closed = loop {
        match stream.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break true,
            Err(_) => break false,
        }
    };
    let elapsed = started.elapsed();
    unsafe { handle.coroutine().cancel() };

    assert!(
        String::from_utf8_lossy(&response).contains("/once"),
        "request was not served"
    );
    assert!(
        closed && elapsed < Duration::from_secs(2),
        "idle connection stayed open for {elapsed:?}"
    );
}

#[test]
fn h1_stalled_partial_request_honors_io_timeout() {
    let cfg = H1Config {
        io_timeout: Duration::from_millis(300),
        ..H1Config::default()
    };
    let (addr, handle) = start_service(FailPostService, cfg);
    let mut stream = TcpStream::connect(&addr).expect("connect h1 server");

    // Incomplete headers, then silence (slowloris).
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n")
        .expect("write partial request");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");

    let started = std::time::Instant::now();
    let mut buf = [0u8; 64];
    let closed = matches!(stream.read(&mut buf), Ok(0))
        || matches!(stream.read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset);
    let elapsed = started.elapsed();
    unsafe { handle.coroutine().cancel() };

    assert!(
        closed && elapsed < Duration::from_secs(2),
        "stalled connection stayed open for {elapsed:?}"
    );
}
