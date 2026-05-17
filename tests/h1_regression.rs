#![cfg(feature = "net-h1-server")]

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

struct EchoFactory;

impl HFactory for EchoFactory {
    type Service = EchoService;

    fn service(&self, _id: usize) -> Self::Service {
        EchoService
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
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set read timeout");

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
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

        fn service(&self, _id: usize) -> Self::Service {
            NoBodyService
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
