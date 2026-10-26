use super::*;
use crate::network::http::session::{HService, Session};
use bytes::Bytes;
use std::io;

/// In-memory transport: reads drain `input`, writes are recorded and can fail
/// once after `fail_write_at` bytes.
struct FakeStream {
    input: Vec<u8>,
    read_pos: usize,
    output: Vec<u8>,
    fail_write_at: Option<usize>,
}

impl FakeStream {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            read_pos: 0,
            output: Vec::new(),
            fail_write_at: None,
        }
    }

    fn output(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }
}

impl Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_pos == self.input.len() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.input.len() - self.read_pos);
        buf[..n].copy_from_slice(&self.input[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut n = buf.len();
        if let Some(limit) = self.fail_write_at {
            let room = limit.saturating_sub(self.output.len());
            if room == 0 {
                self.fail_write_at = None;
                return Err(io::Error::other("injected write failure"));
            }
            n = n.min(room);
        }
        self.output.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Routes;

impl HService for Routes {
    fn call<S: Session>(&self, session: &mut S) -> io::Result<()> {
        match session.req_path().as_str() {
            "/large" => session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Length", "100")?
                .body(Bytes::from(vec![b'x'; 100]))
                .eom(),
            "/forgot" => {
                session.header_str("X-Staged", "leak")?;
                Ok(())
            }
            "/raw" => session.write_all_eom(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nraw"),
            "/short-stream" => {
                session.header_str("Content-Length", "10")?;
                session.start_h1_streaming()?;
                session.send_h1_data(b"abcd", false)?;
                session.eom()
            }
            "/long-stream" => {
                session.header_str("Content-Length", "2")?;
                session.start_h1_streaming()?;
                session.send_h1_data(b"abcd", true)
            }
            "/unframed-stream" => {
                session.start_h1_streaming()?;
                session.send_h1_data(b"abcd", true)
            }
            _ => session
                .status_code(http::StatusCode::OK)
                .header_str("Content-Length", "2")?
                .body(Bytes::from_static(b"ok"))
                .eom(),
        }
    }
}

fn exchange(stream: &mut FakeStream) -> io::Result<bool> {
    let peer = "127.0.0.1".parse().unwrap();
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);
    read_write(stream, &peer, &mut req_buf, &mut rsp_buf, &Routes)
}

fn pipelined(first: &str) -> Vec<u8> {
    format!("GET {first} HTTP/1.1\r\nHost: x\r\n\r\nGET /next HTTP/1.1\r\nHost: x\r\n\r\n")
        .into_bytes()
}

#[test]
fn write_failure_mid_response_closes_without_appending_a_500() {
    let mut stream = FakeStream::new(&pipelined("/large"));
    stream.fail_write_at = Some(90);
    assert!(exchange(&mut stream).is_err());
    let out = stream.output();
    assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
    assert!(!out.contains(" 500 "), "{out}");
}

#[test]
fn handler_returning_ok_without_a_response_gets_a_500_and_no_leaked_headers() {
    let mut stream = FakeStream::new(&pipelined("/forgot"));
    assert!(exchange(&mut stream).is_err());
    let out = stream.output();
    assert!(out.starts_with("HTTP/1.1 500 "), "{out}");
    assert!(!out.contains("X-Staged"), "{out}");
    assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
}

#[test]
fn queued_raw_response_is_written_before_the_next_response() {
    let mut stream = FakeStream::new(&pipelined("/raw"));
    exchange(&mut stream).unwrap();
    let out = stream.output();
    assert!(
        out.starts_with("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nrawHTTP/1.1 200 OK\r\n"),
        "{out}"
    );
    assert!(out.ends_with("\r\n\r\nok"), "{out}");
}

#[test]
fn incomplete_or_unframed_streams_do_not_keep_the_connection() {
    for route in ["/short-stream", "/long-stream", "/unframed-stream"] {
        let mut stream = FakeStream::new(&pipelined(route));
        assert!(exchange(&mut stream).is_err(), "{route}");
        let out = stream.output();
        assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{route}: {out}");
        assert!(
            !out.ends_with("ok"),
            "{route}: next request was served: {out}"
        );
    }
}

#[test]
fn stream_never_writes_more_than_its_content_length() {
    let mut stream = FakeStream::new(&pipelined("/long-stream"));
    assert!(exchange(&mut stream).is_err());
    assert!(!stream.output().contains("abcd"), "{}", stream.output());
}
