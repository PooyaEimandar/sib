use crate::system::buffer::Buffer;

use may::net::TcpStream;
use std::fmt;
use std::io::{self, BufRead, Read};
use std::mem::MaybeUninit;

pub(crate) const MAX_HEADERS: usize = 16;

pub struct BodyReader<'buf, 'stream, const N: usize> {
    req_buf: &'buf mut Buffer<heapless::Vec<u8, N>>,
    body_limit: usize,
    total_read: usize,
    stream: &'stream mut TcpStream,
}

impl<'buf, 'stream, const N: usize> BodyReader<'buf, 'stream, N> {
    fn read_more_data(&mut self) -> io::Result<usize> {
        let cap = self.req_buf.capacity();
        let size = self.req_buf.size();

        if size >= cap {
            let new_size = cap + 1024;
            self.req_buf.resize(new_size, 0)?;
        }

        let write_buf = &mut self.req_buf.as_mut_slice()[size..];
        let read_num = self.stream.read(write_buf)?;

        let new_len = size + read_num;
        self.req_buf.resize(new_len, 0)?;

        Ok(read_num)
    }
}

impl<'buf, 'stream, const N: usize> Read for BodyReader<'buf, 'stream, N> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.total_read >= self.body_limit {
            return Ok(0);
        }

        loop {
            let available = &self.req_buf.as_slice()[self.total_read..];
            if !available.is_empty() {
                let to_read = buf.len().min(self.body_limit - self.total_read);
                let read_num = (&available[..to_read]).read(buf)?;
                self.total_read += read_num;
                return Ok(read_num);
            }

            if self.read_more_data()? == 0 {
                return Ok(0);
            }
        }
    }
}

impl<'buf, 'stream, const N: usize> BufRead for BodyReader<'buf, 'stream, N> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let remain = self.body_limit - self.total_read;
        if remain == 0 {
            return Ok(&[]);
        }

        if self.req_buf.size() <= self.total_read {
            self.read_more_data()?;
        }

        let buf = &self.req_buf.as_slice()[self.total_read..];
        let n = buf.len().min(remain);
        Ok(&buf[..n])
    }

    fn consume(&mut self, amt: usize) {
        let available = self.req_buf.size() - self.total_read;
        let consume_amt = amt.min(available);
        self.total_read += consume_amt;
    }
}

impl<'buf, 'stream, const N: usize> Drop for BodyReader<'buf, 'stream, N> {
    fn drop(&mut self) {
        while let Ok(n) = self.fill_buf().map(|b| b.len()) {
            if n == 0 {
                break;
            }
            self.consume(n);
        }
    }
}

pub struct Request<'buf, 'header, 'stream, const N: usize> {
    req: httparse::Request<'header, 'buf>,
    req_buf: &'buf mut Buffer<heapless::Vec<u8, N>>,
    stream: &'stream mut TcpStream,
}

impl<'buf, 'header, 'stream, const N: usize> Request<'buf, 'header, 'stream, N> {
    pub fn method(&self) -> Option<&str> {
        self.req.method
    }

    pub fn path(&self) -> &str {
        self.req.path.unwrap()
    }

    pub fn version(&self) -> u8 {
        self.req.version.unwrap()
    }

    pub fn headers(&self) -> &[httparse::Header<'_>] {
        self.req.headers
    }

    pub fn body(self) -> BodyReader<'buf, 'stream, N> {
        BodyReader {
            body_limit: self.content_length(),
            total_read: 0,
            stream: self.stream,
            req_buf: self.req_buf,
        }
    }

    fn content_length(&self) -> usize {
        self.req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("content-length"))
            .and_then(|h| std::str::from_utf8(h.value).ok()?.parse().ok())
            .unwrap_or(0)
    }
}

impl<'buf, 'header, 'stream, const N: usize> fmt::Debug for Request<'buf, 'header, 'stream, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<HTTP Request {:?} {}>", self.method(), self.path())
    }
}

pub fn decode<'header, 'buf, 'stream, const N: usize>(
    headers: &'header mut [MaybeUninit<httparse::Header<'buf>>; MAX_HEADERS],
    req_buf: &'buf mut Buffer<heapless::Vec<u8, N>>,
    stream: &'stream mut TcpStream,
) -> io::Result<Option<Request<'buf, 'header, 'stream, N>>> {
    let mut req = httparse::Request::new(&mut []);

    let buf: &'buf [u8] = unsafe { std::mem::transmute(req_buf.as_slice()) };

    let status = match req.parse_with_uninit_headers(buf, headers) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to parse http request: {e:?}");
            eprintln!("{msg}");
            return Err(io::Error::other(msg));
        }
    };

    let len = match status {
        httparse::Status::Complete(amt) => amt,
        httparse::Status::Partial => return Ok(None),
    };

    req_buf.advance(len);

    Ok(Some(Request {
        req,
        req_buf,
        stream,
    }))
}
#[cfg(test)]
mod tests {
    use crate::network::http::request::{MAX_HEADERS, decode};
    use crate::system::buffer::Buffer;
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_body_reader_reads_full_content_from_mock_stream() {
        // Server coroutine
        let handle_server = may::go!(|| {
            let listener = may::net::TcpListener::bind("127.0.0.1:9001").unwrap();
            let (mut stream, _) = listener.accept().unwrap();

            let mut headers = [std::mem::MaybeUninit::uninit(); MAX_HEADERS];
            let mut req_buf =
                Buffer::<heapless::Vec<u8, 1024>>::new(crate::system::buffer::BufferType::TEXT);

            let mut temp = [0u8; 1024];
            let read_num = stream.read(&mut temp).unwrap();
            req_buf.resize(read_num, 0).unwrap();
            req_buf.as_mut_slice()[..read_num].copy_from_slice(&temp[..read_num]);

            let request = decode(&mut headers, &mut req_buf, &mut stream)
                .unwrap()
                .expect("Should decode");

            assert_eq!(request.method(), Some("POST"));
            assert_eq!(request.path(), "/upload");
            assert_eq!(request.version(), 1);

            let mut body = request.body();
            let mut content = vec![];
            body.read_to_end(&mut content).unwrap();
            assert_eq!(content, b"hello world");
        });

        // Client coroutine
        let handle_client = may::go!(|| {
            // wait to the server time to bind
            thread::sleep(Duration::from_millis(100));
            let mut stream = may::net::TcpStream::connect("127.0.0.1:9001").unwrap();

            let body = b"hello world";
            let request = format!(
                "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );

            stream.write_all(request.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        // Give coroutines time to finish
        may::join!(handle_client, handle_server);
    }
}
