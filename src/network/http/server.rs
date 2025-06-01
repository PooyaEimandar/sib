use super::session::{self, Session};
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::net::ToSocketAddrs;

#[cfg(unix)]
use bytes::{BufMut, BytesMut};
#[cfg(unix)]
use may::io::WaitIo;
use may::net::{TcpListener, TcpStream};
use may::{coroutine, go};

const MIN_BUF_LEN: usize = 1024;
const MAX_BODY_LEN: usize = 4096;
pub const BUF_LEN: usize = MAX_BODY_LEN * 8;

// move or continue
macro_rules! mc {
    ($e: expr) => {
        match $e {
            Ok(val) => val,
            Err(_err) => {
                //s_error!("call = {:?}\nerr = {:?}", stringify!($e), err);
                continue;
            }
        }
    };
}

pub trait HttpService {
    fn call(&mut self, req: &mut Session) -> io::Result<()>;
}

pub trait H1ServiceFactory: Send + Sized + 'static {
    type Service: HttpService + Send;
    // create a new http service for each connection
    fn service(&self, id: usize) -> Self::Service;

    /// Spawns the http service, binding to the given address
    /// return a coroutine that you can cancel it when need to stop the service
    fn start<L: ToSocketAddrs>(self, addr: L) -> io::Result<coroutine::JoinHandle<()>> {
        let listener = TcpListener::bind(addr)?;
        go!(
            coroutine::Builder::new().name("H1ServiceFactory".to_owned()),
            move || {
                #[cfg(unix)]
                use std::os::fd::AsRawFd;
                #[cfg(windows)]
                use std::os::windows::io::AsRawSocket;
                for stream in listener.incoming() {
                    let mut stream = mc!(stream);
                    #[cfg(unix)]
                    let id = stream.as_raw_fd() as usize;
                    #[cfg(windows)]
                    let id = stream.as_raw_socket() as usize;
                    mc!(stream.set_nodelay(true));
                    let service = self.service(id);
                    let builder = may::coroutine::Builder::new().id(id);
                    go!(
                        builder,
                        move || if let Err(_e) = serve(&mut stream, service) {
                            //s_error!("service err = {e:?}");
                            stream.shutdown(std::net::Shutdown::Both).ok();
                        }
                    )
                    .unwrap();
                }
            }
        )
    }
}

#[cfg(unix)]
#[inline]
fn read(stream: &mut impl Read, req_buf: &mut BytesMut) -> io::Result<bool> {
    reserve_buf(req_buf);
    let read_buf: &mut [u8] = unsafe { std::mem::transmute(req_buf.chunk_mut()) };
    let len = read_buf.len();

    let mut read_cnt = 0;
    while read_cnt < len {
        match stream.read(unsafe { read_buf.get_unchecked_mut(read_cnt..) }) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "read closed")),
            Ok(n) => read_cnt += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    unsafe { req_buf.advance_mut(read_cnt) };
    Ok(read_cnt < len)
}

#[inline]
pub(crate) fn reserve_buf(buf: &mut BytesMut) {
    let rem = buf.capacity() - buf.len();
    if rem < MIN_BUF_LEN {
        buf.reserve(BUF_LEN - rem);
    }
}

#[cfg(unix)]
fn serve<T: HttpService>(stream: &mut TcpStream, mut service: T) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        let read_blocked = read(stream.inner_mut(), &mut req_buf)?;

        // prepare the requests, we should make sure the request is fully read
        loop {
            let mut headers = [MaybeUninit::uninit(); session::MAX_HEADERS];
            let mut sess =
                match session::new_session(stream, &mut headers, &mut req_buf, &mut rsp_buf)? {
                    Some(req) => req,
                    None => break,
                };

            if let Err(e) = service.call(&mut sess) {
                if e.kind() == std::io::ErrorKind::ConnectionAborted {
                    // abort the connection immediately
                    return Err(e);
                }
            }
        }

        if read_blocked {
            stream.wait_io();
        }
    }
}

#[cfg(not(unix))]
fn serve<T: HttpService>(stream: &mut TcpStream, mut service: T) -> io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);
    let mut body_buf = BytesMut::with_capacity(BUF_LEN);
    loop {
        // read the socket for requests
        reserve_buf(&mut req_buf);
        let read_buf: &mut [u8] = unsafe { std::mem::transmute(&mut *req_buf.chunk_mut()) };
        let read_cnt = stream.read(read_buf)?;
        if read_cnt == 0 {
            //connection was closed
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        unsafe { req_buf.advance_mut(read_cnt) };

        // prepare the requests
        if read_cnt > 0 {
            loop {
                let mut headers = [MaybeUninit::uninit(); session::MAX_HEADERS];
                let req = match session::decode(&mut headers, &mut req_buf, stream)? {
                    Some(req) => req,
                    None => break,
                };
                let mut rsp = Response::new(&mut body_buf);
                match service.call(req, &mut rsp) {
                    Ok(()) => response::encode(rsp, &mut rsp_buf),
                    Err(e) => {
                        //s_error!("service err = {:?}", e);
                        response::encode_error(e, &mut rsp_buf);
                    }
                }
            }
        }

        // send the result back to client
        stream.write_all(&rsp_buf)?;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::Duration,
    };

    use crate::network::http::{
        server::{H1ServiceFactory, HttpService},
        session::Session,
    };

    struct H1Server<T>(pub T);

    struct EchoService;

    impl HttpService for EchoService {
        fn call(&mut self, session: &mut Session) -> std::io::Result<()> {
            let body = bytes::Bytes::from(format!(
                "Echo: {:?} {:?}",
                session.req_method(),
                session.req_path()
            ));
            let mut body_len = itoa::Buffer::new();
            let body_len_str = body_len.format(body.len());
            let sent = session
                .status_code(200, "OK")
                .header("Content-Type", "text/plain")?
                .header("Content-Length", body_len_str)?
                .body(&body)
                .send()?;
            println!("Sent {} bytes", sent);
            Ok(())
        }
    }

    impl H1ServiceFactory for H1Server<EchoService> {
        type Service = EchoService;

        fn service(&self, _id: usize) -> EchoService {
            EchoService
        }
    }

    #[test]
    fn test_http1_gracefull_shutdown() {
        let addr = "127.0.0.1:8080";
        let server_handle = H1Server(EchoService).start(&addr).expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));
            unsafe { server_handle.coroutine().cancel() };
        });

        client_handler.join().expect("client handler failed");
    }

    #[test]
    fn test_http_server_response() {
        // Pick a port and start the server
        let addr = "127.0.0.1:8080";
        let server_handle = H1Server(EchoService).start(&addr).expect("h1 start server");

        let client_handler = may::go!(move || {
            may::coroutine::sleep(Duration::from_millis(100));

            // Client sends HTTP request
            let mut stream = TcpStream::connect(&addr).expect("connect");
            stream
                .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let response = std::str::from_utf8(&buf[..n]).unwrap();

            assert!(response.contains("/test"));
            print!("Response: {}", response);
        });

        may::join!(server_handle, client_handler);

        std::thread::sleep(Duration::from_secs(2));
    }
}
