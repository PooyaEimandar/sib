use crate::network::http::{h1_session::BUF_LEN, session::HService};
use bytes::{BufMut, BytesMut};
use may::net::TcpStream;

#[cfg(unix)]
use std::{
    io::{Read, Write},
    net::IpAddr,
};

#[cfg(unix)]
use may::io::WaitIo;

pub(crate) fn serve<T: HService>(
    stream: &mut TcpStream,
    peer_addr: &std::net::IpAddr,
    mut service: T,
) -> std::io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            #[cfg(unix)]
            {
                stream.get_mut().wait_io();
            }
            #[cfg(windows)]
            {
                may::coroutine::yield_now();
            }
        }
    }
}

pub(crate) fn serve_tls<T: HService>(
    stream: &mut boring::ssl::SslStream<TcpStream>,
    peer_addr: &std::net::IpAddr,
    mut service: T,
) -> std::io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            #[cfg(unix)]
            {
                stream.get_mut().wait_io();
            }
            #[cfg(windows)]
            {
                may::coroutine::yield_now();
            }
        }
    }
}

#[inline]
pub(crate) fn read(
    stream: &mut impl std::io::Read,
    buf: &mut bytes::BytesMut,
) -> std::io::Result<bool> {
    const MIN_RESERVE: usize = 1024;
    const BUF_LEN: usize = 16 * 1024;

    let rem = buf.capacity() - buf.len();
    if rem < MIN_RESERVE {
        buf.reserve(BUF_LEN.saturating_sub(rem));
    }

    let chunk = buf.chunk_mut();
    let len = chunk.len();
    if len == 0 {
        return Ok(true);
    }

    // SAFETY: we'll advance_mut(n) after reading n initialized bytes.
    let read_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), len) };

    let n = {
        #[cfg(unix)]
        {
            let mut io_slice = [std::io::IoSliceMut::new(read_buf)];
            match stream.read_vectored(&mut io_slice) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "read closed",
                    ));
                }
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }

        #[cfg(not(unix))]
        {
            match stream.read(read_buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "read closed",
                    ));
                }
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
    };

    unsafe {
        buf.advance_mut(n);
    }
    Ok(n < len)
}

#[inline]
pub(crate) fn write(
    stream: &mut impl std::io::Write,
    rsp_buf: &mut bytes::BytesMut,
) -> std::io::Result<(usize, bool)> {
    use bytes::Buf;

    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    if len == 0 {
        return Ok((0, false));
    }

    let mut write_cnt = 0usize;
    let mut blocked = false;

    while write_cnt < len {
        // Use vectored on unix (fast path), plain write elsewhere (or also try vectored everywhere).
        #[cfg(unix)]
        {
            use std::io::IoSlice;
            let slice = IoSlice::new(&write_buf[write_cnt..]);
            match stream.write_vectored(std::slice::from_ref(&slice)) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "write closed",
                    ));
                }
                Ok(n) => write_cnt += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        #[cfg(not(unix))]
        {
            match stream.write(&write_buf[write_cnt..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "write closed",
                    ));
                }
                Ok(n) => write_cnt += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }

    rsp_buf.advance(write_cnt);
    Ok((write_cnt, blocked))
}

fn read_write<S, T>(
    stream: &mut S,
    peer_addr: &std::net::IpAddr,
    req_buf: &mut BytesMut,
    rsp_buf: &mut BytesMut,
    service: &mut T,
) -> std::io::Result<bool>
where
    S: std::io::Read + std::io::Write,
    T: HService,
{
    // Prioritize draining any pending response bytes
    let mut blocked = false;
    if !rsp_buf.is_empty() {
        let (_, wblocked) = write(stream, rsp_buf)?;
        blocked |= wblocked;
        if !rsp_buf.is_empty() {
            return Ok(true); // will call wait_io()
        }
    }

    // Now read a fresh request
    let rblocked = read(stream, req_buf)?;
    blocked |= rblocked;

    // Serve as many requests as are fully buffered
    loop {
        use std::mem::MaybeUninit;

        use crate::network::http::h1_session;
        let mut headers = [MaybeUninit::uninit(); h1_session::MAX_HEADERS];
        let mut sess =
            match h1_session::new_session(stream, peer_addr, &mut headers, req_buf, rsp_buf)? {
                Some(sess) => sess,
                None => break,
            };

        if let Err(e) = service.call(&mut sess) {
            if e.kind() == std::io::ErrorKind::ConnectionAborted {
                // only abort if the service explicitly wants hard close
                return Err(e);
            }
            // Any other error just break
            break;
        }
    }

    // final flush
    let (_, wblocked2) = write(stream, rsp_buf)?;
    blocked |= wblocked2;

    Ok(blocked)
}
