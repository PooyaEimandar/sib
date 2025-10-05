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

#[cfg(unix)]
pub(crate) fn serve<T: HService>(
    stream: &mut TcpStream,
    peer_addr: &IpAddr,
    mut service: T,
) -> std::io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.wait_io();
        }
    }
}

#[cfg(unix)]
pub(crate) fn serve_tls<T: HService>(
    stream: &mut boring::ssl::SslStream<TcpStream>,
    peer_addr: &IpAddr,
    mut service: T,
) -> std::io::Result<()> {
    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        if read_write(stream, peer_addr, &mut req_buf, &mut rsp_buf, &mut service)? {
            stream.get_mut().wait_io();
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn serve<T: HService>(stream: &mut TcpStream, mut service: T) -> io::Result<()> {
    use Write;
    use bytes::Buf;

    let mut req_buf = BytesMut::with_capacity(BUF_LEN);
    let mut rsp_buf = BytesMut::with_capacity(BUF_LEN);

    loop {
        // read
        reserve_buf(&mut req_buf);
        let read_buf: &mut [u8] = unsafe { std::mem::transmute(&mut *req_buf.chunk_mut()) };
        let read_cnt = stream.read(read_buf)?;
        if read_cnt == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        unsafe { req_buf.advance_mut(read_cnt) };

        // parse & serve
        if read_cnt > 0 {
            loop {
                use crate::network::http::h1_session; // <-- fix module path
                let mut headers = [MaybeUninit::uninit(); h1_session::MAX_HEADERS];
                let mut sess = match h1_session::new_session(
                    stream,
                    &mut headers,
                    &mut req_buf,
                    &mut rsp_buf,
                )? {
                    Some(sess) => sess,
                    None => break,
                };
                if let Err(e) = service.call(&mut sess) {
                    if e.kind() == std::io::ErrorKind::ConnectionAborted {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        // write (drain)
        while !rsp_buf.is_empty() {
            let n = stream.write(rsp_buf.chunk())?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write closed"));
            }
            rsp_buf.advance(n);
        }
    }
}

#[cfg(unix)]
#[inline]
pub(crate) fn read(stream: &mut impl std::io::Read, buf: &mut BytesMut) -> std::io::Result<bool> {
    // reserve buffer
    let rem = buf.capacity() - buf.len();
    if rem < 1024 {
        buf.reserve(BUF_LEN - rem);
    }

    let chunk = buf.chunk_mut();
    let len = chunk.len();

    // SAFETY: We ensure exclusive access and will commit the right amount
    let read_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), len) };

    let mut io_slice = [std::io::IoSliceMut::new(read_buf)];
    let n = match stream.read_vectored(&mut io_slice) {
        Ok(0) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "read closed",
            ));
        }
        Ok(n) => n,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e),
    };

    unsafe {
        buf.advance_mut(n);
    }
    Ok(n < len)
}

#[cfg(unix)]
#[inline]
pub(crate) fn write(
    stream: &mut impl Write,
    rsp_buf: &mut BytesMut,
) -> std::io::Result<(usize, bool)> {
    use bytes::Buf;
    use std::io::IoSlice;

    let write_buf = rsp_buf.chunk();
    let len = write_buf.len();
    let mut write_cnt = 0;
    let mut blocked = false;

    while write_cnt < len {
        let slice = IoSlice::new(unsafe { write_buf.get_unchecked(write_cnt..) });
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
    rsp_buf.advance(write_cnt);
    Ok((write_cnt, blocked))
}

#[cfg(unix)]
fn read_write<S, T>(
    stream: &mut S,
    peer_addr: &IpAddr,
    req_buf: &mut BytesMut,
    rsp_buf: &mut BytesMut,
    service: &mut T,
) -> std::io::Result<bool>
where
    S: Read + Write,
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
