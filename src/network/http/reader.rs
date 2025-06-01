use super::server::reserve_buf;
use bytes::{Buf, BufMut, BytesMut};
use may::net::TcpStream;
use std::io::{BufRead, Read};

pub struct Reader<'buf, 'stream> {
    // remaining bytes for body
    pub req_buf: &'buf mut BytesMut,
    // the max body length limit
    pub body_limit: usize,
    // total read count
    pub total_read: usize,
    // used to read extra body bytes
    pub stream: &'stream mut TcpStream,
}

impl Reader<'_, '_> {
    fn read_more_data(&mut self) -> std::io::Result<usize> {
        reserve_buf(self.req_buf);
        let chunk_mut = self.req_buf.chunk_mut();
        let mut_slice =
            unsafe { std::slice::from_raw_parts_mut(chunk_mut.as_mut_ptr(), chunk_mut.len()) };
        let mut slices = [std::io::IoSliceMut::new(mut_slice)];
        let n = self.stream.read_vectored(&mut slices)?;
        unsafe { self.req_buf.advance_mut(n) };
        Ok(n)
    }
}

impl Read for Reader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.total_read >= self.body_limit {
            return Ok(0);
        }

        loop {
            if !self.req_buf.is_empty() {
                let min_len = buf.len().min(self.body_limit - self.total_read);
                let available = self.req_buf.chunk();
                let n = min_len.min(available.len());
                buf[..n].copy_from_slice(&available[..n]);
                self.req_buf.advance(n);
                self.total_read += n;
                return Ok(n);
            }

            if self.read_more_data()? == 0 {
                return Ok(0);
            }
        }
    }
}

impl BufRead for Reader<'_, '_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let remain = self.body_limit - self.total_read;
        if remain == 0 {
            return Ok(&[]);
        }
        if self.req_buf.is_empty() {
            self.read_more_data()?;
        }
        let n = self.req_buf.len().min(remain);
        Ok(&self.req_buf.chunk()[0..n])
    }

    fn consume(&mut self, amt: usize) {
        assert!(amt <= self.body_limit - self.total_read);
        assert!(amt <= self.req_buf.len());
        self.total_read += amt;
        self.req_buf.advance(amt)
    }
}

impl Drop for Reader<'_, '_> {
    fn drop(&mut self) {
        // consume all the remaining bytes
        while let Ok(n) = self.fill_buf().map(|b| b.len()) {
            if n == 0 {
                break;
            }
            // println!("drop: {:?}", n);
            self.consume(n);
        }
    }
}
