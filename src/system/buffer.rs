use heapless::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferType {
    BINARY = 0,
    TEXT,
}

#[derive(Clone)]
pub struct Buffer<const N: usize> {
    pub type_: BufferType,
    pub buf: Vec<u8, N>,
}

impl<const N: usize> Buffer<N> {
    #[must_use]
    pub fn new(p_type: BufferType) -> Self {
        Self {
            type_: p_type,
            buf: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if self.type_ == BufferType::TEXT {
            std::str::from_utf8(self.as_slice()).ok()
        } else {
            None
        }
    }

    /// Writes the given bytes into the buffer (truncates if too large).
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.reset(); // Clear previous data
        let len = data.len().min(N);
        self.buf.extend_from_slice(&data[..len]).ok();
        len
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> std::fmt::Debug for Buffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = match self.type_ {
            BufferType::TEXT => self
                .as_str()
                .map(|s| format!("\"{}\"", s))
                .unwrap_or_else(|| format!("{:?}", self.as_slice())),
            BufferType::BINARY => format!("{:?}", self.as_slice()),
        };

        f.debug_struct("Buffer")
            .field("type_", &self.type_)
            .field("size", &self.size())
            .field("capacity", &N)
            .field("content", &content)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestBuffer = Buffer<16>;

    #[test]
    fn test_new_and_capacity() {
        let buf = TestBuffer::new(BufferType::BINARY);
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.capacity(), 16);
        assert_eq!(buf.type_, BufferType::BINARY);
    }

    #[test]
    fn test_write_and_read_binary() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        let data = b"sib";
        let written = buf.write(data);
        assert_eq!(written, data.len());
        assert_eq!(buf.as_slice(), data);
        assert_eq!(buf.size(), data.len());
    }

    #[test]
    fn test_write_truncates_large_input() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        let big_data = [1u8; 32]; // larger than capacity
        let written = buf.write(&big_data);
        assert_eq!(written, 16); // capped at 16
        assert_eq!(buf.size(), 16);
    }

    #[test]
    fn test_reset_clears_contents() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.write(b"12345678");
        buf.reset();
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn test_as_str_valid_utf8() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.write(b"ryan");
        assert_eq!(buf.as_str(), Some("ryan"));
    }

    #[test]
    fn test_as_str_invalid_utf8() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.write(&[0xff, 0xfe, 0xfd]);
        assert_eq!(buf.as_str(), None); // invalid utf-8
    }

    #[test]
    fn test_as_str_returns_none_for_binary_type() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.write(b"pooya");
        assert_eq!(buf.as_str(), None);
    }

    #[test]
    fn test_debug_output() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.write(b"rust");
        let debug_str = format!("{:?}", buf);
        assert!(debug_str.contains("Buffer"));
        assert!(debug_str.contains("rust"));
    }
}
