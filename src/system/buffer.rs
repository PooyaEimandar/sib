use heapless::Vec as HeaplessVec;
use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferType {
    BINARY = 0,
    TEXT,
}

/// Dynamic storage backend
#[derive(Clone)]
pub enum BufferStorage<const N: usize> {
    Heapless(HeaplessVec<u8, N>),
    Heap(SmallVec<[u8; N]>),
}

#[derive(Clone)]
pub struct Buffer<const N: usize> {
    pub type_: BufferType,
    pub buf: BufferStorage<N>,
}

impl<const N: usize> Buffer<N> {
    #[must_use]
    pub fn new(p_type: BufferType) -> Self {
        Self {
            type_: p_type,
            buf: BufferStorage::Heapless(HeaplessVec::new()),
        }
    }

    pub fn reset(&mut self) {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => vec.clear(),
            BufferStorage::Heap(vec) => vec.clear(),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match &self.buf {
            BufferStorage::Heapless(vec) => vec.as_slice(),
            BufferStorage::Heap(vec) => vec.as_slice(),
        }
    }

    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => vec.as_mut(),
            BufferStorage::Heap(vec) => vec.as_mut(),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if self.type_ == BufferType::TEXT {
            std::str::from_utf8(self.as_slice()).ok()
        } else {
            None
        }
    }

    /// Resize the buffer, auto-promoting to heap if needed
    pub fn resize(&mut self, new_len: usize, fill_value: u8) -> anyhow::Result<()> {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => {
                if new_len <= N {
                    vec.resize(new_len, fill_value).map_err(|_| {
                        anyhow::anyhow!("Failed to resize heapless buffer to size {}", new_len)
                    })
                } else {
                    // Promote to heap
                    let mut heap_vec = SmallVec::<[u8; N]>::new();
                    heap_vec.resize(new_len, fill_value);
                    self.buf = BufferStorage::Heap(heap_vec);
                    Ok(())
                }
            }
            BufferStorage::Heap(vec) => {
                vec.resize(new_len, fill_value);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn size(&self) -> usize {
        match &self.buf {
            BufferStorage::Heapless(vec) => vec.len(),
            BufferStorage::Heap(vec) => vec.len(),
        }
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

    type TestBuffer = Buffer<16>; // small buffer for tests

    #[test]
    fn test_heapless_small_write() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.resize(8, 0).unwrap();

        assert_eq!(buf.size(), 8);
        assert_eq!(buf.as_slice(), &[0; 8]);

        match buf.buf {
            BufferStorage::Heapless(_) => {}
            BufferStorage::Heap(_) => panic!("Expected Heapless storage for small write"),
        }
    }

    #[test]
    fn test_heap_promotion_on_large_resize() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.resize(32, 0).unwrap(); // bigger than 16 capacity

        assert_eq!(buf.size(), 32);
        assert_eq!(buf.as_slice(), &[0; 32]);

        match buf.buf {
            BufferStorage::Heap(_) => {}
            BufferStorage::Heapless(_) => panic!("Expected Heap storage after large resize"),
        }
    }

    #[test]
    fn test_reset_clears_buffer() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.resize(10, 1).unwrap();
        buf.reset();

        assert_eq!(buf.size(), 0);
        assert_eq!(buf.as_slice(), <&[u8]>::default());
    }

    #[test]
    fn test_as_str_for_valid_utf8() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"test");

        assert_eq!(buf.as_str(), Some("test"));
    }

    #[test]
    fn test_as_str_for_invalid_utf8() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.resize(3, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(&[0xff, 0xfe, 0xfd]);

        assert_eq!(buf.as_str(), None);
    }

    #[test]
    fn test_as_str_binary_none() {
        let mut buf = TestBuffer::new(BufferType::BINARY);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"data");

        assert_eq!(buf.as_str(), None);
    }

    #[test]
    fn test_debug_formatting() {
        let mut buf = TestBuffer::new(BufferType::TEXT);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"rust");

        let debug_str = format!("{:?}", buf);
        assert!(debug_str.contains("Buffer"));
        assert!(debug_str.contains("rust"));
        assert!(debug_str.contains("size"));
        assert!(debug_str.contains("capacity"));
    }

    #[test]
    fn test_multiple_resize_promote_and_reset() {
        let mut buf = TestBuffer::new(BufferType::BINARY);

        // Step 1: Small resize
        buf.resize(8, 1).unwrap();
        assert_eq!(buf.size(), 8);
        assert_eq!(buf.as_slice(), &[1; 8]);

        // Step 2: Large resize (promote to heap)
        buf.resize(64, 2).unwrap();
        assert_eq!(buf.size(), 64);
        assert_eq!(buf.as_slice(), &[2; 64]);

        // Step 3: Reset and re-use
        buf.reset();
        assert_eq!(buf.size(), 0);
    }
}
