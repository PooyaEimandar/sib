use heapless::Vec as HeaplessVec;
use std::io::{Error, ErrorKind};
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferType {
    BINARY,
    TEXT,
}

/// Internal storage: stack-based (heapless) or heap-based (Vec)
#[derive(Clone)]
pub enum BufferStorage<T> {
    Heapless(T),
    Heap(Vec<u8>),
}

/// Main buffer struct with dynamic promotion and zero-copy support
#[derive(Clone)]
pub struct Buffer<T> {
    pub type_: BufferType,
    pub buf: BufferStorage<T>,
}

impl<const N: usize> Buffer<HeaplessVec<u8, N>> {
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

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.buf {
            BufferStorage::Heapless(vec) => vec.as_slice(),
            BufferStorage::Heap(vec) => vec.as_slice(),
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => vec.as_mut(),
            BufferStorage::Heap(vec) => vec.as_mut(),
        }
    }

    /// # Safety
    /// Use only when you're sure the length is respected and exclusive access is maintained.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => vec.as_mut_ptr(),
            BufferStorage::Heap(vec) => vec.as_mut_ptr(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if self.type_ == BufferType::TEXT {
            std::str::from_utf8(self.as_slice()).ok()
        } else {
            None
        }
    }

    /// Resize the buffer, promoting to heap if needed
    pub fn resize(&mut self, new_len: usize, fill_value: u8) -> Result<(), Error> {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => {
                if new_len <= vec.capacity() {
                    vec.resize(new_len, fill_value).map_err(|_| {
                        Error::new(ErrorKind::Other, "Failed to resize heapless buffer")
                    })
                } else {
                    // Promote to heap and preserve data
                    let mut heap = Vec::with_capacity(new_len.max(vec.capacity()));
                    heap.extend_from_slice(vec.as_slice());
                    heap.resize(new_len, fill_value);
                    self.buf = BufferStorage::Heap(heap);
                    Ok(())
                }
            }
            BufferStorage::Heap(vec) => {
                vec.resize(new_len, fill_value);
                Ok(())
            }
        }
    }

    pub fn size(&self) -> usize {
        match &self.buf {
            BufferStorage::Heapless(vec) => vec.len(),
            BufferStorage::Heap(vec) => vec.len(),
        }
    }

    pub fn capacity(&self) -> usize {
        match &self.buf {
            BufferStorage::Heapless(vec) => vec.capacity(),
            BufferStorage::Heap(vec) => vec.capacity(),
        }
    }

    pub fn truncate(&mut self, len: usize) {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => vec.truncate(len),
            BufferStorage::Heap(vec) => vec.truncate(len),
        }
    }

    pub fn advance(&mut self, len: usize) {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => {
                let available = vec.len();
                let consumed = len.min(available);
                vec.rotate_left(consumed);
                vec.truncate(available - consumed);
            }
            BufferStorage::Heap(vec) => {
                let available = vec.len();
                let consumed = len.min(available);
                vec.rotate_left(consumed);
                vec.truncate(available - consumed);
            }
        }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), Error> {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => {
                if vec.push(byte).is_err() {
                    let mut heap = Vec::with_capacity(vec.capacity() * 2);
                    heap.extend_from_slice(vec.as_slice());
                    heap.push(byte);
                    self.buf = BufferStorage::Heap(heap);
                }
                Ok(())
            }
            BufferStorage::Heap(vec) => {
                vec.push(byte);
                Ok(())
            }
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.buf {
            BufferStorage::Heapless(vec) => {
                if vec.len() + data.len() <= vec.capacity() {
                    vec.extend_from_slice(data).map_err(|_| {
                        Error::new(ErrorKind::Other, "Failed to extend heapless buffer")
                    })
                } else {
                    let mut heap =
                        Vec::with_capacity((vec.len() + data.len()).max(vec.capacity() * 2));
                    heap.extend_from_slice(vec.as_slice());
                    heap.extend_from_slice(data);
                    self.buf = BufferStorage::Heap(heap);
                    Ok(())
                }
            }
            BufferStorage::Heap(vec) => {
                vec.extend_from_slice(data);
                Ok(())
            }
        }
    }
}

impl<const N: usize> Deref for Buffer<HeaplessVec<u8, N>> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const N: usize> DerefMut for Buffer<HeaplessVec<u8, N>> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const N: usize> std::fmt::Debug for Buffer<HeaplessVec<u8, N>> {
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
            .field("capacity", &self.capacity())
            .field("content", &content)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub type Buffer16 = Buffer<HeaplessVec<u8, 16>>;
    pub type Buffer64 = Buffer<HeaplessVec<u8, 64>>;

    #[test]
    fn test_initial_state() {
        let buf = Buffer16::new(BufferType::BINARY);
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.as_slice(), &[]);
        assert!(matches!(buf.buf, BufferStorage::Heapless(_)));
    }

    #[test]
    fn test_resize_within_capacity() {
        let mut buf = Buffer16::new(BufferType::BINARY);
        buf.resize(10, 42).unwrap();

        assert_eq!(buf.size(), 10);
        assert_eq!(buf.as_slice(), &[42; 10]);
        assert!(matches!(buf.buf, BufferStorage::Heapless(_)));
    }

    #[test]
    fn test_resize_over_capacity_promotes_to_heap() {
        let mut buf = Buffer16::new(BufferType::BINARY);
        buf.resize(32, 1).unwrap();

        assert_eq!(buf.size(), 32);
        assert_eq!(buf.as_slice(), &[1; 32]);
        assert!(matches!(buf.buf, BufferStorage::Heap(_)));
    }

    #[test]
    fn test_reset_clears_buffer() {
        let mut buf = Buffer64::new(BufferType::BINARY);
        buf.resize(32, 9).unwrap();
        buf.reset();

        assert_eq!(buf.size(), 0);
        assert_eq!(buf.as_slice(), &[]);
    }

    #[test]
    fn test_text_utf8_valid() {
        let mut buf = Buffer16::new(BufferType::TEXT);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"test");

        assert_eq!(buf.as_str(), Some("test"));
    }

    #[test]
    fn test_text_utf8_invalid_returns_none() {
        let mut buf = Buffer16::new(BufferType::TEXT);
        buf.resize(3, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(&[0xff, 0xfe, 0xfd]);

        assert_eq!(buf.as_str(), None);
    }

    #[test]
    fn test_as_str_binary_none() {
        let mut buf = Buffer16::new(BufferType::BINARY);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"data");

        assert_eq!(buf.as_str(), None);
    }

    #[test]
    fn test_debug_format_includes_fields() {
        let mut buf = Buffer16::new(BufferType::TEXT);
        buf.resize(4, 0).unwrap();
        buf.as_mut_slice().copy_from_slice(b"rust");

        let dbg = format!("{:?}", buf);
        assert!(dbg.contains("Buffer"));
        assert!(dbg.contains("rust"));
        assert!(dbg.contains("size"));
        assert!(dbg.contains("capacity"));
    }

    #[test]
    fn test_double_resize_promotes_and_reuses_heap() {
        let mut buf = Buffer16::new(BufferType::BINARY);

        // Step 1: stack-allocated
        buf.resize(8, 1).unwrap();
        assert!(matches!(buf.buf, BufferStorage::Heapless(_)));

        // Step 2: promote to heap with custom fill
        buf.resize(128, 2).unwrap();
        assert!(matches!(buf.buf, BufferStorage::Heap(_)));

        // Step 3: shrink and overwrite with 3s
        buf.resize(64, 0).unwrap(); // shrink and avoid fill conflict
        buf.as_mut_slice().fill(3);
        assert_eq!(buf.as_slice(), &[3; 64]);
    }

    #[test]
    fn test_truncate_stack_and_heap() {
        let mut buf = Buffer16::new(BufferType::BINARY);
        buf.resize(10, 1).unwrap(); // [1; 10]
        assert_eq!(buf.as_slice(), &[1; 10]);

        buf.truncate(5);
        assert_eq!(buf.as_slice(), &[1; 5]);
        assert!(matches!(buf.buf, BufferStorage::Heapless(_)));

        // Promote to heap
        buf.resize(64, 2).unwrap(); // [1; 5] + [2; 59]
        assert!(matches!(buf.buf, BufferStorage::Heap(_)));

        buf.truncate(8);
        assert_eq!(buf.as_slice(), &[1, 1, 1, 1, 1, 2, 2, 2]);
    }

    #[test]
    fn test_advance_stack_and_heap() {
        let mut buf = Buffer16::new(BufferType::BINARY);
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);

        buf.advance(3);
        assert_eq!(buf.as_slice(), &[4, 5, 6, 7, 8]);

        buf.advance(10); // advance more than remaining
        assert_eq!(buf.as_slice(), &[]);

        // Promote to heap by exceeding heapless capacity
        buf.extend_from_slice(&[0; 32]).unwrap();
        assert!(matches!(buf.buf, BufferStorage::Heap(_)));

        buf.advance(16);
        assert_eq!(buf.size(), 16);
    }
}
