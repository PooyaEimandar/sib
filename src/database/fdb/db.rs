#[derive(Clone, Debug)]
pub struct FDB {
    pub db: *mut foundationdb_sys::FDBDatabase,
}

// SAFETY: FoundationDB's FDBDatabase handle is thread-safe to use across threads.
unsafe impl Send for FDB {}
unsafe impl Sync for FDB {}

impl FDB {
    pub fn new(cluster_file_path: &str) -> std::io::Result<Self> {
        let mut db: *mut foundationdb_sys::FDBDatabase = std::ptr::null_mut();
        let c_path = std::ffi::CString::new(cluster_file_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let res = unsafe { foundationdb_sys::fdb_create_database(c_path.as_ptr(), &mut db) };
        if res != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to setup FoundationDB network: {res}"
            )));
        }
        Ok(Self { db })
    }
}

impl Drop for FDB {
    fn drop(&mut self) {
        if self.db.is_null() {
            return;
        }
        unsafe { foundationdb_sys::fdb_database_destroy(self.db) };
        self.db = std::ptr::null_mut();
    }
}
