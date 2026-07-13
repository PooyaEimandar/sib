use crate::database::fdb::{db::FDB, future::FDBFuture};
use std::ffi::CStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FDBStreamingMode {
    WantAll = -2,
    Iterator = -1,
    Exact = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
    Serial = 4,
}

impl From<FDBStreamingMode> for i32 {
    fn from(mode: FDBStreamingMode) -> i32 {
        match mode {
            FDBStreamingMode::WantAll => {
                foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_WANT_ALL
            }
            FDBStreamingMode::Iterator => {
                foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_ITERATOR
            }
            FDBStreamingMode::Exact => foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_EXACT,
            FDBStreamingMode::Small => foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_SMALL,
            FDBStreamingMode::Medium => {
                foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_MEDIUM
            }
            FDBStreamingMode::Large => foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_LARGE,
            FDBStreamingMode::Serial => {
                foundationdb_sys::FDBStreamingMode_FDB_STREAMING_MODE_SERIAL
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FDBTransactionOption {
    CausalWriteRisky = 10,
    CausalReadRisky = 20,
    CausalReadDisable = 21,
    IncludePortInAddress = 23,
    NextWriteNoWriteConflictRange = 30,
    CommitOnFirstProxy = 40,
    CheckWritesEnable = 50,
    ReadYourWritesDisable = 51,
    ReadAheadDisable = 52,
    ReadServerSideCacheEnable = 507,
    ReadServerSideCacheDisable = 508,
    ReadPriorityNormal = 509,
    ReadPriorityLow = 510,
    ReadPriorityHigh = 511,
    DurabilityDatacenter = 110,
    DurabilityRisky = 120,
    DurabilityDevNullIsWebScale = 130,
    PrioritySystemImmediate = 200,
    PriorityBatch = 201,
    InitializeNewDatabase = 300,
    AccessSystemKeys = 301,
    ReadSystemKeys = 302,
    RawAccess = 303,
    BypassStorageQuota = 304,
    DebugDump = 400,
    DebugRetryLogging = 401,
    TransactionLoggingEnable = 402,
    DebugTransactionIdentifier = 403,
    LogTransaction = 404,
    TransactionLoggingMaxFieldLength = 405,
    ServerRequestTracing = 406,
    Timeout = 500,
    RetryLimit = 501,
    MaxRetryDelay = 502,
    SizeLimit = 503,
    IdempotencyId = 504,
    AutomaticIdempotency = 505,
    SnapshotRYWEnable = 600,
    SnapshotRYWDisable = 601,
    LockAware = 700,
    UsedDuringCommitProtectionDisable = 701,
    ReadLockAware = 702,
    FirstInBatch = 710,
    UseProvisionalProxies = 711,
    ReportConflictingKeys = 712,
    SpecialKeySpaceRelaxed = 713,
    SpecialKeySpaceEnableWrites = 714,
    Tag = 800,
    AutoThrottleTag = 801,
    SpanParent = 900,
    ExpensiveClearCostEstimationEnable = 1000,
    BypassUnreadable = 1100,
    UseGrvCache = 1101,
    SkipGrvCache = 1102,
    AuthorizationToken = 2000,
}

pub struct FDBRange<'a> {
    pub begin_key: &'a [u8],
    pub begin_or_equal: bool,
    pub begin_offset: i32,
    pub end_key: &'a [u8],
    pub end_or_equal: bool,
    pub end_offset: i32,
    pub limit: i32,
    pub target_bytes: i32,
    pub mode: FDBStreamingMode,
    pub iteration: i32,
    pub snapshot: bool,
    pub reverse: bool,
}

pub type FDBKeyValue = (Vec<u8>, Vec<u8>);
pub type FDBRangeResult = (Vec<FDBKeyValue>, bool);

#[inline]
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.last_mut() {
        if *last != 0xFF {
            *last += 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

impl<'a> FDBRange<'a> {
    pub fn between(begin: &'a [u8], end: &'a [u8], limit: i32) -> Self {
        Self {
            begin_key: begin,
            begin_or_equal: false,
            begin_offset: 1,
            end_key: end,
            end_or_equal: false,
            end_offset: 1,
            limit,
            target_bytes: 1 << 20,
            mode: FDBStreamingMode::WantAll,
            iteration: 0,
            snapshot: true,
            reverse: false,
        }
    }

    pub fn exact_prefix(prefix: &'a [u8], end: &'a [u8], limit: i32) -> Self {
        Self::between(prefix, end, limit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FDBOwnedRange {
    pub begin_key: Vec<u8>,
    pub begin_or_equal: bool,
    pub begin_offset: i32,
    pub end_key: Vec<u8>,
    pub end_or_equal: bool,
    pub end_offset: i32,
    pub limit: i32,
    pub target_bytes: i32,
    pub mode: FDBStreamingMode,
    pub iteration: i32,
    pub snapshot: bool,
    pub reverse: bool,
}

impl FDBOwnedRange {
    pub fn between(begin: impl Into<Vec<u8>>, end: impl Into<Vec<u8>>, limit: i32) -> Self {
        Self {
            begin_key: begin.into(),
            begin_or_equal: false,
            begin_offset: 1,
            end_key: end.into(),
            end_or_equal: false,
            end_offset: 1,
            limit,
            target_bytes: 1 << 20,
            mode: FDBStreamingMode::WantAll,
            iteration: 0,
            snapshot: true,
            reverse: false,
        }
    }

    pub fn prefix(prefix: &[u8], limit: i32) -> Option<Self> {
        Some(Self::between(prefix.to_vec(), prefix_end(prefix)?, limit))
    }

    pub fn as_range(&self) -> FDBRange<'_> {
        FDBRange {
            begin_key: &self.begin_key,
            begin_or_equal: self.begin_or_equal,
            begin_offset: self.begin_offset,
            end_key: &self.end_key,
            end_or_equal: self.end_or_equal,
            end_offset: self.end_offset,
            limit: self.limit,
            target_bytes: self.target_bytes,
            mode: self.mode,
            iteration: self.iteration,
            snapshot: self.snapshot,
            reverse: self.reverse,
        }
    }

    pub fn after_key(mut self, key: &[u8]) -> Self {
        self.begin_key.clear();
        self.begin_key.extend_from_slice(key);
        self.begin_or_equal = true;
        self.begin_offset = 1;
        self.iteration = self.iteration.saturating_add(1);
        self
    }

    pub fn with_limit(mut self, limit: i32) -> Self {
        self.limit = limit;
        self
    }

    pub fn with_target_bytes(mut self, target_bytes: i32) -> Self {
        self.target_bytes = target_bytes;
        self
    }

    pub fn with_streaming_mode(mut self, mode: FDBStreamingMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn snapshot(mut self, snapshot: bool) -> Self {
        self.snapshot = snapshot;
        self
    }
}

pub enum FDBTransactionOutcome<R> {
    Ok(R),
    Retry(i32), // FDB error code
}

pub struct FDBTransaction {
    pub trs: *mut foundationdb_sys::FDBTransaction,
}

// SAFETY: FoundationDB transactions are client API handles that may be moved
// between threads. This wrapper owns one transaction pointer and destroys it
// exactly once in Drop.
unsafe impl Send for FDBTransaction {}
// SAFETY: The C API serializes access to transaction handles. Methods on this
// wrapper take `&self`, matching the C handle model; callers are still
// responsible for FoundationDB's transaction semantics.
unsafe impl Sync for FDBTransaction {}

#[inline]
fn fdb_err(code: i32) -> std::io::Error {
    let cstr = unsafe { foundationdb_sys::fdb_get_error(code) };
    let s = unsafe { CStr::from_ptr(cstr) }
        .to_string_lossy()
        .into_owned();
    std::io::Error::other(format!("FDB error {code}: {s}"))
}

impl FDBTransaction {
    #[inline]
    pub fn new(db: &FDB) -> std::io::Result<Self> {
        let mut trs: *mut foundationdb_sys::FDBTransaction = std::ptr::null_mut();
        let rc = unsafe { foundationdb_sys::fdb_database_create_transaction(db.db, &mut trs) };
        if rc != 0 {
            return Err(fdb_err(rc));
        }
        Ok(Self { trs })
    }

    #[inline]
    pub fn clear(&self, key: &[u8]) -> &Self {
        unsafe {
            foundationdb_sys::fdb_transaction_clear(self.trs, key.as_ptr(), key.len() as i32)
        };
        self
    }

    #[inline]
    pub fn set(&self, key: &[u8], value: &[u8]) -> &Self {
        unsafe {
            foundationdb_sys::fdb_transaction_set(
                self.trs,
                key.as_ptr(),
                key.len() as i32,
                value.as_ptr(),
                value.len() as i32,
            )
        };
        self
    }

    #[inline]
    pub fn clear_range(&self, start: &[u8], end: &[u8]) -> &Self {
        unsafe {
            foundationdb_sys::fdb_transaction_clear_range(
                self.trs,
                start.as_ptr(),
                start.len() as i32,
                end.as_ptr(),
                end.len() as i32,
            )
        };
        self
    }

    #[inline]
    pub fn set_option(&self, option: FDBTransactionOption, value: &[u8]) -> &Self {
        let (ptr, len) = if value.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (value.as_ptr(), value.len() as i32)
        };
        unsafe { foundationdb_sys::fdb_transaction_set_option(self.trs, option as u32, ptr, len) };
        self
    }

    #[inline]
    pub fn get(&self, key: &[u8], snapshot: bool) -> std::io::Result<FDBFuture> {
        FDBFuture::new(unsafe {
            foundationdb_sys::fdb_transaction_get(
                self.trs,
                key.as_ptr(),
                key.len() as i32,
                snapshot as i32,
            )
        })
    }

    /// Blocking get (with `on_error` retry). Returns Ok(Some(value)) / Ok(None).
    #[inline]
    pub fn get_blocking_value_optional(
        &self,
        key: &[u8],
        snapshot: bool,
    ) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            let fut = self.get(key, snapshot)?;
            fut.block_until_ready();
            let code = fut.get_error_code();
            if code == 0 {
                match fut.get_value() {
                    Ok(v) => return Ok(Some(v.to_vec())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            self.on_error_blocking(code)?;
        }
    }

    /// Returns a future for range read. (Used only inside retry loop below.)
    #[inline]
    pub fn get_range<'a>(&self, range: &FDBRange<'a>) -> std::io::Result<FDBFuture> {
        FDBFuture::new(unsafe {
            foundationdb_sys::fdb_transaction_get_range(
                self.trs,
                range.begin_key.as_ptr(),
                range.begin_key.len() as i32,
                range.begin_or_equal as i32,
                range.begin_offset,
                range.end_key.as_ptr(),
                range.end_key.len() as i32,
                range.end_or_equal as i32,
                range.end_offset,
                range.limit,
                range.target_bytes,
                i32::from(range.mode),
                range.iteration,
                range.snapshot as i32,
                range.reverse as i32,
            )
        })
    }

    #[inline]
    pub fn get_range_blocking<'a>(&self, range: &FDBRange<'a>) -> std::io::Result<FDBRangeResult> {
        let fut = self.get_range(range)?;
        fut.block_until_ready();

        let code = fut.get_error_code();
        if code != 0 {
            return Err(fdb_err(code)); // use your FDB error mapper
        }

        let mut kvs_ptr: *const foundationdb_sys::FDBKeyValue = std::ptr::null();
        let mut count: i32 = 0;
        let mut more: i32 = 0;
        let rc = unsafe {
            foundationdb_sys::fdb_future_get_keyvalue_array(
                fut.fut,
                &mut kvs_ptr,
                &mut count,
                &mut more,
            )
        };
        if rc != 0 {
            return Err(fdb_err(rc));
        }

        if count <= 0 || kvs_ptr.is_null() {
            return Ok((Vec::new(), more != 0));
        }

        #[inline]
        unsafe fn copy_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
            if ptr.is_null() || len == 0 {
                return Vec::new();
            }
            // NOTE: value/key buffers are byte-aligned; &[u8] is fine.
            unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
        }

        let mut out = Vec::with_capacity(count as usize);

        for i in 0..(count as usize) {
            // Read struct without assuming alignment
            let kv = unsafe { kvs_ptr.add(i).read_unaligned() };

            let klen = kv.key_length as usize;
            let vlen = kv.value_length as usize;

            let key = unsafe { copy_bytes(kv.key, klen) };
            let val = unsafe { copy_bytes(kv.value, vlen) };

            out.push((key, val));
        }

        Ok((out, more != 0))
    }

    #[inline]
    pub fn get_owned_range_blocking(
        &self,
        range: &FDBOwnedRange,
    ) -> std::io::Result<FDBRangeResult> {
        self.get_range_blocking(&range.as_range())
    }

    pub fn scan_prefix_blocking<F>(
        &self,
        prefix: &[u8],
        batch_size: i32,
        mut visit: F,
    ) -> std::io::Result<()>
    where
        F: FnMut(&[FDBKeyValue]) -> std::io::Result<()>,
    {
        if batch_size <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "batch_size must be positive",
            ));
        }

        let mut range = FDBOwnedRange::prefix(prefix, batch_size).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "prefix range has no finite end",
            )
        })?;

        loop {
            let (batch, more) = self.get_owned_range_blocking(&range)?;
            if batch.is_empty() {
                return Ok(());
            }

            visit(&batch)?;

            // Keying off the short batch would silently drop the rest of the prefix.
            if !more {
                return Ok(());
            }

            let Some((last_key, _)) = batch.last() else {
                return Ok(());
            };
            range = range.after_key(last_key);
        }
    }

    #[inline]
    pub fn commit(&self) -> std::io::Result<FDBFuture> {
        FDBFuture::new(unsafe { foundationdb_sys::fdb_transaction_commit(self.trs) })
    }

    /// Simple blocking commit (no replay). Keep for niche cases.
    #[inline]
    pub fn commit_blocking(&self) -> std::io::Result<()> {
        let fut = self.commit()?;
        fut.block_until_ready();
        let code = fut.get_error_code();
        if code != 0 {
            return Err(fdb_err(code));
        }
        Ok(())
    }

    #[inline]
    pub fn watch(&self, key: &[u8]) -> std::io::Result<FDBFuture> {
        FDBFuture::new(unsafe {
            foundationdb_sys::fdb_transaction_watch(self.trs, key.as_ptr(), key.len() as i32)
        })
    }

    #[inline]
    fn on_error_blocking(&self, code: i32) -> std::io::Result<()> {
        let fut =
            FDBFuture::new(unsafe { foundationdb_sys::fdb_transaction_on_error(self.trs, code) })?;
        fut.block_until_ready();
        let rc = fut.get_error_code();
        if rc != 0 {
            return Err(fdb_err(rc));
        }
        Ok(())
    }
}

impl Drop for FDBTransaction {
    fn drop(&mut self) {
        if !self.trs.is_null() {
            unsafe { foundationdb_sys::fdb_transaction_destroy(self.trs) }
        }
    }
}

#[inline]
pub fn run<R, F>(db: &FDB, mut f: F) -> std::io::Result<R>
where
    F: FnMut(&FDBTransaction) -> std::io::Result<FDBTransactionOutcome<R>>,
{
    // Create the transaction ONCE and reuse it across retries
    let trx = FDBTransaction::new(db)?;
    loop {
        // user logic
        let out = match f(&trx)? {
            FDBTransactionOutcome::Ok(v) => v,
            FDBTransactionOutcome::Retry(code) => {
                trx.on_error_blocking(code)?;
                continue;
            }
        };

        // commit
        let fut = trx.commit()?;
        fut.block_until_ready();
        let code = fut.get_error_code();

        if code == 0 {
            return Ok(out);
        }

        trx.on_error_blocking(code)?;
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/database/fdb/trans_tests.rs"]
mod tests;
