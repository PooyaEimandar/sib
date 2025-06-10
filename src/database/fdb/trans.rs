use crate::database::fdb::{db::FDB, future::FDBFuture};

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
    pub reverse: bool,
}

pub struct FDBTransaction {
    pub trs: *mut foundationdb_sys::FDB_transaction,
}

impl FDBTransaction {
    pub fn new(db: &FDB) -> std::io::Result<Self> {
        let mut trs: *mut foundationdb_sys::FDB_transaction = std::ptr::null_mut();
        let err_code =
            unsafe { foundationdb_sys::fdb_database_create_transaction(db.db, &mut trs) };
        if err_code != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to create FDB transaction: error code {err_code}"
            )));
        }
        Ok(Self { trs })
    }

    pub fn clear(&self, key: &[u8]) -> &Self {
        unsafe {
            foundationdb_sys::fdb_transaction_clear(self.trs, key.as_ptr(), key.len() as i32)
        };
        self
    }

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

    pub fn set_option(&self, option: FDBTransactionOption, value: &[u8]) -> &Self {
        unsafe {
            foundationdb_sys::fdb_transaction_set_option(
                self.trs,
                option as u32,
                value.as_ptr(),
                value.len() as i32,
            )
        };
        self
    }

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

    pub async fn get_range<'a>(
        &self,
        range: &'a FDBRange<'a>,
        snapshot: bool,
    ) -> std::io::Result<FDBFuture> {
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
                range.mode as i32,
                range.iteration,
                snapshot as i32,
                range.reverse as i32,
            )
        })
    }

    pub fn commit(&self) -> std::io::Result<FDBFuture> {
        let res = unsafe { foundationdb_sys::fdb_transaction_commit(self.trs) };
        FDBFuture::new(res)
    }

    pub fn watch(&self, key: &[u8]) -> std::io::Result<FDBFuture> {
        FDBFuture::new(unsafe {
            foundationdb_sys::fdb_transaction_watch(self.trs, key.as_ptr(), key.len() as i32)
        })
    }
}

// pub async fn backup(p_backup_dir: &str, timeout: std::time::Duration) -> anyhow::Result<()> {
//     s_info!("Starting FoundationDB backup at {}", p_backup_dir);

//     // Ensure no previous backup is still running
//     match Command::new("fdbbackup")
//         .args(["discontinue"])
//         .status()
//         .await
//     {
//         Ok(status) if status.success() => {
//             println!("Previous backup (if any) successfully discontinued.");
//         }
//         Ok(status) => {
//             eprintln!(
//                 "fdbbackup discontinue exited with non-zero code: {}",
//                 status
//             );
//         }
//         Err(e) => {
//             eprintln!("fdbbackup discontinue failed: {}", e);
//         }
//     }

//     // Start the new backup
//     let status = Command::new("fdbbackup")
//         .args(["start", "-d", p_backup_dir])
//         .status()
//         .await?;

//     if !status.success() {
//         anyhow::bail!("fdbbackup start failed");
//     }

//     let start_time = Instant::now();

//     loop {
//         let mut child = Command::new("fdbbackup")
//             .args(["status"])
//             .stdout(std::process::Stdio::piped())
//             .spawn()?;

//         let stdout = child
//             .stdout
//             .as_mut()
//             .ok_or_else(|| anyhow::anyhow!("fdbbackup failed to capture stdout"))?;

//         let mut output = String::new();
//         stdout.read_to_string(&mut output).await?;

//         let status = child.wait().await?;
//         if !status.success() {
//             anyhow::bail!("fdbbackup status command failed");
//         }

//         println!("fdbbackup status:\n{}", output);

//         if !output.contains("is in progress") {
//             if output.contains("ERROR") || output.contains("failed") {
//                 anyhow::bail!("fdbbackup returned failure:\n{}", output);
//             }
//             println!("fdbbackup completed successfully.");
//             break;
//         }

//         if start_time.elapsed() >= timeout {
//             anyhow::bail!(
//                 "fdbbackup did not complete within {} seconds",
//                 timeout.as_secs()
//             );
//         }

//         time::sleep(Duration::from_secs(1)).await;
//     }

//     println!("Discontinuing completed backup...");

//     match Command::new("fdbbackup")
//         .args(["discontinue"])
//         .status()
//         .await
//     {
//         Ok(status) if status.success() => {
//             println!("fdbbackup successfully discontinued.");
//         }
//         Ok(status) => {
//             eprintln!(
//                 "fdbbackup discontinue exited with non-zero status (possibly no active backup): {}",
//                 status
//             );
//         }
//         Err(e) => {
//             eprintln!("fdbbackup discontinue command failed: {}", e);
//         }
//     }

//     println!("fdbbackup successfully discontinued.");

//     Ok(())
// }

// pub async fn import(
//     data: &Map<String, Value>,
//     pool: &FDBPool,
//     iteration: usize,
//     reverse: bool,
//     snapshot: bool,
// ) -> anyhow::Result<()> {
//     // Extract prefix (assumes common prefix for all keys)
//     let prefix = data
//         .keys()
//         .next()
//         .and_then(|k| k.split('/').nth(1))
//         .map(|s| format!("/{}/", s))
//         .unwrap_or_else(|| "/".to_string());

//     // Load all existing keys from the DB under that prefix
//     let mut existing_keys = Vec::new();
//     let mut begin = foundationdb::KeySelector::first_greater_or_equal(prefix.as_bytes().to_vec());
//     let end = foundationdb::KeySelector::first_greater_or_equal(next_prefix(prefix.as_bytes()));

//     loop {
//         let db = pool.get().await?;
//         let trx = FDBTransaction::new(&db)?;

//         let range = foundationdb::RangeOption {
//             begin: begin.clone(),
//             end: end.clone(),
//             limit: Some(iteration),
//             reverse,
//             ..Default::default()
//         };

//         let kvs = trx.get_range(&range, iteration, snapshot).await?;
//         if kvs.is_empty() {
//             break;
//         }

//         existing_keys.extend(
//             kvs.iter()
//                 .map(|kv| String::from_utf8_lossy(kv.key()).to_string()),
//         );

//         let last_key = kvs
//             .last()
//             .ok_or_else(|| anyhow::anyhow!("No last key was found"))?
//             .key()
//             .to_vec();
//         begin = foundationdb::KeySelector::first_greater_than(last_key);
//     }

//     // Begin a batch import (set and delete)
//     for key in existing_keys {
//         if !data.contains_key(&key) {
//             let db = pool.get().await?;
//             let trx = FDBTransaction::new(&db)?;
//             trx.clear(key.as_bytes());
//             trx.commit().await?;
//             s_info!("Deleted key: {}", key);
//         }
//     }

//     for (key, new_val) in data {
//         let db = pool.get().await?;
//         let trx = FDBTransaction::new(&db)?;

//         let current_val = trx.get(key.as_bytes()).await?;
//         let new_bytes = serde_json::to_vec(&new_val)?;

//         let should_write = match current_val {
//             Some(existing_bytes) => existing_bytes.as_ref() != new_bytes.as_slice(),
//             None => true,
//         };

//         if should_write {
//             s_info!("Updating key: {}", key);
//             trx.set(key.as_bytes(), &new_bytes);
//             trx.commit().await?;
//         } else {
//             s_info!("Skipping unchanged key: {}", key);
//         }
//     }

//     Ok(())
// }

// pub async fn clear(
//     prefix: &str,
//     pool: Arc<FDBPool>,
//     iteration: usize,
//     reverse: bool,
//     snapshot: bool,
// ) -> anyhow::Result<()> {
//     let mut begin = foundationdb::KeySelector::first_greater_or_equal(prefix.as_bytes().to_vec());
//     let end = foundationdb::KeySelector::first_greater_or_equal(next_prefix(prefix.as_bytes()));

//     loop {
//         let db = pool.get().await?;
//         let trx = FDBTransaction::new(&db)?;

//         let range = foundationdb::RangeOption {
//             begin: begin.clone(),
//             end: end.clone(),
//             limit: Some(iteration),
//             reverse,
//             ..Default::default()
//         };

//         let kvs = trx.get_range(&range, iteration, snapshot).await?;
//         if kvs.is_empty() {
//             break;
//         }

//         for kv in &kvs {
//             trx.clear(kv.key());
//             s_info!("Cleared key: {}", String::from_utf8_lossy(kv.key()));
//         }

//         trx.commit().await?;
//         let last_key = match kvs.last() {
//             Some(kv) => kv.key().to_vec(),
//             None => break,
//         };
//         begin = foundationdb::KeySelector::first_greater_than(last_key);
//     }

//     Ok(())
// }

// /// Utility to get the next byte prefix (e.g. `/ads/` → `/ads0`)
// pub fn next_prefix(prefix: &[u8]) -> Vec<u8> {
//     let mut next = prefix.to_vec();
//     for i in (0..next.len()).rev() {
//         if next[i] < 255 {
//             next[i] += 1;
//             next.truncate(i + 1);
//             return next;
//         }
//     }
//     // If all 0xFF, append a null byte
//     next.push(0);
//     next
// }

// #[tokio::test]
// async fn test() -> anyhow::Result<()> {
//     let _network = FDBNetwork::new();

//     // Initialize FoundationDB connection pool
//     let pool = create_fdb_pool(10)?;

//     // export data
//     let data = export(&Bytes::from_static(b"/"), &pool, 0, 100, false, false).await?;
//     println!(
//         "Exported JSON: {}",
//         String::from_utf8(serde_json::to_vec_pretty(&data)?)?
//     );
//     // import data
//     import(&data, &pool, 100, false, false).await?;
//     println!("Data imported successfully.");

//     let pool_cloned = pool.clone();
//     let task1 = tokio::spawn(async move {
//         if let Ok(db) = pool_cloned.get().await {
//             if let Ok(transaction) = FDBTransaction::new(&db) {
//                 transaction.set(b"key1", b"value1");
//                 if let Err(e) = transaction.commit().await {
//                     eprintln!("Transaction 1 failed: {:?}", e);
//                 } else {
//                     println!("Transaction 1 committed!");
//                 }
//             }
//         }
//     });

//     let task2 = tokio::spawn(async move {
//         if let Ok(db) = pool.clone().get().await {
//             if let Ok(transaction) = FDBTransaction::new(&db) {
//                 match transaction.get(b"key1").await {
//                     Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
//                         Ok(s) => println!("Fetched key1: {}", s),
//                         Err(_) => println!("Error: Value is not valid UTF-8"),
//                     },
//                     Ok(None) => println!("Key1 not found"),
//                     Err(e) => eprintln!("Failed to get key1: {:?}", e),
//                 }
//             }
//         }
//     });

//     task1.await?;
//     task2.await?;

//     Ok(())
// }
