// use async_trait::async_trait;
// use base64::{Engine, prelude::BASE64_STANDARD};
// use bytes::Bytes;
// use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleError, RecycleResult};
// use foundationdb::{
//     Database, RangeOption, Transaction, future::FdbValues, options::TransactionOption,
// };
// use serde_json::{Map, Value};
// use std::{sync::Arc, time::Duration};
// use tokio::{
//     io::AsyncReadExt,
//     process::Command,
//     time::{self, Instant},
// };

// use crate::s_info;

// pub struct FDBNetwork {
//     _fdb_network: foundationdb::api::NetworkAutoStop,
// }
// impl FDBNetwork {
//     pub fn new() -> Self {
//         let _fdb_network = unsafe { foundationdb::boot() };
//         Self { _fdb_network }
//     }
// }

// impl Default for FDBNetwork {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// // Manager for FoundationDB connections
// pub struct FDBManager;

// #[allow(clippy::manual_async_fn)]
// #[async_trait]
// impl Manager for FDBManager {
//     type Type = Database;
//     type Error = RecycleError<foundationdb::FdbError>;

//     /// Creates a new instance of [`Manager::Type`].
//     fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
//         async { Database::default().map_err(RecycleError::Backend) }
//     }

//     /// Tries to recycle an instance of [`Manager::Type`].
//     ///
//     /// # Errors
//     ///
//     /// Returns [`Manager::Error`] if the instance couldn't be recycled.
//     fn recycle(
//         &self,
//         _obj: &mut Self::Type,
//         _metrics: &Metrics,
//     ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
//         async { Ok(()) }
//     }

//     /// Detaches an instance of [`Manager::Type`] from this [`Manager`].
//     ///
//     /// This method is called when using the [`Object::take()`] method for
//     /// removing an [`Object`] from a [`Pool`]. If the [`Manager`] doesn't hold
//     /// any references to the handed out [`Object`]s then the default
//     /// implementation can be used which does nothing.
//     fn detach(&self, _obj: &mut Self::Type) {}
// }

// // Type alias for easier usage
// pub type FDBPool = Pool<FDBManager>;

// pub fn create_fdb_pool(pool_size: usize) -> anyhow::Result<FDBPool> {
//     let manager = FDBManager;
//     Pool::builder(manager)
//         .max_size(pool_size)
//         .build()
//         .map_err(|e| anyhow::anyhow!("Failed to create FDB connection pool: {}", e))
// }

// // Wrapper for transactions that auto-release pool slots
// pub struct FDBTransaction {
//     trx: Transaction,
// }

// impl FDBTransaction {
//     pub fn new(db: &Object<FDBManager>) -> anyhow::Result<Self> {
//         let trx = db.create_trx()?;
//         Ok(Self { trx })
//     }

//     pub async fn get(&self, key: &[u8]) -> anyhow::Result<Option<Arc<[u8]>>> {
//         self.trx
//             .get(key, false)
//             .await
//             .map(|opt| opt.map(|slice| Arc::from(slice.as_ref())))
//             .map_err(anyhow::Error::msg)
//     }

//     pub fn set(&self, key: &[u8], value: &[u8]) {
//         self.trx.set(key, value);
//     }

//     pub fn set_option(&self, option: TransactionOption) -> anyhow::Result<()> {
//         self.trx.set_option(option).map_err(anyhow::Error::msg)
//     }

//     pub fn clear(&self, key: &[u8]) {
//         self.trx.clear(key);
//     }

//     pub async fn get_range(
//         &self,
//         range: &RangeOption<'_>,
//         iteration: usize,
//         snapshot: bool,
//     ) -> anyhow::Result<FdbValues> {
//         self.trx
//             .get_range(range, iteration, snapshot)
//             .await
//             .map_err(anyhow::Error::msg)
//     }

//     pub async fn commit(self) -> anyhow::Result<()> {
//         self.trx
//             .commit()
//             .await
//             .map(|_| ())
//             .map_err(anyhow::Error::msg)
//     }

//     pub async fn watch(&self, key: &[u8]) -> anyhow::Result<()> {
//         self.trx.watch(key).await.map_err(anyhow::Error::msg)
//     }
// }

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

// pub async fn export(
//     prefix: &Bytes,
//     pool: &FDBPool,
//     offset: usize,
//     limit: usize,
//     reverse: bool,
//     snapshot: bool,
// ) -> anyhow::Result<Map<String, Value>> {
//     let mut data = Map::new();
//     let mut begin = foundationdb::KeySelector::first_greater_or_equal(prefix.to_vec());
//     let end = foundationdb::KeySelector::first_greater_or_equal(next_prefix(prefix));

//     let mut skipped = 0;
//     let mut collected = 0;
//     let batch_size = 1000; // internal iteration batch

//     loop {
//         let db = pool.get().await?;
//         let trx = FDBTransaction::new(&db)?;

//         let range = foundationdb::RangeOption {
//             begin: begin.clone(),
//             end: end.clone(),
//             limit: Some(batch_size),
//             reverse,
//             ..Default::default()
//         };

//         let kvs = trx
//             .get_range(&range, batch_size, snapshot)
//             .await
//             .map_err(|e| anyhow::anyhow!("get_range failed: {}", e))?;

//         if kvs.is_empty() {
//             break;
//         }

//         for kv in &kvs {
//             if skipped < offset {
//                 skipped += 1;
//                 continue;
//             }

//             if collected >= limit {
//                 return Ok(data);
//             }

//             let key = String::from_utf8_lossy(kv.key()).to_string();
//             if let Ok(json_val) = serde_json::from_slice::<Value>(kv.value()) {
//                 data.insert(key, json_val);
//             } else {
//                 data.insert(key, Value::String(BASE64_STANDARD.encode(kv.value())));
//             }

//             collected += 1;
//         }

//         if collected >= limit {
//             break;
//         }

//         let last_key = match kvs.last() {
//             Some(kv) => kv.key().to_vec(),
//             None => break,
//         };
//         begin = foundationdb::KeySelector::first_greater_than(last_key);
//     }

//     Ok(data)
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
