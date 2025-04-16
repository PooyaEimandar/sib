use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_STANDARD};
use chrono::{Datelike, Timelike};
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use foundationdb::{Database, Transaction, options::TransactionOption};
use serde_json::{Map, Value};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{self, Instant},
};

use crate::s_info;

pub struct FDBNetwork {
    _fdb_network: foundationdb::api::NetworkAutoStop,
}
impl FDBNetwork {
    pub fn new() -> Self {
        let _fdb_network = unsafe { foundationdb::boot() };
        Self { _fdb_network }
    }
}

impl Default for FDBNetwork {
    fn default() -> Self {
        Self::new()
    }
}

// Manager for FoundationDB connections
pub struct FDBManager;

#[allow(clippy::manual_async_fn)]
#[async_trait]
impl Manager for FDBManager {
    type Type = Database;
    type Error = RecycleError<foundationdb::FdbError>;

    /// Creates a new instance of [`Manager::Type`].
    fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
        async { Database::default().map_err(RecycleError::Backend) }
    }

    /// Tries to recycle an instance of [`Manager::Type`].
    ///
    /// # Errors
    ///
    /// Returns [`Manager::Error`] if the instance couldn't be recycled.
    fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Detaches an instance of [`Manager::Type`] from this [`Manager`].
    ///
    /// This method is called when using the [`Object::take()`] method for
    /// removing an [`Object`] from a [`Pool`]. If the [`Manager`] doesn't hold
    /// any references to the handed out [`Object`]s then the default
    /// implementation can be used which does nothing.
    fn detach(&self, _obj: &mut Self::Type) {}
}

// Type alias for easier usage
type FDBPool = Pool<FDBManager>;

pub fn create_fdb_pool(pool_size: usize) -> FDBPool {
    let manager = FDBManager;
    Pool::builder(manager).max_size(pool_size).build().unwrap()
}

// Wrapper for transactions that auto-release pool slots
pub struct FDBTransaction {
    trx: Transaction,
}

impl FDBTransaction {
    pub async fn get(&self, key: &[u8]) -> anyhow::Result<Option<Arc<[u8]>>> {
        self.trx
            .get(key, false)
            .await
            .map(|opt| opt.map(|slice| Arc::from(slice.as_ref())))
            .map_err(anyhow::Error::msg)
    }

    pub fn set(&self, key: &[u8], value: &[u8]) {
        self.trx.set(key, value);
    }

    pub fn set_option(&self, option: TransactionOption) -> anyhow::Result<()> {
        self.trx.set_option(option).map_err(anyhow::Error::msg)
    }

    pub async fn commit(self) -> anyhow::Result<foundationdb::TransactionCommitted> {
        self.trx.commit().await.map_err(anyhow::Error::msg)
    }

    pub async fn watch(&self, key: &[u8]) -> anyhow::Result<()> {
        self.trx.watch(key).await.map_err(anyhow::Error::msg)
    }
}

pub async fn backup(p_backup_path: &str, timeout: std::time::Duration) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let version = format!(
        "{:04}.{:02}.{:02}.{:02}{:02}{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let backup_dir = format!("{}/fdb-backup-{}", p_backup_path, version);
    s_info!("Starting FoundationDB backup at {}", backup_dir);

    // Start the backup
    let status = Command::new("fdbbackup")
        .args(["start", "-d", &backup_dir])
        .status()
        .await?;

    if !status.success() {
        anyhow::bail!("fdbbackup start failed");
    }

    // Poll for backup status with timeout
    let start_time = Instant::now();

    loop {
        let mut child = Command::new("fdbbackup")
            .args(["status"])
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("fdbbackup failed to capture stdout"))?;

        let mut output = String::new();
        stdout.read_to_string(&mut output).await?;

        let status = child.wait().await?;
        if !status.success() {
            anyhow::bail!("fdbbackup status command failed");
        }

        if output.contains("fdbbackup state: Completed")
            || output.contains("The backup has been successfully completed")
        {
            s_info!("fdbbackup completed successfully.");
            break;
        }

        if start_time.elapsed() >= timeout {
            anyhow::bail!(
                "fdbbackup did not complete within {} seconds",
                timeout.as_secs()
            );
        }

        time::sleep(Duration::from_secs(1)).await;
    }

    // Discontinue backup
    let status = Command::new("fdbbackup")
        .args(["discontinue"])
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("fdbbackup discontinue command failed");
    }

    s_info!("fdbbackup successfully discontinued.");

    Ok(())
}

pub async fn export_to_json(
    prefix: &str,
    pool: Arc<FDBPool>,
    batch_limit: usize,
    output_path: &str,
) -> anyhow::Result<()> {
    let mut data = Map::new();
    let mut begin = foundationdb::KeySelector::first_greater_or_equal(prefix.as_bytes().to_vec());
    let end = foundationdb::KeySelector::first_greater_or_equal(next_prefix(prefix.as_bytes()));

    loop {
        let db = pool.get().await?;
        let trx = db.create_trx()?;

        let range = foundationdb::RangeOption {
            begin: begin.clone(),
            end: end.clone(),
            limit: Some(batch_limit),
            reverse: false,
            ..Default::default()
        };

        let kvs = trx
            .get_range(&range, batch_limit, false)
            .await
            .map_err(|e| anyhow::anyhow!("get_range failed: {}", e))?;

        if kvs.is_empty() {
            break;
        }

        for kv in &kvs {
            let key = String::from_utf8_lossy(kv.key()).to_string();
            if let Ok(json_val) = serde_json::from_slice::<Value>(kv.value()) {
                data.insert(key, json_val);
            } else {
                data.insert(key, Value::String(BASE64_STANDARD.encode(kv.value())));
            }
        }

        let last_key = kvs.last().map(|kv| kv.key().to_vec()).unwrap();
        begin = foundationdb::KeySelector::first_greater_than(last_key);
    }

    let out_json = Value::Object(data);
    tokio::fs::write(output_path, serde_json::to_vec_pretty(&out_json)?).await?;

    Ok(())
}

pub async fn import_from_json(input_path: &str, pool: Arc<FDBPool>) -> anyhow::Result<()> {
    let raw_json = tokio::fs::read_to_string(input_path).await?;
    let imported: Map<String, Value> = serde_json::from_str(&raw_json)?;

    // Extract prefix (assumes common prefix for all keys)
    let prefix = imported
        .keys()
        .next()
        .and_then(|k| k.split('/').nth(1))
        .map(|s| format!("/{}/", s))
        .unwrap_or_else(|| "/".to_string());

    // Load all existing keys from the DB under that prefix
    let mut existing_keys = Vec::new();
    let mut begin = foundationdb::KeySelector::first_greater_or_equal(prefix.as_bytes().to_vec());
    let end = foundationdb::KeySelector::first_greater_or_equal(next_prefix(prefix.as_bytes()));

    loop {
        let db = pool.get().await?;
        let trx = db.create_trx()?;

        let range = foundationdb::RangeOption {
            begin: begin.clone(),
            end: end.clone(),
            limit: Some(1000),
            reverse: false,
            ..Default::default()
        };

        let kvs = trx.get_range(&range, 1000, false).await?;
        if kvs.is_empty() {
            break;
        }

        existing_keys.extend(
            kvs.iter()
                .map(|kv| String::from_utf8_lossy(kv.key()).to_string()),
        );

        let last_key = kvs.last().unwrap().key().to_vec();
        begin = foundationdb::KeySelector::first_greater_than(last_key);
    }

    // Begin a batch import (set and delete)
    for key in existing_keys {
        if !imported.contains_key(&key) {
            let db = pool.get().await?;
            let trx = db.create_trx()?;
            trx.clear(key.as_bytes());
            trx.commit().await.map_err(anyhow::Error::msg)?;
            s_info!("Deleted key: {}", key);
        }
    }

    for (key, new_val) in imported {
        let db = pool.get().await?;
        let trx = db.create_trx()?;
        let transaction = FDBTransaction { trx };

        let current_val = transaction.get(key.as_bytes()).await?;
        let new_bytes = serde_json::to_vec(&new_val)?;

        let should_write = match current_val {
            Some(existing_bytes) => existing_bytes.as_ref() != new_bytes.as_slice(),
            None => true,
        };

        if should_write {
            s_info!("Updating key: {}", key);
            transaction.set(key.as_bytes(), &new_bytes);
            transaction.commit().await?;
        } else {
            s_info!("Skipping unchanged key: {}", key);
        }
    }

    Ok(())
}

/// Utility to get the next byte prefix (e.g. `/ads/` → `/ads0`)
fn next_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut next = prefix.to_vec();
    for i in (0..next.len()).rev() {
        if next[i] < 255 {
            next[i] += 1;
            next.truncate(i + 1);
            return next;
        }
    }
    // If all 0xFF, append a null byte
    next.push(0);
    next
}

#[tokio::test]
async fn test() -> anyhow::Result<()> {
    let _network = FDBNetwork::new();

    // Initialize FoundationDB connection pool
    let pool = Arc::new(create_fdb_pool(10));

    let pool_clone = Arc::clone(&pool);
    let task1 = tokio::spawn(async move {
        if let Ok(db) = pool_clone.get().await {
            if let Ok(trx) = db.create_trx() {
                let transaction = FDBTransaction { trx };
                transaction.set(b"key1", b"value1");
                if let Err(e) = transaction.commit().await {
                    eprintln!("Transaction 1 failed: {:?}", e);
                } else {
                    println!("Transaction 1 committed!");
                }
            }
        }
    });

    let pool_clone = Arc::clone(&pool);
    let task2 = tokio::spawn(async move {
        if let Ok(db) = pool_clone.get().await {
            if let Ok(trx) = db.create_trx() {
                let transaction = FDBTransaction { trx };
                match transaction.get(b"key1").await {
                    Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                        Ok(s) => println!("Fetched key1: {}", s),
                        Err(_) => println!("Error: Value is not valid UTF-8"),
                    },
                    Ok(None) => println!("Key1 not found"),
                    Err(e) => eprintln!("Failed to get key1: {:?}", e),
                }
            }
        }
    });

    task1.await.unwrap();
    task2.await.unwrap();

    Ok(())
}

#[tokio::test]
async fn export_import() -> anyhow::Result<()> {
    let _network = FDBNetwork::new();
    let pool = Arc::new(create_fdb_pool(10));

    export_to_json("/", Arc::clone(&pool), 100, "./backup.json")
        .await
        .unwrap();

    import_from_json("./backup.json", Arc::clone(&pool))
        .await
        .unwrap();

    Ok(())
}
