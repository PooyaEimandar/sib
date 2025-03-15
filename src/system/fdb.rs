use anyhow::Result;
use async_trait::async_trait;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use foundationdb::{Database, Transaction, options::TransactionOption};
use std::sync::Arc;

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
    pub async fn get(&self, key: &[u8]) -> Result<Option<Arc<[u8]>>> {
        self.trx
            .get(key, false)
            .await
            .map(|opt| opt.map(|slice| Arc::from(slice.as_ref())))
            .map_err(anyhow::Error::msg)
    }

    pub fn set(&self, key: &[u8], value: &[u8]) {
        self.trx.set(key, value);
    }

    pub fn set_option(&self, option: TransactionOption) -> Result<()> {
        self.trx.set_option(option).map_err(anyhow::Error::msg)
    }

    pub async fn commit(self) -> Result<foundationdb::TransactionCommitted> {
        self.trx.commit().await.map_err(anyhow::Error::msg)
    }

    pub async fn watch(&self, key: &[u8]) -> Result<()> {
        self.trx.watch(key).await.map_err(anyhow::Error::msg)
    }
}

#[tokio::test]
async fn test() -> Result<()> {
    let network = unsafe { foundationdb::boot() };

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

    drop(network);
    Ok(())
}
