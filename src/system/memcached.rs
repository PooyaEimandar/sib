use async_trait::async_trait;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use memcache::{Client, MemcacheError};

// Manager for Memcached connections
pub struct MemcachedManager {
    server_url: String,
}

#[allow(clippy::manual_async_fn)]
#[async_trait]
impl Manager for MemcachedManager {
    type Type = memcache::Client;
    type Error = RecycleError<MemcacheError>;

    /// Creates a new instance of [`Manager::Type`].
    fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
        async { Client::connect(self.server_url.clone()).map_err(RecycleError::Backend) }
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
type MemcachedPool = Pool<MemcachedManager>;

pub fn create_memcached_pool(server_url: &str, pool_size: usize) -> MemcachedPool {
    let manager = MemcachedManager {
        server_url: server_url.to_string(),
    };
    Pool::builder(manager).max_size(pool_size).build().unwrap()
}

// Wrapper for Memcached operations using the pooled client
pub struct MemcachedConnection {
    client: Client,
}

impl MemcachedConnection {
    pub async fn set(&self, key: &str, value: &str, expiration: u32) -> anyhow::Result<()> {
        self.client
            .set(key, value, expiration)
            .map_err(anyhow::Error::msg)
    }

    pub async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.client.get(key).map_err(anyhow::Error::msg)
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete(key)
            .map(|_| ())
            .map_err(anyhow::Error::msg)
    }
}

#[tokio::test]
async fn test() -> anyhow::Result<()> {
    // Create Memcached connection pool
    let pool = create_memcached_pool("memcache://127.0.0.1:11211", 10);

    // Get a connection from the pool
    let client = pool.get().await.unwrap();
    println!("Got a connection");

    // Set a key
    client.set("key1", "value1", 60)?;
    println!("Set key1");

    // Fetch the key
    let value: Option<String> = client.get("key1")?;
    println!("Fetched key1: {:?}", value);

    // Delete the key
    client.delete("key1")?;

    Ok(())
}
