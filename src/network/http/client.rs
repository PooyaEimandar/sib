use dashmap::DashMap;
use deadpool::managed::{Manager, Metrics, Pool, RecycleResult};
use reqwest::{Client, Url};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
pub struct ReqManager {
    timeout: Duration,
}

impl ReqManager {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait::async_trait]
impl Manager for ReqManager {
    type Type = Client;
    type Error = reqwest::Error;

    /// Creates a new instance of Manager::Type.
    fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
        async {
            Client::builder()
                .timeout(self.timeout)
                .pool_idle_timeout(self.timeout)
                .build()
        }
    }

    /// Tries to recycle an instance of Manager::Type.
    ///
    /// # Errors
    ///
    /// Returns Manager::Error if the instance couldn't be recycled.
    fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Detaches an instance of Manager::Type from this Manager.
    ///
    /// This method is called when using the [`Object::take()`] method for
    /// removing an [`Object`] from a [`Pool`]. If the [`Manager`] doesn't hold
    /// any references to the handed out [`Object`]s then the default
    /// implementation can be used which does nothing.
    fn detach(&self, _obj: &mut Self::Type) {}
}

#[derive(Clone)]
pub struct HttpReqPool {
    timeout: Duration,
    max_size: usize,
    inner: Arc<DashMap<Url, Arc<Pool<ReqManager>>>>,
}

impl HttpReqPool {
    pub fn new(timeout: Duration, max_size: usize) -> Self {
        Self {
            timeout,
            max_size,
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn get_for_url(&self, url: Url) -> anyhow::Result<Arc<Pool<ReqManager>>> {
        if let Some(existing) = self.inner.get(&url) {
            return Ok(existing.clone());
        }

        let mgr = ReqManager::new(self.timeout);
        let pool = Pool::builder(mgr)
            .max_size(self.max_size)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HttpReqPool: {}", e))?;

        let arc_pool = Arc::new(pool);
        self.inner.insert(url, arc_pool.clone());
        Ok(arc_pool)
    }
}
