// use dashmap::{DashMap, Entry};
// use deadpool::managed::{Manager, Metrics, Pool, RecycleResult};
// use reqwest::{Client, Url};
// use std::time::Duration;

// #[derive(Debug)]
// pub struct ReqManager {
//     timeout: Duration,
// }

// impl ReqManager {
//     pub fn new(timeout: Duration) -> Self {
//         Self { timeout }
//     }
// }

// #[allow(clippy::manual_async_fn)]
// #[async_trait::async_trait]
// impl Manager for ReqManager {
//     type Type = Client;
//     type Error = reqwest::Error;

//     /// Creates a new instance of Manager::Type.
//     fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
//         async {
//             Client::builder()
//                 .timeout(self.timeout)
//                 .pool_idle_timeout(self.timeout)
//                 .build()
//         }
//     }

//     /// Tries to recycle an instance of Manager::Type.
//     ///
//     /// # Errors
//     ///
//     /// Returns Manager::Error if the instance couldn't be recycled.
//     fn recycle(
//         &self,
//         _obj: &mut Self::Type,
//         _metrics: &Metrics,
//     ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
//         async { Ok(()) }
//     }

//     /// Detaches an instance of Manager::Type from this Manager.
//     ///
//     /// This method is called when using the [`Object::take()`] method for
//     /// removing an [`Object`] from a [`Pool`]. If the [`Manager`] doesn't hold
//     /// any references to the handed out [`Object`]s then the default
//     /// implementation can be used which does nothing.
//     fn detach(&self, _obj: &mut Self::Type) {}
// }

// // Type alias for easier usage
// pub type HttpPool = Pool<ReqManager>;

// #[derive(Clone)]
// pub struct HttpReqPool {
//     timeout: Duration,
//     max_size: usize,
//     inner: DashMap<String, HttpPool>,
// }

// impl HttpReqPool {
//     pub fn new(timeout: Duration, max_size: usize) -> Self {
//         Self {
//             timeout,
//             max_size,
//             inner: DashMap::new(),
//         }
//     }

//     pub fn get_for_url_str(&self, url: &str) -> anyhow::Result<HttpPool> {
//         match self.inner.entry(url.to_owned()) {
//             Entry::Occupied(e) => Ok(e.get().clone()),
//             Entry::Vacant(e) => {
//                 let mgr = ReqManager::new(self.timeout);
//                 let pool = Pool::builder(mgr)
//                     .max_size(self.max_size)
//                     .build()
//                     .map_err(|e| anyhow::anyhow!("Failed to build HttpReqPool: {}", e))?;
//                 e.insert(pool.clone());
//                 Ok(pool)
//             }
//         }
//     }

//     pub fn get_for_url(&self, url: Url) -> anyhow::Result<HttpPool> {
//         let key = match url.host_str() {
//             Some(h) => {
//                 if let Some(port) = url.port() {
//                     format!("{}:{}", h, port)
//                 } else {
//                     h.to_string()
//                 }
//             }
//             None => anyhow::bail!("URL has no host"),
//         };
//         self.get_for_url_str(&key)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_pool() -> anyhow::Result<()> {
//         use rayon::prelude::*;
//         use std::sync::Arc;
//         use std::time::Instant;
//         use url::Url;

//         let pool = HttpReqPool::new(Duration::from_secs(5), 10);
//         let url = Url::parse("https://www.rust-lang.org")?;
//         let pool = Arc::new(pool);
//         let url = Arc::new(url);

//         let iterations = 10;
//         let start = Instant::now();

//         tokio::task::spawn_blocking({
//             let pool = pool.clone();
//             let url = url.clone();

//             move || {
//                 (0..iterations).into_par_iter().for_each(|i| {
//                     let url = url.clone();
//                     let pool = pool.clone();

//                     // Use local runtime per thread (but avoid dropping in async context)
//                     let rt = tokio::runtime::Builder::new_current_thread()
//                         .enable_all()
//                         .build()
//                         .map_err(|e| {
//                             eprintln!("Failed to build runtime: {}", e);
//                             e
//                         })
//                         .unwrap_or_else(|e| panic!("Runtime creation failed: {}", e));

//                     rt.block_on(async {
//                         let client_pool = match pool.get_for_url((*url).clone()) {
//                             Ok(pool) => pool,
//                             Err(err) => {
//                                 eprintln!("[{}] Failed to get client pool: {}", i, err);
//                                 return;
//                             }
//                         };
//                         let client = match client_pool.get().await {
//                             Ok(client) => client,
//                             Err(err) => {
//                                 eprintln!("[{}] Failed to get client: {}", i, err);
//                                 return;
//                             }
//                         };
//                         let res = client
//                             .get((&*url).clone())
//                             .header("Accept-Encoding", "br")
//                             .send()
//                             .await;

//                         match res {
//                             Ok(resp) => println!("[{}] Status: {}", i, resp.status()),
//                             Err(err) => eprintln!("[{}] Error: {}", i, err),
//                         }
//                     });
//                 });
//             }
//         })
//         .await?;

//         let elapsed = start.elapsed();
//         println!("Completed {} requests in {:.2?}", iterations, elapsed);
//         Ok(())
//     }
// }
