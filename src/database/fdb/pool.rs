use crate::database::fdb::db::FDB;
use may::sync::mpsc::{Receiver, Sender, channel};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct FDBPool {
    sender: Sender<FDB>,
    receiver: Arc<Receiver<FDB>>,
}

impl FDBPool {
    pub fn new(cluster_path: String, pool_size: usize) -> std::io::Result<Self> {
        let (sender, receiver) = channel::<FDB>();

        for _ in 0..pool_size {
            let conn = FDB::new(&cluster_path)?;
            sender.send(conn).unwrap();
        }

        Ok(Self {
            sender,
            receiver: Arc::new(receiver),
        })
    }

    fn get(&self, timeout: Duration) -> std::io::Result<FDB> {
        let mut res = Err(std::io::Error::other("Failed to get FDB connection"));
        let receiver = self.receiver.clone();
        let _ = may::select! {
            conn = receiver.recv() => {
                res = conn.map_err(std::io::Error::other);
            },
            _ = may::coroutine::sleep(timeout) => {
                res = Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timeout while getting free FDB connection from pool",
                ));
            }
        };
        res
    }

    fn put(&self, conn: FDB) -> std::io::Result<()> {
        self.sender.send(conn).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to return FDB connection back to the pool: {}",
                e
            ))
        })
    }

    pub fn with_conn<F, R>(&self, timeout: Duration, f: F) -> std::io::Result<R>
    where
        F: FnOnce(&FDB) -> R,
    {
        let conn = self.get(timeout)?;
        let result = f(&conn);
        self.put(conn)?;
        Ok(result)
    }

    pub fn with_conn_mut<F, R>(&self, timeout: Duration, f: F) -> std::io::Result<R>
    where
        F: FnOnce(&mut FDB) -> R,
    {
        let mut conn = self.get(timeout)?;
        let result = f(&mut conn);
        self.put(conn)?;
        Ok(result)
    }
}

// fn next_prefix(prefix: &[u8]) -> Vec<u8> {
//     let mut next = prefix.to_vec();
//     for i in (0..next.len()).rev() {
//         if next[i] < 0xFF {
//             next[i] += 1;
//             next.truncate(i + 1);
//             return next;
//         }
//     }
//     vec![0xFF; prefix.len() + 1]
// }

// pub fn export(
//         prefix: &bytes::Bytes,
//         pool: &FDBPool,
//         offset: usize,
//         limit: usize,
//         reverse: bool,
//         snapshot: bool,
//         timeout: Duration,
//     ) -> std::io::Result<Map<String, Value>> {
//         use super::trans::*;

//         let mut data = Map::new();
//         let mut skipped = 0;
//         let mut collected = 0;
//         let batch_size = 1000;

//         let mut begin_key = prefix.as_ref().to_vec();
//         let end_key = Self::next_prefix(prefix);

//         loop {
//             let result = pool.with_conn(timeout, |db| {
//                 let trx = FDBTransaction::new(db)?;

//                 let range = FDBRange {
//                     begin_key: &begin_key,
//                     begin_or_equal: true,
//                     begin_offset: 0,
//                     end_key: &end_key,
//                     end_or_equal: false,
//                     end_offset: 0,
//                     limit: batch_size as i32,
//                     target_bytes: 0,
//                     mode: super::trans::FDBStreamingMode::WantAll,
//                     iteration: 0,
//                     reverse,
//                 };

//                 let future = trx.get_range(&range, snapshot)?;
//                 future.block_until_ready();

//                 // decode the value here
//                 let kvs_bytes = future.get_value()?;
//                 // You need to decode the returned value here as FDB returns raw bytes.
//                 // Assume kvs_bytes contains length-prefixed tuples (you might need a parser for it)

//                 let mut cursor = &kvs_bytes[..];
//                 let mut local_data = Map::new();

//                 while !cursor.is_empty() && collected < limit {
//                     // You should replace this with proper decoding depending on how kvs_bytes is structured
//                     // This is a placeholder for the format (length-prefixed key + length-prefixed value)
//                     let (key, value): (Vec<u8>, Vec<u8>) = match decode_kv(&mut cursor) {
//                         Some(kv) => kv,
//                         None => break,
//                     };

//                     if skipped < offset {
//                         skipped += 1;
//                         continue;
//                     }

//                     let key_str = String::from_utf8_lossy(&key).to_string();
//                     let val = match serde_json::from_slice::<Value>(&value) {
//                         Ok(json) => json,
//                         Err(_) => Value::String(BASE64_STANDARD.encode(&value)),
//                     };

//                     local_data.insert(key_str, val);
//                     collected += 1;
//                 }

//                 Ok(local_data)
//             });

//             match result {
//                 Ok(batch_data) => {
//                     if batch_data.is_empty() {
//                         break;
//                     }
//                     begin_key = batch_data.keys().last().unwrap().as_bytes().to_vec();
//                     begin_key.push(0); // first_greater_than
//                     data.extend(batch_data);

//                     if collected >= limit {
//                         break;
//                     }
//                 }
//                 Err(e) => return Err(e),
//             }
//         }

//         Ok(data)
//     }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::fdb::network::FDBNetwork;
    use std::time::Duration;

    #[test]
    fn test_fdb_pool_basic_usage() {
        let network = FDBNetwork::new(None).expect("Failed to create FDB network");
        let mut network_for_stop = network.clone();

        let handle_network = std::thread::spawn(move || {
            network.run().expect("Failed to run FDB network");
        });

        // Give it time to start
        std::thread::sleep(std::time::Duration::from_secs(1));

        let cluster_path = if cfg!(target_os = "macos") {
            "/usr/local/etc/foundationdb/fdb.cluster"
        } else {
            "/etc/foundationdb/fdb.cluster"
        }
        .to_string();

        let pool = FDBPool::new(cluster_path.clone(), 2).expect("Failed to create pool");

        may::go!(move || {
            pool.with_conn(Duration::from_secs(1), |conn| {
                println!("Got FDB connection (immutable): {:?}", conn.db);
            })
            .expect("with_conn failed");

            pool.with_conn_mut(Duration::from_secs(1), |conn| {
                println!("Got FDB connection (mutable): {:?}", conn.db);
            })
            .expect("with_conn_mut failed");
        });

        // Give the coroutine time to run
        may::coroutine::sleep(Duration::from_millis(500));

        // Now stop it (separate lock)
        let result = network_for_stop.stop();
        assert!(result.is_ok(), "Failed to stop network");

        // Wait for background thread
        handle_network.join().unwrap();
    }

    #[test]
    fn test_fdb_pool_timeout() {
        let network = FDBNetwork::new(None).expect("Failed to create FDB network");
        let mut network_for_stop = network.clone();

        let handle_network = std::thread::spawn(move || {
            network.run().expect("Failed to run FDB network");
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        let cluster_path = if cfg!(target_os = "macos") {
            "/usr/local/etc/foundationdb/fdb.cluster"
        } else {
            "/etc/foundationdb/fdb.cluster"
        }
        .to_string();

        let pool = FDBPool::new(cluster_path.clone(), 1).expect("Failed to create pool");

        let pool_clone = pool.clone();
        let handle = may::go!(move || {
            let conn = pool_clone.get(Duration::from_secs(5)).unwrap();
            may::coroutine::sleep(Duration::from_secs(2)); // hold it
            pool_clone.put(conn).unwrap();
        });

        // All of this should happen inside a coroutine
        let pool_clone2 = pool.clone();
        may::go!(move || {
            let result = pool_clone2.get(Duration::from_millis(100));
            assert!(result.is_err(), "Expected timeout error");

            may::coroutine::sleep(Duration::from_secs(3));

            // Should now succeed
            let result = pool_clone2.get(Duration::from_secs(1));
            assert!(result.is_ok(), "Expected successful retry after wait");
        });

        // Let all coroutines finish
        may::coroutine::sleep(Duration::from_secs(5));
        handle.join().unwrap();

        let result = network_for_stop.stop();
        assert!(result.is_ok(), "Failed to stop network");
        handle_network.join().unwrap();
    }
}
