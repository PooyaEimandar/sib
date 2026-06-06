use super::*;
use std::num::NonZeroU64;

pub fn default_fdb_cluster_path() -> String {
    // OS defaults
    #[cfg(target_os = "macos")]
    {
        "/usr/local/etc/foundationdb/fdb.cluster".to_owned()
    }
    #[cfg(target_os = "linux")]
    {
        "/etc/foundationdb/fdb.cluster".to_owned()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "".to_owned()
    }
}

fn fdb_cluster_available() -> bool {
    let path = default_fdb_cluster_path();
    !path.is_empty() && std::path::Path::new(&path).exists()
}

#[test]
fn test_fdb_pool_acquire_and_release() {
    // pool of 3 integers initialized to 10, 20, 30
    let pool = Pool::new_with(NonZeroU64::new(3).unwrap(), |i| Ok((i as u32 + 1) * 10)).unwrap();

    // take all three
    let l1 = pool.try_acquire().expect("slot 1");
    let l2 = pool.try_acquire().expect("slot 2");
    let l3 = pool.try_acquire().expect("slot 3");

    // now empty
    assert!(pool.try_acquire().is_none(), "pool should be empty");

    // drop one, should be able to acquire again
    drop(l2);
    let l4 = pool.try_acquire().expect("slot after release");
    // value must be one of the initial values
    let v = *l4;
    assert!([10, 20, 30].contains(&v));
    drop(l1);
    drop(l3);
    drop(l4);

    // After returning all, we can acquire 3 again
    let _a = pool.try_acquire().unwrap();
    let _b = pool.try_acquire().unwrap();
    let _c = pool.try_acquire().unwrap();
    assert!(pool.try_acquire().is_none());
}

#[test]
fn test_zero_copy_mutation() {
    #[derive(Debug, Clone, Copy)]
    struct Item(u64);

    let pool = Pool::new_with(NonZeroU64::new(2).unwrap(), |_i| Ok(Item(0))).unwrap();

    // Acquire both, mutate through &mut Loan to ensure zero-copy uniqueness works.
    let mut a = pool.try_acquire().expect("a");
    let mut b = pool.try_acquire().expect("b");

    a.0 += 5;
    b.0 += 7;
    assert_eq!(a.0, 5);
    assert_eq!(b.0, 7);

    // Release both and reacquire to verify persisted mutation in-place.
    drop(a);
    drop(b);

    // Drain pool and sum values regardless of order.
    let x = pool.try_acquire().unwrap().0;
    let y = pool.try_acquire().unwrap().0;
    assert_eq!(x + y, 12, "mutations must persist in the same slots");
}

#[cfg(feature = "rt-may")]
#[test]
fn test_fdb_pool_concurrent_acquire_and_increment() {
    #[derive(Default)]
    struct Counter {
        hits: u64,
    }

    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 1 * 1024 * 1024);

    let pool = std::sync::Arc::new(
        Pool::new_with(NonZeroU64::new(3).unwrap(), |_i| Ok(Counter::default())).unwrap(),
    );

    // Spawn 30 coroutines; each increments once.
    let jobs = 30usize;
    let mut hs = Vec::new();
    for _ in 0..jobs {
        let pool = pool.clone();
        hs.push(unsafe {
            may::coroutine::spawn(move || {
                // SAFETY: The pool's free-list protocol guarantees unique access.
                let mut loan = pool
                    .acquire_blocking(Duration::from_millis(200))
                    .expect("acquire");
                loan.hits += 1;
                // drop -> return to freelist
            })
        });
    }
    for h in hs {
        h.join().unwrap();
    }

    // Drain and sum
    let mut total = 0u64;
    for _ in 0..3 {
        let l = pool.try_acquire().expect("slot back after tasks");
        total += l.hits;
    }
    assert_eq!(total, jobs as u64);
}

#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn test_fdb_pool_concurrent_acquire_and_increment() {
    // Each slot holds a small counter struct.
    #[derive(Default)]
    struct Counter {
        hits: u64,
    }

    let pool = std::sync::Arc::new(
        Pool::new_with(NonZeroU64::new(4).unwrap(), |_i| Ok(Counter::default())).unwrap(),
    );

    // 64 tasks, each acquires a slot, increments the counter once, and releases.
    let tasks = 64usize;
    let mut joins = Vec::new();
    for _ in 0..tasks {
        let p = pool.clone();
        joins.push(tokio::spawn(async move {
            let mut loan = p
                .acquire(Duration::from_millis(200))
                .await
                .expect("acquire should succeed");
            loan.hits += 1;
        }));
    }
    for j in joins {
        j.await.unwrap();
    }

    // Drain all 4 slots and sum their hits; should equal 64.
    let mut total = 0u64;
    for _ in 0..4 {
        let l = pool.try_acquire().expect("slot back after tasks");
        total += l.hits;
    }
    assert_eq!(total, 64);
}

#[cfg(feature = "rt-may")]
#[test]
fn test_fdb_pool_timeout_when_all_held() {
    const TIME: Duration = Duration::from_millis(5);
    const NUMBER_OF_WORKERS: usize = 1;
    crate::init_global_poller(NUMBER_OF_WORKERS, 1 * 1024 * 1024);

    let pool = Pool::new_with(NonZeroU64::new(1).unwrap(), |_| Ok(123u32)).unwrap();

    // keep the guard alive so the single slot stays held
    let _guard = pool.try_acquire().expect("first acquire");

    let start = std::time::Instant::now();
    let res = pool.acquire_blocking(TIME);

    assert!(res.is_err(), "expected timeout");
    assert!(start.elapsed() >= TIME);
}

#[cfg(feature = "rt-tokio")]
#[tokio::test]
async fn test_fdb_pool_timeout_when_all_held() {
    use std::time::Instant;
    // Pool of size 1; hold it and try to acquire with a short timeout.
    let pool = Pool::new_with(NonZeroU64::new(1).unwrap(), |_| Ok(())).unwrap();

    let loan = pool.try_acquire().expect("first acquire");
    let start = Instant::now();

    let res = pool.acquire(Duration::from_millis(50)).await;
    assert!(res.is_err(), "should time out");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(45),
        "timeout should approximate requested duration"
    );

    drop(loan);
}

#[test]
fn test_fdb_run_transaction_set_and_get() {
    if !fdb_cluster_available() {
        return;
    }

    use crate::database::fdb::trans::FDBTransaction;

    let fdb_guard = crate::fdb_network_start!();

    // give it time to start
    std::thread::sleep(Duration::from_secs(1));

    let cluster_path = default_fdb_cluster_path();
    let pool = FDBPool::new(cluster_path, NonZeroU64::new(1).unwrap()).expect("create pool");

    let lease = pool.try_loan().expect("acquire");
    let key = b"key1";
    let value = b"hello";

    {
        // set
        let tr = FDBTransaction::new(&*lease).expect("new transaction failed");
        tr.set(key, value);
        tr.commit_blocking().expect("commit failed");
    }

    {
        // get
        let tr = FDBTransaction::new(&*lease).expect("new transaction failed");
        let fut: crate::database::fdb::future::FDBFuture = tr.get(key, false).unwrap();
        fut.block_until_ready();
        let result = fut.get_value().expect("get failed");
        assert_eq!(result.iter().as_slice(), value.as_slice(), "value mismatch");
    }

    // Now stop FDB network
    crate::fdb_network_stop!(fdb_guard);
}

#[test]
fn test_fdb_run_transaction_set_and_get_with_run() {
    if !fdb_cluster_available() {
        return;
    }

    let fdb_guard = crate::fdb_network_start!();

    // give it time to start
    std::thread::sleep(Duration::from_secs(1));

    let cluster_path = default_fdb_cluster_path();
    let pool = FDBPool::new(cluster_path, NonZeroU64::new(1).unwrap()).expect("create pool");

    let lease = pool.try_loan().expect("acquire");
    let key = b"key2";
    let value = b"hello";

    // set
    crate::database::fdb::trans::run(&*lease, |tr| {
        tr.set(key, value);
        Ok(crate::database::fdb::trans::FDBTransactionOutcome::Ok(()))
    })
    .expect("commit failed");

    // get
    crate::database::fdb::trans::run(&*lease, |tr| {
        tr.get_blocking_value_optional(key, false)
            .and_then(|res_opt| {
                let res = res_opt.expect("key missing");
                assert_eq!(res.iter().as_slice(), value.as_slice(), "value mismatch");
                Ok(crate::database::fdb::trans::FDBTransactionOutcome::Ok(()))
            })
    })
    .expect("commit failed");

    // Now stop FDB network
    crate::fdb_network_stop!(fdb_guard);
}

#[test]
fn test_fdb_run_transaction_retries_on_conflict_increment() {
    if !fdb_cluster_available() {
        return;
    }

    use crate::database::fdb::pool::FDBPool;
    use crate::database::fdb::trans::{self, FDBTransactionOutcome};

    use std::num::NonZeroU64;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    let fdb_guard = crate::fdb_network_start!();

    // give it time to start
    thread::sleep(Duration::from_secs(1));

    // Pool must allow 2 concurrent leases for the two threads
    let cluster_path = default_fdb_cluster_path();
    let pool =
        Arc::new(FDBPool::new(cluster_path, NonZeroU64::new(2).unwrap()).expect("create pool"));

    // Use a unique key so parallel test runs don’t collide
    let key = "conflict_inc".to_owned()
        + &format!(
            "_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

    // Initialize key = "0"
    {
        let lease = pool.try_loan().expect("acquire init lease");
        trans::run(&*lease, |tr| {
            tr.set(key.as_bytes(), b"0");
            Ok(FDBTransactionOutcome::Ok(()))
        })
        .expect("init commit failed");
    }

    let attempts_a = Arc::new(AtomicUsize::new(0));
    let attempts_b = Arc::new(AtomicUsize::new(0));

    // Thread A
    let pool_a = Arc::clone(&pool);
    let key_a = key.clone();
    let a_ctr = Arc::clone(&attempts_a);
    let t1 = thread::spawn(move || {
        let lease = pool_a.try_loan().expect("acquire lease A");
        trans::run(&*lease, |tr| {
            a_ctr.fetch_add(1, Ordering::Relaxed);

            // Read-modify-write (conflicts with other thread)
            let cur = tr
                .get_blocking_value_optional(key_a.as_bytes(), false)?
                .unwrap_or_else(|| b"0".to_vec());

            // Force overlap so both transactions likely read before either commits
            thread::sleep(Duration::from_millis(50));

            let n = std::str::from_utf8(&cur).unwrap().parse::<u64>().unwrap();
            let next = (n + 1).to_string();
            tr.set(key_a.as_bytes(), next.as_bytes());

            Ok(FDBTransactionOutcome::Ok(()))
        })
    });

    // Thread B
    let pool_b = Arc::clone(&pool);
    let key_b = key.clone();
    let b_ctr = Arc::clone(&attempts_b);
    let t2 = thread::spawn(move || {
        let lease = pool_b.try_loan().expect("acquire lease B");
        trans::run(&*lease, |tr| {
            b_ctr.fetch_add(1, Ordering::Relaxed);

            let cur = tr
                .get_blocking_value_optional(key_b.as_bytes(), false)?
                .unwrap_or_else(|| b"0".to_vec());

            thread::sleep(Duration::from_millis(50));

            let n = std::str::from_utf8(&cur).unwrap().parse::<u64>().unwrap();
            let next = (n + 1).to_string();
            tr.set(key_b.as_bytes(), next.as_bytes());

            Ok(FDBTransactionOutcome::Ok(()))
        })
    });

    t1.join().unwrap().expect("thread 1 failed");
    t2.join().unwrap().expect("thread 2 failed");

    // Final value must be 2 if both increments committed (with retries)
    {
        let lease = pool.try_loan().expect("acquire final lease");
        trans::run(&*lease, |tr| {
            let final_val = tr
                .get_blocking_value_optional(key.as_bytes(), false)?
                .expect("key missing");

            let n = std::str::from_utf8(final_val.as_slice())
                .unwrap()
                .parse::<u64>()
                .unwrap();

            assert_eq!(n, 2, "final value mismatch");
            Ok(FDBTransactionOutcome::Ok(()))
        })
        .expect("final read commit failed");
    }

    eprintln!(
        "attempts: a={}, b={}",
        attempts_a.load(Ordering::Relaxed),
        attempts_b.load(Ordering::Relaxed),
    );

    // Stop FDB network
    crate::fdb_network_stop!(fdb_guard);
}

#[test]
fn test_fdb_run_transaction_retry_branch_is_executed() {
    if !fdb_cluster_available() {
        return;
    }

    use crate::database::fdb::pool::FDBPool;
    use crate::database::fdb::trans::{self, FDBTransactionOutcome};
    use std::num::NonZeroU64;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    // Start FDB network
    let fdb_guard = crate::fdb_network_start!();

    std::thread::sleep(Duration::from_secs(1));

    let cluster_path = default_fdb_cluster_path();
    let pool = FDBPool::new(cluster_path, NonZeroU64::new(1).unwrap()).expect("create pool");
    let lease = pool.try_loan().expect("acquire");

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_cl = Arc::clone(&calls);

    // choose a retryable FDB error code
    const RETRYABLE_CODE: i32 = 1020; // not_committed (commonly retryable)

    let key = "retry_test_key";
    let value = b"ok";

    // Run: first attempt returns Retry, second attempt does the write and commits.
    let res = trans::run(&*lease, move |tr| {
        let n = calls_cl.fetch_add(1, Ordering::SeqCst);

        if n == 0 {
            // Force the Retry branch
            return Ok(FDBTransactionOutcome::Retry(RETRYABLE_CODE));
        }

        tr.set(key.as_bytes(), value);
        Ok(FDBTransactionOutcome::Ok(()))
    });

    assert!(res.is_ok(), "run() should succeed after retry");
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "closure should be invoked at least twice (retry path)"
    );

    // Verify the write landed
    trans::run(&*lease, |tr| {
        let got = tr
            .get_blocking_value_optional(key.as_bytes(), false)?
            .expect("key missing");
        assert_eq!(got.as_slice(), value);
        Ok(FDBTransactionOutcome::Ok(()))
    })
    .expect("verify commit failed");

    // Stop network
    crate::fdb_network_stop!(fdb_guard);
}
