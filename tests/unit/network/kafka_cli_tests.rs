use super::*;
use rdkafka::mocking::MockCluster;

fn settings(brokers: String) -> KafkaSettings {
    KafkaSettings {
        brokers,
        auto_offset_reset: "earliest".into(),
        ..Default::default()
    }
}

#[cfg(all(
    any(feature = "rt-tokio", feature = "rt-glommio"),
    not(feature = "rt-may")
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_message_is_retried_before_later_offsets() {
    let cluster = MockCluster::new(1).unwrap();
    cluster.create_topic("retry", 1, 1).unwrap();
    let cfg = settings(cluster.bootstrap_servers());
    let producer = KafkaAsyncProducer::new(cfg.clone()).unwrap();
    producer.send("retry", "key", b"first").await.unwrap();
    producer.send("retry", "key", b"second").await.unwrap();
    let consumer = KafkaAsyncConsumer::new(cfg).unwrap();
    let cancel = CancellationToken::new();
    let mut seen = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(20),
        consumer.run("retry", cancel.clone(), |payload| {
            seen.push(payload.clone());
            let result = if seen.len() == 1 {
                Err("temporary failure".into())
            } else {
                Ok(())
            };
            if payload == b"second" {
                cancel.cancel();
            }
            std::future::ready(result)
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        seen,
        vec![b"first".to_vec(), b"first".to_vec(), b"second".to_vec()]
    );
}

#[cfg(feature = "rt-may")]
#[test]
fn failed_message_is_retried_before_later_offsets() {
    let cluster = MockCluster::new(1).unwrap();
    cluster.create_topic("retry", 1, 1).unwrap();
    let cfg = settings(cluster.bootstrap_servers());
    let producer = KafkaProducer::new(cfg.clone()).unwrap();
    producer.send("retry", "key", b"first").unwrap();
    producer.send("retry", "key", b"second").unwrap();
    producer.flush().unwrap();
    let consumer = KafkaConsumer::new(cfg).unwrap();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut seen = Vec::new();
    consumer
        .run(
            "retry",
            Duration::from_millis(100),
            cancel.clone(),
            move |payload| {
                seen.push(payload.clone());
                if seen.len() == 1 {
                    return Err("temporary failure".into());
                }
                if payload == b"second" {
                    tx.send(seen.clone()).unwrap();
                    stop.cancel();
                }
                Ok(())
            },
        )
        .unwrap();
    let result = rx.recv_timeout(Duration::from_secs(20));
    cancel.cancel();
    assert_eq!(
        result.unwrap(),
        vec![b"first".to_vec(), b"first".to_vec(), b"second".to_vec()]
    );
}
