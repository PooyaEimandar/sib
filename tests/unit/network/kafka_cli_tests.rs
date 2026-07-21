use super::*;
use std::{sync::mpsc, time::Duration};
use tokio_util::sync::CancellationToken;

static TOPIC: &str = "";
static KEY_NAME: &str = "k1";
static PAYLOAD: &[u8] = b"hello-world";

fn tls_settings(group_id: &str) -> KafkaSettings {
    KafkaSettings {
        brokers: "localhost:9093".into(),
        group_id: group_id.into(),
        auto_offset_reset: "earliest".into(),
        timeout: Duration::from_secs(10),
        tls_ca: Some(chain),
        tls_cert: Some(cert),
        tls_key: Some(key),
        tls_key_password: None,
        tls_verify: true,
        tls_verify_hostname: false,
    }
}

// rt-may
#[cfg(feature = "rt-may")]
#[test]
fn kafka_cli_may_pub_sub() -> std::io::Result<()> {
    const NUMBER_OF_WORKERS: usize = 2;
    const STACK_SIZE: usize = 1024 * 1024;
    crate::init_global_poller(NUMBER_OF_WORKERS, STACK_SIZE);

    let settings = tls_settings("topic-test");
    let producer = KafkaProducer::new(settings.clone())?;
    let consumer = KafkaConsumer::new(settings)?;

    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    // Consumer thread
    let cancel_c = cancel.clone();
    let consumer_thread = std::thread::spawn({
        let consumer = consumer.clone();
        move || {
            // run() spawns a may coroutine and returns immediately
            consumer
                .run(
                    TOPIC,
                    Duration::from_millis(200),
                    cancel_c.clone(),
                    move |msg| {
                        tx.send(msg).map_err(|e| e.to_string())?;
                        Ok(())
                    },
                )
                .map_err(|e| format!("consumer.run failed: {e}"))?;

            // keep OS thread alive until cancelled so may coroutine can poll
            while !cancel_c.is_cancelled() {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok::<(), String>(())
        }
    });

    // Ensure consumer subscribed before producing
    std::thread::sleep(Duration::from_millis(400));

    producer.topic_ready(TOPIC, Duration::from_secs(5))?;

    // Producer thread
    let producer_thread = std::thread::spawn({
        let producer = producer.clone();
        move || -> Result<(), String> {
            producer.send(TOPIC, KEY_NAME, PAYLOAD)?;
            producer.flush().map_err(|e| e.to_string())?;
            Ok(())
        }
    });

    producer_thread
        .join()
        .map_err(|_| std::io::Error::other("producer thread panicked"))?
        .map_err(std::io::Error::other)?;

    let got = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| std::io::Error::other(format!("did not receive message in time: {e}")))?;

    cancel.cancel();

    consumer_thread
        .join()
        .map_err(|_| std::io::Error::other("consumer thread panicked"))?
        .map_err(std::io::Error::other)?;

    assert_eq!(got, PAYLOAD);
    Ok(())
}

// rt-tokio / rt-glommio (FutureProducer/StreamConsumer) TLS test
#[cfg(any(feature = "rt-tokio", feature = "rt-glommio"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_cli_tokio_pub_sub() -> std::io::Result<()> {
    let settings = tls_settings("topic-test");

    let producer = KafkaAsyncProducer::new(settings.clone())?;
    let consumer = KafkaAsyncConsumer::new(settings)?;

    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    // Consumer task (async)
    let cancel_c = cancel.clone();
    let consumer_task = tokio::spawn({
        let consumer = consumer.clone();
        async move {
            consumer
                .run(TOPIC, cancel_c.clone(), move |msg| {
                    let tx = tx.clone();
                    async move {
                        tx.send(msg).map_err(|e| e.to_string())?;
                        Ok(())
                    }
                })
                .await
        }
    });

    // Give consumer time to subscribe
    tokio::time::sleep(Duration::from_millis(400)).await;

    producer.topic_ready(TOPIC, Duration::from_secs(5))?;

    let producer_task = tokio::spawn({
        let producer = producer.clone();
        async move {
            producer.send(TOPIC, KEY_NAME, PAYLOAD).await?;
            producer.flush()?;
            Ok::<(), std::io::Error>(())
        }
    });
    producer_task.await??;

    let got = tokio::task::spawn_blocking(move || {
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|e| std::io::Error::other(format!("did not receive message in time: {e}")))
    })
    .await??;

    cancel.cancel();
    consumer_task
        .await
        .map_err(|e| std::io::Error::other(format!("consumer task panicked: {e}")))?
        .map_err(std::io::Error::other)?;

    assert_eq!(got, PAYLOAD);
    Ok(())
}
