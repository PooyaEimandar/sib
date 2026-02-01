use rdkafka::{
    Message,
    config::ClientConfig,
    consumer::{CommitMode, Consumer},
    producer::Producer,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::error;

#[derive(Clone, Debug)]
pub struct KafkaSettings {
    pub brokers: String,
    pub client_id: Option<String>,
    pub group_id: String,
    pub auto_offset_reset: String,             // "earliest" | "latest"
    pub partition_assignment_strategy: String, // "range" | "roundrobin" | "cooperative-sticky"
    pub timeout: Duration,
    pub buffering_max_ms: u32,

    // TLS
    pub tls_ca: Option<String>,   // path to CA (ca.crt)
    pub tls_cert: Option<String>, // client cert (optional if broker only authenticates server)
    pub tls_key: Option<String>,  // client key  (optional if broker only authenticates server)
    pub tls_key_password: Option<String>,
    pub tls_verify: bool,          // verify broker cert chain
    pub tls_verify_hostname: bool, // verify hostname/SAN match
}

impl Default for KafkaSettings {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".into(),
            client_id: None,
            group_id: "default-group".into(),
            auto_offset_reset: "latest".into(),
            partition_assignment_strategy: "cooperative-sticky".into(),
            timeout: Duration::from_secs(5),
            buffering_max_ms: 5,
            // TLS
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            tls_key_password: None,
            tls_verify: true,
            tls_verify_hostname: true,
        }
    }
}

fn base_client_config(cfg: &KafkaSettings) -> ClientConfig {
    let mut cc = ClientConfig::new();
    cc.set("bootstrap.servers", &cfg.brokers);

    if let Some(cid) = &cfg.client_id {
        cc.set("client.id", cid);
    }

    // TLS wiring
    if cfg.tls_ca.is_some() || cfg.tls_cert.is_some() || cfg.tls_key.is_some() {
        cc.set("security.protocol", "ssl");

        if let Some(ca) = &cfg.tls_ca {
            cc.set("ssl.ca.location", ca);
        }
        if let Some(cert) = &cfg.tls_cert {
            cc.set("ssl.certificate.location", cert);
        }
        if let Some(key) = &cfg.tls_key {
            cc.set("ssl.key.location", key);
        }
        if let Some(pw) = &cfg.tls_key_password {
            cc.set("ssl.key.password", pw);
        }

        // cc.set("debug", "broker,security,protocol");
        // cc.set("log.connection.close", "false");
        // cc.set("socket.timeout.ms", "10000");
        // cc.set("request.timeout.ms", "10000");

        // Verify broker cert chain
        cc.set(
            "enable.ssl.certificate.verification",
            if cfg.tls_verify { "true" } else { "false" },
        );

        // Verify hostname/SAN match
        cc.set(
            "ssl.endpoint.identification.algorithm",
            if cfg.tls_verify_hostname {
                "https"
            } else {
                "none"
            },
        );
    }

    cc
}

fn create_producer_client_config(cfg: &KafkaSettings) -> ClientConfig {
    let mut cc = base_client_config(cfg);
    cc.set("message.timeout.ms", &cfg.timeout.as_millis().to_string());
    cc.set("queue.buffering.max.ms", &cfg.buffering_max_ms.to_string());
    cc
}

fn create_consumer_client_config(cfg: &KafkaSettings) -> ClientConfig {
    let mut cc = base_client_config(cfg);
    cc.set("group.id", &cfg.group_id)
        .set("auto.offset.reset", &cfg.auto_offset_reset)
        .set(
            "partition.assignment.strategy",
            &cfg.partition_assignment_strategy,
        );
    cc
}

fn topic_ready_client<C>(
    client: &rdkafka::client::Client<C>,
    topic: &str,
    timeout: Duration,
) -> std::io::Result<()>
where
    C: rdkafka::ClientContext,
{
    use rdkafka::util::Timeout;

    let md = client
        .fetch_metadata(Some(topic), Timeout::After(timeout))
        .map_err(|e| std::io::Error::other(format!("metadata fetch failed: {e}")))?;

    let t = md
        .topics()
        .iter()
        .find(|t| t.name() == topic)
        .ok_or_else(|| std::io::Error::other("topic not present in metadata"))?;

    if let Some(err) = t.error() {
        return Err(std::io::Error::other(format!(
            "topic metadata error: {:?}",
            err
        )));
    }

    if t.partitions().is_empty() {
        return Err(std::io::Error::other("topic has no partitions"));
    }

    for p in t.partitions() {
        if let Some(perr) = p.error() {
            return Err(std::io::Error::other(format!(
                "partition {} metadata error: {:?}",
                p.id(),
                perr
            )));
        }
        if p.leader() < 0 {
            return Err(std::io::Error::other(format!(
                "partition {} has no leader",
                p.id()
            )));
        }
    }

    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(feature = "rt-may")] {
        use rdkafka::{consumer::BaseConsumer, producer::{BaseProducer, BaseRecord}};

        #[derive(Clone)]
        pub struct KafkaProducer {
            pub producer: Arc<BaseProducer>,
            pub settings: KafkaSettings,
        }

        impl KafkaProducer {
            pub fn new(settings: KafkaSettings) -> std::io::Result<Self> {
                let producer: BaseProducer = create_producer_client_config(&settings)
                    .create()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Kafka producer creation failed: {e}")))?;

                Ok(Self {
                    producer: Arc::new(producer),
                    settings,
                })
            }

            pub fn send(&self, topic: &str, key: &str, payload: &[u8]) -> Result<(), String> {
                let record = BaseRecord::to(topic).key(key).payload(payload);
                self.producer
                    .send(record)
                    .map_err(|(e, msg)| format!("Kafka producer enqueue error: {e}, {msg:?}"))
            }

            pub fn flush(&self) -> std::io::Result<()>  {
                use rdkafka::util::Timeout;
                self.producer
                    .flush(Timeout::After(self.settings.timeout))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Kafka producer flush error: {e}")))
            }

            pub fn topic_ready(&self, topic: &str, timeout: Duration) -> std::io::Result<()> {
                topic_ready_client(self.producer.client(), topic, timeout)
            }
        }

        #[derive(Clone)]
        pub struct KafkaConsumer {
            pub consumer: Arc<BaseConsumer>,
            pub settings: KafkaSettings,
        }

        impl KafkaConsumer {
            pub fn new(settings: KafkaSettings) -> std::io::Result<Self> {
                let consumer: BaseConsumer = create_consumer_client_config(&settings)
                    .create()
                    .map_err(|e| std::io::Error::other(format!("Kafka consumer creation failed: {e}")))?;

                Ok(Self {
                    consumer: Arc::new(consumer),
                    settings,
                })
            }

            pub fn topic_ready(&self, topic: &str, timeout: Duration) -> std::io::Result<()> {
                topic_ready_client(self.consumer.client(), topic, timeout)
            }

            pub fn run<F>(
                &self,
                topic: &str,
                timeout: Duration,
                cancel: CancellationToken,
                mut handler: F,
            ) -> std::io::Result<()>
            where
                F: FnMut(Vec<u8>) -> Result<(), String> + Send + 'static,
            {
                self.consumer
                    .subscribe(&[topic])
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("subscribe failed: {e}")))?;

                let consumer = Arc::clone(&self.consumer);

                may::go!(move || {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }
                        match consumer.poll(timeout) {
                            None => continue,
                            Some(Err(e)) => error!("KafkaConsumer got an error: {e}"),
                            Some(Ok(m)) => {
                                let payload = m.payload().unwrap_or(&[]).to_vec();
                                match handler(payload) {
                                    Ok(_) => {
                                        if let Err(e) = consumer.commit_message(&m, CommitMode::Async) {
                                            error!("KafkaConsumer commit error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        error!("KafkaConsumer handler git an error without committing: {e}");
                                    }
                                }
                            }
                        }
                    }
                });

                Ok(())
            }
        }

    } else if #[cfg(any(feature = "rt-glommio", feature = "rt-tokio"))] {

        use rdkafka::{consumer::StreamConsumer, producer::{FutureRecord, FutureProducer}};

        #[derive(Clone)]
        pub struct KafkaAsyncProducer {
            pub producer: Arc<FutureProducer>,
            pub settings: KafkaSettings,
        }

        impl KafkaAsyncProducer {
            pub fn new(settings: KafkaSettings) -> std::io::Result<Self> {
                let producer: FutureProducer = create_producer_client_config(&settings)
                    .create()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("KafkaAsyncProducer creation failed: {e}")))?;

                Ok(Self {
                    producer: Arc::new(producer),
                    settings,
                })
            }

            pub async fn send(&self, topic: &str, key: &str, payload: &[u8]) -> std::io::Result<()> {
                let record = FutureRecord::to(topic).key(key).payload(payload);

                self.producer
                    .send(record, self.settings.timeout)
                    .await
                    .map(|_delivery| ()) // success
                    .map_err(|(e, msg)| {
                        std::io::Error::other(
                            format!("KafkaAsyncProducer delivery failed: {e}, {msg:?}"),
                        )
                    })
            }

            pub fn flush(&self) -> std::io::Result<()>  {
                use rdkafka::util::Timeout;
                self.producer
                    .flush(Timeout::After(self.settings.timeout))
                    .map_err(|e| std::io::Error::other(format!("KafkaAsyncProducer flush error: {e}")))
            }

            pub fn topic_ready(&self, topic: &str, timeout: Duration) -> std::io::Result<()> {
                topic_ready_client(self.producer.client(), topic, timeout)
            }
        }

        #[derive(Clone)]
        pub struct KafkaAsyncConsumer {
            pub consumer: Arc<StreamConsumer>,
            pub settings: KafkaSettings,
        }

        impl KafkaAsyncConsumer {
            pub fn new(settings: KafkaSettings) -> std::io::Result<Self> {
                let consumer: StreamConsumer = create_consumer_client_config(&settings)
                    .create()
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("KafkaAsyncConsumer creation failed: {e}"),
                        )
                    })?;

                Ok(Self {
                    consumer: Arc::new(consumer),
                    settings,
                })
            }

            pub fn topic_ready(&self, topic: &str, timeout: Duration) -> std::io::Result<()> {
                topic_ready_client(self.consumer.client(), topic, timeout)
            }

            pub async fn run<F, Fut>(&self, topic: &str, cancel: CancellationToken, mut handler: F) -> Result<(), String>
            where
                F: FnMut(Vec<u8>) -> Fut + Send,
                Fut: std::future::Future<Output = Result<(), String>> + Send,
            {
                use futures_lite::StreamExt;

                self.consumer
                    .subscribe(&[topic])
                    .map_err(|e| format!("subscribe failed: {e}"))?;

                let mut stream = self.consumer.stream();

                loop {
                    // Wait for either: next kafka message OR cancellation
                    let next_msg = futures_lite::future::race(
                        async { stream.next().await },
                        async { cancel.cancelled().await; None },
                    )
                    .await;

                    // Cancellation wins -> exit
                    let Some(msg) = next_msg else { break };

                    match msg {
                        Ok(m) => {
                            let payload = m.payload().unwrap_or(&[]).to_vec();
                            match handler(payload).await {
                                Ok(_) => {
                                    if let Err(e) = self.consumer.commit_message(&m, CommitMode::Async) {
                                        error!("KafkaAsyncConsumer commit error: {e}");
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "KafkaAsyncConsumer handler got an error without committing: {e}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("KafkaAsyncConsumer got an error: {e}");
                        }
                    }
                }

                Ok(())
            }


        }

    } else {
        compile_error!("Enable either `rt-may` or `rt-tokio` to use this Kafka module.");
    }
}

#[cfg(test)]
mod tests {
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
        const STACK_SIZE: usize = 1 * 1024 * 1024;
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
}
