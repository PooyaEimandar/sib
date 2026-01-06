use rdkafka::{
    Message,
    config::ClientConfig,
    consumer::{CommitMode, Consumer},
    producer::Producer,
};
use std::{sync::Arc, time::Duration};
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
}

impl KafkaSettings {
    pub fn new(brokers: impl Into<String>, group_id: impl Into<String>) -> Self {
        Self {
            brokers: brokers.into(),
            client_id: None,
            group_id: group_id.into(),
            auto_offset_reset: "latest".into(),
            partition_assignment_strategy: "cooperative-sticky".into(),
            timeout: Duration::from_secs(5),
            buffering_max_ms: 5,
        }
    }
}

fn base_client_config(cfg: &KafkaSettings) -> ClientConfig {
    let mut cc = ClientConfig::new();
    cc.set("bootstrap.servers", &cfg.brokers);
    if let Some(cid) = &cfg.client_id {
        cc.set("client.id", cid);
    }
    cc
}

fn create_producer_client_config(cfg: &KafkaSettings) -> ClientConfig {
    let mut cc = base_client_config(cfg);
    cc.set("message.timeout.ms", cfg.timeout.as_millis().to_string());
    cc.set("queue.buffering.max.ms", cfg.buffering_max_ms.to_string());
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
                    .map_err(|e| std::io::Error::other(format!("Kafka producer creation failed: {e}")))?;

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
                    .map_err(|e| std::io::Error::other(format!("Kafka producer flush error: {e}")))
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

            pub fn run<F>(
                &self,
                topic: &str,
                timeout: Duration,
                mut handler: F,
            ) -> std::io::Result<()>
            where
                F: FnMut(Vec<u8>) -> Result<(), String> + Send + 'static,
            {
                self.consumer
                    .subscribe(&[topic])
                    .map_err(|e| std::io::Error::other(format!("subscribe failed: {e}")))?;

                let consumer = Arc::clone(&self.consumer);

                may::go!(move || {
                    loop {
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
        pub struct KafkarAsyncProduce {
            pub producer: Arc<FutureProducer>,
            pub settings: KafkaSettings,
        }

        impl KafkarAsyncProduce {
            pub fn new(settings: KafkaSettings) -> std::io::Result<Self> {
                let producer: FutureProducer = create_producer_client_config(&settings)
                    .create()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("KafkarAsyncProduce creation failed: {e}")))?;

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
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("KafkaAsyncProducer flush error: {e}")))
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

            pub async fn run<F, Fut>(&self, topic: &str, mut handler: F) -> Result<(), String>
            where
                F: FnMut(Vec<u8>) -> Fut + Send,
                Fut: std::future::Future<Output = Result<(), String>> + Send,
            {
                use futures_lite::StreamExt;

                self.consumer
                    .subscribe(&[topic])
                    .map_err(|e| format!("subscribe failed: {e}"))?;

                let mut stream = self.consumer.stream();

                while let Some(msg) = stream.next().await {
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
