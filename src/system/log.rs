use klickhouse::{Client, ClientOptions};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{Event, Subscriber};
use tracing_appender::rolling;
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Enum for configuring log filtering levels.
#[derive(Debug, Clone, Copy)]
pub enum LogFilterLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    OFF,
}

/// A structured representation of a single log event for ClickHouse.
#[derive(Debug)]
pub struct LogEvent {
    timestamp: String,
    level: tracing::Level,
    message: String,
}

/// Enum for configuring how logs are rotated on disk when using a file logger.
#[derive(Clone, Debug)]
pub enum LogRolling {
    NEVER,
    MINUTELY,
    HOURLY,
    DAILY,
}

/// Configuration for writing logs to files when using a file logger.
#[derive(Clone, Debug)]
pub struct LogFileConfig {
    pub roller: LogRolling,
    pub dir: String,
    pub file_name: String,
    pub ansi: bool,
}

/// Configuration for sending logs to ClickHouse.
#[derive(Clone, Debug)]
pub struct ClickhouseConfig {
    /// The address of the ClickHouse server (e.g., "127.0.0.1:9000").
    pub address: String,
    /// ClickHouse database name.
    pub database: String,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// Query to initialize the log table.
    pub init_query: String,
    /// Query prefix used for log insertion.
    pub insert_query: String,
    /// Maximum number of logs to batch before flush.
    pub max_num_flush: usize,
    /// Time-based flush interval for batch logs.
    pub flush_interval: Duration,
    /// Buffer size for the log channel.
    pub channel_buffer_size: usize,
}

impl Default for ClickhouseConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:9000".to_owned(),
            database: "default".to_owned(),
            username: "default".to_string(),
            password: String::new(),
            init_query: r#"
            CREATE TABLE IF NOT EXISTS LOG (
            timestamp DateTime64(3) DEFAULT now(),
            level String,
            message String) ENGINE = MergeTree() ORDER BY timestamp;
            "#
            .to_owned(),
            insert_query: r#"INSERT INTO LOG (timestamp, level, message) VALUES "#.to_owned(),
            max_num_flush: 1024,
            flush_interval: Duration::from_secs(5),
            channel_buffer_size: 1024,
        }
    }
}

/// A custom visitor to extract formatted log messages.
struct LogVisitor<'a>(&'a mut String);

impl tracing::field::Visit for LogVisitor<'_> {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{:#?}", value));
    }
}

/// A custom tracing layer that sends logs to a background task for ClickHouse.
struct AsyncLogLayer {
    sender: mpsc::Sender<LogEvent>,
}

impl<S> Layer<S> for AsyncLogLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let metadata = event.metadata();
        let level = *metadata.level();

        let mut message = String::new();
        let mut visitor = LogVisitor(&mut message);
        event.record(&mut visitor);

        // Filter out ClickHouse packet logs and TRACE level logs to avoid excessive logging.
        if message.starts_with("clickhouse packet") || metadata.level() == &tracing::Level::TRACE {
            return;
        }

        let timestamp = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string();

        let log_event = LogEvent {
            timestamp,
            level,
            message,
        };

        if let Err(err) = self.sender.try_send(log_event) {
            tracing::error!("Failed to send log event: {:?}", err);
        }
    }
}

/// Send a batch of logs to ClickHouse using the provided client and insert query.
async fn send_logs_to_clickhouse(
    client: &Client,
    insert_query: &str,
    logs: &[LogEvent],
) -> anyhow::Result<()> {
    if logs.is_empty() {
        return Ok(());
    }

    let mut query = insert_query.to_owned();
    for (index, log) in logs.iter().enumerate() {
        if index > 0 {
            query.push_str(", ");
        }
        query.push_str(&format!(
            "('{}', '{}', '{}')",
            log.timestamp,
            log.level,
            log.message.replace('\'', "''")
        ));
    }

    client.execute(&query).await?;
    Ok(())
}

/// The background task that buffers and periodically flushes logs to ClickHouse.
async fn store_logs_in_clickhouse(
    config: ClickhouseConfig,
    client: klickhouse::Client,
    mut receiver: mpsc::Receiver<LogEvent>,
    mut shutdown_signal: oneshot::Receiver<()>,
    done_signal: oneshot::Sender<()>,
) {
    let log_buffer = Arc::new(Mutex::new(Vec::with_capacity(config.max_num_flush)));
    let mut flush_interval = tokio::time::interval(config.flush_interval);

    loop {
        tokio::select! {
            Some(log_event) = receiver.recv() => {
                let mut buffer = log_buffer.lock().await;
                buffer.push(log_event);

                if buffer.len() >= config.max_num_flush {
                    if let Err(e) = send_logs_to_clickhouse(&client, &config.insert_query, &buffer).await {
                        tracing::error!("Failed to send logs to ClickHouse: {:?}", e);
                    }
                    buffer.clear();
                }
            }
            _ = flush_interval.tick() => {
                let mut buffer = log_buffer.lock().await;
                if !buffer.is_empty() {
                    if let Err(e) = send_logs_to_clickhouse(&client, &config.insert_query, &buffer).await {
                        tracing::error!("Periodic flush failed: {:?}", e);
                    }
                    buffer.clear();
                }
            }
            _ = &mut shutdown_signal => {
                let buffer = log_buffer.lock().await;
                if !buffer.is_empty() {
                    if let Err(e) = send_logs_to_clickhouse(&client, &config.insert_query, &buffer).await {
                        tracing::error!("Shutdown flush failed: {:?}", e);
                    }
                }
                let _ = done_signal.send(());
                break;
            }
        }
    }
}

/// A handle to gracefully shut down the logging system.
pub struct Log {
    shutdown_sender: Option<oneshot::Sender<()>>,
    done_receiver: Option<oneshot::Receiver<()>>,
}

impl Log {
    pub fn new(shutdown_sender: oneshot::Sender<()>, done_receiver: oneshot::Receiver<()>) -> Self {
        Self {
            shutdown_sender: Some(shutdown_sender),
            done_receiver: Some(done_receiver),
        }
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        if let Some(shutdown_sender) = self.shutdown_sender.take() {
            let done_receiver = self.done_receiver.take();
            tokio::spawn(async move {
                let _ = shutdown_sender.send(());
                if let Some(done_receiver) = done_receiver {
                    let _ = done_receiver.await;
                }
            });
        }
    }
}

/// Initializes the global logging system with file and/or ClickHouse logging.
pub async fn init_log(
    filter_level: LogFilterLevel,
    file_config: Option<LogFileConfig>,
    clickhouse_config: Option<ClickhouseConfig>,
) -> Log {
    let level = match filter_level {
        LogFilterLevel::TRACE => tracing::level_filters::LevelFilter::TRACE,
        LogFilterLevel::DEBUG => tracing::level_filters::LevelFilter::DEBUG,
        LogFilterLevel::INFO => tracing::level_filters::LevelFilter::INFO,
        LogFilterLevel::WARN => tracing::level_filters::LevelFilter::WARN,
        LogFilterLevel::ERROR => tracing::level_filters::LevelFilter::ERROR,
        LogFilterLevel::OFF => tracing::level_filters::LevelFilter::OFF,
    };
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .parse_lossy(format!("{level},klickhouse=off"));

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (done_sender, done_receiver) = oneshot::channel();

    let async_log_layer = if let Some(config) = clickhouse_config {
        let config_cloned = config.clone();

        let clickhouse_opt = ClientOptions {
            default_database: config.database,
            username: config.username,
            password: config.password,
            ..ClientOptions::default()
        };
        let client = Client::connect(config.address, clickhouse_opt).await;
        match client {
            Ok(client) => {
                // on connection success initialize the table
                if let Err(e) = client.execute(config.init_query).await {
                    eprintln!("Failed to execute ClickHouse init query: {:?}", e);
                    None
                } else {
                    let (sender, receiver) = mpsc::channel::<LogEvent>(config.channel_buffer_size);

                    tokio::spawn(store_logs_in_clickhouse(
                        config_cloned,
                        client,
                        receiver,
                        shutdown_receiver,
                        done_sender,
                    ));
                    Some(AsyncLogLayer { sender })
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to ClickHouse: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let console_layer = fmt::layer()
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_filter(filter);

    if let Some(file) = file_config {
        let file_appender = match file.roller {
            LogRolling::NEVER => rolling::never(file.dir, file.file_name),
            LogRolling::MINUTELY => rolling::minutely(file.dir, file.file_name),
            LogRolling::HOURLY => rolling::hourly(file.dir, file.file_name),
            LogRolling::DAILY => rolling::daily(file.dir, file.file_name),
        };

        let file_layer = fmt::layer().with_writer(file_appender).with_ansi(file.ansi);
        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .with(async_log_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(console_layer)
            .with(async_log_layer)
            .init();
    }

    Log::new(shutdown_sender, done_receiver)
}

/// Emits a debug-level log.
#[macro_export]
macro_rules! s_debug {
    ($($arg:tt)*) => {{
        tracing::debug!("{}", format!($($arg)*));
    }};
}

/// Emits an info-level log.
#[macro_export]
macro_rules! s_info {
    ($($arg:tt)*) => {{
        tracing::info!("{}", format!($($arg)*));
    }};
}

/// Emits a warning-level log.
#[macro_export]
macro_rules! s_warn {
    ($($arg:tt)*) => {{
        tracing::warn!("{}", format!($($arg)*));
    }};
}

/// Emits an error-level log.
#[macro_export]
macro_rules! s_error {
    ($($arg:tt)*) => {{
        tracing::error!("{}", format!($($arg)*));
    }};
}

/// Emits a trace-level log with file, line, and function info.
#[macro_export]
macro_rules! s_trace {
    ($($arg:tt)*) => {{
        let user_msg = format!($($arg)*);
        let message = format!(
            "{} [{}:{}:{}]",
            user_msg,
            file!(),
            line!(),
            std::any::type_name::<fn()>()
        );
        tracing::trace!(message = %message);
    }};
}

/// Emits a trace-level log that records the entry time, exit time, and execution duration of a code block.
#[macro_export]
macro_rules! s_trace_time {
    ($msg:expr, $block:block) => {{
        let __start_time = std::time::Instant::now();
        $crate::s_trace!("ENTER TRACE [{}]", $msg);

        let __result = { $block };

        $crate::s_trace!(
            "EXIT TRACE [{}] (duration: {:.3?})",
            $msg,
            __start_time.elapsed()
        );

        __result
    }};
}

#[tokio::test]
async fn test() {
    let log_file = LogFileConfig {
        roller: LogRolling::DAILY,
        dir: "log".to_owned(),
        file_name: "app.log".to_owned(),
        ansi: false,
    };
    let clickhouse_config = ClickhouseConfig::default();
    let _log_system = init_log(
        LogFilterLevel::TRACE,
        Some(log_file),
        Some(clickhouse_config),
    )
    .await;

    s_debug!("This is a debug message from Sib");
    s_info!("This is an info message from Sib");
    s_warn!("This is a warning message from Sib");
    s_error!("This is an error message from Sib");
    s_trace!("This is a trace message from Sib");

    let x = 10;
    s_trace_time!("TRACE ID: 11", {
        s_info!("X:{} from info", x);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        s_warn!("X:{} from warn", x);
    });

    println!("Logging system shut down, check result via http://localhost:8123/play");
}
