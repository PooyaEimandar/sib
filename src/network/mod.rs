#[cfg(all(
    any(feature = "net-h2-server", feature = "net-h3-server"),
    feature = "rt-glommio",
    feature = "rt-tokio"
))]
compile_error!("Features `rt-glommio` and `rt-tokio` are mutually exclusive. Pick one.");

#[cfg(any(
    feature = "net-h1-server",
    feature = "net-h2-server",
    feature = "net-h3-server",
    feature = "net-ws-server",
    feature = "net-wt-server",
))]
pub mod http;

#[cfg(feature = "net-kafka-cli")]
pub mod kafka_cli;
