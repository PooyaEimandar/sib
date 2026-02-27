pub mod server;

#[cfg(feature = "net-file-server")]
pub mod file;

#[cfg(any(
    feature = "net-h1-server",
    feature = "net-h2-server",
    feature = "net-h3-server",
    feature = "net-ws-server",
))]
pub mod session;

#[cfg(all(
    feature = "net-ws-server",
    any(feature = "net-h1-server", feature = "net-h2-server")
))]
pub mod ws;

cfg_if::cfg_if! {
    if #[cfg(feature = "net-ratelimiter")] {
        pub mod ratelimit;
        pub mod rlid;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "net-h1-server")] {
        pub mod date;
        pub mod h1_session;
        pub mod h1_server;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "net-h2-server")] {
        pub mod h1_session_async;
        pub mod h2_session;
        pub mod h2_server;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "net-h3-server")] {
        pub mod h3_session;
        pub mod h3_server;
    }
}

#[cfg(feature = "net-wt-server")]
pub mod wt;
