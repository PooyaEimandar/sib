pub mod ratelimit;
pub mod server;
pub mod session;

#[cfg(feature = "net-file-server")]
pub mod file;

cfg_if::cfg_if! {
    if #[cfg(feature = "net-h1-server")] {
        pub mod h1_session;
        pub mod h1_server;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "net-h2-server")] {
        pub mod h2_session;
        pub mod h2_server;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "net-h3-server", feature = "rt-glommio", target_os = "linux"))] {
        pub mod h3_session;
        pub mod h3_server;
    }
}
