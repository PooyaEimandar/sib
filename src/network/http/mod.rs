cfg_if::cfg_if! {
    if #[cfg(any(feature = "net-h1-server", feature = "net-h3-server"))] {
        pub mod ratelimit;
        pub mod server;
        pub mod session;
        pub mod util;

        // HTTP/1 coroutine
        #[cfg(feature = "net-h1-server")]
        pub mod h1_session;
        #[cfg(feature = "net-h1-server")]
        pub mod h1_server_coro;

        // HTTP/3 coroutine
        #[cfg(feature = "net-h3-server")]
        pub mod h3_session;
        #[cfg(feature = "net-h3-server")]
        pub mod h3_server_coro;
    }
}

// Make file server independent of the coro features
#[cfg(feature = "net-file-server")]
pub mod file;
