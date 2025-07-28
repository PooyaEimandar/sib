cfg_if::cfg_if! {
    if #[cfg(any(feature = "net-h1-server", feature = "net-h3-server"))] {
        // Shared modules
        pub mod ratelimit;
        pub mod server;
        pub mod session;
        pub mod util;

        #[cfg(feature = "net-file-server")]
        pub mod file;
        
        #[cfg(feature = "net-h1-server")]
        pub mod h1_session;

        #[cfg(feature = "net-h3-server")]
        pub mod h3_session;
    }
}
