#[cfg(feature = "net-h1-server")]
pub mod h1;

#[cfg(feature = "net-h3-server")]
pub mod h3;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "net-h1-server", feature = "net-h3-server"))] {
        pub mod ratelimit;
        pub mod session;
        pub mod util;

        #[cfg(feature = "net-file-server")]
        pub mod file;
    }
}