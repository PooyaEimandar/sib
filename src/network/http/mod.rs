cfg_if::cfg_if! {
    if #[cfg(feature = "net-h1-server")] {
        pub mod h1;
        pub mod message;
        pub mod reader;
        pub mod session;
    }
}

#[cfg(feature = "net-h3-server")]
pub mod h3;
