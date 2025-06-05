cfg_if::cfg_if! {
    if #[cfg(feature = "h1-server")] {
        pub mod h1;
        pub mod message;
        pub mod reader;
        pub mod session;
    }
}

#[cfg(feature = "h3-server")]
pub mod h3;
