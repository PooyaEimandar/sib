cfg_if::cfg_if! {
    if #[cfg(any(windows, target_os = "android", target_os = "ios"))] {
        #[global_allocator]
        static GLOBAL: std::alloc::System = std::alloc::System;
    } else {
        extern crate tikv_jemallocator;
        #[global_allocator]
        static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
    }
}

#[cfg(feature = "http-server")]
pub mod network;

#[cfg(feature = "system")]
pub mod system;
