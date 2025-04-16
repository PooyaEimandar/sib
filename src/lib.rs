#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "http-server")]
pub mod network;

#[cfg(feature = "system")]
pub mod system;
