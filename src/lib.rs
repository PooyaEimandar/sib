#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "sib-http")]
pub mod network;

#[cfg(feature = "sib-sys")]
pub mod system;
