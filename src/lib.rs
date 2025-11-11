pub mod database;
pub mod network;

#[cfg(any(feature = "stm-receiver", feature = "stm-sender"))]
pub mod stream;

#[cfg(any(feature = "rt-may", feature = "net-h1-server"))]
pub fn init_global_poller(num_of_workers: usize, stack_size: usize) {
    may::config()
        .set_workers(num_of_workers)
        .set_stack_size(stack_size);
}
