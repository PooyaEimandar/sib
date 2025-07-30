pub mod database;
pub mod network;

#[cfg(any(feature = "stm-receiver", feature = "stm-sender"))]
pub mod stream;

#[cfg(any(feature = "net-h1-server", feature = "net-h3-server", feature = "db-fdb", feature = "net-file-server"))]
pub fn init(num_of_workers: usize, stack_size: usize)
{
    may::config().set_workers(num_of_workers).set_stack_size(stack_size);
}