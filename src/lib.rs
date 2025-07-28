pub mod database;
pub mod network;

#[cfg(any(feature = "stm-receiver", feature = "stm-sender"))]
pub mod stream;

#[cfg(any(feature = "net-h1-server", feature = "net-h3-server", feature = "db-fdb", feature = "net-file-server"))]
pub fn set_num_workers(num: usize)
{
    may::config().set_workers(num);
}