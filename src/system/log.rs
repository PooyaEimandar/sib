#[macro_export]
macro_rules! s_trace {
    ($msg:expr) => {
        anyhow::anyhow!(
            "[{}:{}:{}] {}",
            file!(),
            line!(),
            std::any::type_name::<fn()>(),
            $msg
        )
    };
}
