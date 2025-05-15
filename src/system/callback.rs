use std::sync::Arc;

/// Generic callback wrapper supporting Fn-based closures with typed arguments
#[derive(Clone)]
pub struct Callback<T>
where
    T: ?Sized,
{
    inner: Arc<CallbackFn<T>>,
}

impl<T> Callback<T>
where
    T: ?Sized,
{
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&T) -> anyhow::Result<()> + Send + Sync + 'static,
    {
        Self { inner: Arc::new(f) }
    }

    pub fn run(&self, arg: &T) -> anyhow::Result<()> {
        (self.inner)(arg)
    }
}

impl<T> std::fmt::Debug for Callback<T>
where
    T: ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Callback")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

// Private type alias for clarity
type CallbackFn<T> = dyn Fn(&T) -> anyhow::Result<()> + Send + Sync;
