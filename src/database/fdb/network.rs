#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FDBNetworkOption {
    LocalAddress = 10,
    ClusterFile = 20,
    TraceEnable = 30,
    TraceRollSize = 31,
    TraceMaxLogsSize = 32,
    TraceLogGroup = 33,
    TraceFormat = 34,
    TraceClockSource = 35,
    TraceFileIdentifier = 36,
    TraceShareAmongClientThreads = 37,
    TraceInitializeOnSetup = 38,
    TracePartialFileSuffix = 39,
    Knob = 40,
    TlsPlugin = 41,
    TlsCertBytes = 42,
    TlsCertPath = 43,
    TlsKeyBytes = 45,
    TlsKeyPath = 46,
    TlsVerifyPeers = 47,
    BuggifyEnable = 48,
    BuggifyDisable = 49,
    BuggifySectionActivatedProbability = 50,
    BuggifySectionFiredProbability = 51,
    TlsCaBytes = 52,
    TlsCaPath = 53,
    TlsPassword = 54,
    DisableMultiVersionClientApi = 60,
    CallbacksOnExternalThreads = 61,
    ExternalClientLibrary = 62,
    ExternalClientDirectory = 63,
    DisableLocalClient = 64,
    ClientThreadsPerVersion = 65,
    FutureVersionClientLibrary = 66,
    RetainClientLibraryCopies = 67,
    IgnoreExternalClientFailures = 68,
    FailIncompatibleClient = 69,
    DisableClientStatisticsLogging = 70,
    EnableRunLoopSlowTaskProfiling = 71,
    DisableClientBypass = 72,
    ClientBuggifyEnable = 80,
    ClientBuggifyDisable = 81,
    ClientBuggifySectionActivatedProbability = 82,
    ClientBuggifySectionFiredProbability = 83,
    DistributedClientTracer = 90,
    ClientTmpDir = 91,
    SupportedClientVersions = 1000,
    ExternalClient = 1001,
    ExternalClientTransportId = 1002,
}

pub struct FDBNetworkOptionValue {
    pub option: FDBNetworkOption,
    pub value: String,
}

/// Process-global FoundationDB network handle.
///
/// There is exactly one network per process. This type is **not** `Clone`:
/// `Drop` calls `fdb_stop_network()`, so duplicating an owning value would stop
/// the singleton network twice. Share it across the run/stop threads with
/// `Arc<FDBNetwork>` instead.
#[derive(Default, Debug)]
pub struct FDBNetwork {
    init: std::sync::atomic::AtomicBool,
}

impl FDBNetwork {
    pub fn new(option: Option<FDBNetworkOptionValue>) -> std::io::Result<Self> {
        let res = unsafe { foundationdb_sys::fdb_select_api_version_impl(730, 730) };
        if res != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to select FoundationDB API version: {res}"
            )));
        }
        if let Some(opt) = option {
            let res = unsafe {
                foundationdb_sys::fdb_network_set_option(
                    opt.option as u32,
                    opt.value.as_bytes().as_ptr(),
                    opt.value.len() as i32,
                )
            };
            if res != 0 {
                return Err(std::io::Error::other(format!(
                    "Failed to setup FoundationDB network option: {res}"
                )));
            }
        }
        let res = unsafe { foundationdb_sys::fdb_setup_network() };
        if res != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to setup FoundationDB network: {res}"
            )));
        }
        Ok(Self {
            init: std::sync::atomic::AtomicBool::new(true),
        })
    }

    pub fn run(&self) -> std::io::Result<()> {
        let res = unsafe { foundationdb_sys::fdb_run_network() };
        if res != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to start FoundationDB network: {res}"
            )));
        }
        Ok(())
    }

    /// Stop the process-global network. Idempotent: only the first caller
    /// (across all `Arc` clones and `Drop`) actually calls `fdb_stop_network()`.
    pub fn stop(&self) -> std::io::Result<()> {
        if !self.init.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("FoundationDB network is not started"));
        }
        // stop the foundationdb network
        let res = unsafe { foundationdb_sys::fdb_stop_network() };
        if res != 0 {
            // Restore the flag so the network can be stopped again on Drop.
            self.init.store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(std::io::Error::other(format!(
                "Failed to stop FoundationDB network: {res}"
            )));
        }
        Ok(())
    }
}

impl Drop for FDBNetwork {
    fn drop(&mut self) {
        // `stop()` is idempotent; if it was already called this is a no-op.
        if let Err(_e) = self.stop() {
            //s_error!!("Error stopping FoundationDB network: {}", e);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/database/fdb/network_tests.rs"]
mod tests;
