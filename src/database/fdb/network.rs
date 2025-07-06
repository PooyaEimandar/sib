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

#[derive(Default, Clone, Debug)]
pub struct FDBNetwork {
    init: bool,
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
        Ok(Self { init: true })
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

    pub fn stop(&mut self) -> std::io::Result<()> {
        if !self.init {
            return Err(std::io::Error::other("FoundationDB network is not started"));
        }
        // stop the foundationdb network
        let res = unsafe { foundationdb_sys::fdb_stop_network() };
        if res != 0 {
            return Err(std::io::Error::other(format!(
                "Failed to stop FoundationDB network: {res}"
            )));
        }
        self.init = false;
        Ok(())
    }
}

impl Drop for FDBNetwork {
    fn drop(&mut self) {
        if !self.init {
            return;
        }

        if let Err(_e) = self.stop() {
            //s_error!!("Error stopping FoundationDB network: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_fdb_network_start_and_stop() {
        let network = FDBNetwork::new(None).expect("Failed to create FDB network");
        let mut network_for_stop = network.clone();

        let handle = thread::spawn(move || {
            network.run().expect("Failed to run FDB network");
        });

        // Give it time to start
        thread::sleep(Duration::from_secs(1));

        // Now stop it (separate lock)
        let result = network_for_stop.stop();
        assert!(result.is_ok(), "Failed to stop network");

        // Wait for background thread
        handle.join().unwrap();
    }
}
