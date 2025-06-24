use crossbeam::channel::{Receiver, Sender, unbounded};

#[derive(Debug)]
pub enum Command {
    SetBitrate(u32),
    SetFps(u32),
    SetResolution(u32, u32),
    Stop,
}

#[derive(Clone)]
pub struct ControlHandle {
    tx: Sender<Vec<Command>>,
    rx: Receiver<Vec<Command>>,
}

impl Default for ControlHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlHandle {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self { tx, rx }
    }

    /// Send a batch of commands
    pub fn send(&self, cmds: Vec<Command>) {
        let _ = self.tx.send(cmds);
    }

    /// Receive a batch of commands if available
    pub fn try_recv(&self) -> Option<Vec<Command>> {
        self.rx.try_recv().ok()
    }
}
