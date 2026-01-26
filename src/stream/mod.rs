#[derive(Clone, PartialEq)]
pub enum Codec {
    H264,
    AV1,
}

#[derive(Clone)]
pub enum Protocol {
    UDP,
    SRT,
}

#[cfg(any(feature = "stm-udp-receiver", feature = "stm-udp-sender"))]
pub(crate) fn set_pipeline_state(
    pipeline: &gstreamer::Pipeline,
    state: gstreamer::State,
) -> std::io::Result<()> {
    use gstreamer::prelude::ElementExt;
    pipeline.set_state(state).map(|_| ()).map_err(|e| {
        std::io::Error::other(format!("Failed to set state to GStreamer pipeline: {e}"))
    })
}

cfg_if::cfg_if! {
    if #[cfg(feature = "stm-udp-sender")] {
        pub mod control;
        pub mod sender;
    }
}

#[cfg(feature = "stm-udp-receiver")]
pub mod receiver;

#[cfg(feature = "stm-webrtc-sender")]
pub mod webrtc;
