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
    if #[cfg(feature = "stm-sender")] {
        pub mod control;
        pub mod sender;
    }
}

#[cfg(feature = "stm-receiver")]
pub mod receiver;
