use crate::stream::{Codec, Protocol};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSinkCallbacks};
use gstreamer_video::VideoInfo;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub codec: Codec,
    pub protocol: Protocol,
    pub latency_ms: u32,
}

pub struct Receiver {
    pub config: Config,
}

impl Receiver {
    pub fn new(config: Config) -> std::io::Result<Self> {
        gst::init().map_err(|e| std::io::Error::other(format!("failed to init gstreamer: {e}")))?;
        Ok(Self { config })
    }

    fn build_pipeline(&self) -> std::io::Result<gst::Pipeline> {
        let srcsink = match self.config.protocol {
            Protocol::UDP => {
                let decode = match self.config.codec {
                    Codec::H264 => "rtph264depay ! avdec_h264",
                    Codec::AV1 => "rtpav1depay ! av1parse ! dav1ddec",
                };
                format!(
                    "udpsrc port={} caps=\"application/x-rtp, media=video, payload=96, clock-rate=90000\" ! rtpjitterbuffer ! {}",
                    self.config.port, decode
                )
            }
            Protocol::SRT => {
                let decode = match self.config.codec {
                    Codec::H264 => "tsdemux ! h264parse ! avdec_h264",
                    Codec::AV1 => "matroskademux ! av1parse ! dav1ddec",
                };
                format!(
                    "srtsrc uri=\"srt://{}:{}?mode=caller&latency={}\" ! {}",
                    self.config.host, self.config.port, self.config.latency_ms, decode
                )
            }
        };

        let pipeline_str = format!("{srcsink} ! appsink name=appsink sync=false");
        let pipeline = gst::parse::launch(&pipeline_str)
            .map_err(|e| std::io::Error::other(format!("Pipeline parse error: {e}")))?
            .downcast::<gst::Pipeline>()
            .map_err(|e| std::io::Error::other(format!("Not a pipeline: {e:?}")))?;

        Ok(pipeline)
    }

    pub fn run<F>(&self, callback: F) -> std::io::Result<()>
    where
        F: FnMut(&[u8], usize, usize) + Send + 'static,
    {
        let pipeline = self.build_pipeline()?;
        let element = pipeline
            .by_name("appsink")
            .ok_or_else(|| std::io::Error::other("appsink element not found"))?;
        let appsink = element
            .downcast::<AppSink>()
            .map_err(|_| std::io::Error::other("appsink downcast failed"))?;

        let callback_ref = Arc::new(Mutex::new(Some(callback)));

        let cb = callback_ref.clone();
        appsink.set_callbacks(
            AppSinkCallbacks::builder()
                .new_sample(move |sink| {
                    let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                    let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                    let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                    let caps = sample.caps().ok_or(gst::FlowError::Error)?;
                    let info = VideoInfo::from_caps(caps).map_err(|_| gst::FlowError::Error)?;

                    let width = info.width() as usize;
                    let height = info.height() as usize;
                    let data = map.as_slice();

                    if let Some(ref mut cb) = *cb.lock().unwrap() {
                        cb(data, width, height);
                    }

                    Ok(gst::FlowSuccess::Ok)
                })
                .build(),
        );

        pipeline
            .set_state(gst::State::Playing)
            .map_err(|e| std::io::Error::other(format!("Failed to start pipeline: {e}")))?;

        let bus = pipeline.bus().unwrap();
        for msg in bus.iter_timed(gst::ClockTime::NONE) {
            use gst::MessageView;
            match msg.view() {
                MessageView::Error(err) => {
                    eprintln!(
                        "Error from {:?}: {} ({:?})",
                        err.src().map(|s| s.path_string()),
                        err.error(),
                        err.debug()
                    );
                    break;
                }
                MessageView::Eos(..) => {
                    println!("EOS received");
                    break;
                }
                _ => {}
            }
        }

        pipeline
            .set_state(gst::State::Null)
            .map(|_| ())
            .map_err(|e| std::io::Error::other(format!("Shutdown failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver() {
        let config: Config = Config {
            host: "127.0.0.1".to_string(),
            port: 5004,
            codec: Codec::H264,
            protocol: Protocol::UDP,
            latency_ms: 50,
        };

        let receiver = Receiver::new(config).unwrap();
        receiver
            .run(move |data, width, height| {
                println!(
                    "Received frame of size: {}x{} with len:{}",
                    width,
                    height,
                    data.len()
                );
            })
            .unwrap();
    }
}
