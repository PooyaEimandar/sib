use crate::stream::{
    Codec, Protocol,
    control::{Command, ControlHandle},
    set_pipeline_state,
};
use gstreamer as gst;
use gstreamer::prelude::*;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub width: u32,
    pub height: u32,
    pub bitrate: u32,
    pub fps: u32,
    pub ping: u32,
    pub protocol: Protocol,
    pub codec: Codec,
}

pub struct Sender {
    config: Arc<Mutex<Config>>,
    control: ControlHandle,
}

impl Sender {
    pub fn new(config: Config, control: ControlHandle) -> std::io::Result<Self> {
        gst::init()
            .map_err(|e| std::io::Error::other(format!("failed to init gstreamer because: {e}")))?;
        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            control,
        })
    }

    fn build_sink(cfg: &Config) -> String {
        match cfg.protocol {
            Protocol::UDP => {
                let payloader = if cfg.codec == Codec::H264 {
                    "rtph264pay config-interval=1 pt=96"
                } else {
                    "rtpav1pay pt=96"
                };
                format!(
                    " {payloader} ! udpsink host={} port={} sync=false",
                    cfg.host, cfg.port
                )
            }
            Protocol::SRT => {
                let payloader = if cfg.codec == Codec::H264 {
                    "h264parse ! mpegtsmux"
                } else {
                    "av1parse ! matroskamux"
                };
                let latency = ((cfg.ping as f64 * 3.5).round() as u64).clamp(50, 8000);
                format!(
                    " {payloader} ! srtsink uri=\"srt://{}:{}?mode=listener&latency={}\"",
                    cfg.host, cfg.port, latency
                )
            }
        }
    }

    pub fn run(&mut self) -> std::io::Result<()> {
        let mut pipeline = self.build_pipeline()?;
        let bus = match pipeline.bus() {
            Some(bus) => bus,
            None => {
                return Err(std::io::Error::other(
                    "failed to get bus from gstreamer pipeline",
                ));
            }
        };

        set_pipeline_state(&pipeline, gst::State::Playing)?;
        println!("GStreamer pipeline started");

        loop {
            if let Some(msg) = bus.timed_pop(gst::ClockTime::from_mseconds(10)) {
                match msg.view() {
                    gst::MessageView::Eos(..) => break,
                    gst::MessageView::Error(err) => {
                        eprintln!(
                            "Error from {:?}: {}",
                            err.src().map(|s| s.path_string()),
                            err.error()
                        );
                        break;
                    }
                    _ => {}
                }
            }

            let mut needs_restart = false;
            let mut pending_bitrate: Option<u32> = None;
            let mut pending_fps: Option<u32> = None;
            let mut pending_resolution: Option<(u32, u32)> = None;

            // Collect all control commands in a batch
            while let Some(batch) = self.control.try_recv() {
                for cmd in batch {
                    match cmd {
                        Command::SetBitrate(br) => {
                            pending_bitrate = Some(br);
                        }
                        Command::SetFps(fps) => {
                            pending_fps = Some(fps);
                            needs_restart = true;
                        }
                        Command::SetResolution(w, h) => {
                            pending_resolution = Some((w, h));
                            needs_restart = true;
                        }
                        Command::Stop => {
                            println!("Received stop command, shutting down GStreamer");
                            return pipeline
                                .set_state(gst::State::Null)
                                .map(|_| ())
                                .map_err(|e| {
                                    std::io::Error::other(format!(
                                        "Failed to set NULL state to GStreamer pipeline: {e}"
                                    ))
                                });
                        }
                    }
                }
            }

            // Apply updates
            let mut cfg = self.config.lock().map_err(|e| {
                std::io::Error::other(format!("could not lock gstreamer config: {e}"))
            })?;

            if let Some(br) = pending_bitrate {
                cfg.bitrate = br;
                if !needs_restart {
                    if let Some(enc) = pipeline.by_name("encoder") {
                        if cfg.codec == Codec::H264 {
                            enc.set_property("bitrate", br);
                            println!("GStreamer x264 bitrate updated to {br} kbps");
                        } else {
                            println!("GStreamer AV1 CRF update based on bitrate");
                        }
                    }
                }
            }

            if let Some(fps) = pending_fps {
                cfg.fps = fps;
                println!("GStreamer FPS changed to {fps}");
            }

            if let Some((w, h)) = pending_resolution {
                cfg.width = w;
                cfg.height = h;
                println!("GStreamer resolution changed to {w}x{h}");
            }

            drop(cfg);

            if needs_restart {
                println!("Restarting GStreamer pipeline...");
                set_pipeline_state(&pipeline, gst::State::Null)?;
                pipeline = self.build_pipeline()?;
                set_pipeline_state(&pipeline, gst::State::Playing)?;
                println!("GStreamer pipeline restarted");
            }
        }

        println!("GStreamer is shutting down");
        set_pipeline_state(&pipeline, gst::State::Null)
    }

    fn build_pipeline(&self) -> std::io::Result<gst::Pipeline> {
        let cfg = self
            .config
            .lock()
            .map_err(|e| std::io::Error::other(format!("could not lock gstreamer config: {e}")))?;

        let video_src = if cfg!(target_os = "macos") {
            "avfvideosrc capture-screen=true"
        } else if cfg!(target_os = "windows") {
            "d3d11screencapturesrc"
        } else {
            panic!("Unsupported platform");
        };

        let pipeline_str = if cfg.codec == Codec::AV1 {
            let crf = match (cfg.width * cfg.height, cfg.bitrate) {
                // ≤360p (e.g., 640×360 or less)
                (res, b) if res <= 640 * 360 => match b {
                    0..=500 => 40,
                    501..=800 => 35,
                    801..=1500 => 30,
                    _ => 28,
                },
                // 480p–720p range
                (res, b) if res <= 1280 * 720 => match b {
                    0..=500 => 38,
                    501..=800 => 33,
                    801..=1500 => 28,
                    1501..=2500 => 26,
                    _ => 24,
                },
                // ≥1080p
                (_, b) => match b {
                    0..=1000 => 36,
                    1001..=2000 => 30,
                    2001..=4000 => 26,
                    _ => 24,
                },
            };
            // videotestsrc is-live=true
            format!(
                "{video_src} capture-screen=true !video/x-raw,framerate={f}/1 ! videoscale ! video/x-raw,width={w},height={h} ! videoconvert ! \
                svtav1enc name=encoder crf={crf} preset=12 target-socket=-1 intra-period-length=15 ! \
                av1parse ! {sink}",
                f = cfg.fps,
                w = cfg.width,
                h = cfg.height,
                sink = Self::build_sink(&cfg),
            )
        } else {
            // videotestsrc is-live=true
            format!(
                "{video_src} capture-screen=true ! video/x-raw,framerate={f}/1 ! videoscale ! video/x-raw,width={w},height={h} ! videoconvert ! \
                x264enc name=encoder tune=zerolatency bitrate={b} speed-preset=ultrafast ! {sink}",
                f = cfg.fps,
                w = cfg.width,
                h = cfg.height,
                b = cfg.bitrate,
                sink = Self::build_sink(&cfg),
            )
        };

        println!("GStreamer is building: {pipeline_str}");
        gst::parse::launch(&pipeline_str)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Parse error: {e}"),
                )
            })?
            .downcast::<gst::Pipeline>()
            .map_err(|e| std::io::Error::other(format!("Not a pipeline: {e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::control::{Command, ControlHandle};
    use std::thread;
    use std::time::Duration;

    /*
       Reciver GStreamer pipeline for testing:
       x264-UDP:
       gst-launch-1.0 -v udpsrc port=5004 caps="application/x-rtp, media=video, encoding-name=H264, payload=96, clock-rate=90000" ! rtpjitterbuffer ! rtph264depay ! avdec_h264 ! fpsdisplaysink video-sink=autovideosink text-overlay=true sync=false

       x264-SRT:
       gst-launch-1.0 -v srtsrc uri="srt://127.0.0.1:5004?mode=caller&latency=50" ! tsdemux ! h264parse ! avdec_h264 ! fpsdisplaysink video-sink=autovideosink text-overlay=true sync=false

       av1-UDP:
       gst-launch-1.0 -v udpsrc port=5004 caps="application/x-rtp, media=video, encoding-name=AV1, payload=96, clock-rate=90000" ! rtpjitterbuffer ! rtpav1depay ! av1parse ! dav1ddec ! fpsdisplaysink video-sink=autovideosink text-overlay=true sync=false

       av1-SRT:
       gst-launch-1.0 -v srtsrc uri="srt://127.0.0.1:5004?mode=caller&latency=50" ! matroskademux ! av1parse ! dav1ddec ! fpsdisplaysink video-sink=autovideosink text-overlay=true sync=false
    */
    #[test]
    fn test_sender() {
        gst::init().unwrap();

        let control = ControlHandle::new();
        let config = Config {
            host: "127.0.0.1".to_string(),
            port: 5004,
            width: 640,
            height: 480,
            bitrate: 1000,
            fps: 30,
            ping: 1,
            codec: Codec::H264,
            protocol: Protocol::UDP,
        };

        let mut sender =
            Sender::new(config, control.clone()).expect("could not create stream object");
        let handle = thread::spawn(move || {
            let _ = sender.run();
        });

        // Let the stream run
        thread::sleep(Duration::from_secs(20));

        control.send(vec![
            Command::SetBitrate(4000),
            Command::SetFps(60),
            Command::SetResolution(1920, 1080),
        ]);
        println!("Sent control commands to change bitrate, fps, and resolution");

        // Let it run for another 10 seconds
        thread::sleep(Duration::from_secs(20));

        control.send(vec![Command::Stop]);
        println!("Sent stop command to the streamer");
        // Wait for the streamer to finish
        thread::sleep(Duration::from_secs(3));
        handle.join().unwrap();
    }
}
