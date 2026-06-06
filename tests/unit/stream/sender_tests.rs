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

    let mut sender = Sender::new(config, control.clone()).expect("could not create stream object");
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
    info!("Sent control commands to change bitrate, fps, and resolution");

    // Let it run for another 10 seconds
    thread::sleep(Duration::from_secs(20));

    control.send(vec![Command::Stop]);
    info!("Sent stop command to the streamer");
    // Wait for the streamer to finish
    thread::sleep(Duration::from_secs(3));
    handle.join().unwrap();
}
