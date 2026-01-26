use crate::network::http::server::HFactory;
use crate::network::http::session::{HAsyncService, Session};
use crate::network::http::ws::OpCode;

use bytes::{Bytes, BytesMut};
use glib::{prelude::ObjectExt, types::StaticType};
use gst::prelude::*;
use gstreamer as gst;
use gstreamer_app as gst_app;
use gstreamer_video as gst_video;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use webrtc::{
    api::{APIBuilder, media_engine::MediaEngine},
    data_channel::data_channel_message::DataChannelMessage,
    ice_transport::ice_server::RTCIceServer,
    interceptor::registry::Registry,
    peer_connection::{RTCPeerConnection, configuration::RTCConfiguration},
    rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType},
    track::track_local::track_local_static_sample::TrackLocalStaticSample,
};

/// Initialize GStreamer once in your binary
pub fn init() -> std::io::Result<()> {
    gst::init().map_err(|e| std::io::Error::other(format!("gst init failed: {e:?}")))
}

/// Public server/service config (extend as you need).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP ephemeral range for ICE (EphemeralUDP::new(min,max)).
    pub udp_min: u16,
    pub udp_max: u16,
    /// STUN servers.
    pub stun_urls: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp_min: 50000,
            udp_max: 50100,
            stun_urls: vec!["stun:stun.l.google.com:19302".into()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamCtrl {
    pub width: i32,
    pub height: i32,
    pub fps: i32,
    pub bitrate_kbps: i32,
}

impl Default for StreamCtrl {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_kbps: 6000,
        }
    }
}

fn ctrl_needs_restart(prev: &StreamCtrl, next: &StreamCtrl) -> bool {
    prev.width != next.width || prev.height != next.height || prev.fps != next.fps
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IceCandidateWire {
    candidate: String,
    #[serde(rename = "sdpMid")]
    sdp_mid: Option<String>,
    #[serde(rename = "sdpMLineIndex")]
    sdp_mline_index: Option<u16>,
    #[serde(rename = "usernameFragment")]
    username_fragment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
enum WsMsg {
    Offer(String),
    Answer(String),

    Ice(IceCandidateWire),

    ClientStats(ClientStats),
    ServerStats(ServerStats),

    Ctrl {
        width: i32,
        height: i32,
        fps: i32,
        bitrate_kbps: i32,
    },

    Info(String),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientStats {
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss: Option<f64>,
    pub fps: Option<f64>,
    pub available_in_bps: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerStats {
    pub fps: f64,
    pub dropped_samples: u64,
}

struct GstStream {
    pipeline: gst::Pipeline,
    capsfilter: gst::Element,
    encoder: gst::Element,
    frame_counter: Arc<AtomicU64>,
    dropped_counter: Arc<AtomicU64>,
}

struct StreamRuntime {
    stream: GstStream,

    pump_stop: CancellationToken,
    pump_handle: tokio::task::JoinHandle<()>,

    fps_stop: CancellationToken,
    fps_handle: tokio::task::JoinHandle<()>,

    bus_stop: CancellationToken,
    bus_handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    H264,
}

impl Codec {
    fn mime(self) -> &'static str {
        match self {
            Codec::H264 => "video/H264",
        }
    }
    fn offer_rtpmap_token(self) -> &'static str {
        match self {
            Codec::H264 => "H264/90000",
        }
    }
    fn default_pt(self) -> u8 {
        96
    }
}

fn choose_codec_from_offer(_offer_sdp: &str) -> Codec {
    Codec::H264
}

fn find_pt_in_offer(offer_sdp: &str, rtpmap_token: &str) -> Option<u8> {
    for line in offer_sdp.lines() {
        if let Some(rest) = line.strip_prefix("a=rtpmap:")
            && let Some((pt_str, codec_part)) = rest.split_once(' ')
            && codec_part.trim() == rtpmap_token
            && let Ok(pt) = pt_str.trim().parse::<u16>()
            && pt <= 255
        {
            return Some(pt as u8);
        }
    }
    None
}

fn find_fmtp_in_offer(offer_sdp: &str, pt: u8) -> Option<String> {
    let prefix = format!("a=fmtp:{pt} ");
    for line in offer_sdp.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn codec_cap(codec: Codec, fmtp_from_offer: Option<&str>) -> RTCRtpCodecCapability {
    match codec {
        Codec::H264 => RTCRtpCodecCapability {
            mime_type: codec.mime().to_string(),
            clock_rate: 90000,
            channels: 0,
            // try to match browser fmtp exactly
            sdp_fmtp_line: fmtp_from_offer
                .unwrap_or("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f")
                .to_string(),
            rtcp_feedback: vec![],
        },
    }
}

fn prop_type(elem: &gst::Element, prop: &str) -> Option<glib::Type> {
    elem.find_property(prop).map(|ps| ps.value_type())
}

fn set_prop_best_u32(elem: &gst::Element, prop: &str, value: u32) {
    let Some(t) = prop_type(elem, prop) else {
        return;
    };

    if t == u32::static_type() {
        elem.set_property(prop, value);
    } else if t == i32::static_type() {
        elem.set_property(prop, value as i32);
    } else if t == u64::static_type() {
        elem.set_property(prop, value as u64);
    } else if t == i64::static_type() {
        elem.set_property(prop, value as i64);
    }
}

fn set_prop_from_str(elem: &gst::Element, prop: &str, value: &str) {
    if elem.find_property(prop).is_some() {
        elem.set_property_from_str(prop, value);
    }
}

fn gst_stop_pipeline(p: &gst::Pipeline) {
    if let Err(e) = p.set_state(gst::State::Null) {
        warn!("gst set_state(NULL) failed: {e:?}");
    }
}

fn gst_has_element(name: &str) -> bool {
    gst::ElementFactory::find(name).is_some()
}

fn build_pipeline_h264(
    ctrl: &StreamCtrl,
) -> std::io::Result<(GstStream, mpsc::Receiver<gst::Sample>)> {
    let src = if cfg!(target_os = "macos") {
        "avfvideosrc capture-screen=true"
    } else if cfg!(target_os = "windows") {
        "d3d11screencapturesrc show-cursor=true ! d3d11convert ! d3d11download"
    } else {
        return Err(std::io::Error::other("Unsupported platform"));
    };

    let src_factory = if cfg!(target_os = "macos") {
        "avfvideosrc"
    } else {
        "d3d11screencapturesrc"
    };

    if !gst_has_element(src_factory) {
        return Err(std::io::Error::other(format!(
            "Missing {src_factory}. Install GStreamer."
        )));
    }

    let (enc, enc_is_amf) = if gst_has_element("amfh264enc") {
        ("amfh264enc", true)
    } else if gst_has_element("x264enc") {
        ("x264enc", false)
    } else {
        return Err(std::io::Error::other(
            "No H264 encoder found (amfh264enc/x264enc).",
        ));
    };

    let pipeline_desc = format!(
        "{src} !
         videoconvert !
         videorate !
         video/x-raw,framerate={fps}/1 !
         videoscale !
         video/x-raw,format=NV12 !
         capsfilter name=vcaps caps=video/x-raw,width={w},height={h},framerate={fps}/1 !
         identity name=ftap signal-handoffs=true silent=true !
         {enc} name=venc !
         h264parse config-interval=1 !
         video/x-h264,stream-format=byte-stream,alignment=au !
         identity name=keyreq silent=true !
         appsink name=hsink emit-signals=true sync=false max-buffers=2 drop=true",
        fps = ctrl.fps,
        w = ctrl.width,
        h = ctrl.height,
        enc = enc
    );

    let pipeline = gst::parse::launch(&pipeline_desc)
        .map_err(|e| std::io::Error::other(format!("parse_launch failed: {e:?}")))?
        .downcast::<gst::Pipeline>()
        .map_err(|e| std::io::Error::other(format!("not a pipeline: {e:?}")))?;

    let (sample_tx, sample_rx) = mpsc::channel::<gst::Sample>(8);

    let dropped_counter = Arc::new(AtomicU64::new(0));
    let dropped_counter_cb = dropped_counter.clone();

    let appsink = pipeline
        .by_name("hsink")
        .ok_or_else(|| std::io::Error::other("appsink hsink not found"))?
        .downcast::<gst_app::AppSink>()
        .map_err(|e| std::io::Error::other(format!("hsink not AppSink: {e:?}")))?;

    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                if sample_tx.try_send(sample).is_err() {
                    dropped_counter_cb.fetch_add(1, Ordering::Relaxed);
                }
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    let capsfilter = pipeline
        .by_name("vcaps")
        .ok_or_else(|| std::io::Error::other("capsfilter vcaps not found"))?;

    let encoder = pipeline
        .by_name("venc")
        .ok_or_else(|| std::io::Error::other("encoder venc not found"))?;

    // Low latency settings
    if enc_is_amf {
        set_prop_from_str(&encoder, "usage", "lowlatency");
        set_prop_from_str(&encoder, "rate-control", "cbr");
        set_prop_best_u32(&encoder, "bitrate", ctrl.bitrate_kbps as u32);
        set_prop_best_u32(&encoder, "b-frames", 0);
        set_prop_best_u32(&encoder, "gop-size", ctrl.fps as u32);
    } else {
        set_prop_best_u32(&encoder, "bitrate", ctrl.bitrate_kbps as u32);
        set_prop_from_str(&encoder, "tune", "zerolatency");
        set_prop_from_str(&encoder, "speed-preset", "ultrafast");
        set_prop_best_u32(&encoder, "key-int-max", ctrl.fps as u32);
        set_prop_best_u32(&encoder, "bframes", 0);
        set_prop_best_u32(&encoder, "byte-stream", 1);
    }

    // Server FPS counter
    let ftap = pipeline
        .by_name("ftap")
        .ok_or_else(|| std::io::Error::other("identity ftap not found"))?;

    let frame_counter = Arc::new(AtomicU64::new(0));
    {
        let fc = frame_counter.clone();
        let _ = ftap.connect("handoff", false, move |_values| {
            fc.fetch_add(1, Ordering::Relaxed);
            None
        });
    }

    Ok((
        GstStream {
            pipeline,
            capsfilter,
            encoder,
            frame_counter,
            dropped_counter,
        },
        sample_rx,
    ))
}

fn request_keyframe(pipeline: &gst::Pipeline) {
    let Some(keyreq) = pipeline.by_name("keyreq") else {
        return;
    };
    let Some(srcpad) = keyreq.static_pad("src") else {
        return;
    };

    let ev = gst_video::UpstreamForceKeyUnitEvent::builder()
        .all_headers(true)
        .build();

    if !srcpad.send_event(ev) {
        warn!("request_keyframe: send_event returned false");
    }
}

fn apply_ctrl(stream: &GstStream, ctrl: &StreamCtrl) -> std::io::Result<()> {
    let caps = gst::Caps::builder("video/x-raw")
        .field("width", ctrl.width)
        .field("height", ctrl.height)
        .field("framerate", gst::Fraction::new(ctrl.fps, 1))
        .build();
    stream.capsfilter.set_property("caps", &caps);
    set_prop_best_u32(&stream.encoder, "bitrate", ctrl.bitrate_kbps as u32);
    Ok(())
}

async fn pump_h264_samples(
    mut sample_rx: mpsc::Receiver<gst::Sample>,
    track: Arc<TrackLocalStaticSample>,
    ctrl_state: Arc<RwLock<StreamCtrl>>,
    stop: CancellationToken,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => {
                info!("pump_h264_samples cancelled");
                break;
            }
            opt = sample_rx.recv() => {
                let Some(sample) = opt else {
                    info!("sample_rx closed");
                    break;
                };

                let buffer = sample.buffer().ok_or_else(|| std::io::Error::other("no buffer"))?;
                let map = buffer.map_readable()
                    .map_err(|e| std::io::Error::other(format!("map buffer: {e}")))?;
                let data = map.as_slice();

                let fps = ctrl_state.read().await.fps.max(1) as u64;
                let dur = buffer.duration()
                    .map(|d| std::time::Duration::from_nanos(d.nseconds()))
                    .filter(|d| d.as_nanos() > 0)
                    .unwrap_or_else(|| std::time::Duration::from_nanos(1_000_000_000u64 / fps));

                let s = webrtc::media::Sample {
                    data: Bytes::copy_from_slice(data),
                    duration: dur,
                    ..Default::default()
                };

                if let Err(e) = track.write_sample(&s).await {
                    warn!("track.write_sample failed: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}

fn spawn_gst_bus_logger(
    pipeline: &gst::Pipeline,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let bus = pipeline.bus().expect("pipeline has no bus");
    tokio::spawn(async move {
        use gst::MessageView;
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    while let Some(msg) = bus.pop() {
                        match msg.view() {
                            MessageView::Error(e) => {
                                error!(
                                    "gst error from {:?}: {} (debug: {:?})",
                                    e.src().map(|s| s.path_string()),
                                    e.error(),
                                    e.debug()
                                );
                            }
                            MessageView::Warning(w) => {
                                warn!(
                                    "gst warning from {:?}: {} (debug: {:?})",
                                    w.src().map(|s| s.path_string()),
                                    w.error(),
                                    w.debug()
                                );
                            }
                            MessageView::StateChanged(s) => {
                                if let Some(src) = msg.src()
                                    && src.type_().name() == "GstPipeline" {
                                        info!("gst state changed: {:?} -> {:?}", s.old(), s.current());
                                }
                            }
                            MessageView::Eos(..) => warn!("gst EOS"),
                            _ => {}
                        }
                    }
                }
            }
        }
        info!("gst bus logger stopped");
    })
}

async fn start_stream_runtime(
    ctrl: StreamCtrl,
    ctrl_state: Arc<RwLock<StreamCtrl>>,
    track: Arc<TrackLocalStaticSample>,
    out_tx: mpsc::Sender<WsMsg>,
) -> std::io::Result<StreamRuntime> {
    let (stream, sample_rx) = build_pipeline_h264(&ctrl)?;

    stream
        .pipeline
        .set_state(gst::State::Playing)
        .map_err(|e| std::io::Error::other(format!("gst set_state(Playing) failed: {e:?}")))?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    request_keyframe(&stream.pipeline);
    info!("gstreamer pipeline -> PLAYING");

    // bus logger
    let bus_stop = CancellationToken::new();
    let bus_handle = spawn_gst_bus_logger(&stream.pipeline, bus_stop.child_token());

    // FPS reporter
    let fps_stop = CancellationToken::new();
    let fps_stop_child = fps_stop.child_token();
    let fc = stream.frame_counter.clone();
    let dropped = stream.dropped_counter.clone();
    let out_tx_fps = out_tx.clone();
    let fps_handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = fps_stop_child.cancelled() => break,
                _ = tick.tick() => {
                    let frames = fc.swap(0, Ordering::Relaxed);
                    let dropped_samples = dropped.swap(0, Ordering::Relaxed);
                    let _ = out_tx_fps.send(WsMsg::ServerStats(ServerStats {
                        fps: frames as f64,
                        dropped_samples,
                    })).await;
                }
            }
        }
        info!("fps reporter stopped");
    });

    // Pump
    let pump_stop = CancellationToken::new();
    let pump_stop_child = pump_stop.child_token();
    let pump_handle = tokio::spawn(async move {
        if let Err(e) = pump_h264_samples(sample_rx, track, ctrl_state, pump_stop_child).await {
            warn!("pump_h264_samples error: {e}");
        }
        info!("pump task ended");
    });

    Ok(StreamRuntime {
        stream,
        pump_stop,
        pump_handle,
        fps_stop,
        fps_handle,
        bus_stop,
        bus_handle,
    })
}

async fn stop_stream_runtime(rt: StreamRuntime) {
    rt.pump_stop.cancel();
    rt.fps_stop.cancel();
    rt.bus_stop.cancel();

    gst_stop_pipeline(&rt.stream.pipeline);

    let _ = rt.pump_handle.await;
    let _ = rt.fps_handle.await;
    let _ = rt.bus_handle.await;

    info!("stream runtime fully stopped");
}

/// Handle one complete JSON message (Offer / Ice / Ctrl / ClientStats).
async fn handle_ws_json(
    cfg: &ServerConfig,
    ctrl_state: Arc<RwLock<StreamCtrl>>,
    dc_next_id: Arc<std::sync::atomic::AtomicU64>,
    on_dc_message: Option<DataChannelMessageCallback>,
    out_tx: mpsc::Sender<WsMsg>,
    pc: Arc<RwLock<Option<Arc<RTCPeerConnection>>>>,
    runtime: Arc<RwLock<Option<StreamRuntime>>>,
    text: &str,
    track_slot: Arc<RwLock<Option<Arc<TrackLocalStaticSample>>>>,
) -> std::io::Result<()> {
    let m: WsMsg =
        serde_json::from_str(text).map_err(|e| std::io::Error::other(format!("Bad JSON: {e}")))?;

    match m {
        WsMsg::Offer(offer_sdp) => {
            // stop previous
            if let Some(old) = runtime.write().await.take() {
                stop_stream_runtime(old).await;
            }
            if let Some(old_peer) = pc.write().await.take() {
                let _ = old_peer.close().await;
            }
            *track_slot.write().await = None;

            let codec = choose_codec_from_offer(&offer_sdp);
            let negotiated_pt = find_pt_in_offer(&offer_sdp, codec.offer_rtpmap_token())
                .unwrap_or(codec.default_pt());
            let fmtp = find_fmtp_in_offer(&offer_sdp, negotiated_pt);

            let _ = out_tx
                .send(WsMsg::Info(format!("Selected codec: {codec:?}")))
                .await;
            let _ = out_tx
                .send(WsMsg::Info(format!("Negotiated PT: {negotiated_pt}")))
                .await;

            // MediaEngine / Interceptors
            let mut me = MediaEngine::default();
            me.register_codec(
                webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecParameters {
                    capability: codec_cap(codec, fmtp.as_deref()),
                    payload_type: negotiated_pt,
                    ..Default::default()
                },
                RTPCodecType::Video,
            )
            .map_err(|e| std::io::Error::other(format!("register_codec: {e}")))?;

            let mut registry = Registry::new();
            registry =
                webrtc::api::interceptor_registry::register_default_interceptors(registry, &mut me)
                    .map_err(|e| std::io::Error::other(format!("register interceptors: {e}")))?;

            // UDP ephemeral ports
            use webrtc::api::setting_engine::SettingEngine;
            let udp_network = webrtc::ice::udp_network::UDPNetwork::Ephemeral(
                webrtc::ice::udp_network::EphemeralUDP::new(cfg.udp_min, cfg.udp_max)
                    .map_err(|e| std::io::Error::other(format!("EphemeralUDP: {e}")))?,
            );
            let mut se = SettingEngine::default();
            se.set_udp_network(udp_network);

            let api = APIBuilder::new()
                .with_setting_engine(se)
                .with_media_engine(me)
                .with_interceptor_registry(registry)
                .build();

            let config = RTCConfiguration {
                ice_servers: vec![RTCIceServer {
                    urls: cfg.stun_urls.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            };

            let peer = Arc::new(
                api.new_peer_connection(config)
                    .await
                    .map_err(|e| std::io::Error::other(format!("new_peer_connection: {e}")))?,
            );

            //state logs + Info pushes
            {
                let out_tx = out_tx.clone();
                peer.on_peer_connection_state_change(Box::new(move |s| {
                    let out_tx = out_tx.clone();
                    Box::pin(async move {
                        info!("pc state: {s:?}");
                        let _ = out_tx.send(WsMsg::Info(format!("PC state: {s:?}"))).await;
                    })
                }));
            }
            {
                let out_tx = out_tx.clone();
                peer.on_ice_connection_state_change(Box::new(move |s| {
                    let out_tx = out_tx.clone();
                    Box::pin(async move {
                        info!("ice conn state: {s:?}");
                        let _ = out_tx
                            .send(WsMsg::Info(format!("ICE conn state: {s:?}")))
                            .await;
                    })
                }));
            }
            {
                let out_tx = out_tx.clone();
                peer.on_ice_gathering_state_change(Box::new(move |s| {
                    let out_tx = out_tx.clone();
                    Box::pin(async move {
                        info!("ice gathering state: {s:?}");
                        let _ = out_tx
                            .send(WsMsg::Info(format!("ICE gathering: {s:?}")))
                            .await;
                    })
                }));
            }
            // ICE -> outgoing
            {
                let out_tx = out_tx.clone();
                peer.on_ice_candidate(Box::new(move |c| {
                    let out_tx = out_tx.clone();
                    Box::pin(async move {
                        let Some(c) = c else { return };
                        match c.to_json() {
                            Ok(ice_init) => {
                                let wire = IceCandidateWire {
                                    candidate: ice_init.candidate,
                                    sdp_mid: ice_init.sdp_mid,
                                    sdp_mline_index: ice_init.sdp_mline_index,
                                    username_fragment: ice_init.username_fragment,
                                };
                                let _ = out_tx.send(WsMsg::Ice(wire)).await;
                            }
                            Err(e) => {
                                let _ = out_tx
                                    .send(WsMsg::Error(format!("ICE to_json failed: {e}")))
                                    .await;
                            }
                        }
                    })
                }));
            }

            {
                peer.on_data_channel(Box::new(move |dc| {
                    let on_dc_message = on_dc_message.clone();
                    let dc_next_id = dc_next_id.clone();

                    Box::pin(async move {
                        let dc_id = dc_next_id.fetch_add(1, Ordering::Relaxed);
                        let label = dc.label().to_string();
                        info!("[dc#{dc_id}] opened label={label}");

                        // Per-channel message forwarder
                        let cb = on_dc_message.clone();
                        dc.on_message(Box::new(move |msg: DataChannelMessage| {
                            let cb = cb.clone();
                            Box::pin(async move {
                                let Some(cb) = cb.as_ref() else {
                                    return;
                                };

                                if msg.is_string {
                                    match String::from_utf8(msg.data.to_vec()) {
                                        Ok(s) => cb(dc_id, DataChannelPayload::Text(s)),
                                        Err(_) => {
                                            cb(
                                                dc_id,
                                                DataChannelPayload::Binary(Bytes::copy_from_slice(
                                                    &msg.data,
                                                )),
                                            );
                                        }
                                    }
                                } else {
                                    cb(
                                        dc_id,
                                        DataChannelPayload::Binary(Bytes::copy_from_slice(
                                            &msg.data,
                                        )),
                                    );
                                }
                            })
                        }));
                    })
                }));
            }

            // Track
            let track = Arc::new(TrackLocalStaticSample::new(
                codec_cap(codec, fmtp.as_deref()),
                "video".to_string(),
                "desktop".to_string(),
            ));
            peer.add_track(track.clone())
                .await
                .map_err(|e| std::io::Error::other(format!("add_track: {e}")))?;

            // SDP
            peer.set_remote_description(
                webrtc::peer_connection::sdp::session_description::RTCSessionDescription::offer(
                    offer_sdp,
                )
                .map_err(|e| std::io::Error::other(format!("offer parse: {e}")))?,
            )
            .await
            .map_err(|e| std::io::Error::other(format!("set_remote_description: {e}")))?;

            let answer = peer
                .create_answer(None)
                .await
                .map_err(|e| std::io::Error::other(format!("create_answer: {e}")))?;
            peer.set_local_description(answer)
                .await
                .map_err(|e| std::io::Error::other(format!("set_local_description: {e}")))?;

            if let Some(local) = peer.local_description().await {
                let _ = out_tx.send(WsMsg::Answer(local.sdp)).await;
            }

            // Start runtime
            let ctrl = ctrl_state.read().await.clone();
            let rt = start_stream_runtime(ctrl, ctrl_state.clone(), track.clone(), out_tx.clone())
                .await?;

            *track_slot.write().await = Some(track);
            *runtime.write().await = Some(rt);
            *pc.write().await = Some(peer);

            let _ = out_tx.send(WsMsg::Info("Streaming started".into())).await;
        }

        WsMsg::Ice(cand) => {
            if let Some(peer) = pc.read().await.as_ref() {
                let c = webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                    candidate: cand.candidate,
                    sdp_mid: cand.sdp_mid,
                    sdp_mline_index: cand.sdp_mline_index,
                    username_fragment: cand.username_fragment,
                };
                if let Err(e) = peer.add_ice_candidate(c).await {
                    let _ = out_tx
                        .send(WsMsg::Error(format!("add_ice_candidate failed: {e}")))
                        .await;
                }
            } else {
                let _ = out_tx
                    .send(WsMsg::Error("ICE received but peer is not ready".into()))
                    .await;
            }
        }

        WsMsg::ClientStats(st) => {
            info!(
                "[client-stats] rtt={:?}ms jitter={:?}ms loss={:?} fps={:?} in_bps={:?}",
                st.rtt_ms, st.jitter_ms, st.loss, st.fps, st.available_in_bps
            );
        }

        WsMsg::Ctrl {
            width,
            height,
            fps,
            bitrate_kbps,
        } => {
            let prev = ctrl_state.read().await.clone();
            {
                let mut st = ctrl_state.write().await;
                st.width = width;
                st.height = height;
                st.fps = fps;
                st.bitrate_kbps = bitrate_kbps;
            }
            let next = ctrl_state.read().await.clone();
            let need_restart = ctrl_needs_restart(&prev, &next);

            if need_restart {
                let _ = out_tx
                    .send(WsMsg::Info(
                        "CTRL requires restart (size/fps changed)".into(),
                    ))
                    .await;

                if let Some(old) = runtime.write().await.take() {
                    stop_stream_runtime(old).await;
                }

                let Some(track) = track_slot.read().await.clone() else {
                    let _ = out_tx
                        .send(WsMsg::Error(
                            "Cannot restart: track not initialized. Send Offer first.".into(),
                        ))
                        .await;
                    return Ok(());
                };

                let rt =
                    start_stream_runtime(next.clone(), ctrl_state.clone(), track, out_tx.clone())
                        .await?;
                *runtime.write().await = Some(rt);

                let _ = out_tx
                    .send(WsMsg::Info(format!(
                        "CTRL applied with restart: {}x{}@{} bitrate={}kbps",
                        next.width, next.height, next.fps, next.bitrate_kbps
                    )))
                    .await;
            } else if let Some(rt) = runtime.read().await.as_ref() {
                if let Err(e) = apply_ctrl(&rt.stream, &next) {
                    let _ = out_tx
                        .send(WsMsg::Error(format!("apply_ctrl failed: {e}")))
                        .await;
                } else {
                    request_keyframe(&rt.stream.pipeline);
                    let _ = out_tx
                        .send(WsMsg::Info(format!(
                            "CTRL applied: {}x{}@{} bitrate={}kbps",
                            next.width, next.height, next.fps, next.bitrate_kbps
                        )))
                        .await;
                }
            } else {
                let _ = out_tx
                    .send(WsMsg::Error(
                        "CTRL received but stream is not running".into(),
                    ))
                    .await;
            }
        }
        // Other messages are ignored
        _ => {}
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub enum DataChannelPayload {
    Text(String),
    Binary(Bytes),
}

pub type DataChannelMessageCallback =
    Arc<dyn Fn(u64 /*id*/, DataChannelPayload) + Send + Sync + 'static>;

/// Public service you register into your router.
pub struct WebRTCServer {
    pub cfg: ServerConfig,
    pub initial_ctrl: StreamCtrl,
    pub index: Option<Bytes>,
    dc_next_id: Arc<std::sync::atomic::AtomicU64>,
    on_dc_message: Option<DataChannelMessageCallback>,
}

impl WebRTCServer {
    pub fn new(cfg: ServerConfig) -> Self {
        Self {
            cfg,
            initial_ctrl: StreamCtrl::default(),
            index: None,
            dc_next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            on_dc_message: None,
        }
    }

    pub fn set_on_dc_message(&mut self, cb: DataChannelMessageCallback) {
        self.on_dc_message = Some(cb);
    }
}

#[async_trait::async_trait(?Send)]
impl HAsyncService for WebRTCServer {
    async fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
        if !session.is_ws() {
            if let Some(index) = self.index.clone() {
                return session
                    .status_code(http::StatusCode::OK)
                    .header(
                        http::header::CONTENT_LENGTH,
                        http::HeaderValue::from_str(&index.len().to_string()).map_err(|e| {
                            std::io::Error::other(format!("Invalid header value: {e}"))
                        })?,
                    )?
                    .body(index)
                    .eom();
            }
            session
                .status_code(http::StatusCode::NOT_FOUND)
                .body(bytes::Bytes::from_static(b"WebRTC index page not found"))
                .eom()?;
            return Ok(());
        }

        // Accept WS
        if let Err(e) = session.ws_accept_async().await {
            session
                .status_code(http::StatusCode::BAD_REQUEST)
                .header_str("Connection", "close")?
                .eom()?;
            return Err(e);
        }

        let (out_tx, mut out_rx) = mpsc::channel::<WsMsg>(64);

        let pc: Arc<RwLock<Option<Arc<RTCPeerConnection>>>> = Arc::new(RwLock::new(None));
        let runtime: Arc<RwLock<Option<StreamRuntime>>> = Arc::new(RwLock::new(None));
        let track_slot: Arc<RwLock<Option<Arc<TrackLocalStaticSample>>>> =
            Arc::new(RwLock::new(None));
        let ctrl_state: Arc<RwLock<StreamCtrl>> = Arc::new(RwLock::new(self.initial_ctrl.clone()));

        let _ = out_tx.send(WsMsg::Info("WS connected".into())).await;

        // Fragmentation state
        let mut frag_buf = BytesMut::new();
        let mut expecting_cont = false;
        let mut initial_is_text = false;

        let err_protocol = Bytes::from_static(b"protocol error");
        let err_unexpected = Bytes::from_static(b"unexpected continue");
        let err_utf8 = Bytes::from_static(b"invalid utf8");

        loop {
            tokio::select! {
                // Prefer reading frames so we don't build up backpressure if client is chatty
                biased;

                incoming = session.ws_read_async() => {
                    let (code, payload, fin) = incoming?;

                    match code {
                        OpCode::Ping => session.ws_write_async(OpCode::Pong, payload, true).await?,
                        OpCode::Pong => {}
                        OpCode::Close => {
                            session.ws_write_async(OpCode::Close, payload, true).await?;
                            break;
                        }

                        OpCode::Text | OpCode::Binary => {
                            if expecting_cont {
                                session.ws_close_async(Some(err_protocol)).await?;
                                break;
                            }

                            if !fin {
                                frag_buf.clear();
                                frag_buf.extend_from_slice(payload.as_ref());
                                expecting_cont = true;
                                initial_is_text = matches!(code, OpCode::Text);
                                continue;
                            }

                            // parity with Warp: ignore non-text by default
                            if matches!(code, OpCode::Binary) {
                                continue;
                            }

                            // single-frame text JSON
                            let text = match std::str::from_utf8(payload.as_ref()) {
                                Ok(s) => s,
                                Err(_) => {
                                    session.ws_close_async(Some(err_utf8)).await?;
                                    break;
                                }
                            };

                            if let Err(e) = handle_ws_json(
                                &self.cfg,
                                ctrl_state.clone(),
                                self.dc_next_id.clone(),
                                self.on_dc_message.clone(),
                                out_tx.clone(),
                                pc.clone(),
                                runtime.clone(),
                                text,
                                track_slot.clone(),
                            ).await {
                                let _ = out_tx.send(WsMsg::Error(format!("{e}"))).await;
                            }
                        }

                        OpCode::Continue => {
                            if !expecting_cont {
                                session.ws_close_async(Some(err_unexpected)).await?;
                                break;
                            }

                            frag_buf.extend_from_slice(payload.as_ref());

                            if fin {
                                let whole = frag_buf.as_ref();

                                if initial_is_text {
                                    let text = match std::str::from_utf8(whole) {
                                        Ok(s) => s,
                                        Err(_) => {
                                            session.ws_close_async(Some(err_utf8)).await?;
                                            break;
                                        }
                                    };

                                    if let Err(e) = handle_ws_json(
                                        &self.cfg,
                                        ctrl_state.clone(),
                                        self.dc_next_id.clone(),
                                        self.on_dc_message.clone(),
                                        out_tx.clone(),
                                        pc.clone(),
                                        runtime.clone(),
                                        text,
                                        track_slot.clone(),
                                    ).await {
                                        let _ = out_tx.send(WsMsg::Error(format!("{e}"))).await;
                                    }
                                } else {
                                    // binary fragmented: parity with Warp (ignore)
                                }

                                frag_buf.clear();
                                expecting_cont = false;
                                initial_is_text = false;
                            }
                        }
                    }
                }

                opt = out_rx.recv() => {
                    let Some(m) = opt else { break };

                    let bytes = match serde_json::to_vec(&m) {
                        Ok(v) => v,
                        Err(e) => {
                            // best-effort fallback JSON
                            format!(r#"{{"type":"Error","data":"json encode failed: {e}"}}"#).into_bytes()
                        }
                    };

                    session.ws_write_async(OpCode::Text, Bytes::from(bytes), true).await?;
                }
            }
        }

        // Cleanup
        if let Some(rt) = runtime.write().await.take() {
            stop_stream_runtime(rt).await;
        }
        if let Some(peer) = pc.write().await.take()
            && let Err(e) = peer.close().await
        {
            warn!("peer.close failed: {e}");
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "ws done",
        ))
    }
}

impl HFactory for WebRTCServer {
    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    type HAsyncService = Self;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        WebRTCServer {
            cfg: self.cfg.clone(),
            initial_ctrl: self.initial_ctrl.clone(),
            index: self.index.clone(),
            dc_next_id: self.dc_next_id.clone(),
            on_dc_message: self.on_dc_message.clone(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::network::http::server::{H2Config, HFactory};
    use crate::stream::webrtc::{DataChannelPayload, WebRTCServer, init};
    use bytes::Bytes;
    use tracing::info;

    #[test]
    fn test_webrtc() {
        use crate::network::http::server::tests::create_self_signed_tls_pems;
        let (cert, key) = create_self_signed_tls_pems();

        let html_file = std::path::Path::new(file!())
            .parent()
            .unwrap()
            .join("webrtc.html");

        init().expect("webRTC init failed");
        const ADDRESS_PORT: &str = "127.0.0.1:8080";
        let mut webrtc_server = WebRTCServer {
            cfg: Default::default(),
            initial_ctrl: Default::default(),
            index: std::fs::read(html_file).ok().map(Bytes::from),
            dc_next_id: Default::default(),
            on_dc_message: Default::default(),
        };
        webrtc_server.set_on_dc_message(std::sync::Arc::new(|dc_id, payload| match payload {
            DataChannelPayload::Text(s) => info!("[dc#{dc_id}] TEXT: {}", s),
            DataChannelPayload::Binary(b) => info!("[dc#{dc_id}] BIN: {} bytes", b.len()),
        }));
        webrtc_server
            .start_h2_tls(
                ADDRESS_PORT,
                (None, cert.as_bytes(), key.as_bytes()),
                H2Config::default(),
            )
            .expect("start_webrtc_server failed");
    }
}
