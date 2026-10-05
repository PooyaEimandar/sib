use crate::network::http::server::{H2Config, HFactory};
use crate::stream::webrtc::{DataChannelPayload, Server};
use bytes::Bytes;
use tracing::info;

#[test]
fn test_webrtc() {
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let mtls = crate::MtlsIdentity::generate(&[], &[], false);

    let html_file = std::path::Path::new(file!())
        .parent()
        .unwrap()
        .join("webrtc.html");

    crate::stream::init().expect("webRTC init failed");
    const ADDRESS_PORT: &str = "127.0.0.1:8080";

    let mut webrtc_server = Server::new(
        Default::default(),
        Default::default(),
        std::fs::read(html_file).ok().map(Bytes::from),
        None, // Some(RtmpBroadcaster {
              //     ingest_url: "".to_owned(),
              //     stream_key: "".to_owned(),
              //     bitrate_kbps: Some(2500),
              //     gop_seconds: Some(2),
              // }),
    );

    webrtc_server.set_on_dc_message(std::sync::Arc::new(|dc_id, payload| match payload {
        DataChannelPayload::Text(s) => info!("[dc#{dc_id}] TEXT: {}", s),
        DataChannelPayload::Binary(b) => info!("[dc#{dc_id}] BIN: {} bytes", b.len()),
    }));

    webrtc_server.set_on_event(std::sync::Arc::new(|ev| {
        info!("[event] {:?}", ev);
    }));

    webrtc_server
        .start_h2_tls(
            ADDRESS_PORT,
            (
                Some(mtls.ca_cert_pem.as_bytes()),
                mtls.server_cert_pem.as_bytes(),
                mtls.server_key_pem.as_bytes(),
            ),
            H2Config::default(),
            cancel_token,
        )
        .expect("start_webrtc_server failed");
}

/// Drives the server half of a session against a webrtc client peer over
/// loopback: offer, answer, trickled ICE both ways, media out, data in. Runs
/// without GStreamer's capture sources, so it needs no screen or microphone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_peer_streams_samples_and_receives_data_channel_messages() {
    use super::*;
    use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    use tokio::time::timeout;
    use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};

    const WAIT: Duration = Duration::from_secs(20);
    // SPS, PPS and an IDR slice, Annex-B framed.
    const H264_FRAME: &[u8] = &[
        0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, 0xda, 0x01, 0x40, 0x16, 0xe8, 0x40, //
        0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, //
        0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x33, 0xff, 0xfe, 0xf6, 0xf0, 0xfe,
    ];

    struct Client {
        ice_tx: mpsc::UnboundedSender<RTCIceCandidateInit>,
        track_tx: mpsc::UnboundedSender<Arc<dyn TrackRemote>>,
    }

    #[async_trait::async_trait]
    impl PeerConnectionEventHandler for Client {
        async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
            if let Ok(init) = event.candidate.to_json() {
                let _ = self.ice_tx.send(init);
            }
        }
        async fn on_track(&self, track: Arc<dyn TrackRemote>) {
            let _ = self.track_tx.send(track);
        }
    }

    // The server half, as a WebSocket session sets it up.
    let (out_tx, mut out_rx) = mpsc::channel::<WsMsg>(64);
    let (dc_tx, mut dc_rx) = mpsc::unbounded_channel::<(u64, DataChannelPayload)>();
    let ctx = WsCtx {
        ws_id: 1,
        cfg: Arc::new(ServerConfig {
            stun_urls: Vec::new(),
            ..Default::default()
        }),
        out_tx,
        ctrl_state: Arc::new(RwLock::new(StreamCtrl::default())),
        pc: Arc::new(RwLock::new(None)),
        runtime: Arc::new(RwLock::new(None)),
        track_slot: Arc::new(RwLock::new(None)),
        audio_track_slot: Arc::new(RwLock::new(None)),
        pc_id_slot: Arc::new(RwLock::new(None)),
        pc_next_id: Arc::new(AtomicU64::new(1)),
        on_event: None,
        dc_next_id: Arc::new(AtomicU64::new(1)),
        on_dc_message: Some(Arc::new(move |dc_id, payload| {
            let _ = dc_tx.send((dc_id, payload));
        })),
        last_keyreq_ms: Arc::new(AtomicU64::new(0)),
        last_bitrate_change_ms: Arc::new(AtomicU64::new(0)),
        rtmp: None,
    };

    // The browser half: receive-only media and one data channel.
    let (ice_tx, mut ice_rx) = mpsc::unbounded_channel();
    let (track_tx, mut track_rx) = mpsc::unbounded_channel();
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().unwrap();
    let registry = register_default_interceptors(Registry::new(), &mut media_engine).unwrap();
    let client: Arc<dyn PeerConnection> = Arc::new(
        PeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_handler(Arc::new(Client { ice_tx, track_tx }))
            .with_udp_addrs(vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))])
            .build()
            .await
            .unwrap(),
    );
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        client
            .add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
    }
    let client_dc = client.create_data_channel("ctrl", None).await.unwrap();
    let offer = client.create_offer(None).await.unwrap();
    client.set_local_description(offer).await.unwrap();
    let offer_sdp = client.local_description().await.unwrap().sdp;

    let (video, audio) = negotiate(&ctx, offer_sdp).await.unwrap();
    let ports = ctx.cfg.udp_min..=ctx.cfg.udp_max;
    assert!(ctx.pc.read().await.is_some());

    // Frames written before ICE connects are dropped, not fatal.
    assert!(video.write(H264_FRAME, Duration::from_millis(33)).await);

    // Relay signalling until the client hears the server's media.
    let server_ice = |ctx: WsCtx, init: RTCIceCandidateInit| async move {
        let wire = WsMsg::Ice(IceCandidateWire {
            candidate: init.candidate,
            sdp_mid: init.sdp_mid,
            sdp_mline_index: init.sdp_mline_index,
            username_fragment: init.username_fragment,
        });
        handle_ws_json(ctx, &serde_json::to_string(&wire).unwrap())
            .await
            .unwrap();
    };
    let writer = {
        let (video, audio) = (video.clone(), audio.clone());
        tokio::spawn(async move {
            loop {
                assert!(video.write(H264_FRAME, Duration::from_millis(33)).await);
                assert!(
                    audio
                        .write(&[0xfc, 0xff, 0xfe], Duration::from_millis(20))
                        .await
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    let mut server_candidate_ports = Vec::new();
    let video_track = timeout(WAIT, async {
        loop {
            tokio::select! {
                Some(msg) = out_rx.recv() => match msg {
                    WsMsg::Answer(sdp) => client
                        .set_remote_description(RTCSessionDescription::answer(sdp).unwrap())
                        .await
                        .unwrap(),
                    WsMsg::Ice(wire) => {
                        if let Some(port) = wire.candidate.split_whitespace().nth(5) {
                            server_candidate_ports.push(port.parse::<u16>().unwrap());
                        }
                        client
                            .add_ice_candidate(RTCIceCandidateInit {
                                candidate: wire.candidate,
                                sdp_mid: wire.sdp_mid,
                                sdp_mline_index: wire.sdp_mline_index,
                                username_fragment: wire.username_fragment,
                                ..Default::default()
                            })
                            .await
                            .unwrap();
                    }
                    WsMsg::Error(e) => panic!("server reported: {e}"),
                    _ => {}
                },
                Some(init) = ice_rx.recv() => server_ice(ctx.clone(), init).await,
                Some(track) = track_rx.recv() => {
                    if track.kind().await == RtpCodecKind::Video {
                        break track;
                    }
                }
            }
        }
    })
    .await
    .expect("the client never received the video track");

    // Every packet carries the server's SSRC and the payload type the
    // client offered for H.264.
    let packet = timeout(WAIT, async {
        loop {
            match video_track.poll().await {
                Some(TrackRemoteEvent::OnRtpPacket(packet)) => break packet,
                Some(_) => continue,
                None => panic!("the video track ended before any packet"),
            }
        }
    })
    .await
    .expect("no video RTP packet arrived");
    assert_eq!(packet.header.ssrc, video.ssrc);
    assert_eq!(packet.header.payload_type, video.payload_type);
    assert!(!server_candidate_ports.is_empty());
    assert!(
        server_candidate_ports
            .iter()
            .all(|port| ports.contains(port)),
        "ICE candidates {server_candidate_ports:?} left {ports:?}"
    );

    // Data channel messages reach the session's callback, text and binary.
    timeout(WAIT, async {
        while !matches!(
            client_dc.poll().await,
            Some(DataChannelEvent::OnOpen) | None
        ) {}
    })
    .await
    .expect("the data channel never opened");
    client_dc.send_text("hello").await.unwrap();
    client_dc
        .send(bytes::BytesMut::from(&[1_u8, 2, 3][..]))
        .await
        .unwrap();
    let mut received = Vec::new();
    while received.len() < 2 {
        let (_, payload) = timeout(WAIT, dc_rx.recv())
            .await
            .expect("a data channel message never arrived")
            .unwrap();
        received.push(payload);
    }
    assert!(matches!(&received[0], DataChannelPayload::Text(text) if text == "hello"));
    assert!(matches!(&received[1], DataChannelPayload::Binary(data) if data[..] == [1, 2, 3]));

    writer.abort();
    client.close().await.unwrap();
    if let Some(peer) = ctx.pc.write().await.take() {
        peer.close().await.unwrap();
    }
}
