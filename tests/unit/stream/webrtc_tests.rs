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
