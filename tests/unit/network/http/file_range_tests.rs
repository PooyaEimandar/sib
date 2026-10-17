use super::{EncodingType, FileCache};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version, header};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};
use tokio::io::AsyncReadExt;

struct Fixture {
    root: PathBuf,
    cache: FileCache,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Wall-clock timestamps can coincide across concurrent test threads.
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sib-file-ranges-{}-{unique}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        for (directory, extension, compressed) in [
            ("gz", "gz", super::encode_gzip(b"0123456789", 1).unwrap()),
            (
                "br",
                "br",
                super::encode_brotli(b"0123456789", 4096, 1, 22).unwrap(),
            ),
            (
                "zstd",
                "zstd",
                super::encode_zstd(b"0123456789", 1).unwrap(),
            ),
        ] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            for name in ["asset.txt", "asset.wasm", "asset.pak"] {
                std::fs::write(root.join(name), b"0123456789").unwrap();
                std::fs::write(
                    root.join(directory).join(format!("{name}.{extension}")),
                    &compressed,
                )
                .unwrap();
            }
        }
        std::fs::write(root.join("plain.txt"), b"0123456789").unwrap();
        std::fs::write(root.join("texture.ktx2"), b"0123456789").unwrap();
        std::fs::write(root.join("empty.txt"), b"").unwrap();
        Self {
            root,
            cache: FileCache::new(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    #[cfg(feature = "net-h1-server")]
    H1Sync,
    H1Async,
    H2,
}

const PROTOCOLS: &[Protocol] = &[
    #[cfg(feature = "net-h1-server")]
    Protocol::H1Sync,
    Protocol::H1Async,
    Protocol::H2,
];

struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn parse_h1(bytes: &[u8]) -> Response {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(body_start) = parsed.parse(bytes).unwrap() else {
        panic!("incomplete HTTP response");
    };
    Response {
        status: StatusCode::from_u16(parsed.code.unwrap()).unwrap(),
        headers: parsed
            .headers
            .iter()
            .map(|h| {
                (
                    http::HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
                    HeaderValue::from_bytes(h.value).unwrap(),
                )
            })
            .collect(),
        body: bytes[body_start..].to_vec(),
    }
}

async fn response(
    fixture: &Fixture,
    protocol: Protocol,
    file: &str,
    method: Method,
    headers: HeaderMap,
    allow_ranges: bool,
) -> Response {
    let encodings = [
        EncodingType::Br {
            buffer_size: 4096,
            quality: 1,
            lgwindow: 22,
        },
        EncodingType::Gzip { level: 1 },
        EncodingType::Zstd { level: 1 },
    ];
    response_with_encodings(
        fixture,
        protocol,
        file,
        method,
        headers,
        allow_ranges,
        &encodings,
    )
    .await
}

async fn response_with_encodings(
    fixture: &Fixture,
    protocol: Protocol,
    file: &str,
    method: Method,
    headers: HeaderMap,
    allow_ranges: bool,
    encodings: &[EncodingType],
) -> Response {
    tokio::time::timeout(Duration::from_secs(10), async {
        let path = fixture.root.join(file);
        let thresholds = (1, 64 * 1024); // Exercise on-the-fly fallback for plain.txt too.
        let streaming = (64 * 1024, 1024);
        let options = ("inline", allow_ranges);
        match protocol {
            #[cfg(feature = "net-h1-server")]
            Protocol::H1Sync => {
                use crate::network::http::h1_session::new_session;
                use bytes::BytesMut;
                let mut request = format!("{method} /{file} HTTP/1.1\r\nHost: localhost\r\n");
                for (name, value) in &headers {
                    request.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
                }
                request.push_str("\r\n");
                let mut request = BytesMut::from(request.as_bytes());
                let mut reply = BytesMut::new();
                let mut stream = std::io::Cursor::new(Vec::new());
                let peer = "127.0.0.1".parse().unwrap();
                let mut session = new_session(&mut stream, &peer, &mut request, &mut reply)
                    .unwrap()
                    .unwrap();
                super::serve_h1(
                    &mut session,
                    &path,
                    &fixture.cache,
                    encodings,
                    thresholds,
                    streaming,
                    options,
                )
                .unwrap();
                drop(session);
                parse_h1(stream.get_ref())
            }
            Protocol::H1Async => {
                use crate::network::http::h1_session_async::H1SessionAsync;
                let (mut server, mut client) = tokio::io::duplex(16 * 1024);
                let mut session = H1SessionAsync::new(
                    "127.0.0.1".parse().unwrap(),
                    &mut server,
                    (method, Version::HTTP_11),
                    Uri::from_static("/asset.txt"),
                    (headers, Bytes::new()),
                    false,
                    false,
                );
                super::serve_h1_async(
                    &mut session,
                    &path,
                    &fixture.cache,
                    encodings,
                    thresholds,
                    streaming,
                    options,
                )
                .await
                .unwrap();
                drop(session);
                drop(server);
                let mut bytes = Vec::new();
                client.read_to_end(&mut bytes).await.unwrap();
                parse_h1(&bytes)
            }
            Protocol::H2 => {
                use crate::network::http::h2_session::H2Session;
                let (server_io, client_io) = tokio::io::duplex(16 * 1024);
                let server = async {
                    let mut conn = h2::server::handshake(server_io).await.unwrap();
                    let (request, reply) = conn.accept().await.unwrap().unwrap();
                    let mut session = H2Session::new("127.0.0.1".parse().unwrap(), request, reply);
                    super::serve_h2(
                        &mut session,
                        &path,
                        &fixture.cache,
                        encodings,
                        thresholds,
                        streaming,
                        options,
                    )
                    .await
                    .unwrap();
                    drop(session);
                    conn.graceful_shutdown();
                    // Keep driving the connection until the response is delivered.
                    assert!(
                        !matches!(conn.accept().await, Some(Ok(_))),
                        "unexpected second request"
                    );
                };
                let client = async {
                    let (mut sender, conn) = h2::client::handshake(client_io).await.unwrap();
                    let request = async {
                        let mut request = http::Request::builder()
                            .method(method)
                            .uri("https://localhost/asset.txt")
                            .body(())
                            .unwrap();
                        *request.headers_mut() = headers;
                        let (response, _) = sender.send_request(request, true).unwrap();
                        let response = response.await.unwrap();
                        let (parts, mut body) = response.into_parts();
                        let mut bytes = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            bytes.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                        Response {
                            status: parts.status,
                            headers: parts.headers,
                            body: bytes,
                        }
                    };
                    // The driver can finish after queuing the final DATA frame but before
                    // the response future consumes it. Drain both before checking completion.
                    let (result, response) = tokio::join!(conn, request);
                    result.unwrap();
                    response
                };
                let ((), response) = tokio::join!(server, client);
                response
            }
        }
    })
    .await
    .expect("file range response must complete")
}

fn range_headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_str(value).unwrap());
    headers
}

#[tokio::test(flavor = "current_thread")]
async fn single_byte_ranges_have_correct_status_headers_and_payload() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for (range, status, content_range, body) in [
            ("bytes=2-4", 206, Some("bytes 2-4/10"), "234"),
            ("bytes=8-", 206, Some("bytes 8-9/10"), "89"),
            ("bytes=-3", 206, Some("bytes 7-9/10"), "789"),
            ("bytes=-100", 206, Some("bytes 0-9/10"), "0123456789"),
            (
                "bytes=8-18446744073709551616",
                206,
                Some("bytes 8-9/10"),
                "89",
            ),
            ("bytes=10-", 416, Some("bytes */10"), ""),
            ("bytes=20-30", 416, Some("bytes */10"), ""),
            ("bytes=-0", 416, Some("bytes */10"), ""),
            ("bytes=2-bad", 200, None, "0123456789"),
            ("bytes=bad-2", 200, None, "0123456789"),
            ("bytes=4-2", 200, None, "0123456789"),
            ("bytes=0-1,4-5", 200, None, "0123456789"),
            ("items=0-1", 200, None, "0123456789"),
        ] {
            let r = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                range_headers(range),
                true,
            )
            .await;
            assert_eq!(r.status.as_u16(), status, "{protocol:?}: {range}");
            assert_eq!(
                r.headers
                    .get(header::CONTENT_RANGE)
                    .map(|h| h.to_str().unwrap()),
                content_range,
                "{protocol:?}: {range}"
            );
            assert_eq!(r.body, body.as_bytes(), "{protocol:?}: {range}");
            assert_eq!(r.headers[header::CONTENT_LENGTH], body.len().to_string());
            assert_eq!(r.headers[header::ACCEPT_RANGES], "bytes");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ranges_respect_method_configuration_and_cache_preconditions() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        let r = response(
            &fixture,
            protocol,
            "asset.txt",
            Method::HEAD,
            range_headers("bytes=20-"),
            true,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(!r.headers.contains_key(header::CONTENT_RANGE));
        assert!(r.body.is_empty());

        let r = response(
            &fixture,
            protocol,
            "asset.txt",
            Method::GET,
            range_headers("bytes=20-"),
            false,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(!r.headers.contains_key(header::CONTENT_RANGE));
        assert!(!r.headers.contains_key(header::ACCEPT_RANGES));
        assert_eq!(r.body, b"0123456789");

        // Without trustworthy If-Range validation, a full response avoids combining
        // bytes from different representations, even for an out-of-bounds range.
        for range in ["bytes=2-4", "bytes=20-"] {
            let mut headers = range_headers(range);
            headers.insert(
                header::IF_RANGE,
                HeaderValue::from_static("\"old-version\""),
            );
            let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
            assert_eq!(r.status, StatusCode::OK);
            assert!(!r.headers.contains_key(header::CONTENT_RANGE));
            assert_eq!(r.body, b"0123456789");
        }

        let mut headers = range_headers("bytes=20-");
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED);
        assert!(!r.headers.contains_key(header::CONTENT_RANGE));
        assert!(r.body.is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn empty_files_and_encoded_representations_have_safe_range_errors() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for (range, status, content_range) in [
            ("bytes=0-", 416, Some("bytes */0")),
            ("bytes=-0", 416, Some("bytes */0")),
            ("bytes=-1", 200, None),
        ] {
            let r = response(
                &fixture,
                protocol,
                "empty.txt",
                Method::GET,
                range_headers(range),
                true,
            )
            .await;
            assert_eq!(r.status.as_u16(), status);
            assert_eq!(
                r.headers
                    .get(header::CONTENT_RANGE)
                    .map(|h| h.to_str().unwrap()),
                content_range
            );
            assert!(r.body.is_empty());
        }
        let mut headers = range_headers("bytes=99999-");
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
        let size = std::fs::metadata(fixture.root.join("asset.txt"))
            .unwrap()
            .len();
        assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(r.headers[header::CONTENT_RANGE], format!("bytes */{size}"));
        assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
        assert_eq!(r.headers[header::CONTENT_LENGTH], "0");
        assert!(r.body.is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn compressed_sidecars_never_change_asset_range_offsets() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for encoding in ["gzip", "br", "zstd"] {
            for file in ["asset.txt", "asset.wasm", "asset.pak", "plain.txt"] {
                let original = response(
                    &fixture,
                    protocol,
                    file,
                    Method::GET,
                    HeaderMap::new(),
                    true,
                )
                .await;
                for (range, status, content_range, body) in [
                    ("bytes=2-4", 206, "bytes 2-4/10", "234"),
                    ("bytes=-3", 206, "bytes 7-9/10", "789"),
                    ("bytes=-100", 206, "bytes 0-9/10", "0123456789"),
                    ("bytes=10-", 416, "bytes */10", ""),
                    ("bytes=20-", 416, "bytes */10", ""),
                ] {
                    let mut headers = range_headers(range);
                    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(encoding));
                    let r = response(&fixture, protocol, file, Method::GET, headers, true).await;
                    assert_eq!(
                        r.status.as_u16(),
                        status,
                        "{protocol:?}: {encoding} {file} {range}"
                    );
                    assert_eq!(r.headers[header::CONTENT_RANGE], content_range);
                    assert_eq!(r.headers[header::CONTENT_LENGTH], body.len().to_string());
                    assert_eq!(r.headers[header::VARY], "Accept-Encoding, Range");
                    assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
                    assert_eq!(r.body, body.as_bytes());
                    if status == 206 {
                        assert_eq!(r.headers[header::ETAG], original.headers[header::ETAG]);
                    }
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn range_requests_reject_forbidden_identity_encoding() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for file in ["asset.wasm", "texture.ktx2", "plain.txt"] {
            for accept in [
                "gzip, br, zstd, identity;q=0",
                "gzip, *;q=0",
                "*;q=0",
                "IDENTITY;Q=0.000",
            ] {
                let mut headers = range_headers("bytes=2-4");
                headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(accept));
                let r = response(&fixture, protocol, file, Method::GET, headers, true).await;
                assert_eq!(
                    r.status,
                    StatusCode::NOT_ACCEPTABLE,
                    "{protocol:?}: {accept} {file}"
                );
                assert_eq!(r.headers[header::CONTENT_LENGTH], "0");
                assert_eq!(r.headers[header::VARY], "Accept-Encoding, Range");
                assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
                assert!(!r.headers.contains_key(header::CONTENT_RANGE));
                assert!(r.body.is_empty());
            }
            // Explicit identity permission overrides a wildcard exclusion, even
            // when the client gives compression a higher preference.
            let mut headers = range_headers("bytes=2-4");
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("gzip;q=1, identity;q=0.1, *;q=0"),
            );
            let r = response(&fixture, protocol, file, Method::GET, headers, true).await;
            assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
            assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
            assert_eq!(r.body, b"234");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn full_downloads_keep_compression_and_range_validators_use_original_bytes() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for (encoding, sidecar) in [
            ("gzip", "gz/asset.txt.gz"),
            ("br", "br/asset.txt.br"),
            ("zstd", "zstd/asset.txt.zstd"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(encoding));
            for file in ["asset.txt", "plain.txt"] {
                let r =
                    response(&fixture, protocol, file, Method::GET, headers.clone(), true).await;
                assert_eq!(r.status, StatusCode::OK);
                assert_eq!(r.headers[header::CONTENT_ENCODING], encoding);
                assert_eq!(r.headers[header::VARY], "Accept-Encoding, Range");
                assert_eq!(r.body, std::fs::read(fixture.root.join(sidecar)).unwrap());
            }
            let compressed = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            let original = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                HeaderMap::new(),
                true,
            )
            .await;
            assert_ne!(
                compressed.headers[header::ETAG],
                original.headers[header::ETAG]
            );

            headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-4"));
            let disabled = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                false,
            )
            .await;
            assert_eq!(disabled.status, StatusCode::OK);
            assert_eq!(disabled.headers[header::CONTENT_ENCODING], encoding);
            assert_eq!(disabled.headers[header::VARY], "Accept-Encoding");
            assert_eq!(disabled.body, compressed.body);
            let head = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::HEAD,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(head.status, StatusCode::OK);
            assert_eq!(head.headers[header::CONTENT_ENCODING], encoding);
            assert!(!head.headers.contains_key(header::CONTENT_RANGE));
            assert!(head.body.is_empty());

            headers.insert(
                header::IF_NONE_MATCH,
                compressed.headers[header::ETAG].clone(),
            );
            let r = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
            assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
            assert_eq!(r.body, b"234");
            headers.insert(
                header::IF_NONE_MATCH,
                original.headers[header::ETAG].clone(),
            );
            let r = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(r.status, StatusCode::NOT_MODIFIED);
            assert_eq!(r.headers[header::VARY], "Accept-Encoding, Range");
            assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
            assert!(r.body.is_empty());

            headers.remove(header::IF_NONE_MATCH);
            headers.insert(header::IF_RANGE, compressed.headers[header::ETAG].clone());
            let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
            assert_eq!(r.status, StatusCode::OK);
            assert!(!r.headers.contains_key(header::CONTENT_ENCODING));
            assert!(!r.headers.contains_key(header::CONTENT_RANGE));
            assert_eq!(r.headers[header::ETAG], original.headers[header::ETAG]);
            assert_eq!(r.body, b"0123456789");
        }
    }
}

#[path = "file_precondition_tests.rs"]
mod precondition_tests;

#[path = "file_etag_tests.rs"]
mod etag_tests;

#[path = "file_streaming_tests.rs"]
mod streaming_tests;

#[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
#[path = "file_h2_io_tests.rs"]
mod h2_io_tests;
