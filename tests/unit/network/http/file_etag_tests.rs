use super::*;
use sha2::{Digest, Sha256};
use std::fs::{File, FileTimes};

fn set_modified(path: &std::path::Path, modified: SystemTime) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(modified))
        .unwrap();
}

fn expected_tag(bytes: &[u8], encoding: &str) -> String {
    let suffix = if encoding.is_empty() {
        String::new()
    } else {
        format!("-{encoding}")
    };
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("\"sha256-{digest}{suffix}\"")
}

#[tokio::test(flavor = "current_thread")]
async fn etags_hash_the_selected_bytes_including_empty_and_compressed_files() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for file in ["plain.txt", "asset.txt", "empty.txt"] {
            for encoding in ["", "gzip", "br", "zstd"] {
                let mut headers = HeaderMap::new();
                if !encoding.is_empty() {
                    headers.insert(
                        header::ACCEPT_ENCODING,
                        HeaderValue::from_str(encoding).unwrap(),
                    );
                }
                let r =
                    response(&fixture, protocol, file, Method::GET, headers.clone(), true).await;
                assert_eq!(r.status, StatusCode::OK);
                let actual_encoding = r
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .map_or("", |h| h.to_str().unwrap());
                assert_eq!(
                    r.headers[header::ETAG],
                    expected_tag(&r.body, actual_encoding),
                    "{protocol:?}: {file} / {encoding}"
                );
                let head = response(
                    &fixture,
                    protocol,
                    file,
                    Method::HEAD,
                    headers.clone(),
                    true,
                )
                .await;
                assert_eq!(head.headers[header::ETAG], r.headers[header::ETAG]);
                assert!(head.body.is_empty());
                headers.insert(header::IF_NONE_MATCH, r.headers[header::ETAG].clone());
                let unchanged =
                    response(&fixture, protocol, file, Method::GET, headers, true).await;
                assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
                assert!(unchanged.body.is_empty());
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn etags_change_for_same_size_rewrites_with_equal_earlier_or_subsecond_mtime() {
    for &protocol in PROTOCOLS {
        for offset in [
            Duration::ZERO,
            Duration::from_nanos(100),
            Duration::from_secs(1),
        ] {
            let fixture = Fixture::new();
            let path = fixture.root.join("plain.txt");
            let initial_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);
            set_modified(&path, initial_time);
            let original = response(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                HeaderMap::new(),
                true,
            )
            .await;
            std::fs::write(&path, b"abcdefghij").unwrap();
            let updated_time = if offset == Duration::from_secs(1) {
                initial_time - offset
            } else {
                initial_time + offset
            };
            set_modified(&path, updated_time);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::IF_NONE_MATCH,
                original.headers[header::ETAG].clone(),
            );
            let changed =
                response(&fixture, protocol, "plain.txt", Method::GET, headers, true).await;
            assert_eq!(changed.status, StatusCode::OK, "{protocol:?}: {offset:?}");
            assert_eq!(changed.body, b"abcdefghij");
            assert_ne!(
                changed.headers[header::ETAG],
                original.headers[header::ETAG]
            );
            let mut headers = range_headers("bytes=0-2");
            headers.insert(header::IF_MATCH, original.headers[header::ETAG].clone());
            let stale = response(&fixture, protocol, "plain.txt", Method::GET, headers, true).await;
            assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
            assert!(stale.body.is_empty());
            fixture.cache.clear();
            let fresh = response(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                HeaderMap::new(),
                true,
            )
            .await;
            assert_eq!(fresh.headers[header::ETAG], changed.headers[header::ETAG]);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn etags_survive_metadata_only_changes_and_refresh_replacements_and_sizes() {
    for &protocol in PROTOCOLS {
        let fixture = Fixture::new();
        let path = fixture.root.join("plain.txt");
        let initial_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_modified(&path, initial_time);
        let original = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        set_modified(&path, initial_time + Duration::from_secs(2));
        let touched = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        assert_eq!(
            original.headers[header::ETAG],
            touched.headers[header::ETAG]
        );
        let replacement = fixture.root.join("replacement.txt");
        std::fs::write(&replacement, b"abcdefghij").unwrap();
        set_modified(&replacement, initial_time + Duration::from_secs(2));
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let replaced = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        assert_eq!(replaced.body, b"abcdefghij");
        assert_ne!(
            replaced.headers[header::ETAG],
            original.headers[header::ETAG]
        );
        std::fs::write(&path, b"size changed").unwrap();
        set_modified(&path, initial_time + Duration::from_secs(2));
        let resized = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        assert_eq!(resized.body, b"size changed");
        assert_ne!(
            resized.headers[header::ETAG],
            replaced.headers[header::ETAG]
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sidecar_rewrites_are_detected_without_changing_the_source_file() {
    for &protocol in PROTOCOLS {
        for (encoding, directory, extension, bytes) in [
            (
                "gzip",
                "gz",
                "gz",
                super::super::encode_gzip(b"abcdefghij", 1).unwrap(),
            ),
            (
                "br",
                "br",
                "br",
                super::super::encode_brotli(b"abcdefghij", 4096, 1, 22).unwrap(),
            ),
            (
                "zstd",
                "zstd",
                "zstd",
                super::super::encode_zstd(b"abcdefghij", 1).unwrap(),
            ),
        ] {
            let fixture = Fixture::new();
            let path = fixture
                .root
                .join(directory)
                .join(format!("asset.txt.{extension}"));
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(encoding));
            let original = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(original.body.len(), bytes.len());
            std::fs::write(&path, &bytes).unwrap();
            set_modified(&path, modified);
            headers.insert(
                header::IF_NONE_MATCH,
                original.headers[header::ETAG].clone(),
            );
            let changed = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(changed.status, StatusCode::OK);
            assert_eq!(changed.body, bytes);
            assert_ne!(
                changed.headers[header::ETAG],
                original.headers[header::ETAG]
            );
            headers.remove(header::IF_NONE_MATCH);
            headers.insert(header::IF_MATCH, original.headers[header::ETAG].clone());
            let stale = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
            headers.remove(header::IF_MATCH);
            std::fs::remove_file(&path).unwrap();
            let removed = response(
                &fixture,
                protocol,
                "asset.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await;
            assert_eq!(removed.status, StatusCode::OK);
            assert_eq!(removed.body, original.body); // Dynamic encoding of the unchanged source.
            std::fs::write(&path, &bytes).unwrap();
            let added = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
            assert_eq!(added.status, StatusCode::OK);
            assert_eq!(added.body, bytes);
            assert_eq!(added.headers[header::ETAG], changed.headers[header::ETAG]);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_compression_etags_follow_output_when_settings_change() {
    for &protocol in PROTOCOLS {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.root.join("plain.txt"),
            b"compressible contents!".repeat(100),
        )
        .unwrap();
        for (encoding, low, high) in [
            (
                "gzip",
                EncodingType::Gzip { level: 1 },
                EncodingType::Gzip { level: 9 },
            ),
            (
                "br",
                EncodingType::Br {
                    buffer_size: 4096,
                    quality: 1,
                    lgwindow: 22,
                },
                EncodingType::Br {
                    buffer_size: 4096,
                    quality: 9,
                    lgwindow: 22,
                },
            ),
            (
                "zstd",
                EncodingType::Zstd { level: 1 },
                EncodingType::Zstd { level: 19 },
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(encoding));
            let first = response_with_encodings(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                headers.clone(),
                true,
                &[low],
            )
            .await;
            let second = response_with_encodings(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                headers.clone(),
                true,
                &[high.clone()],
            )
            .await;
            assert_eq!(first.status, StatusCode::OK);
            assert_eq!(second.status, StatusCode::OK);
            assert_ne!(
                first.body, second.body,
                "fixture must produce distinct {encoding} outputs"
            );
            assert_ne!(first.headers[header::ETAG], second.headers[header::ETAG]);
            headers.insert(header::IF_MATCH, first.headers[header::ETAG].clone());
            let stale = response_with_encodings(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                headers.clone(),
                true,
                &[high.clone()],
            )
            .await;
            assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
            headers.remove(header::IF_MATCH);
            headers.insert(header::IF_NONE_MATCH, first.headers[header::ETAG].clone());
            let changed = response_with_encodings(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                headers,
                true,
                &[high],
            )
            .await;
            assert_eq!(changed.status, StatusCode::OK);
            assert_eq!(changed.body, second.body);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn validation_errors_do_not_reuse_a_cached_success_or_validator() {
    for &protocol in PROTOCOLS {
        let fixture = Fixture::new();
        let path = fixture.root.join("plain.txt");
        let original = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            original.headers[header::ETAG].clone(),
        );
        let failed = response(&fixture, protocol, "plain.txt", Method::GET, headers, true).await;
        assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(failed.body.is_empty());
        assert!(!failed.headers.contains_key(header::ETAG));
    }
}
