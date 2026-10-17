use super::*;

fn assert_precondition_failed(response: &Response) {
    assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(response.headers[header::CONTENT_LENGTH], "0");
    assert_eq!(response.headers[header::VARY], "Accept-Encoding, Range");
    assert!(!response.headers.contains_key(header::CONTENT_RANGE));
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert!(response.body.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn if_match_requires_a_strong_tag_or_standalone_wildcard() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        let original = response(
            &fixture,
            protocol,
            "asset.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        let tag = original.headers[header::ETAG].to_str().unwrap();
        for method in [Method::GET, Method::HEAD] {
            for (condition, matches) in [
                (tag.to_owned(), true),
                ("*".to_owned(), true),
                (format!("\"old\", {tag}"), true),
                (format!("{tag}, \"old\""), true),
                (format!("W/{tag}, {tag}"), true),
                (format!("\"tag,with,commas\", {tag}"), true),
                ("\"old\"".to_owned(), false),
                (format!("W/{tag}"), false),
                (format!("{tag}, garbage"), false),
                (format!("*, {tag}"), false),
                (String::new(), false),
            ] {
                let mut headers = HeaderMap::new();
                headers.insert(header::IF_MATCH, HeaderValue::from_str(&condition).unwrap());
                let r = response(
                    &fixture,
                    protocol,
                    "asset.txt",
                    method.clone(),
                    headers,
                    true,
                )
                .await;
                if matches {
                    assert_eq!(r.status, StatusCode::OK, "{protocol:?}: {condition}");
                    assert_eq!(r.headers[header::ETAG], tag);
                    assert_eq!(
                        r.body.as_slice(),
                        if method == Method::HEAD {
                            b"".as_slice()
                        } else {
                            b"0123456789".as_slice()
                        }
                    );
                } else {
                    assert_precondition_failed(&r);
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn if_match_precedes_not_modified_and_range_responses() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        let original = response(
            &fixture,
            protocol,
            "asset.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        for range in ["bytes=2-4", "bytes=20-"] {
            let mut headers = range_headers(range);
            headers.insert(header::IF_MATCH, HeaderValue::from_static("\"old\""));
            assert_precondition_failed(
                &response(
                    &fixture,
                    protocol,
                    "asset.txt",
                    Method::GET,
                    headers.clone(),
                    true,
                )
                .await,
            );
            headers.insert(
                header::IF_NONE_MATCH,
                original.headers[header::ETAG].clone(),
            );
            assert_precondition_failed(
                &response(
                    &fixture,
                    protocol,
                    "asset.txt",
                    Method::GET,
                    headers.clone(),
                    true,
                )
                .await,
            );

            headers.insert(header::IF_MATCH, original.headers[header::ETAG].clone());
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
            assert!(r.body.is_empty());
            headers.remove(header::IF_NONE_MATCH);
            let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
            assert_eq!(
                r.status,
                if range == "bytes=2-4" {
                    StatusCode::PARTIAL_CONTENT
                } else {
                    StatusCode::RANGE_NOT_SATISFIABLE
                }
            );
        }
        // Normal request errors take precedence over preconditions.
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("*"));
        let missing = response(
            &fixture,
            protocol,
            "missing.txt",
            Method::GET,
            headers.clone(),
            true,
        )
        .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("*;q=0"));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"old\""));
        let unacceptable =
            response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
        assert_eq!(unacceptable.status, StatusCode::NOT_ACCEPTABLE);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn if_match_checks_the_selected_sidecar_or_dynamic_representation() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        for file in ["asset.txt", "plain.txt", "empty.txt"] {
            let original = response(
                &fixture,
                protocol,
                file,
                Method::GET,
                HeaderMap::new(),
                true,
            )
            .await;
            for encoding in ["gzip", "br", "zstd"] {
                let mut headers = HeaderMap::new();
                headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(encoding));
                let selected =
                    response(&fixture, protocol, file, Method::GET, headers.clone(), true).await;
                for tag in [
                    selected.headers[header::ETAG].clone(),
                    HeaderValue::from_static("*"),
                ] {
                    headers.insert(header::IF_MATCH, tag);
                    let r = response(&fixture, protocol, file, Method::GET, headers.clone(), true)
                        .await;
                    assert_eq!(r.status, StatusCode::OK);
                    assert_eq!(r.headers[header::ETAG], selected.headers[header::ETAG]);
                    assert_eq!(r.body, selected.body);
                }
                for tag in [
                    HeaderValue::from_static("\"old\""),
                    HeaderValue::from_str(&format!(
                        "W/{}",
                        selected.headers[header::ETAG].to_str().unwrap()
                    ))
                    .unwrap(),
                ] {
                    headers.insert(header::IF_MATCH, tag);
                    for method in [Method::GET, Method::HEAD] {
                        assert_precondition_failed(
                            &response(&fixture, protocol, file, method, headers.clone(), true)
                                .await,
                        );
                    }
                }
                if file != "empty.txt" {
                    headers.insert(header::IF_MATCH, original.headers[header::ETAG].clone());
                    assert_precondition_failed(
                        &response(&fixture, protocol, file, Method::GET, headers.clone(), true)
                            .await,
                    );
                }
                headers.insert(header::IF_MATCH, selected.headers[header::ETAG].clone());
                headers.insert(
                    header::IF_NONE_MATCH,
                    selected.headers[header::ETAG].clone(),
                );
                let r =
                    response(&fixture, protocol, file, Method::GET, headers.clone(), true).await;
                assert_eq!(r.status, StatusCode::NOT_MODIFIED);
                assert!(r.body.is_empty());
                headers.remove(header::IF_NONE_MATCH);
                headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-4"));
                if file != "empty.txt" {
                    // A compressed validator cannot authorize a range of the original bytes.
                    assert_precondition_failed(
                        &response(&fixture, protocol, file, Method::GET, headers, true).await,
                    );
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn if_match_combines_repeated_fields_without_discarding_conditions() {
    let fixture = Fixture::new();
    for &protocol in PROTOCOLS {
        let original = response(
            &fixture,
            protocol,
            "asset.txt",
            Method::GET,
            HeaderMap::new(),
            true,
        )
        .await;
        let current = original.headers[header::ETAG].clone();
        let old = HeaderValue::from_static("\"old\"");
        for values in [
            [current.clone(), old.clone()],
            [old.clone(), current.clone()],
        ] {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::IF_MATCH, value);
            }
            let r = response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await;
            assert_eq!(r.status, StatusCode::OK, "{protocol:?}");
            assert_eq!(r.body, b"0123456789");
        }
        for invalid in ["*", "garbage", "\"unterminated"] {
            let mut headers = HeaderMap::new();
            headers.append(header::IF_MATCH, HeaderValue::from_static(invalid));
            headers.append(header::IF_MATCH, current.clone());
            assert_precondition_failed(
                &response(&fixture, protocol, "asset.txt", Method::GET, headers, true).await,
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn if_match_rejects_an_old_validator_after_cached_file_refresh() {
    use std::fs::{File, FileTimes};
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
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"updated asset bytes").unwrap();
        // A distinct modification time avoids relying on filesystem clock resolution.
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(modified + Duration::from_secs(2)))
            .unwrap();
        let mut headers = range_headers("bytes=0-6");
        headers.insert(header::IF_MATCH, original.headers[header::ETAG].clone());
        assert_precondition_failed(
            &response(
                &fixture,
                protocol,
                "plain.txt",
                Method::GET,
                headers.clone(),
                true,
            )
            .await,
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("*"));
        let updated = response(
            &fixture,
            protocol,
            "plain.txt",
            Method::GET,
            headers.clone(),
            true,
        )
        .await;
        assert_eq!(updated.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(updated.body, b"updated");
        assert_ne!(
            updated.headers[header::ETAG],
            original.headers[header::ETAG]
        );
        headers.insert(header::IF_MATCH, updated.headers[header::ETAG].clone());
        let current = response(&fixture, protocol, "plain.txt", Method::GET, headers, true).await;
        assert_eq!(current.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(current.body, b"updated");
    }
}
