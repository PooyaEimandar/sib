use crate::network::http::session::Session;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use mime::Mime;
use std::{fs::Metadata, ops::Range, path::PathBuf, time::SystemTime};

#[derive(Debug, Clone, PartialEq)]
pub enum EncodingType {
    None,
    NotAcceptable,
    Gzip {
        level: u32,
    },
    Br {
        buffer_size: usize,
        quality: u32,
        lgwindow: u32,
    },
    Zstd {
        level: i32,
    },
}

impl EncodingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncodingType::Gzip { .. } => "gzip",
            EncodingType::Br { .. } => "br",
            EncodingType::Zstd { .. } => "zstd",
            EncodingType::None => "",
            EncodingType::NotAcceptable => "not-acceptable",
        }
    }
}

#[derive(Clone)]
pub struct FileInfo {
    etag: String,
    mime_type: String,
    path: PathBuf,
    size: u64,
    modified: SystemTime,
    last_modified_str: String, // pre-rendered RFC1123 for hot reuse
    gz_info: Option<(PathBuf, u64)>,
    br_info: Option<(PathBuf, u64)>,
    zstd_info: Option<(PathBuf, u64)>,
}

pub type FileCache = DashMap<String, FileInfo>;

fn serve_fn<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut http::HeaderMap,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
) -> std::io::Result<()> {
    let min_bytes_on_the_fly_size = min_max_compress_thresholds.0;
    let max_bytes_on_the_fly_size = min_max_compress_thresholds.1;

    // canonicalise
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            eprintln!("File server failed to canonicalize path: {path}");
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom();
        }
    };
    // meta
    let meta = match std::fs::metadata(&canonical) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                canonical.display(),
                e
            );
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom();
        }
    };

    // look or fill cache
    let key = canonical.to_string_lossy().to_string();

    // Get modified time once
    let modified = match meta.modified() {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "Failed to read modified time for: {}: {}",
                canonical.display(),
                e
            );
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom();
        }
    };

    // file cache lookup
    let file_info = if let Some(info) = file_cache.get(&key) {
        if modified <= info.modified {
            info.clone()
        } else {
            // outdated cache entry, fall through to regeneration
            generate_file_info(&key, &canonical, &meta, modified, file_cache)
        }
    } else {
        // cache miss, generate and insert
        generate_file_info(&key, &canonical, &meta, modified, file_cache)
    };

    let range_requested = session.req_header(&header::RANGE).is_some();
    let encoding = match session.req_header(&header::ACCEPT_ENCODING) {
        Some(val) => {
            let mime_type: Mime = file_info
                .mime_type
                .parse()
                .unwrap_or(mime::APPLICATION_OCTET_STREAM);
            choose_encoding(&val, &mime_type, encoding_order)
        }
        _ => EncodingType::None,
    };

    let mut applied_encoding: Option<&'static str> = None;
    let (file_path, total_size) = match encoding {
        EncodingType::None => {
            // Serve file directly
            (file_info.path.clone(), file_info.size)
        }
        EncodingType::NotAcceptable => {
            return session
                .status_code(StatusCode::NOT_ACCEPTABLE)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom();
        }
        EncodingType::Br {
            buffer_size,
            quality,
            lgwindow,
        } => {
            if let Some(br_info) = file_info.br_info {
                // we already have the br info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
                applied_encoding = Some("br");
                br_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "br", |b| {
                            encode_brotli(b, buffer_size, quality, lgwindow)
                        })?;

                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom();
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Gzip { level } => {
            if let Some(gz_info) = file_info.gz_info {
                // we already have the gz info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                applied_encoding = Some("gzip");
                gz_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "gzip", |b| {
                            encode_gzip(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom();
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Zstd { level } => {
            if let Some(zstd_info) = file_info.zstd_info {
                // we already have the zstd info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
                applied_encoding = Some("zstd");
                zstd_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "zstd", |b| {
                            encode_zstd(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom();
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
    };

    let range: Option<Range<u64>> = session
        .req_header(&header::RANGE)
        .and_then(|h| parse_byte_range(&h, total_size));

    let etag_to_send = rep_etag(&file_info.etag, applied_encoding);
    if let Some(header_val) = session.req_header(&header::IF_NONE_MATCH)
        && if_none_match_contains(&header_val, &etag_to_send)
    {
        if let Some(enc) = applied_encoding {
            rsp_headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(enc).map_err(std::io::Error::other)?,
            );
        }
        rsp_headers.extend([
            (header::CONTENT_LENGTH, HeaderValue::from_static("0")),
            (
                header::ETAG,
                HeaderValue::from_str(&etag_to_send).map_err(std::io::Error::other)?,
            ),
            (
                header::LAST_MODIFIED,
                HeaderValue::from_str(&file_info.last_modified_str)
                    .map_err(std::io::Error::other)?,
            ),
            (header::VARY, HeaderValue::from_static("Accept-Encoding")),
        ]);
        return session
            .status_code(StatusCode::NOT_MODIFIED)
            .headers(rsp_headers)?
            .body(Bytes::new())
            .eom();
    }
    rsp_headers.extend([
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&file_info.mime_type).map_err(std::io::Error::other)?,
        ),
        (
            header::LAST_MODIFIED,
            HeaderValue::from_str(&file_info.last_modified_str).map_err(std::io::Error::other)?,
        ),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
        (
            header::ETAG,
            HeaderValue::from_str(&etag_to_send).map_err(std::io::Error::other)?,
        ),
        (header::VARY, HeaderValue::from_static("Accept-Encoding")),
    ]);

    let (status, start, end) = if let Some(r) = range {
        let content_length = r.end - r.start;
        rsp_headers.extend([
            (
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end - 1, total_size))
                    .map_err(std::io::Error::other)?,
            ),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&content_length.to_string())
                    .map_err(std::io::Error::other)?,
            ),
        ]);

        (StatusCode::PARTIAL_CONTENT, r.start, r.end)
    } else {
        rsp_headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&total_size.to_string()).map_err(std::io::Error::other)?,
        );
        (StatusCode::OK, 0, total_size)
    };
    rsp_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if session.req_method() == http::Method::HEAD {
        return session
            .status_code(status)
            .headers(rsp_headers)?
            .body(Bytes::new())
            .eom();
    }

    *file_tuple = Some((status, file_path, start, end));
    Ok(())
}

#[cfg(feature = "net-h3-server")]
async fn serve_async_fn<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut http::HeaderMap,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
) -> std::io::Result<()> {
    let min_bytes_on_the_fly_size = min_max_compress_thresholds.0;
    let max_bytes_on_the_fly_size = min_max_compress_thresholds.1;

    // canonicalise
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            eprintln!("File server failed to canonicalize path: {path}");
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };
    // meta
    let meta = match std::fs::metadata(&canonical) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                canonical.display(),
                e
            );
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

    // look or fill cache
    let key = canonical.to_string_lossy().to_string();

    // Get modified time once
    let modified = match meta.modified() {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "Failed to read modified time for: {}: {}",
                canonical.display(),
                e
            );
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

    // file cache lookup
    let file_info = if let Some(info) = file_cache.get(&key) {
        if modified <= info.modified {
            info.clone()
        } else {
            // outdated cache entry, fall through to regeneration
            generate_file_info(&key, &canonical, &meta, modified, file_cache)
        }
    } else {
        // cache miss, generate and insert
        generate_file_info(&key, &canonical, &meta, modified, file_cache)
    };

    let range_requested = session.req_header(&header::RANGE).is_some();
    let encoding = match session.req_header(&header::ACCEPT_ENCODING) {
        Some(val) => {
            let mime_type: Mime = file_info
                .mime_type
                .parse()
                .unwrap_or(mime::APPLICATION_OCTET_STREAM);
            choose_encoding(&val, &mime_type, encoding_order)
        }
        _ => EncodingType::None,
    };

    let mut applied_encoding: Option<&'static str> = None;
    let (file_path, total_size) = match encoding {
        EncodingType::None => {
            // Serve file directly
            (file_info.path.clone(), file_info.size)
        }
        EncodingType::NotAcceptable => {
            return session
                .status_code(StatusCode::NOT_ACCEPTABLE)
                .headers(rsp_headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
        EncodingType::Br {
            buffer_size,
            quality,
            lgwindow,
        } => {
            if let Some(br_info) = file_info.br_info {
                // we already have the br info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
                applied_encoding = Some("br");
                br_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "br", |b| {
                            encode_brotli(b, buffer_size, quality, lgwindow)
                        })?;

                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom_async()
                        .await;
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Gzip { level } => {
            if let Some(gz_info) = file_info.gz_info {
                // we already have the gz info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                applied_encoding = Some("gzip");
                gz_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "gzip", |b| {
                            encode_gzip(b, level)
                        })?;
                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom_async()
                        .await;
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Zstd { level } => {
            if let Some(zstd_info) = file_info.zstd_info {
                // we already have the zstd info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
                applied_encoding = Some("zstd");
                zstd_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    let (status, body) =
                        compress_then_respond(rsp_headers, &file_info, "zstd", |b| {
                            encode_zstd(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(rsp_headers)?
                        .body(body)
                        .eom_async()
                        .await;
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
    };

    let range: Option<Range<u64>> = session
        .req_header(&header::RANGE)
        .and_then(|h| parse_byte_range(&h, total_size));

    let etag_to_send = rep_etag(&file_info.etag, applied_encoding);
    if let Some(header_val) = session.req_header(&header::IF_NONE_MATCH)
        && if_none_match_contains(&header_val, &etag_to_send)
    {
        if let Some(enc) = applied_encoding {
            rsp_headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(enc).map_err(std::io::Error::other)?,
            );
        }
        rsp_headers.extend([
            (header::CONTENT_LENGTH, HeaderValue::from_static("0")),
            (
                header::ETAG,
                HeaderValue::from_str(&etag_to_send).map_err(std::io::Error::other)?,
            ),
            (
                header::LAST_MODIFIED,
                HeaderValue::from_str(&file_info.last_modified_str)
                    .map_err(std::io::Error::other)?,
            ),
            (header::VARY, HeaderValue::from_static("Accept-Encoding")),
        ]);
        return session
            .status_code(StatusCode::NOT_MODIFIED)
            .headers(rsp_headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }
    rsp_headers.extend([
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&file_info.mime_type).map_err(std::io::Error::other)?,
        ),
        (
            header::LAST_MODIFIED,
            HeaderValue::from_str(&file_info.last_modified_str).map_err(std::io::Error::other)?,
        ),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
        (
            header::ETAG,
            HeaderValue::from_str(&etag_to_send).map_err(std::io::Error::other)?,
        ),
        (header::VARY, HeaderValue::from_static("Accept-Encoding")),
    ]);

    let (status, start, end) = if let Some(r) = range {
        let content_length = r.end - r.start;
        rsp_headers.extend([
            (
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end - 1, total_size))
                    .map_err(std::io::Error::other)?,
            ),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&content_length.to_string())
                    .map_err(std::io::Error::other)?,
            ),
        ]);

        (StatusCode::PARTIAL_CONTENT, r.start, r.end)
    } else {
        rsp_headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&total_size.to_string()).map_err(std::io::Error::other)?,
        );
        (StatusCode::OK, 0, total_size)
    };
    rsp_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if session.req_method() == http::Method::HEAD {
        return session
            .status_code(status)
            .headers(rsp_headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    *file_tuple = Some((status, file_path, start, end));
    Ok(())
}

pub fn serve_h1<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut http::HeaderMap,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;
    let result = serve_fn(
        session,
        path,
        file_cache,
        rsp_headers,
        encoding_order,
        min_max_compress_thresholds,
        &mut file_tuple,
    );

    // If we have a file tuple, it means it is ready to be served directly from mmap
    if let Some((status, file_path, start, end)) = file_tuple {
        let mmap = match std::fs::File::open(&file_path) {
            Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
                Ok(mmap) => mmap,
                Err(e) => {
                    eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .headers(rsp_headers)?
                        .body(Bytes::new())
                        .eom();
                }
            },
            Err(e) => {
                eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                return session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .headers(rsp_headers)?
                    .body(Bytes::new())
                    .eom();
            }
        };

        return session
            .status_code(status)
            .headers(rsp_headers)?
            .body(Bytes::copy_from_slice(&mmap[start as usize..end as usize]))
            .eom();
    }
    // we have already sent the response
    result
}

#[cfg(feature = "net-h2-server")]
pub async fn serve_h2<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut http::HeaderMap,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;
    let result = serve_fn(
        session,
        path,
        file_cache,
        rsp_headers,
        encoding_order,
        min_max_compress_thresholds,
        &mut file_tuple,
    );

    // If we have a file tuple, it means it is ready to be served directly from mmap
    if let Some((status, file_path, start, end)) = file_tuple {
        let bytes_to_send = end - start;

        if bytes_to_send >= stream_threshold_and_chunk_size.0 {
            // HTTP/2 streaming
            return serve_h2_streaming(
                session,
                status,
                rsp_headers,
                &file_path,
                start,
                end,
                stream_threshold_and_chunk_size.1,
            )
            .await;
        } else {
            // Send all at once
            let mmap = match std::fs::File::open(&file_path) {
                Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
                    Ok(mmap) => mmap,
                    Err(e) => {
                        eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                        return session
                            .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                            .headers(rsp_headers)?
                            .body(Bytes::new())
                            .eom();
                    }
                },
                Err(e) => {
                    eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .headers(rsp_headers)?
                        .body(Bytes::new())
                        .eom();
                }
            };

            return session
                .status_code(status)
                .headers(rsp_headers)?
                .body(Bytes::copy_from_slice(&mmap[start as usize..end as usize]))
                .eom();
        }
    }
    result
}

#[cfg(feature = "net-h3-server")]
pub async fn serve_h3<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut http::HeaderMap,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;
    let result = serve_async_fn(
        session,
        path,
        file_cache,
        rsp_headers,
        encoding_order,
        min_max_compress_thresholds,
        &mut file_tuple,
    )
    .await;

    // If we have a file tuple, it means it is ready to be served directly from mmap
    if let Some((status, file_path, start, end)) = file_tuple {
        let bytes_to_send = end - start;

        if bytes_to_send >= stream_threshold_and_chunk_size.0 {
            return serve_h3_streaming(
                session,
                status,
                rsp_headers,
                &file_path,
                start,
                end,
                stream_threshold_and_chunk_size.1,
            )
            .await;
        } else {
            // Send all at once
            let mmap = match std::fs::File::open(&file_path) {
                Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
                    Ok(mmap) => mmap,
                    Err(e) => {
                        eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                        return session
                            .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                            .headers(rsp_headers)?
                            .body(Bytes::new())
                            .eom_async()
                            .await;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .headers(rsp_headers)?
                        .body(Bytes::new())
                        .eom_async()
                        .await;
                }
            };

            return session
                .status_code(status)
                .headers(rsp_headers)?
                .body(Bytes::copy_from_slice(&mmap[start as usize..end as usize]))
                .eom_async()
                .await;
        }
    }
    result
}

#[inline]
fn rep_etag(base: &str, enc: Option<&str>) -> String {
    if let Some(e) = enc {
        if base.starts_with('"') && base.ends_with('"') && base.len() >= 2 {
            let inner = &base[1..base.len() - 1];
            format!("\"{inner}-{e}\"")
        } else {
            format!("\"{base}-{e}\"")
        }
    } else {
        base.to_string()
    }
}

#[inline]
fn if_none_match_contains(header: &HeaderValue, target: &str) -> bool {
    let header_val_str = match header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if header_val_str.trim() == "*" {
        return true;
    }
    // Accept both strong and weak forms.
    // Split on commas, trim, and compare case-sensitively after normalizing weak prefix.
    let t_strong = target.trim();
    let t_weak = if t_strong.starts_with('\"') {
        // turn "abc" into W/"abc"
        let mut s = String::from("W/");
        s.push_str(t_strong);
        s
    } else {
        // already quoted via rep_etag; this branch should not happen
        format!("W/{}", t_strong)
    };

    header_val_str
        .split(',')
        .map(|s| s.trim())
        .any(|tag| tag == t_strong || tag == t_weak)
}

pub fn load_file_cache(capacity: usize) -> FileCache {
    DashMap::with_capacity(capacity)
}

fn compress_then_respond(
    headers: &mut HeaderMap,
    file_info: &FileInfo,
    encoding_name: &str,
    compress_fn: impl Fn(&[u8]) -> std::io::Result<Bytes>,
) -> std::io::Result<(StatusCode, Bytes)> {
    let res = (|| {
        let f = std::fs::File::open(&file_info.path)?;
        let mmap = unsafe { memmap2::Mmap::map(&f) }.map_err(std::io::Error::other)?;
        compress_fn(&mmap[..])
    })();

    match res {
        Ok(compressed) => {
            let etag_val = rep_etag(&file_info.etag, Some(encoding_name));
            headers.extend([
                (
                    header::CONTENT_ENCODING,
                    HeaderValue::from_str(encoding_name).map_err(std::io::Error::other)?,
                ),
                (
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&compressed.len().to_string())
                        .map_err(std::io::Error::other)?,
                ),
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(&file_info.mime_type).map_err(std::io::Error::other)?,
                ),
                (
                    header::ETAG,
                    HeaderValue::from_str(&etag_val).map_err(std::io::Error::other)?,
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("inline"),
                ),
                (header::VARY, HeaderValue::from_static("Accept-Encoding")),
                (
                    header::LAST_MODIFIED,
                    HeaderValue::from_str(&file_info.last_modified_str)
                        .map_err(std::io::Error::other)?,
                ),
            ]);

            Ok((StatusCode::OK, compressed))
        }
        Err(e) => {
            eprintln!(
                "Compression failed ({encoding_name}) for {}: {e}",
                file_info.path.display()
            );

            Ok((StatusCode::INTERNAL_SERVER_ERROR, Bytes::new()))
        }
    }
}

fn generate_file_info(
    key: &str,
    canonical: &PathBuf,
    meta: &Metadata,
    modified: SystemTime,
    cache: &FileCache,
) -> FileInfo {
    let duration = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let etag = format!("\"{}-{}\"", duration.as_secs(), meta.len());
    let mime_type = mime_guess::from_path(canonical)
        .first()
        .unwrap_or(mime::APPLICATION_OCTET_STREAM);

    // Precompute Last-Modified string once
    let last_modified_str = httpdate::HttpDate::from(modified).to_string();

    // Probe precompressed siblings once
    let parent = canonical.parent();
    let file_stem = canonical.file_name().and_then(|f| f.to_str());

    let (mut gz_info, mut br_info, mut zstd_info) = (None, None, None);

    if let (Some(p), Some(stem)) = (parent, file_stem) {
        let gz_path = p.join("gz").join(format!("{stem}.gz"));
        if let Ok(m) = std::fs::metadata(&gz_path) {
            gz_info = Some((gz_path, m.len()));
        }
        let br_path = p.join("br").join(format!("{stem}.br"));
        if let Ok(m) = std::fs::metadata(&br_path) {
            br_info = Some((br_path, m.len()));
        }
        let zstd_path = p.join("zstd").join(format!("{stem}.zstd"));
        if let Ok(m) = std::fs::metadata(&zstd_path) {
            zstd_info = Some((zstd_path, m.len()));
        }
    }

    let info = FileInfo {
        etag,
        mime_type: mime_type.to_string(),
        path: canonical.clone(),
        size: meta.len(),
        modified,
        last_modified_str,
        gz_info,
        br_info,
        zstd_info,
    };

    cache.insert(key.to_string(), info.clone());
    info
}

fn parse_byte_range(header: &HeaderValue, total_size: u64) -> Option<Range<u64>> {
    let header_str = header.to_str().unwrap_or("");
    if header_str.is_empty() || !header_str.starts_with("bytes=") {
        return None;
    }
    let parts: Vec<&str> = header_str.trim_start_matches("bytes=").split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    match (parts[0].parse::<u64>().ok(), parts[1].parse::<u64>().ok()) {
        (Some(start), Some(end)) if start < total_size && start <= end => {
            Some(start..(end + 1).min(total_size))
        }
        (Some(start), None) if start < total_size => Some(start..total_size),
        (None, Some(suffix_len)) if suffix_len != 0 && suffix_len <= total_size => {
            Some(total_size - suffix_len..total_size)
        }
        _ => None,
    }
}

fn choose_encoding(accept: &HeaderValue, mime: &Mime, order: &[EncodingType]) -> EncodingType {
    let accept_str = match accept.to_str() {
        Ok(s) => s,
        Err(_) => return EncodingType::None,
    };
    let is_media = matches!(mime.type_(), mime::IMAGE | mime::AUDIO | mime::VIDEO);
    let is_svg = mime.type_() == mime::IMAGE
        && (mime.subtype() == mime::SVG || mime.suffix() == Some(mime::XML));
    if order.is_empty() || (is_media && !is_svg) {
        return EncodingType::None;
    }

    #[derive(Copy, Clone)]
    struct Pref {
        q: f32,
    }

    let has_header = !accept_str.trim().is_empty();
    let mut prefs: std::collections::HashMap<String, Pref> = std::collections::HashMap::new();
    let mut star_q: Option<f32> = None;
    let mut identity_q: Option<f32> = None;

    for item in accept_str.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.split(';');
        let token_raw = parts.next().unwrap_or_default().trim();
        let token = token_raw.to_ascii_lowercase();
        let mut q: f32 = 1.0;
        for p in parts {
            let p = p.trim();
            if let Some(v) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(val) = v.trim().parse::<f32>()
            {
                q = val;
            }
        }
        match token.as_str() {
            "*" => star_q = Some(q),
            "identity" => identity_q = Some(q),
            _ => {
                prefs.insert(token, Pref { q });
            }
        }
    }

    // is encoding allowed (q>0)?
    let allowed = |name: &str| -> bool {
        let lname = name.to_ascii_lowercase();
        if lname == "identity" {
            return identity_q.unwrap_or(1.0) > 0.0;
        }
        if let Some(pref) = prefs.get(&lname) {
            return pref.q > 0.0;
        }
        if let Some(q) = star_q {
            return q > 0.0;
        }
        // If the header is present and the encoding wasn't mentioned and no wildcard,
        // it's NOT acceptable. Only when no header at all => everything is acceptable.
        if has_header {
            return false;
        }
        true
    };

    for enc in order {
        let name = enc.as_str();
        if !name.is_empty() && allowed(name) {
            return enc.clone();
        }
        if name.is_empty() && allowed("identity") {
            // If `order` includes `None`, only pick it if identity is allowed.
            return EncodingType::None;
        }
    }

    // Fallback to identity if allowed
    if allowed("identity") {
        EncodingType::None
    } else {
        // If you have this variant; otherwise return None and let caller send 406.
        EncodingType::NotAcceptable
    }
}

pub fn encode_brotli<T: AsRef<[u8]>>(
    input: T,
    buffer_size: usize,
    q: u32,
    lgwin: u32,
) -> std::io::Result<Bytes> {
    let mut out = vec![];
    let mut encoder =
        brotli::CompressorReader::new(std::io::Cursor::new(input.as_ref()), buffer_size, q, lgwin);
    std::io::copy(&mut encoder, &mut out)?;
    Ok(Bytes::from(out))
}

pub fn encode_zstd<T: AsRef<[u8]>>(input: T, level: i32) -> std::io::Result<Bytes> {
    let mut out = vec![];
    zstd::stream::copy_encode(std::io::Cursor::new(input.as_ref()), &mut out, level)?;
    Ok(Bytes::from(out))
}

pub fn encode_gzip<T: AsRef<[u8]>>(input: T, level: u32) -> std::io::Result<Bytes> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut out = vec![];
    let mut encoder = GzEncoder::new(&mut out, Compression::new(level));
    std::io::copy(&mut std::io::Cursor::new(input.as_ref()), &mut encoder)?;
    encoder.finish()?;
    Ok(Bytes::from(out))
}

#[cfg(feature = "net-h2-server")]
pub async fn serve_h2_streaming<S: Session>(
    session: &mut S,
    status: http::StatusCode,
    headers: &mut http::HeaderMap,
    file_path: &std::path::Path,
    start: u64,
    end: u64,
    chunk_size: usize,
) -> std::io::Result<()> {
    use bytes::Bytes;
    use http::header;
    use std::convert::TryFrom;

    // Open & stat file
    let file = std::fs::File::open(file_path)?;
    let meta = file.metadata()?;
    let file_len = meta.len();

    // Validate & clamp range
    if start >= file_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("range start {} beyond EOF {}", start, file_len),
        ));
    }
    let end_excl = end.min(file_len).max(start);
    let total_u64 = end_excl.saturating_sub(start);
    let total = usize::try_from(total_u64)
        .map_err(|_| std::io::Error::other("range too large for usize"))?;

    // Map after validation
    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .map_err(|e| std::io::Error::other(format!("mmap failed: {e}")))?;

    // Headers
    headers.insert(
        header::ACCEPT_RANGES,
        http::HeaderValue::from_static("bytes"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&total.to_string())
            .map_err(|e| std::io::Error::other(format!("bad Content-Length: {e}")))?,
    );
    if status == http::StatusCode::PARTIAL_CONTENT && total > 0 {
        let end_inclusive = end_excl - 1;
        let cr = format!("bytes {}-{}/{}", start, end_inclusive, file_len);
        headers.insert(
            header::CONTENT_RANGE,
            http::HeaderValue::from_str(&cr)
                .map_err(|e| std::io::Error::other(format!("bad Content-Range: {e}")))?,
        );
    }

    // Send status + headers (no body yet)
    session.status_code(status).headers(headers)?;

    // Start H2 streaming
    let mut stream = session.start_h2_streaming()?;

    // Fast-path: empty body (valid even for 206)
    if total == 0 {
        stream.send_data(Bytes::new(), true)?;
        return Ok(());
    }

    // Ask for all credits up front; H2 will trickle it
    stream.reserve_capacity(total);

    let mut off = start as usize;
    let end_usize = end_excl as usize;

    while off < end_usize {
        // Consume any already granted capacity before awaiting new credit
        let mut cap = stream.capacity();
        if cap == 0 {
            const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3); // seconds
            // Ensure we keep requesting capacity (some peers grant lazily)
            stream.reserve_capacity(chunk_size);

            // Protect against stalls if WINDOW_UPDATEs stop
            #[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))]
            {
                cap = match glommio::timer::timeout(TIMEOUT, async {
                    stream
                        .next_capacity()
                        .await
                        .map_err(glommio::GlommioError::IoError)
                })
                .await
                {
                    Ok(c) => c,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("H2 next_capacity timed out after {:?}", TIMEOUT),
                        ));
                    }
                }
            };

            #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
            {
                cap = tokio::select! {
                    res = stream.next_capacity() => res,
                    _ = tokio::time::sleep(TIMEOUT) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("H2 next_capacity timed out after {:?}", TIMEOUT),
                    )),
                }?
            };

            if cap == 0 {
                // try again
                continue;
            }
        }

        let remaining = end_usize - off;
        let to_send = cap.min(remaining).min(chunk_size);
        let last = to_send == remaining;

        // Copy from mmap into Bytes (safe; mmap slice lives long enough)
        let data = Bytes::copy_from_slice(&mmap[off..off + to_send]);

        // Send DATA; set end_stream on the LAST DATA frame
        stream.send_data(data, last)?;
        off += to_send;

        if !last {
            // Hint more credit if peer is conservative
            stream.reserve_capacity(chunk_size);
        }

        #[cfg(all(feature = "rt-glommio", target_os = "linux"))]
        glommio::yield_if_needed().await;
    }

    Ok(())
}

#[cfg(feature = "net-h3-server")]
pub async fn serve_h3_streaming<S: Session>(
    session: &mut S,
    status: http::StatusCode,
    headers: &mut http::HeaderMap,
    file_path: &std::path::Path,
    start: u64,
    end: u64,
    chunk_size: usize,
) -> std::io::Result<()> {
    use bytes::Bytes;
    use http::header;

    // Open/map file and compute range (same validations as H2 path)
    let file = std::fs::File::open(file_path)?;
    let meta = file.metadata()?;
    let file_len = meta.len();
    if start >= file_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("range start {} beyond EOF {}", start, file_len),
        ));
    }
    let end_excl = end.min(file_len).max(start);
    let total = (end_excl - start) as usize;

    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .map_err(|e| std::io::Error::other(format!("mmap failed: {e}")))?;

    // Standard headers
    headers.insert(
        header::ACCEPT_RANGES,
        http::HeaderValue::from_static("bytes"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&total.to_string()).map_err(std::io::Error::other)?,
    );
    if status == http::StatusCode::PARTIAL_CONTENT && total > 0 {
        let end_inclusive = end_excl - 1;
        let cr = format!("bytes {}-{}/{}", start, end_inclusive, file_len);
        headers.insert(
            header::CONTENT_RANGE,
            http::HeaderValue::from_str(&cr).map_err(std::io::Error::other)?,
        );
    }

    // Apply head, then start streaming (no body yet)
    session.status_code(status).headers(headers)?;
    session.start_h3_streaming().await?;

    // Empty body send FIN ASAP
    if total == 0 {
        return session.send_h3_data(Bytes::new(), true).await;
    }

    // Sending chunks
    let mut off = start as usize;
    let end_usize = end_excl as usize;

    while off < end_usize {
        let to_send = (end_usize - off).min(chunk_size);
        let last = off + to_send == end_usize;

        let chunk = Bytes::copy_from_slice(&mmap[off..off + to_send]);
        session.send_h3_data(chunk, last).await?;

        off += to_send;

        glommio::yield_if_needed().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::network::http::server::H1Config;
    use crate::network::http::session::{HService, Session};
    use crate::network::http::{
        file::{EncodingType, FileInfo},
        server::HFactory,
    };
    use dashmap::DashMap;
    use http::HeaderMap;
    use std::sync::OnceLock;

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    use crate::network::http::session::HAsyncService;

    struct FileServer<T>(pub T);

    struct FileService;

    static FILE_CACHE: OnceLock<DashMap<String, FileInfo>> = OnceLock::new();
    fn get_cache() -> &'static DashMap<String, FileInfo> {
        FILE_CACHE.get_or_init(|| DashMap::with_capacity(128))
    }

    impl HService for FileService {
        fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
            const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
            const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB

            let mut rsp_headers = HeaderMap::new();
            rsp_headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("close"),
            );

            let rel_file = file!();
            use crate::network::http::file::serve_h1;
            serve_h1(
                session,
                rel_file,
                get_cache(),
                &mut rsp_headers,
                &[
                    EncodingType::Zstd { level: 3 },
                    EncodingType::Br {
                        buffer_size: 4096,
                        quality: 4,
                        lgwindow: 19,
                    },
                    EncodingType::Gzip { level: 4 },
                    EncodingType::None,
                ],
                (MIN_BYTES_ON_THE_FLY_SIZE, MAX_BYTES_ON_THE_FLY_SIZE),
            )
        }
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[async_trait::async_trait(?Send)]
    impl HAsyncService for FileService {
        async fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
            const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
            const H2_STREAM_THRESHOLD: u64 = 256 * 1024; // 256 KB
            const H2_STREAM_CHUNK_SIZE: usize = 128 * 1024; // 128 KB

            let mut rsp_headers = HeaderMap::new();
            let rel_file = file!();

            if session.req_http_version() == http::Version::HTTP_2 {
                rsp_headers.insert(
                    http::header::ALT_SVC,
                    http::HeaderValue::from_static("h3=\":8081\"; ma=86400"),
                );
                use crate::network::http::file::serve_h2;
                if let Err(e) = serve_h2(
                    session,
                    rel_file,
                    get_cache(),
                    &mut rsp_headers,
                    &[
                        EncodingType::Zstd { level: 3 },
                        EncodingType::Br {
                            buffer_size: 4096,
                            quality: 4,
                            lgwindow: 19,
                        },
                        EncodingType::Gzip { level: 4 },
                        EncodingType::None,
                    ],
                    (MIN_BYTES_ON_THE_FLY_SIZE, MAX_BYTES_ON_THE_FLY_SIZE),
                    (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
                )
                .await
                {
                    eprintln!("H2 FileService failed: {e}");
                    return session
                        .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(bytes::Bytes::new())
                        .eom();
                };
            } else {
                #[cfg(all(
                    feature = "net-h3-server",
                    feature = "rt-glommio",
                    target_os = "linux"
                ))]
                if let Err(e) = crate::network::http::file::serve_h3(
                    session,
                    rel_file,
                    get_cache(),
                    &mut rsp_headers,
                    &[
                        EncodingType::Zstd { level: 3 },
                        EncodingType::Br {
                            buffer_size: 4096,
                            quality: 4,
                            lgwindow: 19,
                        },
                        EncodingType::Gzip { level: 4 },
                        EncodingType::None,
                    ],
                    (MIN_BYTES_ON_THE_FLY_SIZE, MAX_BYTES_ON_THE_FLY_SIZE),
                    (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
                )
                .await
                {
                    eprintln!("H3 FileService failed: {e}");
                    return session
                        .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(bytes::Bytes::new())
                        .eom_async()
                        .await;
                };
            }
            Ok(())
        }
    }

    impl HFactory for FileServer<FileService> {
        type Service = FileService;

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
        type HAsyncService = FileService;

        #[cfg(feature = "net-h1-server")]
        fn service(&self, _id: usize) -> Self::Service {
            FileService
        }

        #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
        fn async_service(&self, _id: usize) -> Self::HAsyncService {
            FileService
        }
    }

    fn create_self_signed_tls_pems() -> (String, String) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        use sha2::{Digest, Sha256};

        let mut params: CertificateParams = Default::default();
        params.not_before = date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        // Get PEM strings
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Convert PEM -> DER by stripping header/footer and base64-decoding
        let mut der_b64 = String::with_capacity(cert_pem.len());
        for line in cert_pem.lines() {
            if !line.starts_with("-----") {
                der_b64.push_str(line.trim());
            }
        }
        let cert_der = b64.decode(der_b64).expect("PEM base64 decode");

        // SHA-256 over DER, base64 encode result
        let hash = Sha256::digest(&cert_der);
        let base64_hash = b64.encode(hash);

        println!("BASE64_SHA256_OF_DER_CERT: {}", base64_hash);

        rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        )
        .expect("install aws-lc-rs");

        (cert_pem, key_pem)
    }

    #[test]
    fn file_server() {
        const NUMBER_OF_WORKERS: usize = 2;
        const STACK_SIZE: usize = 2 * 1024 * 1024;
        crate::init_global_poller(NUMBER_OF_WORKERS, STACK_SIZE);

        // Pick a port and start the server
        let mut threads = Vec::new();

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();

        for _ in 0..NUMBER_OF_WORKERS {
            let addr = "0.0.0.0:8080";
            let cert_pem = certs.0.clone();
            let key_pem = certs.1.clone();
            let h1_handle = std::thread::spawn(move || {
                let id = std::thread::current().id();
                println!("Starting H1 server on {addr} with thread: {id:?}");
                FileServer(FileService)
                    .start_h1_tls(
                        addr,
                        (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                        H1Config::default(),
                        None,
                    )
                    .unwrap_or_else(|_| panic!("H1 file server failed to start for thread {id:?}"))
                    .join()
                    .unwrap_or_else(|_| panic!("H1 file server failed to joining thread {id:?}"));
            });
            threads.push(h1_handle);
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "net-h2-server")] {
                let cert_h2_pem = certs.0.clone();
                let key_h2_pem = certs.1.clone();
                let h2_handle = std::thread::spawn(move || {
                    use crate::network::http::server::H2Config;
                    let addr = "0.0.0.0:8081";
                    let cert_pem = cert_h2_pem.as_bytes();
                    let key_pem = key_h2_pem.as_bytes();
                    let id = std::thread::current().id();
                    println!("Starting H2 server on {addr} with thread: {id:?}");
                    FileServer(FileService)
                        .start_h2_tls(addr, (None, cert_pem, key_pem), H2Config::default(), None)
                        .unwrap_or_else(|_| panic!("H2 file server failed to start for thread {id:?}"));
                });
                threads.push(h2_handle);
            }
        }

        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "linux", feature = "net-h3-server"))] {
                let cert_h3_pem = certs.0.clone();
                let key_h3_pem = certs.1.clone();
                let h3_handle = std::thread::spawn(move || {
                    use crate::network::http::server::H3Config;
                    let addr = "0.0.0.0:8081";
                    let cert_pem = cert_h3_pem.as_bytes();
                    let key_pem = key_h3_pem.as_bytes();
                    let id = std::thread::current().id();
                    println!("Starting H2 server on {addr} with thread: {id:?}");
                    FileServer(FileService)
                        .start_h3_tls(addr, (None, cert_pem, key_pem), H3Config::default(), None)
                        .unwrap_or_else(|_| panic!("H3 file server failed to start for thread {id:?}"));
                });
                threads.push(h3_handle);
            }
        }

        // Wait for all threads to complete (they won’t unless crashed)
        for handle in threads {
            handle.join().expect("Thread panicked");
        }
    }
}
