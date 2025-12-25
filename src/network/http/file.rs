use crate::network::http::session::Session;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use mime::Mime;
use std::{fs::Metadata, ops::Range, path::PathBuf, time::SystemTime};

macro_rules! get_error_headers {
    ($close:expr) => {{
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        if $close {
            headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }
        headers
    }};
}

macro_rules! get_file_info {
    ($session:expr, $path:expr, $meta:expr, $file_cache:expr, $close:expr) => {{
        let key = $path.to_string_lossy().to_string();

        // get modified time
        let modified = match $meta.modified() {
            Ok(sys_time) => sys_time,
            Err(e) => {
                eprintln!("Failed to read modified time for: {}: {}", &key, e);

                let headers = get_error_headers!($close);
                return $session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .headers(&headers)?
                    .body(Bytes::new())
                    .eom();
            }
        };

        // file cache lookup
        if let Some(info) = $file_cache.get(&key) {
            if modified <= info.modified {
                // up-to-date entry
                info.clone()
            } else {
                // outdated entry, regenerate
                generate_file_info($path, &$meta, modified, $file_cache)
            }
        } else {
            // generate new entry
            generate_file_info($path, &$meta, modified, $file_cache)
        }
    }};
}

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
    file_info: FileInfo,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    content_disposition_allow_ranges: (&str, bool),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
    close_connection_on_failed: bool,
) -> std::io::Result<()> {
    let min_bytes_on_the_fly_size = min_max_compress_thresholds.0;
    let max_bytes_on_the_fly_size = min_max_compress_thresholds.1;

    let content_disposition = content_disposition_allow_ranges.0;
    let allow_ranges = content_disposition_allow_ranges.1;

    let range_header = if allow_ranges {
        session.req_header(&header::RANGE)
    } else {
        None
    };
    let range_requested = range_header.is_some();
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

    let mut rsp_headers = http::HeaderMap::new();
    let mut applied_encoding: Option<&'static str> = None;
    let (file_path, total_size) = match encoding {
        EncodingType::None => {
            // Serve file directly
            (file_info.path.clone(), file_info.size)
        }
        EncodingType::NotAcceptable => {
            let headers = get_error_headers!(close_connection_on_failed);
            return session
                .status_code(StatusCode::NOT_ACCEPTABLE)
                .headers(&headers)?
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
                        compress_then_respond(&mut rsp_headers, &file_info, "br", |b| {
                            encode_brotli(b, buffer_size, quality, lgwindow)
                        })?;

                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
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
                        compress_then_respond(&mut rsp_headers, &file_info, "gzip", |b| {
                            encode_gzip(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
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
                        compress_then_respond(&mut rsp_headers, &file_info, "zstd", |b| {
                            encode_zstd(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
                        .body(body)
                        .eom();
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
    };

    let range = range_header.and_then(|h| parse_byte_range(&h, total_size));

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
            .headers(&rsp_headers)?
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
            HeaderValue::from_str(content_disposition).map_err(std::io::Error::other)?,
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

    if allow_ranges {
        rsp_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }

    if session.req_method() == http::Method::HEAD {
        return session
            .status_code(status)
            .headers(&rsp_headers)?
            .body(Bytes::new())
            .eom();
    }

    session.status_code(status);
    session.headers(&rsp_headers)?;
    *file_tuple = Some((status, file_path, start, end));
    Ok(())
}

#[cfg(feature = "net-h3-server")]
async fn serve_async_fn<S: Session>(
    session: &mut S,
    path: &PathBuf,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
) -> std::io::Result<()> {
    use crate::network::http::session;

    let min_bytes_on_the_fly_size = min_max_compress_thresholds.0;
    let max_bytes_on_the_fly_size = min_max_compress_thresholds.1;

    // meta
    let meta = match tokio::fs::metadata(&path).await {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                &path, e
            );
            return session
                .status_code(StatusCode::NOT_FOUND)
                .body(Bytes::new())
                .eom();
        }
    };

    // file cache lookup
    let file_info = get_file_info!(session, path, meta, file_cache, false);

    let range_header = session.req_header(&header::RANGE);
    let range_requested = range_header.is_some();
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

    let mut rsp_headers = http::HeaderMap::new();
    let mut applied_encoding: Option<&'static str> = None;
    let (file_path, total_size) = match encoding {
        EncodingType::None => {
            // Serve file directly
            (file_info.path.clone(), file_info.size)
        }
        EncodingType::NotAcceptable => {
            return session
                .status_code(StatusCode::NOT_ACCEPTABLE)
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
                        compress_then_respond(&mut rsp_headers, &file_info, "br", |b| {
                            encode_brotli(b, buffer_size, quality, lgwindow)
                        })?;

                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
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
                        compress_then_respond(&mut rsp_headers, &file_info, "gzip", |b| {
                            encode_gzip(b, level)
                        })?;
                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
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
                        compress_then_respond(&mut rsp_headers, &file_info, "zstd", |b| {
                            encode_zstd(b, level)
                        })?;

                    return session
                        .status_code(status)
                        .headers(&rsp_headers)?
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

    let range = range_header.and_then(|h| parse_byte_range(&h, total_size));

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
            .headers(&rsp_headers)?
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
            .headers(&rsp_headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    session.headers(&rsp_headers)?;
    *file_tuple = Some((status, file_path, start, end));
    Ok(())
}

/// Serve a file over HTTP/1.x
/// # Arguments
/// * `session` - The HTTP session to use for serving
/// * `path` - The path to the file to serve
/// * `file_cache` - The file cache to use for caching file metadata
/// * `encoding_order` - The order of encodings to consider for compression
/// * `min_max_compress_thresholds` - The minimum and maximum size thresholds for on-the-fly compression
/// * `stream_threshold_and_chunk_size` - The threshold size for streaming and the chunk size to use for streaming
/// * `content_disposition` - The content disposition header value to use (e.g., "inline" or "attachment; filename=\"sample.m4v\"")
/// * `allow_ranges` - Whether to allow range requests or not. If false, all requests will return the full file with status 200. If true, range requests will be honored for partial content delivery like download managers.
#[cfg(feature = "net-h1-server")]
pub fn serve_h1<S: Session>(
    session: &mut S,
    path: &PathBuf,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
    content_disposition: &str,
    allow_ranges: bool,
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;

    // meta
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                path.display(),
                e
            );
            let headers = get_error_headers!(true);
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(&headers)?
                .body(Bytes::new())
                .eom();
        }
    };

    // file cache lookup
    const CLOSE_CONNECTION_ON_FAILED: bool = true;
    let file_info = get_file_info!(session, &path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    // Handle headers, range parsing, etc.
    serve_fn(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition,
        allow_ranges,
        &mut file_tuple,
        CLOSE_CONNECTION_ON_FAILED,
    )?;

    // If we have a file tuple, it means it is ready to be served
    if let Some((status, file_path, start, end)) = file_tuple {
        let bytes_to_send = end - start;

        // HEAD already handled inside serve_fn
        if bytes_to_send == 0 {
            return session.status_code(status).body(Bytes::new()).eom();
        }

        // detect if this was a Range request
        let is_range_response = status == StatusCode::PARTIAL_CONTENT;

        // Always send non-streaming body for 206 / Range responses.
        if is_range_response {
            let file = std::fs::File::open(&file_path)?;
            let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(std::io::Error::other)?;
            let slice = &mmap[start as usize..end as usize];

            return session
                .status_code(status)
                .body(Bytes::copy_from_slice(slice))
                .eom();
        }

        // existing streaming logic for non-Range responses
        let file = match std::fs::File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                let headers = get_error_headers!(true);
                return session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .headers(&headers)?
                    .body(Bytes::new())
                    .eom();
            }
        };

        let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
            256 * 1024 // 256 KB
        } else {
            stream_threshold_and_chunk_size.0
        };

        if bytes_to_send < stream_threshold {
            // small: mmap, but still go through H1 streaming so we reuse the headers
            let mmap = match unsafe { memmap2::Mmap::map(&file) } {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                    let headers = get_error_headers!(true);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .headers(&headers)?
                        .body(Bytes::new())
                        .eom();
                }
            };

            session.status_code(status);
            session.start_h1_streaming()?;

            let slice = &mmap[start as usize..end as usize];
            session.send_h1_data(slice, true)?;
        } else {
            use std::io::{Read, Seek, SeekFrom};

            session.status_code(status);
            session.start_h1_streaming()?;

            let mut f = file;
            f.seek(SeekFrom::Start(start))?;

            let stream_chunk = if stream_threshold_and_chunk_size.1 == 0 {
                64 * 1024 // 64 KB
            } else {
                stream_threshold_and_chunk_size.1
            };

            let mut remaining = bytes_to_send as usize;
            let mut buf = vec![0u8; stream_chunk];

            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = f.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                remaining -= n;

                session.send_h1_data(&buf[..n], remaining == 0)?;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "net-h2-server")]
pub async fn serve_h1_async<S: Session>(
    session: &mut S,
    path: &PathBuf,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
    content_disposition_allow_ranges: (&str, bool),
) -> std::io::Result<()> {
    use bytes::Bytes;
    use http::StatusCode;
    use std::io::SeekFrom;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;

    // meta (async)
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                path.display(),
                e
            );

            // In async servers you usually do NOT want to force close; but keep your behavior if you want.
            // We'll keep it consistent with your sync serve_h1: close on failure.
            let headers = get_error_headers!(true);
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(&headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

    // file cache lookup (same macro; tokio metadata supports modified()/len())
    const CLOSE_CONNECTION_ON_FAILED: bool = true;
    let file_info = get_file_info!(session, path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    // Build headers / decide file tuple via your existing sync helper
    serve_fn(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition_allow_ranges,
        &mut file_tuple,
        CLOSE_CONNECTION_ON_FAILED,
    )?;

    // If serve_fn already responded (HEAD / 304 / 406 etc.), it wouldn't set file_tuple.
    let Some((status, file_path, start, end)) = file_tuple else {
        return Ok(());
    };

    let bytes_to_send = end - start;

    // 0 bytes
    if bytes_to_send == 0 {
        return session
            .status_code(status)
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    // Range responses: ALWAYS non-streaming (same as your serve_h1)
    let is_range_response = status == StatusCode::PARTIAL_CONTENT;
    if is_range_response {
        let (status2, body) =
            tokio::task::spawn_blocking(move || -> std::io::Result<(StatusCode, Bytes)> {
                let file = std::fs::File::open(&file_path)?;
                let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(std::io::Error::other)?;
                let slice = &mmap[start as usize..end as usize];
                Ok((status, Bytes::copy_from_slice(slice)))
            })
            .await
            .map_err(|e| std::io::Error::other(format!("spawn_blocking join error: {e}")))??;

        return session.status_code(status2).body(body).eom_async().await;
    }

    // Non-range: decide streaming threshold
    let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
        256 * 1024
    } else {
        stream_threshold_and_chunk_size.0
    };

    // Small body: send all at once (mmap in spawn_blocking)
    if bytes_to_send < stream_threshold {
        let (status2, body) =
            tokio::task::spawn_blocking(move || -> std::io::Result<(StatusCode, Bytes)> {
                let file = std::fs::File::open(&file_path)?;
                let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(std::io::Error::other)?;
                let slice = &mmap[start as usize..end as usize];
                Ok((status, Bytes::copy_from_slice(slice)))
            })
            .await
            .map_err(|e| std::io::Error::other(format!("spawn_blocking join error: {e}")))??;

        return session.status_code(status2).body(body).eom_async().await;
    }

    // Large body: H1 chunked streaming
    let chunk_size = if stream_threshold_and_chunk_size.1 == 0 {
        64 * 1024
    } else {
        stream_threshold_and_chunk_size.1
    };

    // Start streaming response (your start_h1_streaming should set Transfer-Encoding: chunked)
    session.status_code(status);
    session.start_h1_streaming_async().await?;

    let mut f = tokio::fs::File::open(&file_path).await.map_err(|e| {
        std::io::Error::other(format!("Failed to open file {}: {e}", file_path.display()))
    })?;
    f.seek(SeekFrom::Start(start)).await?;

    let mut remaining = bytes_to_send;
    let mut buf = vec![0u8; chunk_size];

    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = f.read(&mut buf[..to_read]).await?;
        if n == 0 {
            break;
        }
        remaining -= n as u64;

        // send_h1_data is sync; your H1AsyncSession should block_in_place internally.
        session
            .send_h1_data_async(&buf[..n], remaining == 0)
            .await?;
    }

    Ok(())
}

#[cfg(feature = "net-h2-server")]
pub async fn serve_h2<S: Session>(
    session: &mut S,
    path: &PathBuf,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
    content_disposition_allow_ranges: (&str, bool),
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;

    // meta
    let meta = match tokio::fs::metadata(&path).await {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!(
                "File server failed to get metadata for path: {}: {}",
                path.display(),
                e
            );
            return session
                .status_code(StatusCode::NOT_FOUND)
                .body(Bytes::new())
                .eom();
        }
    };

    // file cache lookup
    const CLOSE_CONNECTION_ON_FAILED: bool = false;
    let file_info = get_file_info!(session, &path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    let result = serve_fn(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition_allow_ranges,
        &mut file_tuple,
        CLOSE_CONNECTION_ON_FAILED,
    );

    // If we have a file tuple, it means it is ready to be served
    if let Some((status, file_path, start, end)) = file_tuple {
        let bytes_to_send = end - start;

        // HEAD was already handled inside serve_fn and returned early (no tuple),
        // so if we are here we have a non-HEAD request and some body to send.

        if bytes_to_send == 0 {
            // Just finish with empty body and headers already set by serve_fn.
            return Ok(());
        }

        let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
            256 * 1024 // fallback
        } else {
            stream_threshold_and_chunk_size.0
        };

        let chunk_size = if stream_threshold_and_chunk_size.1 == 0 {
            64 * 1024
        } else {
            stream_threshold_and_chunk_size.1
        };

        // Case 1: large body ⇒ H2 streaming
        if bytes_to_send >= stream_threshold {
            return serve_h2_streaming(session, status, &file_path, start, end, chunk_size).await;
        }

        // Case 2: small body, send all at once (mmap + eom)
        let mmap = match std::fs::File::open(&file_path) {
            Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
                Ok(mmap) => mmap,
                Err(e) => {
                    eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Bytes::new())
                        .eom();
                }
            },
            Err(e) => {
                eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                return session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Bytes::new())
                    .eom();
            }
        };

        return session
            .status_code(status)
            .body(Bytes::copy_from_slice(&mmap[start as usize..end as usize]))
            .eom();
    }

    // If serve_fn already fully responded (e.g. HEAD / 304 / 406), just return its result.
    result
}

#[cfg(feature = "net-h3-server")]
pub async fn serve_h3<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    stream_threshold_and_chunk_size: (u64, usize),
) -> std::io::Result<()> {
    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;
    let result = serve_async_fn(
        session,
        path,
        file_cache,
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
                            .body(Bytes::new())
                            .eom_async()
                            .await;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Bytes::new())
                        .eom_async()
                        .await;
                }
            };

            return session
                .status_code(status)
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

/// Create a file cache with specified capacity. For better performance use thread_local! to
/// create per-thread caches.
/// # Arguments
/// * `capacity` - The initial capacity of the file cache
/// # Returns
/// A DashMap-based file cache
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
    path: &PathBuf,
    meta: &Metadata,
    modified: SystemTime,
    cache: &FileCache,
) -> FileInfo {
    let duration = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let etag = format!("\"{}-{}\"", duration.as_secs(), meta.len());
    let mime_type = mime_guess::from_path(path)
        .first()
        .unwrap_or(mime::APPLICATION_OCTET_STREAM);

    // Precompute Last-Modified string once
    let last_modified_str = httpdate::HttpDate::from(modified).to_string();

    // Probe precompressed siblings once
    let parent = path.parent();
    let file_stem = path.file_name().and_then(|f| f.to_str());
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
        path: path.clone(),
        size: meta.len(),
        modified,
        last_modified_str,
        gz_info,
        br_info,
        zstd_info,
    };

    cache.insert(path.to_string_lossy().to_string(), info.clone());
    info
}

fn parse_byte_range(header: &HeaderValue, total_size: u64) -> Option<Range<u64>> {
    let header_str = header.to_str().ok()?;
    if !header_str.starts_with("bytes=") {
        return None;
    }

    let ranges_part = header_str["bytes=".len()..].trim();

    // If multiple ranges are requested (comma present), we don't support
    // multipart/byteranges yet – treat as "no range" so caller sends 200 OK.
    if ranges_part.contains(',') {
        return None;
    }

    let (start_str, end_str) = ranges_part.split_once('-')?;

    match (start_str.parse::<u64>().ok(), end_str.parse::<u64>().ok()) {
        // "bytes=0-1445"
        (Some(start), Some(end)) if start < total_size && start <= end => {
            Some(start..(end + 1).min(total_size))
        }
        // "bytes=6008766-"
        (Some(start), None) if start < total_size => Some(start..total_size),
        // "bytes=-500"
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
    let mut headers = http::HeaderMap::new();
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
    session.status_code(status).headers(&headers)?;

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
                }?;
            }

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
    let mut headers = http::HeaderMap::new();
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
    session.status_code(status).headers(&headers)?;
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

        #[cfg(all(feature = "rt-glommio", not(feature = "rt-tokio"), target_os = "linux"))]
        glommio::yield_if_needed().await;

        #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
        tokio::task::yield_now().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "net-h1-server")]
    use crate::network::http::server::H1Config;
    use crate::network::http::session::Session;
    use crate::network::http::{
        file::{EncodingType, FileInfo},
        server::HFactory,
    };
    use dashmap::DashMap;
    use std::sync::OnceLock;

    struct FileServer<T>(pub T);

    struct FileService;

    static FILE_CACHE: OnceLock<DashMap<String, FileInfo>> = OnceLock::new();
    fn get_cache() -> &'static DashMap<String, FileInfo> {
        FILE_CACHE.get_or_init(|| DashMap::with_capacity(128))
    }

    #[cfg(feature = "net-h1-server")]
    impl crate::network::http::session::HService for FileService {
        fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
            const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
            const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
            const H1_STREAM_THRESHOLD: u64 = 256 * 1024; // 256 KB
            const H1_STREAM_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

            // session.header(
            //     http::header::CONNECTION,
            //     http::HeaderValue::from_static("close"),
            // )?;

            use crate::network::http::file::serve_h1;
            serve_h1(
                session,
                &std::path::PathBuf::from(file!()),
                get_cache(),
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
                (H1_STREAM_THRESHOLD, H1_STREAM_CHUNK_SIZE),
                "inline",
                true,
            )
        }
    }

    #[cfg(any(feature = "net-h2-server", feature = "net-h3-server"))]
    #[async_trait::async_trait(?Send)]
    impl crate::network::http::session::HAsyncService for FileService {
        async fn call<SE: Session>(&mut self, session: &mut SE) -> std::io::Result<()> {
            const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
            const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
            const H2_STREAM_THRESHOLD: u64 = 128 * 1024; // 128 KB
            const H2_STREAM_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

            if session.req_http_version() == http::Version::HTTP_3 {
                #[cfg(all(
                    feature = "net-h3-server",
                    feature = "rt-glommio",
                    target_os = "linux"
                ))]
                if let Err(e) = crate::network::http::file::serve_h3(
                    session,
                    file!(),
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
            } else if session.req_http_version() == http::Version::HTTP_2 {
                let _ = session.header(
                    http::header::ALT_SVC,
                    http::HeaderValue::from_static("h3=\":8082\"; ma=86400"),
                );

                #[cfg(feature = "net-h2-server")]
                if let Err(e) = crate::network::http::file::serve_h2(
                    session,
                    &std::path::PathBuf::from(file!()),
                    get_cache(),
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
                    ("inline", true),
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
                let _ = session.header(
                    http::header::ALT_SVC,
                    http::HeaderValue::from_static("h3=\":8082\"; ma=86400"),
                );

                #[cfg(feature = "net-h2-server")]
                if let Err(e) = crate::network::http::file::serve_h1_async(
                    session,
                    &std::path::PathBuf::from(file!()),
                    get_cache(),
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
                    ("inline", true),
                )
                .await
                {
                    eprintln!("H2 FileService failed: {e}");
                    return session
                        .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(bytes::Bytes::new())
                        .eom();
                };
            }
            Ok(())
        }
    }

    impl HFactory for FileServer<FileService> {
        #[cfg(feature = "net-h1-server")]
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
        // Pick a port and start the server
        let mut threads = Vec::new();

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();

        cfg_if::cfg_if! {
            if #[cfg(feature = "net-h1-server")] {
                const NUMBER_OF_WORKERS: usize = 2;
                const STACK_SIZE: usize = 2 * 1024 * 1024;
                crate::init_global_poller(NUMBER_OF_WORKERS, STACK_SIZE);

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
                            )
                            .unwrap_or_else(|_| panic!("H1 file server failed to start for thread {id:?}"))
                            .join()
                            .unwrap_or_else(|_| panic!("H1 file server failed to joining thread {id:?}"));
                    });
                    threads.push(h1_handle);
                }
            }
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
                        .start_h2_tls(addr, (None, cert_pem, key_pem), H2Config::default())
                        .unwrap_or_else(|_| panic!("H2 file server failed to start for thread {id:?}"));
                });
                threads.push(h2_handle);
            }
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "net-h3-server")] {
                let cert_h3_pem = certs.0.clone();
                let key_h3_pem = certs.1.clone();
                let h3_handle = std::thread::spawn(move || {
                    use crate::network::http::server::H3Config;
                    let addr = "0.0.0.0:8082";
                    let cert_pem = cert_h3_pem.as_bytes();
                    let key_pem = key_h3_pem.as_bytes();
                    let id = std::thread::current().id();
                    println!("Starting H2 server on {addr} with thread: {id:?}");
                    FileServer(FileService)
                        .start_h3_tls(addr, (None, cert_pem, key_pem), H3Config::default())
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
