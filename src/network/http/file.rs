use crate::network::http::session::Session;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use mime::Mime;
use std::{
    fs::Metadata,
    ops::Range,
    path::{Component, Path, PathBuf},
    time::SystemTime,
};
use tracing::error;

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
                error!("Failed to read modified time for: {}: {}", &key, e);

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
    close_connection_on_failed_and_disable_content_length: (bool, bool),
) -> std::io::Result<()> {
    let (min_bytes_on_the_fly_size, max_bytes_on_the_fly_size) = min_max_compress_thresholds;

    let (content_disposition, allow_ranges) = content_disposition_allow_ranges;
    let (close_connection_on_failed, disable_content_length) =
        close_connection_on_failed_and_disable_content_length;

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
        // Serve file directly
        EncodingType::None => (file_info.path.clone(), file_info.size),
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
                    let (status, body) = compress_then_respond(
                        &mut rsp_headers,
                        &file_info,
                        "br",
                        disable_content_length,
                        |b| encode_brotli(b, buffer_size, quality, lgwindow),
                    )?;

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
            } else if file_info.size >= min_bytes_on_the_fly_size
                && file_info.size <= max_bytes_on_the_fly_size
                && !range_requested
            {
                // On-the-fly only if size is within [min,max] AND not a Range request
                let (status, body) = compress_then_respond(
                    &mut rsp_headers,
                    &file_info,
                    "gzip",
                    disable_content_length,
                    |b| encode_gzip(b, level),
                )?;

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

        EncodingType::Zstd { level } => {
            if let Some(zstd_info) = file_info.zstd_info {
                // we already have the zstd info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
                applied_encoding = Some("zstd");
                zstd_info
            } else if file_info.size >= min_bytes_on_the_fly_size
                && file_info.size <= max_bytes_on_the_fly_size
                && !range_requested
            {
                // On-the-fly only if size is within [min,max] AND not a Range request
                let (status, body) = compress_then_respond(
                    &mut rsp_headers,
                    &file_info,
                    "zstd",
                    disable_content_length,
                    |b| encode_zstd(b, level),
                )?;

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
        if !disable_content_length {
            rsp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        rsp_headers.extend([
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
        rsp_headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end - 1, total_size))
                .map_err(std::io::Error::other)?,
        );
        if !disable_content_length {
            let content_length = r.end - r.start;
            rsp_headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&content_length.to_string())
                    .map_err(std::io::Error::other)?,
            );
        }
        (StatusCode::PARTIAL_CONTENT, r.start, r.end)
    } else {
        if !disable_content_length {
            rsp_headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&total_size.to_string()).map_err(std::io::Error::other)?,
            );
        }
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

async fn serve_fn_async<S: Session>(
    session: &mut S,
    file_info: FileInfo,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    content_disposition_allow_ranges: (&str, bool),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
    close_connection_on_failed_and_disable_content_length: (bool, bool),
) -> std::io::Result<()> {
    let (min_bytes_on_the_fly_size, max_bytes_on_the_fly_size) = min_max_compress_thresholds;

    let (content_disposition, allow_ranges) = content_disposition_allow_ranges;
    let (close_connection_on_failed, disable_content_length) =
        close_connection_on_failed_and_disable_content_length;

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
        // Serve file directly
        EncodingType::None => (file_info.path.clone(), file_info.size),
        EncodingType::NotAcceptable => {
            let headers = get_error_headers!(close_connection_on_failed);
            return session
                .status_code(StatusCode::NOT_ACCEPTABLE)
                .headers(&headers)?
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
                    let (status, body) = compress_then_respond_async(
                        &mut rsp_headers,
                        &file_info,
                        "br",
                        disable_content_length,
                        move |b| encode_brotli(b, buffer_size, quality, lgwindow),
                    )
                    .await?;

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
            } else if file_info.size >= min_bytes_on_the_fly_size
                && file_info.size <= max_bytes_on_the_fly_size
                && !range_requested
            {
                // On-the-fly only if size is within [min,max] AND not a Range request
                let (status, body) = compress_then_respond_async(
                    &mut rsp_headers,
                    &file_info,
                    "gzip",
                    disable_content_length,
                    move |b| encode_gzip(b, level),
                )
                .await?;

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

        EncodingType::Zstd { level } => {
            if let Some(zstd_info) = file_info.zstd_info {
                // we already have the zstd info in the cache
                rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
                applied_encoding = Some("zstd");
                zstd_info
            } else if file_info.size >= min_bytes_on_the_fly_size
                && file_info.size <= max_bytes_on_the_fly_size
                && !range_requested
            {
                let (status, body) = compress_then_respond_async(
                    &mut rsp_headers,
                    &file_info,
                    "zstd",
                    disable_content_length,
                    move |b| encode_zstd(b, level),
                )
                .await?;

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
        if !disable_content_length {
            rsp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        rsp_headers.extend([
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
            HeaderValue::from_str(content_disposition).map_err(std::io::Error::other)?,
        ),
        (
            header::ETAG,
            HeaderValue::from_str(&etag_to_send).map_err(std::io::Error::other)?,
        ),
        (header::VARY, HeaderValue::from_static("Accept-Encoding")),
    ]);

    let (status, start, end) = if let Some(r) = range {
        rsp_headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end - 1, total_size))
                .map_err(std::io::Error::other)?,
        );
        if !disable_content_length {
            let content_length = r.end - r.start;
            rsp_headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&content_length.to_string())
                    .map_err(std::io::Error::other)?,
            );
        }
        (StatusCode::PARTIAL_CONTENT, r.start, r.end)
    } else {
        if !disable_content_length {
            rsp_headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&total_size.to_string()).map_err(std::io::Error::other)?,
            );
        }
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
            .eom_async()
            .await;
    }

    session.status_code(status);
    session.headers(&rsp_headers)?;
    *file_tuple = Some((status, file_path, start, end));
    Ok(())
}

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
async fn serve_async_fn<S: Session>(
    session: &mut S,
    path: &PathBuf,
    file_cache: &FileCache,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
    file_tuple: &mut Option<(StatusCode, PathBuf, u64, u64)>,
) -> std::io::Result<()> {
    use crate::network::http::session;

    let (min_bytes_on_the_fly_size, max_bytes_on_the_fly_size) = min_max_compress_thresholds;
    const DISABLE_CONTENT_LENGTH: bool = true;

    // meta
    let meta = match tokio::fs::metadata(path).await {
        Ok(meta) => meta,
        Err(e) => {
            error!(
                "File server failed to get metadata for path: {}: {}",
                path.display(),
                e
            );
            return session
                .status_code(StatusCode::NOT_FOUND)
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

    let file_info = get_file_info!(session, path, meta, file_cache, false);

    // Reuse same logic as async fn: but content-disposition fixed to inline for h3
    serve_fn_async(
        session,
        file_info,
        encoding_order,
        (min_bytes_on_the_fly_size, max_bytes_on_the_fly_size),
        ("inline", true),
        file_tuple,
        (false, DISABLE_CONTENT_LENGTH),
    )
    .await
}

#[cfg(feature = "net-h1-server")]
pub fn serve_h1<S: Session>(
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
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            error!(
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
    let file_info = get_file_info!(session, path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    // Handle headers, range parsing, etc.
    serve_fn(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition_allow_ranges,
        &mut file_tuple,
        (CLOSE_CONNECTION_ON_FAILED, false),
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
                error!("Failed to open file: {}: {}", file_path.display(), e);
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
                    error!("Failed to memory-map file: {}: {}", file_path.display(), e);
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
    use std::io::SeekFrom;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file_tuple: Option<(StatusCode, PathBuf, u64, u64)> = None;

    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => {
            error!(
                "File server failed to get metadata for path: {}: {}",
                path.display(),
                e
            );

            let headers = get_error_headers!(true);
            return session
                .status_code(StatusCode::NOT_FOUND)
                .headers(&headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

    // file cache lookup
    const CLOSE_CONNECTION_ON_FAILED: bool = true;
    let file_info = get_file_info!(session, path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    // async path must use serve_fn_async
    serve_fn_async(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition_allow_ranges,
        &mut file_tuple,
        (CLOSE_CONNECTION_ON_FAILED, false),
    )
    .await?;

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

    // Range response
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

    // Non-range responses, decide streaming threshold
    let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
        256 * 1024
    } else {
        stream_threshold_and_chunk_size.0
    };

    // Small body: send all at once
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

    // Start streaming response
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

        // send_h1_data is sync
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
            error!(
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
    let file_info = get_file_info!(session, path, meta, file_cache, CLOSE_CONNECTION_ON_FAILED);

    let result = serve_fn_async(
        session,
        file_info,
        encoding_order,
        min_max_compress_thresholds,
        content_disposition_allow_ranges,
        &mut file_tuple,
        (CLOSE_CONNECTION_ON_FAILED, true),
    )
    .await;

    // If we have a file tuple, it means it is ready to be served
    if let Some((status, file_path, start, end)) = file_tuple {
        let bytes_to_send = end - start;

        // HEAD was already handled inside serve_fn and returned early (no tuple),
        // so if we are here, we have a non-HEAD request and some body to send.

        if bytes_to_send == 0 {
            // Just finish with empty body and headers already set by serve_fn.
            return session.body(Bytes::new()).eom();
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
                    error!("Failed to memory-map file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Bytes::new())
                        .eom();
                }
            },
            Err(e) => {
                error!("Failed to open file: {}: {}", file_path.display(), e);
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

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
pub async fn serve_h3<S: Session>(
    session: &mut S,
    path: &PathBuf,
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
                        error!("Failed to memory-map file: {}: {}", file_path.display(), e);
                        return session
                            .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Bytes::new())
                            .eom_async()
                            .await;
                    }
                },
                Err(e) => {
                    error!("Failed to open file: {}: {}", file_path.display(), e);
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

fn compress_file_blocking(
    path: &std::path::Path,
    compress_fn: impl Fn(&[u8]) -> std::io::Result<Bytes>,
) -> std::io::Result<Bytes> {
    let f = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&f) }.map_err(std::io::Error::other)?;
    compress_fn(&mmap[..])
}

fn compress_then_respond(
    headers: &mut HeaderMap,
    file_info: &FileInfo,
    encoding_name: &str,
    disable_content_length: bool,
    compress_fn: impl Fn(&[u8]) -> std::io::Result<Bytes>,
) -> std::io::Result<(StatusCode, Bytes)> {
    let res = compress_file_blocking(&file_info.path, compress_fn);
    apply_compressed_headers(
        headers,
        file_info,
        encoding_name,
        disable_content_length,
        res,
    )
}

#[cfg(any(feature = "rt-tokio", all(feature = "rt-glommio", target_os = "linux")))]
async fn compress_then_respond_async(
    headers: &mut HeaderMap,
    file_info: &FileInfo,
    encoding_name: &str,
    disable_content_length: bool,
    compress_fn: impl Fn(&[u8]) -> std::io::Result<Bytes> + Send + 'static,
) -> std::io::Result<(StatusCode, Bytes)> {
    let path = file_info.path.clone();

    #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
    let res = tokio::task::spawn_blocking(move || compress_file_blocking(&path, compress_fn))
        .await
        .map_err(|e| std::io::Error::other(format!("spawn_blocking join error: {e}")))?;

    #[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))]
    let res = compress_file_blocking(&path, compress_fn);

    apply_compressed_headers(
        headers,
        file_info,
        encoding_name,
        disable_content_length,
        res,
    )
}

fn apply_compressed_headers(
    headers: &mut HeaderMap,
    file_info: &FileInfo,
    encoding_name: &str,
    disable_content_length: bool,
    res: std::io::Result<Bytes>,
) -> std::io::Result<(StatusCode, Bytes)> {
    match res {
        Ok(compressed) => {
            let etag_val = rep_etag(&file_info.etag, Some(encoding_name));
            if !disable_content_length {
                headers.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&compressed.len().to_string())
                        .map_err(std::io::Error::other)?,
                );
            }
            headers.extend([
                (
                    header::CONTENT_ENCODING,
                    HeaderValue::from_str(encoding_name).map_err(std::io::Error::other)?,
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
            error!(
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
    // multipart/byteranges yet, treat as "no range" so caller sends 200 OK.
    if ranges_part.contains(',') {
        return None;
    }

    let (start_str, end_str) = ranges_part.split_once('-')?;

    match (start_str.parse::<u64>().ok(), end_str.parse::<u64>().ok()) {
        // "bytes=0-1445"
        (Some(start), Some(end)) if start < total_size && start <= end => {
            // the end is clamped to total_size regardless
            Some(start..end.saturating_add(1).min(total_size))
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

/// Safely map a request path (e.g. from `Session::req_path()`) to a filesystem path
/// confined under `root`, or `None` if it would escape the root.
///
/// The input must already be percent-decoded
pub fn safe_join(root: &Path, req_path: &str) -> Option<PathBuf> {
    // Defensive: ignore any query/fragment if a raw target was passed in.
    let path = req_path.split(['?', '#']).next().unwrap_or("");

    let mut out = root.to_path_buf();
    let mut depth: usize = 0;

    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                // Never allow climbing above the confinement root.
                depth = depth.checked_sub(1)?;
                out.pop();
            }
            seg => {
                if seg.contains('\0') {
                    return None;
                }
                // Accept only a single "normal" path component; anything the OS would
                // treat as a root, prefix (e.g. `C:`), or separator is rejected.
                let mut comps = Path::new(seg).components();
                match (comps.next(), comps.next()) {
                    (Some(Component::Normal(c)), None) => {
                        out.push(c);
                        depth += 1;
                    }
                    _ => return None,
                }
            }
        }
    }

    Some(out)
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
            stream.reserve_capacity(chunk_size);

            #[cfg(all(feature = "rt-tokio", not(feature = "rt-glommio")))]
            {
                const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
                cap = tokio::select! {
                    res = stream.next_capacity() => res,
                    _ = tokio::time::sleep(TIMEOUT) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("H2 next_capacity timed out after {:?}", TIMEOUT),
                    )),
                }?;
            }

            #[cfg(all(target_os = "linux", feature = "rt-glommio", not(feature = "rt-tokio")))]
            {
                const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
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
                };
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

#[cfg(all(feature = "net-h3-server", target_os = "linux"))]
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
#[path = "../../../tests/unit/network/http/file_tests.rs"]
mod tests;
