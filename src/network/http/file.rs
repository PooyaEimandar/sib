use crate::network::http::session::Session;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use mime::Mime;
use sha2::{Digest, Sha256};
use std::{
    fs::Metadata,
    io::Read,
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

// Metadata is only a cache key, never the HTTP validator. On Unix include
// inode identity and change time so restoring mtime cannot hide a rewrite.
// Other platforms rehash until an equally reliable change key is available.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    size: u64,
    modified: SystemTime,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(unix)]
    changed: (i64, i64),
}

impl FileStamp {
    fn from_metadata(meta: &Metadata) -> std::io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            size: meta.len(),
            modified: meta.modified()?,
            #[cfg(unix)]
            identity: (meta.dev(), meta.ino()),
            #[cfg(unix)]
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    fn can_reuse(&self, other: &Self) -> bool {
        cfg!(unix) && self == other
    }
}

#[derive(Clone)]
struct FileVersion {
    path: PathBuf,
    stamp: FileStamp,
    etag: String,
}

#[derive(Clone)]
pub struct FileInfo {
    original: FileVersion,
    mime_type: String,
    last_modified_str: String,
    gz_info: Option<FileVersion>,
    br_info: Option<FileVersion>,
    zstd_info: Option<FileVersion>,
}

pub type FileCache = DashMap<String, FileInfo>;

fn file_vary_header(allow_ranges: bool) -> HeaderValue {
    // A cache must not satisfy an identity range from a stored compressed response.
    HeaderValue::from_static(if allow_ranges {
        "Accept-Encoding, Range"
    } else {
        "Accept-Encoding"
    })
}

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

    let range_header = if allow_ranges && session.req_method() == http::Method::GET {
        session.req_header(&header::RANGE)
    } else {
        None
    };
    let range_requested = range_header.is_some();
    // Asset offsets refer to the original file. Disable sidecars as well as
    // on-the-fly compression, but still reject an explicit identity exclusion.
    let encoding_order: &[EncodingType] = if range_requested {
        &[EncodingType::None]
    } else {
        encoding_order
    };

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

    let can_compress = file_info.original.stamp.size >= min_bytes_on_the_fly_size
        && file_info.original.stamp.size <= max_bytes_on_the_fly_size
        && !range_requested;
    let encoding = available_file_encoding(&file_info, encoding, can_compress);

    let mut rsp_headers = http::HeaderMap::new();
    rsp_headers.insert(header::VARY, file_vary_header(allow_ranges));
    let applied_encoding = match encoding {
        EncodingType::None | EncodingType::NotAcceptable => None,
        _ => Some(encoding.as_str()),
    };

    let selected_file = selected_file_version(&file_info, &encoding);
    let compressed = if selected_file.is_none() && encoding != EncodingType::NotAcceptable {
        match compress_file_blocking(&file_info.original.path, encoding.clone()) {
            Ok(compressed) => Some(compressed),
            Err(e) => {
                error!(
                    "Compression failed for {}: {e}",
                    file_info.original.path.display()
                );
                let mut headers = get_error_headers!(close_connection_on_failed);
                headers.insert(header::VARY, file_vary_header(allow_ranges));
                return session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .headers(&headers)?
                    .body(Bytes::new())
                    .eom();
            }
        }
    } else {
        None
    };
    let etag_to_send = if let Some((_, etag)) = &compressed {
        etag.clone()
    } else {
        rep_etag(
            &selected_file.unwrap_or(&file_info.original).etag,
            applied_encoding,
        )
    };

    // Normal request errors (such as 406) win; otherwise If-Match must run
    // before If-None-Match, range handling and sending the response body.
    if encoding != EncodingType::NotAcceptable
        && session.req_header(&header::IF_MATCH).is_some()
        && !if_match_satisfied(&session.req_headers(), &etag_to_send)
    {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::PRECONDITION_FAILED)
            .headers(&headers)?
            .body(Bytes::new())
            .eom();
    }

    if encoding != EncodingType::NotAcceptable
        && let Some(header_val) = session.req_header(&header::IF_NONE_MATCH)
        && if_none_match_contains(&header_val, &etag_to_send)
    {
        if let Some(enc) = applied_encoding {
            rsp_headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(enc).map_err(std::io::Error::other)?,
            );
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
        ]);

        return session
            .status_code(StatusCode::NOT_MODIFIED)
            .headers(&rsp_headers)?
            .body(Bytes::new())
            .eom();
    }

    if encoding == EncodingType::NotAcceptable {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::NOT_ACCEPTABLE)
            .headers(&headers)?
            .body(Bytes::new())
            .eom();
    }

    if let Some((body, _)) = compressed {
        apply_compressed_headers(
            &mut rsp_headers,
            &file_info,
            encoding.as_str(),
            disable_content_length,
            &etag_to_send,
            body.len(),
        )?;
        let body = if session.req_method() == http::Method::HEAD {
            Bytes::new()
        } else {
            body
        };
        return session
            .status_code(StatusCode::OK)
            .headers(&rsp_headers)?
            .body(body)
            .eom();
    }

    // Not-acceptable and compressed-on-the-fly responses returned above.
    let Some(selected_file) = selected_file else {
        return Err(std::io::Error::other("no file representation to serve"));
    };
    let (file_path, total_size) = (selected_file.path.clone(), selected_file.stamp.size);
    if let Some(enc) = applied_encoding {
        rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    // If-Range matching is not implemented yet; keep returning the complete
    // representation rather than applying an unchecked conditional range.
    let range = if session.req_header(&header::IF_RANGE).is_some() {
        ByteRange::Ignored
    } else {
        range_header
            .as_ref()
            .map_or(ByteRange::Ignored, |h| parse_byte_range(h, total_size))
    };

    if range == ByteRange::Unsatisfiable {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{total_size}"))
                .map_err(std::io::Error::other)?,
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::RANGE_NOT_SATISFIABLE)
            .headers(&headers)?
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
    ]);

    let (status, start, end) = if let ByteRange::Satisfiable(r) = range {
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

    let range_header = if allow_ranges && session.req_method() == http::Method::GET {
        session.req_header(&header::RANGE)
    } else {
        None
    };
    let range_requested = range_header.is_some();
    // Asset offsets refer to the original file. Disable sidecars as well as
    // on-the-fly compression, but still reject an explicit identity exclusion.
    let encoding_order: &[EncodingType] = if range_requested {
        &[EncodingType::None]
    } else {
        encoding_order
    };

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

    let can_compress = file_info.original.stamp.size >= min_bytes_on_the_fly_size
        && file_info.original.stamp.size <= max_bytes_on_the_fly_size
        && !range_requested;
    let encoding = available_file_encoding(&file_info, encoding, can_compress);

    let mut rsp_headers = http::HeaderMap::new();
    rsp_headers.insert(header::VARY, file_vary_header(allow_ranges));
    let applied_encoding = match encoding {
        EncodingType::None | EncodingType::NotAcceptable => None,
        _ => Some(encoding.as_str()),
    };

    let selected_file = selected_file_version(&file_info, &encoding);
    let compressed = if selected_file.is_none() && encoding != EncodingType::NotAcceptable {
        match compress_file_async(&file_info.original.path, encoding.clone()).await {
            Ok(compressed) => Some(compressed),
            Err(e) => {
                error!(
                    "Compression failed for {}: {e}",
                    file_info.original.path.display()
                );
                let mut headers = get_error_headers!(close_connection_on_failed);
                headers.insert(header::VARY, file_vary_header(allow_ranges));
                return session
                    .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .headers(&headers)?
                    .body(Bytes::new())
                    .eom_async()
                    .await;
            }
        }
    } else {
        None
    };
    let etag_to_send = if let Some((_, etag)) = &compressed {
        etag.clone()
    } else {
        rep_etag(
            &selected_file.unwrap_or(&file_info.original).etag,
            applied_encoding,
        )
    };

    // Normal request errors (such as 406) win; otherwise If-Match must run
    // before If-None-Match, range handling and sending the response body.
    if encoding != EncodingType::NotAcceptable
        && session.req_header(&header::IF_MATCH).is_some()
        && !if_match_satisfied(&session.req_headers(), &etag_to_send)
    {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::PRECONDITION_FAILED)
            .headers(&headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    if encoding != EncodingType::NotAcceptable
        && let Some(header_val) = session.req_header(&header::IF_NONE_MATCH)
        && if_none_match_contains(&header_val, &etag_to_send)
    {
        if let Some(enc) = applied_encoding {
            rsp_headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(enc).map_err(std::io::Error::other)?,
            );
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
        ]);

        return session
            .status_code(StatusCode::NOT_MODIFIED)
            .headers(&rsp_headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    if encoding == EncodingType::NotAcceptable {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::NOT_ACCEPTABLE)
            .headers(&headers)?
            .body(Bytes::new())
            .eom_async()
            .await;
    }

    if let Some((body, _)) = compressed {
        apply_compressed_headers(
            &mut rsp_headers,
            &file_info,
            encoding.as_str(),
            disable_content_length,
            &etag_to_send,
            body.len(),
        )?;
        let body = if session.req_method() == http::Method::HEAD {
            Bytes::new()
        } else {
            body
        };
        return session
            .status_code(StatusCode::OK)
            .headers(&rsp_headers)?
            .body(body)
            .eom_async()
            .await;
    }

    // Not-acceptable and compressed-on-the-fly responses returned above.
    let Some(selected_file) = selected_file else {
        return Err(std::io::Error::other("no file representation to serve"));
    };
    let (file_path, total_size) = (selected_file.path.clone(), selected_file.stamp.size);
    if let Some(enc) = applied_encoding {
        rsp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    // If-Range matching is not implemented yet; keep returning the complete
    // representation rather than applying an unchecked conditional range.
    let range = if session.req_header(&header::IF_RANGE).is_some() {
        ByteRange::Ignored
    } else {
        range_header
            .as_ref()
            .map_or(ByteRange::Ignored, |h| parse_byte_range(h, total_size))
    };

    if range == ByteRange::Unsatisfiable {
        let mut headers = get_error_headers!(close_connection_on_failed);
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{total_size}"))
                .map_err(std::io::Error::other)?,
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(header::VARY, file_vary_header(allow_ranges));
        return session
            .status_code(StatusCode::RANGE_NOT_SATISFIABLE)
            .headers(&headers)?
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
    ]);

    let (status, start, end) = if let ByteRange::Satisfiable(r) = range {
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

    let file_info = match get_file_info_async(path, meta, file_cache).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to validate file {}: {e}", path.display());
            let headers = get_error_headers!(false);
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(&headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

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

// Read an exact extent of a file. A file that shrank since its metadata was
// cached fails with UnexpectedEof instead of faulting a mapping or panicking.
fn read_file_extent(path: &Path, start: u64, len: u64) -> std::io::Result<Bytes> {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let size = usize::try_from(len).map_err(std::io::Error::other)?;
    let mut body = vec![0; size];
    file.read_exact(&mut body)?;
    Ok(Bytes::from(body))
}

// Once body streaming starts, an error must close the connection: the client
// still expects the advertised bytes and cannot parse a second HTTP response.
fn abort_file_stream(error: std::io::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, error)
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
    let file_info = match get_file_info(path, meta, file_cache) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to validate file {}: {e}", path.display());
            let headers = get_error_headers!(CLOSE_CONNECTION_ON_FAILED);
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(&headers)?
                .body(Bytes::new())
                .eom();
        }
    };

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

        let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
            256 * 1024
        } else {
            stream_threshold_and_chunk_size.0
        };

        // Snapshot small responses before headers. mmap could fault if a file
        // is truncated during delivery, and stale ranges could panic on slicing.
        if bytes_to_send < stream_threshold {
            let body =
                read_file_extent(&file_path, start, bytes_to_send).map_err(abort_file_stream)?;
            return session.status_code(status).body(body).eom();
        }

        // Open the file before sending streaming headers.
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

        {
            use std::io::{Read, Seek, SeekFrom};

            let mut f = file;
            f.seek(SeekFrom::Start(start))?;

            session.status_code(status);
            session.start_h1_streaming().map_err(abort_file_stream)?;

            let stream_chunk = if stream_threshold_and_chunk_size.1 == 0 {
                64 * 1024 // 64 KB
            } else {
                stream_threshold_and_chunk_size.1
            };

            let mut remaining = bytes_to_send;
            let mut buf = vec![0u8; remaining.min(stream_chunk as u64) as usize];

            while remaining > 0 {
                let to_read = remaining.min(buf.len() as u64) as usize;
                let n = match f.read(&mut buf[..to_read]) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result.map_err(abort_file_stream)?,
                };
                if n == 0 {
                    return Err(abort_file_stream(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "file ended before the advertised response length",
                    )));
                }
                remaining -= n as u64;

                session
                    .send_h1_data(&buf[..n], remaining == 0)
                    .map_err(abort_file_stream)?;
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
    let file_info = match get_file_info_async(path, meta, file_cache).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to validate file {}: {e}", path.display());
            let headers = get_error_headers!(CLOSE_CONNECTION_ON_FAILED);
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(&headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

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

    // Apply the streaming threshold to both ranges and full downloads.
    let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
        256 * 1024
    } else {
        stream_threshold_and_chunk_size.0
    };

    // Snapshot a small response with runtime file I/O before sending headers.
    if bytes_to_send < stream_threshold {
        let mut file = tokio::fs::File::open(&file_path)
            .await
            .map_err(abort_file_stream)?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(abort_file_stream)?;
        let size = usize::try_from(bytes_to_send).map_err(std::io::Error::other)?;
        let mut body = vec![0; size];
        file.read_exact(&mut body)
            .await
            .map_err(abort_file_stream)?;
        return session
            .status_code(status)
            .body(Bytes::from(body))
            .eom_async()
            .await;
    }

    // Large body: bounded H1 streaming with the known Content-Length.
    let chunk_size = if stream_threshold_and_chunk_size.1 == 0 {
        64 * 1024
    } else {
        stream_threshold_and_chunk_size.1
    };

    let mut f = tokio::fs::File::open(&file_path).await.map_err(|e| {
        std::io::Error::other(format!("Failed to open file {}: {e}", file_path.display()))
    })?;
    f.seek(SeekFrom::Start(start)).await?;

    session.status_code(status);
    session
        .start_h1_streaming_async()
        .await
        .map_err(abort_file_stream)?;

    let mut remaining = bytes_to_send;
    let mut buf = vec![0u8; remaining.min(chunk_size as u64) as usize];

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = match f.read(&mut buf[..to_read]).await {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(abort_file_stream)?,
        };
        if n == 0 {
            return Err(abort_file_stream(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file ended before the advertised response length",
            )));
        }
        remaining -= n as u64;

        session
            .send_h1_data_async(&buf[..n], remaining == 0)
            .await
            .map_err(abort_file_stream)?;
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
                .eom_async()
                .await;
        }
    };

    // file cache lookup
    const CLOSE_CONNECTION_ON_FAILED: bool = false;
    let file_info = match get_file_info_async(path, meta, file_cache).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to validate file {}: {e}", path.display());
            let headers = get_error_headers!(CLOSE_CONNECTION_ON_FAILED);
            return session
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .headers(&headers)?
                .body(Bytes::new())
                .eom_async()
                .await;
        }
    };

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

    let Some((status, file_path, start, end)) = file_tuple else {
        return Ok(());
    };
    let bytes_to_send = end - start;
    if bytes_to_send == 0 {
        return session.body(Bytes::new()).eom_async().await;
    }

    let stream_threshold = if stream_threshold_and_chunk_size.0 == 0 {
        256 * 1024
    } else {
        stream_threshold_and_chunk_size.0
    };
    let mut file = H2FileReader::open(&file_path, start, end).await?;
    if bytes_to_send >= stream_threshold {
        // serve_fn_async already set the response headers, including the range.
        return send_h2_file(
            session,
            status,
            file,
            bytes_to_send,
            stream_threshold_and_chunk_size.1,
        )
        .await;
    }

    // Buffer only the small-body path. File reads must not fault mmap pages or
    // wait on the filesystem on the thread driving other connections.
    let size = usize::try_from(bytes_to_send).map_err(std::io::Error::other)?;
    let body = file.read_exact_bytes(size).await?;
    session.status_code(status).body(body).eom_async().await
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

    // If we have a file tuple, it means it is ready to be served
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
            let body = match read_file_extent(&file_path, start, bytes_to_send) {
                Ok(body) => body,
                Err(e) => {
                    error!("Failed to read file: {}: {}", file_path.display(), e);
                    return session
                        .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Bytes::new())
                        .eom_async()
                        .await;
                }
            };

            return session.status_code(status).body(body).eom_async().await;
        }
    }

    result
}

// Compression may fall back to identity when no sidecar exists and the file
// is outside the on-the-fly size limits. Preconditions must use that actual ETag.
fn available_file_encoding(
    file_info: &FileInfo,
    encoding: EncodingType,
    can_compress: bool,
) -> EncodingType {
    match encoding {
        EncodingType::Br { .. } if file_info.br_info.is_none() && !can_compress => {
            EncodingType::None
        }
        EncodingType::Gzip { .. } if file_info.gz_info.is_none() && !can_compress => {
            EncodingType::None
        }
        EncodingType::Zstd { .. } if file_info.zstd_info.is_none() && !can_compress => {
            EncodingType::None
        }
        other => other,
    }
}

// Called only after confirming that the file exists. Repeated field lines form
// one list. Invalid syntax fails closed, including a wildcard mixed with tags.
fn if_match_satisfied(headers: &HeaderMap, target: &str) -> bool {
    let mut value = Vec::new();
    for (index, header) in headers.get_all(header::IF_MATCH).iter().enumerate() {
        if index != 0 {
            value.push(b',');
        }
        value.extend_from_slice(header.as_bytes());
    }
    if !headers.contains_key(header::IF_MATCH) {
        return true;
    }
    let mut rest = value.trim_ascii();
    if rest == b"*" {
        return true;
    }
    let mut matched = false;
    while !rest.is_empty() {
        rest = rest.trim_ascii_start();
        // HTTP list syntax permits empty members.
        if let Some(tail) = rest.strip_prefix(b",") {
            rest = tail;
            continue;
        }
        if rest.is_empty() {
            break;
        }
        let weak = rest.starts_with(b"W/");
        if weak {
            rest = &rest[2..];
        }
        if !rest.starts_with(b"\"") {
            return false;
        }
        let Some(end) = rest[1..].iter().position(|&b| b == b'"').map(|i| i + 1) else {
            return false;
        };
        // Entity tags are opaque bytes, not quoted strings: commas and backslashes
        // inside them are literal. Spaces, controls and DEL are not valid etagc.
        if !rest[1..end]
            .iter()
            .all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80)
        {
            return false;
        }
        matched |= !weak && &rest[..=end] == target.as_bytes();
        rest = rest[end + 1..].trim_ascii_start();
        if !rest.is_empty() && !rest.starts_with(b",") {
            return false;
        }
    }
    matched
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
///
/// ETags hash representation bytes. Unix caches reuse hashes while file identity,
/// size, modification time and change time match. Other platforms rehash on each
/// lookup. Publish assets atomically and keep them immutable during transfers.
/// # Arguments
/// * `capacity` - The initial capacity of the file cache
/// # Returns
/// A DashMap-based file cache
pub fn load_file_cache(capacity: usize) -> FileCache {
    DashMap::with_capacity(capacity)
}

fn selected_file_version<'a>(
    info: &'a FileInfo,
    encoding: &EncodingType,
) -> Option<&'a FileVersion> {
    match encoding {
        EncodingType::None => Some(&info.original),
        EncodingType::Gzip { .. } => info.gz_info.as_ref(),
        EncodingType::Br { .. } => info.br_info.as_ref(),
        EncodingType::Zstd { .. } => info.zstd_info.as_ref(),
        EncodingType::NotAcceptable => None,
    }
}

fn digest_etag(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tag = String::with_capacity(73);
    tag.push_str("\"sha256-");
    for byte in digest {
        tag.push(char::from(HEX[usize::from(byte >> 4)]));
        tag.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    tag.push('"');
    tag
}

fn compress_file_blocking(path: &Path, encoding: EncodingType) -> std::io::Result<(Bytes, String)> {
    // The size thresholds bound this allocation. Hash the exact encoded bytes,
    // so compression settings and encoder upgrades cannot reuse a stale tag.
    let input = std::fs::read(path)?;
    let bytes = match encoding {
        EncodingType::Gzip { level } => encode_gzip(&input, level)?,
        EncodingType::Br {
            buffer_size,
            quality,
            lgwindow,
        } => encode_brotli(&input, buffer_size, quality, lgwindow)?,
        EncodingType::Zstd { level } => encode_zstd(&input, level)?,
        _ => {
            return Err(std::io::Error::other(
                "expected a compressed representation",
            ));
        }
    };
    let tag = rep_etag(
        &digest_etag(&Sha256::digest(&bytes)),
        Some(encoding.as_str()),
    );
    Ok((bytes, tag))
}

async fn compress_file_async(
    path: &Path,
    encoding: EncodingType,
) -> std::io::Result<(Bytes, String)> {
    #[cfg(feature = "rt-tokio")]
    {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || compress_file_blocking(&path, encoding))
            .await
            .map_err(std::io::Error::other)?
    }
    #[cfg(not(feature = "rt-tokio"))]
    compress_file_blocking(path, encoding)
}

fn apply_compressed_headers(
    headers: &mut HeaderMap,
    file_info: &FileInfo,
    encoding_name: &str,
    disable_content_length: bool,
    etag: &str,
    size: usize,
) -> std::io::Result<()> {
    if !disable_content_length {
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&size.to_string()).map_err(std::io::Error::other)?,
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
            HeaderValue::from_str(etag).map_err(std::io::Error::other)?,
        ),
        (
            header::LAST_MODIFIED,
            HeaderValue::from_str(&file_info.last_modified_str).map_err(std::io::Error::other)?,
        ),
    ]);
    Ok(())
}

fn get_file_info(path: &Path, meta: Metadata, cache: &FileCache) -> std::io::Result<FileInfo> {
    let key = path.to_string_lossy().to_string();
    // Clone before inserting: retaining a DashMap read guard here can deadlock.
    let previous = cache.get(&key).map(|entry| entry.clone());
    let info = generate_file_info(path, meta, previous.as_ref())?;
    cache.insert(key, info.clone());
    Ok(info)
}

async fn get_file_info_async(
    path: &Path,
    meta: Metadata,
    cache: &FileCache,
) -> std::io::Result<FileInfo> {
    #[cfg(feature = "rt-tokio")]
    {
        let key = path.to_string_lossy().to_string();
        let previous = cache.get(&key).map(|entry| entry.clone());
        let path = path.to_owned();
        let info =
            tokio::task::spawn_blocking(move || generate_file_info(&path, meta, previous.as_ref()))
                .await
                .map_err(std::io::Error::other)??;
        cache.insert(key, info.clone());
        Ok(info)
    }
    #[cfg(not(feature = "rt-tokio"))]
    get_file_info(path, meta, cache)
}

fn load_file_version(
    path: &Path,
    meta: Metadata,
    previous: Option<&FileVersion>,
) -> std::io::Result<FileVersion> {
    let stamp = FileStamp::from_metadata(&meta)?;
    if let Some(previous) = previous
        && previous.stamp.can_reuse(&stamp)
    {
        return Ok(previous.clone());
    }

    // Hash through a bounded buffer, not an allocation the size of a pak file.
    // Retry if a publisher changes/replaces the file while it is being hashed.
    // As with streaming, published assets should be replaced atomically instead
    // of being rewritten in place during active transfers.
    for _ in 0..3 {
        let mut file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::other("expected a regular file"));
        }
        let before = FileStamp::from_metadata(&meta)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let count = match file.read(&mut buffer) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            size += count as u64;
        }
        let after = FileStamp::from_metadata(&file.metadata()?)?;
        let current = FileStamp::from_metadata(&std::fs::metadata(path)?)?;
        if before == after && after == current && size == after.size {
            return Ok(FileVersion {
                path: path.to_owned(),
                stamp: after,
                etag: digest_etag(&digest.finalize()),
            });
        }
    }
    Err(std::io::Error::other(
        "file changed while generating its ETag",
    ))
}

fn load_sidecar(
    path: PathBuf,
    previous: Option<&FileVersion>,
) -> std::io::Result<Option<FileVersion>> {
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => load_file_version(&path, meta, previous).map(Some),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn generate_file_info(
    path: &Path,
    meta: Metadata,
    previous: Option<&FileInfo>,
) -> std::io::Result<FileInfo> {
    let original = load_file_version(path, meta, previous.map(|info| &info.original))?;
    let last_modified_str = httpdate::HttpDate::from(original.stamp.modified).to_string();
    let (mut gz_info, mut br_info, mut zstd_info) = (None, None, None);
    // Sidecars have independent lifetimes: probe them even when the source did
    // not change, and hash their own bytes rather than decorating the source tag.
    if let (Some(parent), Some(stem)) = (path.parent(), path.file_name().and_then(|f| f.to_str())) {
        gz_info = load_sidecar(
            parent.join("gz").join(format!("{stem}.gz")),
            previous.and_then(|i| i.gz_info.as_ref()),
        )?;
        br_info = load_sidecar(
            parent.join("br").join(format!("{stem}.br")),
            previous.and_then(|i| i.br_info.as_ref()),
        )?;
        zstd_info = load_sidecar(
            parent.join("zstd").join(format!("{stem}.zstd")),
            previous.and_then(|i| i.zstd_info.as_ref()),
        )?;
    }
    Ok(FileInfo {
        original,
        mime_type: mime_for_path(path).to_string(),
        last_modified_str,
        gz_info,
        br_info,
        zstd_info,
    })
}

fn mime_for_path(path: &Path) -> Mime {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("ktx2"))
    {
        "image/ktx2"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM)
    } else {
        mime_guess::from_path(path)
            .first()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ByteRange {
    // Malformed, unknown-unit and multipart ranges are ignored: send the full response.
    Ignored,
    Unsatisfiable,
    Satisfiable(Range<u64>),
}

fn parse_byte_range(header: &HeaderValue, total_size: u64) -> ByteRange {
    let Ok(value) = header.to_str() else {
        return ByteRange::Ignored;
    };
    let Some((unit, ranges)) = value.trim().split_once('=') else {
        return ByteRange::Ignored;
    };
    if !unit.eq_ignore_ascii_case("bytes") || ranges.contains(',') {
        return ByteRange::Ignored;
    }
    let Some((first, last)) = ranges.trim().split_once('-') else {
        return ByteRange::Ignored;
    };

    // Only decimal digits are valid. Saturate arbitrarily large numerals rather
    // than treating a malformed/overflowing end as an omitted end or suffix.
    fn number(value: &str) -> Option<u64> {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(value.parse().unwrap_or(u64::MAX))
    }

    if first.is_empty() {
        let Some(length) = number(last) else {
            return ByteRange::Ignored;
        };
        if length == 0 {
            return ByteRange::Unsatisfiable;
        }
        // A nonzero suffix of an empty representation is valid. Ignore it instead
        // of emitting an impossible Content-Range with an inclusive end of -1.
        if total_size == 0 {
            return ByteRange::Ignored;
        }
        return ByteRange::Satisfiable(total_size.saturating_sub(length)..total_size);
    }

    let Some(start) = number(first) else {
        return ByteRange::Ignored;
    };
    let end = if last.is_empty() {
        total_size
    } else {
        let Some(last) = number(last) else {
            return ByteRange::Ignored;
        };
        if last < start {
            return ByteRange::Ignored;
        }
        last.saturating_add(1).min(total_size)
    };
    if start >= total_size {
        return ByteRange::Unsatisfiable;
    }
    ByteRange::Satisfiable(start..end)
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

    // Media and an empty preference list still need identity negotiation.
    let order: &[EncodingType] = if is_media && !is_svg { &[] } else { order };

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
            // Identity is acceptable by default, except for an explicit exclusion
            // or *;q=0 without a more specific identity preference (RFC 9110 12.5.3).
            return identity_q.map_or(star_q != Some(0.0), |q| q > 0.0);
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

// Use the selected runtime's file I/O rather than mmap on its networking thread.
#[cfg(feature = "net-h2-server")]
struct H2FileReader {
    #[cfg(feature = "rt-tokio")]
    file: tokio::fs::File,
    #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
    file: glommio::io::BufferedFile,
    #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
    offset: u64,
    file_len: u64,
}

#[cfg(feature = "net-h2-server")]
impl H2FileReader {
    async fn open(path: &Path, start: u64, end: u64) -> std::io::Result<Self> {
        if start > end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reversed file extent",
            ));
        }
        #[cfg(feature = "rt-tokio")]
        {
            use tokio::io::AsyncSeekExt;
            let mut file = tokio::fs::File::open(path).await?;
            let file_len = file.metadata().await?.len();
            Self::validate_extent(end, file_len)?;
            file.seek(std::io::SeekFrom::Start(start)).await?;
            Ok(Self { file, file_len })
        }
        #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
        {
            let file = glommio::io::BufferedFile::open(path).await?;
            let file_len = file.file_size().await?;
            Self::validate_extent(end, file_len)?;
            Ok(Self {
                file,
                offset: start,
                file_len,
            })
        }
        #[cfg(not(any(feature = "rt-tokio", all(feature = "rt-glommio", target_os = "linux"))))]
        {
            let _ = path;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "HTTP/2 file I/O requires an async runtime",
            ))
        }
    }

    fn validate_extent(end: u64, file_len: u64) -> std::io::Result<()> {
        if end > file_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file is shorter than the selected response extent",
            ));
        }
        Ok(())
    }

    async fn read_exact_bytes(&mut self, size: usize) -> std::io::Result<Bytes> {
        #[cfg(feature = "rt-tokio")]
        {
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0; size];
            self.file.read_exact(&mut bytes).await?;
            Ok(Bytes::from(bytes))
        }
        #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
        {
            let mut bytes = Vec::with_capacity(size);
            while bytes.len() < size {
                let chunk = self.file.read_at(self.offset, size - bytes.len()).await?;
                if chunk.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "file ended during the response",
                    ));
                }
                self.offset += chunk.len() as u64;
                bytes.extend_from_slice(&chunk);
            }
            Ok(Bytes::from(bytes))
        }
        #[cfg(not(any(feature = "rt-tokio", all(feature = "rt-glommio", target_os = "linux"))))]
        {
            let _ = size;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "HTTP/2 file I/O requires an async runtime",
            ))
        }
    }
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
    let file = H2FileReader::open(file_path, start, end).await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if status == StatusCode::PARTIAL_CONTENT && start < end {
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end - 1, file.file_len))
                .map_err(std::io::Error::other)?,
        );
    }
    session.headers(&headers)?;
    send_h2_file(session, status, file, end - start, chunk_size).await
}

#[cfg(feature = "net-h2-server")]
async fn send_h2_file<S: Session>(
    session: &mut S,
    status: StatusCode,
    mut file: H2FileReader,
    mut remaining: u64,
    chunk_size: usize,
) -> std::io::Result<()> {
    let chunk_size = if chunk_size == 0 {
        64 * 1024
    } else {
        chunk_size
    };
    session.status_code(status);
    let mut stream = session.start_h2_streaming()?;
    let result = async {
        if remaining == 0 {
            return stream.send_data(Bytes::new(), true);
        }
        while remaining > 0 {
            let wanted = remaining.min(chunk_size as u64) as usize;
            // Reserve and read only one chunk at a time. A slow peer must not
            // cause a whole file to be read or retained in the H2 send queue.
            stream.reserve_capacity(wanted);
            let mut cap = stream.capacity();
            if cap == 0 {
                #[cfg(feature = "rt-tokio")]
                {
                    cap = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        stream.next_capacity(),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "H2 send capacity timed out",
                        )
                    })??;
                }
                #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
                {
                    cap = glommio::timer::timeout(std::time::Duration::from_secs(3), async {
                        stream
                            .next_capacity()
                            .await
                            .map_err(glommio::GlommioError::IoError)
                    })
                    .await?;
                }
                if cap == 0 {
                    continue;
                }
            }
            let to_send = cap.min(wanted);
            let bytes = file.read_exact_bytes(to_send).await?;
            remaining -= to_send as u64;
            stream.send_data(bytes, remaining == 0)?;

            #[cfg(feature = "rt-tokio")]
            tokio::task::yield_now().await;
            #[cfg(all(not(feature = "rt-tokio"), feature = "rt-glommio", target_os = "linux"))]
            glommio::yield_if_needed().await;
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        // Never send END_STREAM on an incomplete file, including truncation
        // after headers. Fail this stream without closing unrelated requests.
        stream.send_reset(h2::Reason::INTERNAL_ERROR.into());
    }
    result
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
    use std::io::{Seek, SeekFrom};

    let chunk_size = if chunk_size == 0 {
        64 * 1024
    } else {
        chunk_size
    };

    // Open file and compute range (same validations as H2 path). Read it in
    // bounded chunks: a mapping faults with SIGBUS if the file shrinks mid-send.
    let mut file = std::fs::File::open(file_path)?;
    let file_len = file.metadata()?.len();

    if start >= file_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("range start {} beyond EOF {}", start, file_len),
        ));
    }

    let end_excl = end.min(file_len).max(start);
    let total = end_excl - start;
    file.seek(SeekFrom::Start(start))?;

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
    let mut remaining = total;
    while remaining > 0 {
        let to_send = remaining.min(chunk_size as u64) as usize;
        let mut chunk = vec![0; to_send];
        file.read_exact(&mut chunk)?;
        remaining -= to_send as u64;
        session
            .send_h3_data(Bytes::from(chunk), remaining == 0)
            .await?;

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

#[cfg(all(test, feature = "net-h2-server"))]
#[path = "../../../tests/unit/network/http/file_range_tests.rs"]
mod range_tests;
