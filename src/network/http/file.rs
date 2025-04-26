use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use httpdate::HttpDate;
use memmap2::Mmap;
use mime_guess::{Mime, mime};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::{fs::Metadata, ops::Range, path::PathBuf, time::SystemTime};
use tokio::fs;

use crate::{
    network::http::session::{HTTPMethod, Session},
    s_error,
    system::{
        buffer::{Buffer, BufferType},
        compress,
    },
};

const CHUNK_SIZE: usize = 16 * 1024;
const MIN_BYTES: u64 = 1024;

const MAX_ON_THE_FLY_SIZE: u64 = 512 * 1024;
type FileBuffer = Buffer<{ MAX_ON_THE_FLY_SIZE as usize }>; // 512 KB

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncodingType {
    None,
    Gzip,
    Br,
    Zstd,
}

impl EncodingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncodingType::Gzip => "gzip",
            EncodingType::Br => "br",
            EncodingType::Zstd => "zstd",
            EncodingType::None => "",
        }
    }
}

impl std::str::FromStr for EncodingType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "gzip" => Ok(EncodingType::Gzip),
            "br" => Ok(EncodingType::Br),
            "zstd" => Ok(EncodingType::Zstd),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileInfo {
    etag: String,
    mime_type: String,
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

pub type FileCache = Cache<String, FileInfo>;

pub async fn serve(
    session: &mut Session,
    path: &str,
    root: &str,
    // encoding_order: &Vec<EncodingType>,
    file_cache: FileCache,
) -> anyhow::Result<()> {
    let static_root = fs::canonicalize(root).await?;
    let requested_path = PathBuf::from(root).join(path);
    let canonical = match fs::canonicalize(&requested_path).await {
        Ok(path) => path,
        Err(_) => {
            s_error!(
                "File server failed to canonicalize path: {}",
                requested_path.display()
            );
            return session.send_status_eom(StatusCode::NOT_FOUND).await;
        }
    };

    if !canonical.starts_with(&static_root) {
        return session.send_status_eom(StatusCode::FORBIDDEN).await;
    }

    let meta = fs::metadata(&canonical).await?;

    let key = canonical.to_string_lossy().to_string();
    let mut file_info_opt: Option<FileInfo> = None;

    {
        if let Some(info) = file_cache.get(&key).await {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if modified <= info.modified {
                file_info_opt = Some(info.clone());
            }
        }
    }

    let file_info = if let Some(info) = file_info_opt {
        info
    } else {
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let etag = format!(
            "\"{}-{}\"",
            modified.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            meta.len()
        );
        let mime_type = mime_guess::from_path(&canonical).first_or_octet_stream();
        let info = FileInfo {
            etag,
            mime_type: mime_type.to_string(),
            path: canonical.clone(),
            size: meta.len(),
            modified,
        };

        file_cache.insert(key.clone(), info.clone()).await;
        info
    };

    if let Some(p_header_val) = session.read_req_header(http::header::IF_NONE_MATCH) {
        if p_header_val == &file_info.etag {
            return session.send_status_eom(StatusCode::NOT_MODIFIED).await;
        }
    }

    let mime_type: Mime = file_info
        .mime_type
        .parse()
        .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    let encoding = get_encoding(
        session.read_req_header(http::header::ACCEPT_ENCODING),
        &mime_type, // encoding_order,
    );

    let mut meta_opt: Option<Metadata> = None;
    let mut file_path = file_info.path.clone();
    if file_info.size > MIN_BYTES {
        let parent = match file_info.path.parent() {
            Some(parent) => parent,
            None => {
                session.send_status_eom(StatusCode::NOT_FOUND).await?;
                return Ok(());
            }
        };
        let file_name_osstr = match file_info.path.file_name() {
            Some(name) => name,
            None => {
                session
                    .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                    .await?;
                return Ok(());
            }
        };

        let filename = match file_name_osstr.to_str() {
            Some(name) => name,
            None => {
                session
                    .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                    .await?;
                return Ok(());
            }
        };

        (file_path, meta_opt) = match encoding {
            EncodingType::Gzip => {
                let com_file = parent.join("gz").join(format!("{filename}.gz"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("gzip"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let buffer = get_file_buffer(&file_info.path).await?;
                    let compressed = compress::encode_gzip(buffer.as_slice()).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("gzip"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
                        ),
                        (
                            http::header::CONTENT_TYPE,
                            HeaderValue::from_str(file_info.mime_type.as_ref())?,
                        ),
                    ]);

                    session.send_status(StatusCode::OK).await?;
                    session.send_body(compressed, true).await?;
                    session.send_eom().await?;
                    return Ok(());
                } else {
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Br => {
                let com_file = parent.join("br").join(format!("{filename}.br"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("br"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let buffer = get_file_buffer(&file_info.path).await?;
                    let compressed =
                        compress::encode_brotli(buffer.as_slice(), 4096, 9, 18).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("br"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
                        ),
                        (
                            http::header::CONTENT_TYPE,
                            HeaderValue::from_str(file_info.mime_type.as_ref())?,
                        ),
                    ]);

                    session.send_status(StatusCode::OK).await?;
                    session.send_body(compressed, true).await?;
                    session.send_eom().await?;
                    return Ok(());
                } else {
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Zstd => {
                let com_file = parent.join("zstd").join(format!("{filename}.zstd"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("zstd"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let buffer = get_file_buffer(&file_info.path).await?;
                    let compressed = compress::encode_zstd(buffer.as_slice(), 9).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("zstd"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
                        ),
                        (
                            http::header::CONTENT_TYPE,
                            HeaderValue::from_str(file_info.mime_type.as_ref())?,
                        ),
                    ]);

                    session.send_status(StatusCode::OK).await?;
                    session.send_body(compressed, true).await?;
                    session.send_eom().await?;
                    return Ok(());
                } else {
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::None => (file_info.path.clone(), None),
        };
    }

    let meta = if let Some(meta) = meta_opt {
        meta
    } else {
        fs::metadata(&file_path).await?
    };
    let total_size = meta.len();
    let mut range: Option<Range<u64>> = None;

    if let Some(range_header) = session.read_req_header(http::header::RANGE) {
        if let Ok(range_str) = range_header.to_str() {
            if let Some(parsed) = parse_byte_range(range_str, total_size) {
                range = Some(parsed);
            }
        }
    }

    session.append_headers(&[
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(file_info.mime_type.as_ref())?,
        ),
        (http::header::ETAG, HeaderValue::from_str(&file_info.etag)?),
        (
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&HttpDate::from(file_info.modified).to_string())?,
        ),
        (
            http::header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
    ]);

    let (status, start, end) = if let Some(r) = range {
        let content_length = r.end - r.start;
        session.append_headers(&[
            (
                http::header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end - 1, total_size))?,
            ),
            (
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&content_length.to_string())?,
            ),
        ]);
        (StatusCode::PARTIAL_CONTENT, r.start, r.end)
    } else {
        session.append_headers(&[(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&total_size.to_string())?,
        )]);
        (StatusCode::OK, 0, total_size)
    };

    if session.get_method() == &HTTPMethod::Head {
        session.send_status_eom(status).await?;
        return Ok(());
    }
    let mmap = tokio::task::spawn_blocking({
        let file_path = file_path.clone(); // if needed
        move || {
            let std_file = std::fs::File::open(&file_path)?;
            let mmap = unsafe { Mmap::map(&std_file)? };
            anyhow::Ok(mmap)
        }
    })
    .await??;

    session.send_status(status).await?;

    let total_size = mmap.len();
    let mut offset = start as usize;
    let end = end as usize;

    while offset < end {
        let chunk_end = (offset + CHUNK_SIZE).min(end);

        let chunk_bytes = Bytes::copy_from_slice(&mmap[offset..chunk_end]);

        session.send_body(chunk_bytes, chunk_end == end).await?;

        offset = chunk_end;

        if total_size > (1 << 20) && (offset / CHUNK_SIZE) % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }

    session.send_eom().await
}

pub fn load_file_cache(capacity: u64, ttl: Option<std::time::Duration>) -> FileCache {
    if let Some(ttl_time) = ttl {
        Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl_time)
            .build()
    } else {
        Cache::builder().max_capacity(capacity).build()
    }
}

fn parse_byte_range(header: &str, total_size: u64) -> Option<Range<u64>> {
    if !header.starts_with("bytes=") {
        return None;
    }
    let range = header
        .trim_start_matches("bytes=")
        .split('-')
        .collect::<Vec<_>>();
    if range.len() != 2 {
        return None;
    }
    let start = range[0].parse::<u64>().ok()?;
    let end = if let Ok(end_val) = range[1].parse::<u64>() {
        (end_val + 1).min(total_size)
    } else {
        total_size
    };
    if start >= end || start >= total_size {
        return None;
    }
    Some(start..end)
}

async fn get_file_buffer(path: &PathBuf) -> anyhow::Result<FileBuffer> {
    let mut file_buf = FileBuffer::new(BufferType::BINARY);
    let mut file = fs::File::open(&path).await?;
    // calculate the file size
    let file_size = file.metadata().await?.len();
    file_buf
        .buf
        .resize(file_size as usize, 0)
        .map_err(|_| anyhow::anyhow!("Failed to resize buffer"))?;
    let _size = tokio::io::AsyncReadExt::read(&mut file, file_buf.as_mut_slice()).await?;
    Ok(file_buf)
}

fn get_encoding(accept_encoding: Option<&HeaderValue>, mime: &Mime) -> EncodingType {
    // skip compression for media types
    if (mime.type_() == mime::IMAGE || mime.type_() == mime::AUDIO || mime.type_() == mime::VIDEO)
        && *mime != mime::IMAGE_SVG
    {
        return EncodingType::None;
    }

    let header = match accept_encoding.and_then(|h| h.to_str().ok()) {
        Some(value) => value.to_ascii_lowercase(),
        None => return EncodingType::None,
    };

    let candidates = vec![EncodingType::Zstd, EncodingType::Br, EncodingType::Gzip];
    for enc in candidates {
        if !enc.as_str().is_empty() && header.contains(enc.as_str()) {
            return enc;
        }
    }

    EncodingType::None
}
