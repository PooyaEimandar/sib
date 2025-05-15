use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use httpdate::HttpDate;
use memmap2::Mmap;
use mime_guess::{Mime, mime};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::{ops::Range, path::PathBuf, time::SystemTime};
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
type FileBuffer = Buffer<{ CHUNK_SIZE as usize }>; // 32 KB

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
    encoding_order: &Vec<EncodingType>,
    file_cache: FileCache,
) -> anyhow::Result<()> {
    let requested_path = PathBuf::from(root).join(path.trim_start_matches('/'));

    let canonical = fs::canonicalize(&requested_path).await.map_err(|_| {
        s_error!(
            "File server failed to canonicalize path: {}",
            requested_path.display()
        );
        // Return the error from send_status_eom directly
        return anyhow::anyhow!("File not found");
    })?;
    // If canonicalization fails, send the status
    if !canonical.exists() {
        session.send_status_eom(StatusCode::NOT_FOUND).await?;
        return Ok(());
    }

    let static_root = fs::canonicalize(root).await?;
    if !canonical.starts_with(&static_root) {
        return session.send_status_eom(StatusCode::FORBIDDEN).await;
    }

    let meta = fs::metadata(&canonical).await?;
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let key = canonical.to_string_lossy().into_owned();

    let file_info = match file_cache.get(&key).await {
        Some(info) if modified <= info.modified => info,
        _ => {
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
            file_cache.insert(key, info.clone()).await;
            info
        }
    };

    if session
        .read_req_header(http::header::IF_NONE_MATCH)
        .map_or(false, |etag| etag == &file_info.etag)
    {
        return session.send_status_eom(StatusCode::NOT_MODIFIED).await;
    }

    let encoding = get_encoding(
        session.read_req_header(http::header::ACCEPT_ENCODING),
        &file_info
            .mime_type
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM),
        encoding_order,
    );

    let (file_path, meta_opt) = match try_precompressed(session, &file_info, &encoding).await? {
        Some(_result) => return Ok(()),
        None => (file_info.path.clone(), None),
    };

    let meta = meta_opt.unwrap_or(fs::metadata(&file_path).await?);
    let total_size = meta.len();

    let mut range: Option<Range<u64>> = None;
    if let Some(range_header) = session.read_req_header(http::header::RANGE) {
        if let Ok(range_str) = range_header.to_str() {
            range = parse_byte_range(range_str, total_size);
        }
    }

    let headers = vec![
        (http::header::CONTENT_TYPE, file_info.mime_type.parse()?),
        (http::header::ETAG, file_info.etag.parse()?),
        (
            http::header::LAST_MODIFIED,
            HttpDate::from(file_info.modified).to_string().parse()?,
        ),
        (
            http::header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
    ];

    session.append_headers(&headers);

    let (status, start, end) = match range {
        Some(r) => {
            session.append_headers(&[
                (
                    http::header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", r.start, r.end - 1, total_size).parse()?,
                ),
                (
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&(r.end - r.start).to_string())?,
                ),
            ]);
            (StatusCode::PARTIAL_CONTENT, r.start, r.end)
        }
        None => {
            session.append_header(
                &http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&total_size.to_string())?,
            );
            (StatusCode::OK, 0, total_size)
        }
    };

    if session.get_method() == &HTTPMethod::Head {
        return session.send_status_eom(status).await;
    }

    let mmap = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        move || {
            let file = std::fs::File::open(&file_path)?;
            let mmap = unsafe { Mmap::map(&file)? };
            Ok::<_, anyhow::Error>(mmap)
        }
    })
    .await??;

    session.send_status(status).await?;

    let mut offset = start as usize;
    let end = end as usize;

    while offset < end {
        let chunk_end = (offset + CHUNK_SIZE).min(end);
        let chunk = Bytes::copy_from_slice(&mmap[offset..chunk_end]);
        session.send_body(chunk, chunk_end == end).await?;
        offset = chunk_end;

        if total_size > 1 << 20 && (offset / CHUNK_SIZE) % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }

    session.send_eom().await
}

type EncoderFn = Box<
    dyn Fn(Bytes) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<Bytes>> + Send>>
        + Send
        + Sync,
>;

async fn try_precompressed(
    session: &mut Session,
    file_info: &FileInfo,
    encoding: &EncodingType,
) -> anyhow::Result<Option<()>> {
    let parent = file_info
        .path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let filename = file_info
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 filename"))?;

    let (ext, encoder_fn, header_val): (&str, EncoderFn, &str) = match encoding {
        EncodingType::Gzip => (
            "gz",
            Box::new(|d| Box::pin(compress::encode_gzip(d))),
            "gzip",
        ),
        EncodingType::Br => (
            "br",
            Box::new(|d| Box::pin(compress::encode_brotli(d, 4096, 9, 18))),
            "br",
        ),
        EncodingType::Zstd => (
            "zstd",
            Box::new(|d| Box::pin(compress::encode_zstd(d, 9))),
            "zstd",
        ),
        EncodingType::None => return Ok(None),
    };

    let com_path = parent.join(ext).join(format!("{filename}.{ext}"));

    if let Ok(_meta) = tokio::fs::metadata(&com_path).await {
        session.append_header(
            &http::header::CONTENT_ENCODING,
            HeaderValue::from_static(header_val),
        );
        // let the caller mmap and stream it
        return Ok(None);
    }

    if file_info.size > CHUNK_SIZE as u64 {
        return Ok(None);
    }

    let buffer = Bytes::copy_from_slice(get_file_buffer(&file_info.path).await?.as_slice());
    let compressed = encoder_fn(buffer).await?;

    session.append_headers(&[
        (
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static(header_val),
        ),
        (
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&compressed.len().to_string())?,
        ),
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(file_info.mime_type.as_ref())?,
        ),
        (
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&HttpDate::from(file_info.modified).to_string())?,
        ),
        (http::header::ETAG, HeaderValue::from_str(&file_info.etag)?),
        (
            http::header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
    ]);

    session.send_status(StatusCode::OK).await?;
    session.send_body(compressed, true).await?;
    session.send_eom().await?;

    Ok(Some(()))
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
    let mut file = fs::File::open(path).await?;
    let file_size = file.metadata().await?.len();

    file_buf
        .resize(file_size as usize, 0)
        .map_err(|_| anyhow::anyhow!("Failed to resize buffer for file: {}", path.display()))?;

    let slice = file_buf.as_mut_slice();
    tokio::io::AsyncReadExt::read_exact(&mut file, slice).await?;

    Ok(file_buf)
}

fn get_encoding(
    accept_encoding: Option<&HeaderValue>,
    mime: &Mime,
    encoding_order: &Vec<EncodingType>,
) -> EncodingType {
    // skip compression for media types
    if (encoding_order.is_empty()
        || mime.type_() == mime::IMAGE
        || mime.type_() == mime::AUDIO
        || mime.type_() == mime::VIDEO)
        && *mime != mime::IMAGE_SVG
    {
        return EncodingType::None;
    }

    let header = match accept_encoding.and_then(|h| h.to_str().ok()) {
        Some(value) => value.to_ascii_lowercase(),
        None => return EncodingType::None,
    };

    for &enc in encoding_order {
        if !enc.as_str().is_empty() && header.contains(enc.as_str()) {
            return enc;
        }
    }

    EncodingType::None
}
