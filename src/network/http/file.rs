use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use httpdate::HttpDate;
use lru::LruCache;
use memmap2::Mmap;
use mime_guess::{Mime, mime};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File as StdFile, Metadata},
    io::{BufReader, BufWriter},
    num::NonZeroUsize,
    ops::Range,
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};
use tokio::{fs, sync::RwLock};

use crate::{
    network::http::session::{HTTPMethod, Session},
    system::memcached::MemcachedPool,
};

const CHUNK_SIZE: usize = 16 * 1024;
const MIN_BYTES: u64 = 1024;
const MAX_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
const CACHE_PERSIST_PATH: &str = "./sib_asset_cache.json";

#[derive(Debug, Clone, Copy, PartialEq)]
enum EncodingType {
    None,
    Gzip,
    Br,
    Zstd,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileInfo {
    etag: String,
    mime_type: String,
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

pub type FileCache = Arc<RwLock<LruCache<String, FileInfo>>>;

pub async fn serve(
    session: &mut Session,
    path: &str,
    root: &str,
    file_cache: FileCache,
    memcached_pool: Option<MemcachedPool>,
) -> anyhow::Result<()> {
    let static_root = fs::canonicalize(root).await?;
    let requested_path = PathBuf::from(root).join(path);
    let canonical = match fs::canonicalize(&requested_path).await {
        Ok(path) => path,
        Err(_) => return session.send_status_eom(StatusCode::BAD_REQUEST).await,
    };

    if !canonical.starts_with(&static_root) {
        return session.send_status_eom(StatusCode::FORBIDDEN).await;
    }

    let meta = fs::metadata(&canonical).await?;

    let key = canonical.to_string_lossy().to_string();
    let mut file_info_opt: Option<FileInfo> = None;

    {
        let mut cache = file_cache.write().await;
        if let Some(info) = cache.get(&key) {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if modified <= info.modified {
                file_info_opt = Some(info.clone());
            }
        }
    }

    if file_info_opt.is_none() {
        if let Some(pool) = &memcached_pool {
            if let Ok(mem_client) = pool.get().await {
                if let Ok(Some(json)) = mem_client.get::<String>(&key) {
                    if let Ok(info) = serde_json::from_str::<FileInfo>(&json) {
                        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                        if modified <= info.modified {
                            file_info_opt = Some(info.clone());
                            file_cache.write().await.put(key.clone(), info);
                        }
                    }
                }
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

        {
            let mut cache = file_cache.write().await;
            cache.put(key.clone(), info.clone());
            let cache_res = persist_cache(&cache);
            if let Err(err) = cache_res {
                crate::s_error!(
                    "File server failed to write to the LRU persistent cache: {}",
                    err
                );
            }
        }

        if let Some(pool) = &memcached_pool {
            if let Ok(mem_client) = pool.get().await {
                let memcached_res = mem_client.set(&key, &serde_json::to_string(&info)?, 300);
                if let Err(err) = memcached_res {
                    crate::s_error!("File server failed to write to the memcached: {}", err);
                }
            }
        }

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
        &mime_type,
    );

    let mut meta_opt: Option<Metadata> = None;
    let mut file_path = file_info.path.clone();
    if file_info.size > MIN_BYTES {
        let parent = file_info.path.parent().unwrap();
        let filename = file_info.path.file_name().unwrap().to_str().unwrap();
        let file_ext = file_info
            .path
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        (file_path, meta_opt) = match encoding {
            EncodingType::Gzip => {
                let com_file = parent.join("gz").join(format!("{filename}.{file_ext}.gz"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("gzip"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let content = fs::read(&file_info.path).await?;
                    let compressed = compress_gzip(&content).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("gzip"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
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
                let com_file = parent.join("br").join(format!("{filename}.{file_ext}.br"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("br"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let content = fs::read(&file_info.path).await?;
                    let compressed = compress_brotli(&content).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("br"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
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
                let com_file = parent
                    .join("zstd")
                    .join(format!("{filename}.{file_ext}.zstd"));
                let com_meta_res = fs::metadata(&com_file).await;
                if let Ok(com_meta) = com_meta_res {
                    session.append_header(
                        &http::header::CONTENT_ENCODING,
                        HeaderValue::from_static("zstd"),
                    );
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_ON_THE_FLY_SIZE {
                    let content = fs::read(&file_info.path).await?;
                    let compressed = compress_zstd(&content).await?;

                    session.append_headers(&[
                        (
                            http::header::CONTENT_ENCODING,
                            HeaderValue::from_static("zstd"),
                        ),
                        (
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&compressed.len().to_string())?,
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

    #[cfg(target_os = "linux")]
    let file_uring = tokio_uring::fs::File::open(&file_path).await?;

    #[cfg(not(target_os = "linux"))]
    let mmap = tokio::task::spawn_blocking(move || {
        let std_file = std::fs::File::open(&file_path)?;
        unsafe { Mmap::map(&std_file) }
    })
    .await??;

    session.send_status(status).await?;

    let base = Bytes::copy_from_slice(&mmap);
    let mut chunk_count = 0;
    let mut offset = start as usize;
    let end = end as usize;

    while offset < end {
        let chunk_end = (offset + CHUNK_SIZE).min(end);
        let is_last_chunk = chunk_end == end;

        #[cfg(target_os = "linux")]
        let chunk = {
            let read_size = chunk_end - offset;
            let (res, _) = file_uring.read_at(offset as u64, read_size).await;
            Bytes::from(res?)
        };

        #[cfg(not(target_os = "linux"))]
        let chunk = base.slice(offset..chunk_end);

        session.send_body(chunk, is_last_chunk).await?;

        offset = chunk_end;
        chunk_count += 1;

        // Only yield if the file is larger than 1MB
        if total_size > (1 << 20) && chunk_count % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }

    session.send_eom().await
}

pub fn load_cache(capacity: usize) -> FileCache {
    let file = StdFile::open(CACHE_PERSIST_PATH);
    let mut cache = LruCache::new(NonZeroUsize::new(capacity).unwrap());
    if let Ok(f) = file {
        if let Ok(map) = serde_json::from_reader::<_, HashMap<String, FileInfo>>(BufReader::new(f))
        {
            for (k, v) in map {
                cache.put(k, v);
            }
        }
    }
    Arc::new(RwLock::new(cache))
}

fn persist_cache(cache: &LruCache<String, FileInfo>) -> std::io::Result<()> {
    let file = StdFile::create(CACHE_PERSIST_PATH)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(
        writer,
        &cache
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<_, _>>(),
    )?;
    Ok(())
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

fn get_encoding(accept_encoding: Option<&HeaderValue>, mime: &Mime) -> EncodingType {
    if (mime.type_() == mime::IMAGE || mime.type_() == mime::AUDIO || mime.type_() == mime::VIDEO)
        && *mime != mime::IMAGE_SVG
    {
        return EncodingType::None;
    }
    let header = match accept_encoding.and_then(|h| h.to_str().ok()) {
        Some(value) => value.to_ascii_lowercase(),
        None => return EncodingType::None,
    };
    if header.contains("zstd") {
        EncodingType::Zstd
    } else if header.contains("br") {
        EncodingType::Br
    } else if header.contains("gzip") {
        EncodingType::Gzip
    } else {
        EncodingType::None
    }
}

async fn compress_brotli(input: &[u8]) -> anyhow::Result<Bytes> {
    let input_owned = input.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut out = vec![];
        let mut encoder =
            brotli::CompressorReader::new(std::io::Cursor::new(input_owned), 4096, 9, 18);
        std::io::copy(&mut encoder, &mut out)?;
        Ok::<_, std::io::Error>(Bytes::from(out))
    })
    .await?
    .map_err(Into::into)
}

async fn compress_zstd(input: &[u8]) -> anyhow::Result<Bytes> {
    let input_owned = input.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut out = vec![];
        zstd::stream::copy_encode(std::io::Cursor::new(input_owned), &mut out, 9)?;
        Ok::<_, std::io::Error>(Bytes::from(out))
    })
    .await?
    .map_err(Into::into)
}

async fn compress_gzip(input: &[u8]) -> anyhow::Result<Bytes> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let input_owned = input.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut out = vec![];
        let mut encoder = GzEncoder::new(&mut out, Compression::default());
        std::io::copy(&mut std::io::Cursor::new(input_owned), &mut encoder)?;
        encoder.finish()?;
        Ok::<_, std::io::Error>(Bytes::from(out))
    })
    .await?
    .map_err(Into::into)
}
