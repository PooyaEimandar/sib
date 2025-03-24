use bytes::BytesMut;
use http::{HeaderValue, StatusCode};
use httpdate::HttpDate;
use lru::LruCache;
use memmap2::Mmap;
use mime_guess::{Mime, mime};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File as StdFile,
    io::{BufReader, BufWriter},
    num::NonZeroUsize,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    fs::{self, File},
    sync::RwLock,
};

use crate::network::http::session::{HTTPMethod, Session};

const CHUNK_SIZE: usize = 16 * 1024;
const MIN_BYTES: u64 = 1024;
const CACHE_PERSIST_PATH: &str = "./sib_static_server_cache.json";

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

pub fn start_file_watcher<P: AsRef<Path>>(
    watch_path: P,
    file_cache: FileCache,
) -> notify::Result<RecommendedWatcher> {
    let cache = file_cache.clone();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    if let Some(path) = event.paths.first() {
                        if let Ok(canon_path) = std::fs::canonicalize(path) {
                            let key = canon_path.to_string_lossy().to_string();
                            let mut cache = futures::executor::block_on(cache.write());
                            cache.pop(&key);
                        }
                    }
                }
            }
        },
        notify::Config::default(),
    )?;
    watcher.watch(watch_path.as_ref(), RecursiveMode::Recursive)?;
    Ok(watcher)
}

pub async fn serve(
    session: &mut Session,
    path: &str,
    root: &str,
    file_cache: FileCache,
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

    let mut cache = file_cache.write().await;
    let key = canonical.to_string_lossy().to_string();
    let mut refresh = false;
    let file_info = if let Some(info) = cache.get(&key) {
        if let Ok(meta) = fs::metadata(&canonical).await {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if modified > info.modified {
                refresh = true;
            }
        }
        info.clone()
    } else {
        refresh = true;
        FileInfo {
            etag: String::new(),
            mime_type: mime::APPLICATION_OCTET_STREAM.to_string(),
            path: PathBuf::new(),
            size: 0,
            modified: SystemTime::UNIX_EPOCH,
        }
    };

    let file_info = if refresh {
        let meta = fs::metadata(&canonical).await?;
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
        cache.put(key.clone(), info.clone());
        let _ = persist_cache(&*cache);
        info
    } else {
        file_info
    };
    drop(cache);

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

        file_path = match encoding {
            EncodingType::Gzip => parent.join("gz").join(format!("{filename}.{file_ext}.gz")),
            EncodingType::Br => parent.join("gz").join(format!("{filename}.{file_ext}.br")),
            EncodingType::Zstd => parent.join("gz").join(format!("{filename}.{file_ext}.zst")),
            EncodingType::None => file_info.path.clone(),
        };

        if fs::metadata(&file_path).await.is_err() {
            file_path = file_info.path.clone();
        }
    }

    let meta = fs::metadata(&file_path).await?;
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

    if encoding != EncodingType::None {
        let encoding_str = match encoding {
            EncodingType::Gzip => Some("gzip"),
            EncodingType::Br => Some("br"),
            EncodingType::Zstd => Some("zstd"),
            _ => None,
        };
        if let Some(enc) = encoding_str {
            session.append_headers(&[(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static(enc),
            )]);
        }
    }

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

    let file = File::open(&file_path).await?;
    let mmap = unsafe { Mmap::map(&file.into_std().await)? };
    session.send_status(status).await?;

    let mut chunk_count = 0;
    let mut offset = start as usize;
    let end = end as usize;

    while offset < end {
        let chunk_end = (offset + CHUNK_SIZE).min(end);
        let chunk = &mmap[offset..chunk_end];
        let is_last_chunk = chunk_end == end;
        session
            .send_body(BytesMut::from(chunk).freeze(), is_last_chunk)
            .await?;

        offset = chunk_end;
        chunk_count += 1;
        if chunk_count % 8 == 0 {
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
