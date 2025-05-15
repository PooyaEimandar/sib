// Optimized `serve` function with compression (zstd, br) support and mmap reuse
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use httpdate::HttpDate;
use memmap2::Mmap;
use moka::future::Cache;
use tokio::{fs, sync::RwLock};

use crate::{
    network::http::session::{HTTPMethod, Session},
    system::{buffer::Buffer, compress},
};

const CHUNK_SIZE_SMALL: usize = 16 * 1024;
const CHUNK_SIZE_LARGE: usize = 32 * 1024;

#[derive(Clone)]
pub struct FileInfo {
    pub etag: String,
    pub mime_type: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}

pub type FileCache = Cache<String, FileInfo>;
pub type MmapCache = Arc<RwLock<HashMap<String, Arc<Mmap>>>>;

pub async fn serve(
    session: &mut Session,
    path: &str,
    root: &str,
    encoding_order: &[&str],
    file_cache: &FileCache,
    mmap_cache: &MmapCache,
) -> anyhow::Result<()> {
    let requested_path = PathBuf::from(root).join(path.trim_start_matches('/'));
    let canonical = match fs::canonicalize(&requested_path).await {
        Ok(p) => p,
        Err(_) => return session.send_status_eom(StatusCode::NOT_FOUND).await,
    };

    let static_root = fs::canonicalize(root).await?;
    if !canonical.starts_with(&static_root) {
        return session.send_status_eom(StatusCode::FORBIDDEN).await;
    }

    let meta = fs::metadata(&canonical).await?;
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let size = meta.len();
    let etag = format!(
        "\"{}-{}\"",
        modified.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
        size
    );

    let mime_type = mime_guess::from_path(&canonical)
        .first_or_octet_stream()
        .to_string();

    let key = canonical.to_string_lossy().to_string();
    let file_info = file_cache
        .get_with(key.clone(), async {
            FileInfo {
                etag: etag.clone(),
                mime_type: mime_type.clone(),
                path: canonical.clone(),
                size,
                modified,
            }
        })
        .await;

    if session
        .read_req_header(http::header::IF_NONE_MATCH)
        .map_or(false, |h| h == &file_info.etag)
    {
        return session.send_status_eom(StatusCode::NOT_MODIFIED).await;
    }

    let accept_encoding = session
        .read_req_header(http::header::ACCEPT_ENCODING)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut file_path = file_info.path.clone();
    let mut encoding: Option<&str> = None;

    for enc in encoding_order {
        let ext = match *enc {
            "br" => "br",
            "zstd" => "zst",
            "gzip" => "gz",
            _ => continue,
        };
        if !accept_encoding.contains(enc) {
            continue;
        }
        let compressed_path = file_path
            .parent()
            .unwrap_or(Path::new(""))
            .join(ext)
            .join(file_path.file_name().unwrap().to_string_lossy().to_string() + "." + ext);

        if fs::metadata(&compressed_path).await.is_ok() {
            file_path = compressed_path;
            encoding = Some(*enc);
            break;
        } else if file_info.size <= CHUNK_SIZE_SMALL as u64 {
            let mut buffer =
                Buffer::<{ CHUNK_SIZE_SMALL }>::new(crate::system::buffer::BufferType::BINARY);
            let mut file = fs::File::open(&file_info.path).await?;
            let slice = buffer.as_mut_slice();
            tokio::io::AsyncReadExt::read_exact(&mut file, slice).await?;
            let compressed = match *enc {
                "br" => compress::encode_brotli(slice, 4096, 9, 18).await?,
                "zstd" => compress::encode_zstd(slice, 9).await?,
                "gzip" => compress::encode_gzip(slice).await?,
                _ => continue,
            };
            session.append_header(&http::header::CONTENT_ENCODING, HeaderValue::from_str(enc)?);
            session.append_headers(&[
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_str(&file_info.mime_type)?,
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
        }
    }

    if let Some(enc) = encoding {
        session.append_header(&http::header::CONTENT_ENCODING, HeaderValue::from_str(enc)?);
    }

    session.append_headers(&[
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&file_info.mime_type)?,
        ),
        (http::header::ETAG, HeaderValue::from_str(&file_info.etag)?),
        (
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&HttpDate::from(file_info.modified).to_string())?,
        ),
    ]);

    if session.get_method() == &HTTPMethod::Head {
        return session.send_status_eom(StatusCode::OK).await;
    }

    let mmap_arc = {
        let mut mmap_guard = mmap_cache.write().await;
        if let Some(existing) = mmap_guard.get(&key) {
            Arc::clone(existing)
        } else {
            let file = std::fs::File::open(&file_path)?;
            let mmap = unsafe { Mmap::map(&file)? };
            let mmap_arc = Arc::new(mmap);
            mmap_guard.insert(key.clone(), Arc::clone(&mmap_arc));
            mmap_arc
        }
    };

    let data = &mmap_arc[..];
    let total_size = data.len();
    let chunk_size = if total_size > (1 << 20) {
        CHUNK_SIZE_LARGE
    } else {
        CHUNK_SIZE_SMALL
    };

    session.append_header(
        &http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&total_size.to_string())?,
    );
    session.send_status(StatusCode::OK).await?;

    let mut offset = 0;
    while offset < total_size {
        let end = (offset + chunk_size).min(total_size);
        let chunk = Bytes::copy_from_slice(&data[offset..end]);
        session.send_body(chunk.clone(), end == total_size).await?;
        offset = end;
    }

    session.send_eom().await
}
