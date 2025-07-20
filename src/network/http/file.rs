use std::{fs::Metadata, io::{Read, Write}, ops::Range, path::PathBuf, time::SystemTime};
use bytes::{Bytes, BytesMut};
use mime::Mime;
use moka::sync::Cache;
use crate::network::http::{session::Session, util::{HttpHeader, Status}};

const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 512;
const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 32 * 1024; // 32 KB

#[derive(Debug, Clone, PartialEq)]
pub enum EncodingType {
    None,
    Gzip { level: u32 },
    Br { buffer_size: usize, quality: u32, lgwindow: u32 },
    Zstd { level: i32 },
}

impl EncodingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncodingType::Gzip { .. } => "gzip",
            EncodingType::Br { .. } => "br",
            EncodingType::Zstd { .. } => "zstd",
            EncodingType::None => "",
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
}

pub type FileCache = Cache<String, FileInfo>;

pub fn serve<'buf, 'header, 'stream, S: Read + Write>(
    session: &mut Session<'buf, 'header, 'stream, S>,
    path: &str,
    file_cache: FileCache,
    encoding_order: &[EncodingType],
){
    // canonicalise
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            eprintln!(
                "File server failed to canonicalize path: {path}"
            );
            return session.status_code(Status::NotFound).body_static("").eom();
        }
    };
     // meta
    let meta = match std::fs::metadata(&canonical)
    {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("File server failed to get metadata for path: {}: {}", canonical.display(), e);
            return session.status_code(Status::NotFound).body_static("").eom();
        }
    };

    // look or fill cache
    let key = canonical.to_string_lossy().to_string();

    // Get modified time once
    let modified = match meta.modified() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read modified time for: {}: {}", canonical.display(), e);
            return session.status_code(Status::InternalServerError).body_static("").eom();
        }
    };

    // file cache lookup
    let file_info = if let Some(info) = file_cache.get(&key) {
        if modified <= info.modified {
            info.clone()
        } else {
            // outdated cache entry, fall through to regeneration
            generate_file_info(&key, canonical, &meta, modified, &file_cache)
        }
    } else {
        // cache miss, generate and insert
        generate_file_info(&key, canonical, &meta, modified, &file_cache)
    };

    // check ‘If-None-Match’ header
    if let Ok(p_header_val) = session.req_header(&HttpHeader::IfNoneMatch) {
        if p_header_val == file_info.etag {
            let headers = &[
                (HttpHeader::Etag, file_info.etag.as_str()),
                (
                    HttpHeader::LastModified,
                    &httpdate::HttpDate::from(file_info.modified).to_string(),
                ),
                (HttpHeader::ContentLength, "0"), // prevent keep-alive
                (HttpHeader::Connection, "close"), // or keep-alive
            ];
            if let Ok(session) = session.status_code(Status::NotModified).headers(headers) {
                session.body_static("").eom();
            } else {
                session.status_code(Status::InternalServerError).body_static("").eom();
            }
            return;
        }
    }

    let encoding = match session.req_header(&HttpHeader::AcceptEncoding)
    {
        Ok(val) => 
        {
            let mime_type: Mime = file_info
                .mime_type
                .parse()
                .unwrap_or(mime::APPLICATION_OCTET_STREAM);
            choose_encoding(
                val,
                &mime_type,
                encoding_order,
            )
        },
        Err(_) => {
            EncodingType::None
        }
    };

    let mut headers: Vec<(HttpHeader, String)> = vec![
        (HttpHeader::Connection, "close".to_string()),
    ];

    let mut meta_opt: Option<Metadata> = None;
    let mut file_path = file_info.path.clone();
    if file_info.size > MIN_BYTES_ON_THE_FLY_SIZE {
        let parent = match file_info.path.parent() {
            Some(parent) => parent,
            None => {
                eprintln!("File server failed to get parent directory for path: {}", file_info.path.display());
                return session.status_code(Status::NotFound).body_static("").eom();
            }
        };
        let file_name_osstr = match file_info.path.file_name() {
            Some(name) => name,
            None => {
                eprintln!("File server failed to get file name for path: {}", file_info.path.display());
                return session.status_code(Status::InternalServerError).body_static("").eom();
            }
        };

        let filename = match file_name_osstr.to_str() {
            Some(name) => name,
            None => {
                eprintln!("File server failed to convert file name to string for path: {}", file_info.path.display());
                return session.status_code(Status::InternalServerError).body_static("").eom();
            }
        };

        (file_path, meta_opt) = match encoding {
            EncodingType::Gzip{level} => {
                let com_file = parent.join("gz").join(format!("{filename}.gz"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    headers.push((
                        HttpHeader::ContentEncoding,
                        "gzip".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {  
                    respond_with_compressed(
                        session,
                        &file_info.path,
                        file_info.mime_type.as_ref(),
                        &file_info.etag,
         "gzip",
                        |b| encode_gzip(b, level),
                    );
                    return;
                } else {
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Br{buffer_size, quality, lgwindow} => {
                let com_file = parent.join("br").join(format!("{filename}.br"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    headers.push((
                        HttpHeader::ContentEncoding,
                        "br".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {
                    respond_with_compressed(
                            session,
                            &file_info.path,
                            file_info.mime_type.as_ref(),
                            &file_info.etag,
                            "br",
                            |b| encode_brotli(b, buffer_size, quality, lgwindow),
                        );
                    return;
                } else {
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Zstd{level} => {
                let com_file = parent.join("zstd").join(format!("{filename}.zstd"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    headers.push((
                        HttpHeader::ContentEncoding,
                        "zstd".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {
                    respond_with_compressed(
                        session,
                        &file_info.path,
                        file_info.mime_type.as_ref(),
                        &file_info.etag,
                        "zstd",
                        |b| encode_zstd(b, level),
                    );
                    return;
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
        std::fs::metadata(&file_path).unwrap()
    };
    let total_size = meta.len();

    let range: Option<Range<u64>> = session
    .req_header(&HttpHeader::Range)
    .ok()
    .and_then(|h| parse_byte_range(h, total_size));

    headers.extend([
        (
            HttpHeader::ContentType,
            file_info.mime_type,
        ),
        (
            HttpHeader::LastModified,
            httpdate::HttpDate::from(file_info.modified).to_string(),
        ),
        (
            HttpHeader::ContentDisposition,
            "inline".to_owned(),
        ),
        (
            HttpHeader::Etag,
            file_info.etag.clone(),
        )
    ]);

    let (status, start, end) = if let Some(r) = range {
        let content_length = r.end - r.start;
        headers.extend([
            (
                HttpHeader::ContentRange,
                format!("bytes {}-{}/{}", r.start, r.end - 1, total_size),
            ),
            (
                HttpHeader::ContentLength,
                content_length.to_string(),
            ),
        ]);

        (Status::PartialContent, r.start, r.end)
    } else {
        headers.push((
            HttpHeader::ContentLength,
            total_size.to_string(),
        ));
        (Status::Ok, 0, total_size)
    };

    if session.req_method() == Some("Head") {
        match session.status_code(status).headers_vec(&headers) {
            Ok(session) => {
                session.body_static("").eom();
                return;
            }
            Err(e) => {
                eprintln!("Failed to write headers for HEAD request: {e}");
                session.status_code(Status::InternalServerError).body_static("").eom();
                return;
            }
        }
    }

    let mmap = match std::fs::File::open(&file_path) {
        Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
            Ok(mmap) => mmap,
            Err(e) => {
                eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                session.status_code(Status::InternalServerError).body_static("").eom();
                return;
            }
        },
        Err(e) => {
            eprintln!("Failed to open file: {}: {}", file_path.display(), e);
            session.status_code(Status::InternalServerError).body_static("").eom();
            return;
        }
    };

    let offset = start as usize;
    let end = end as usize;

    match session.status_code(status).headers_vec(&headers) {
        Ok(session) => {
            session.body_slice(&mmap[offset..end]).eom();
        }
        Err(e) => {
            eprintln!("Failed to write final file server response: {e}");
            session.status_code(Status::InternalServerError).body_static("").eom();
        }
    }
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

fn respond_with_compressed<S: Read + Write>(session: &mut Session<'_, '_, '_, S>,
                               file_path: &PathBuf,
                               mime_type: &str,
                               etag: &str,
                               encoding_name: &str,
                               compress_fn: impl Fn(Bytes) -> std::io::Result<Bytes>) {
    match get_file_buffer(file_path).and_then(compress_fn) {
        Ok(compressed) => {
            let headers = &[
                (HttpHeader::ContentEncoding, encoding_name),
                (HttpHeader::ContentLength, &compressed.len().to_string()),
                (HttpHeader::ContentType, mime_type),
                (HttpHeader::Etag, etag),
                (HttpHeader::ContentDisposition, "inline"),
            ];
            if let Ok(session) = session.status_code(Status::Ok).headers(headers) {
                session.body(&compressed).eom();
            } else {
                session.status_code(Status::InternalServerError).body_static("").eom();
            }
        }
        Err(e) => {
            eprintln!(
                "Compression failed ({encoding_name}) for {}: {e}",
                file_path.display()
            );
            session.status_code(Status::InternalServerError).body_static("").eom();
        }
    }
}

fn generate_file_info(
    key: &str,
    canonical: PathBuf,
    meta: &Metadata,
    modified: SystemTime,
    cache: &FileCache,
) -> FileInfo {
    let duration = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let etag = format!("\"{}-{}\"", duration.as_secs(), meta.len());
    let mime_type = mime_guess::from_path(&canonical)
    .first()
    .unwrap_or(mime::APPLICATION_OCTET_STREAM);


    let info = FileInfo {
        etag,
        mime_type: mime_type.to_string(),
        path: canonical.clone(),
        size: meta.len(),
        modified,
    };

    cache.insert(key.to_string(), info.clone());
    info
}

fn parse_byte_range(header: &str, total_size: u64) -> Option<Range<u64>> {
    if !header.starts_with("bytes=") {
        return None;
    }
    let parts: Vec<&str> = header.trim_start_matches("bytes=").split('-').collect();
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

fn get_file_buffer(path: &PathBuf) -> std::io::Result<Bytes> {
    // open the file and read its contents into a buffer
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut buf = BytesMut::with_capacity(file_size as usize);
    buf.resize(file_size as usize, 0);
    file.read_exact(&mut buf)?;
    Ok(buf.freeze())
}

fn choose_encoding(
    accept: &str,
    mime: &Mime,
    order: &[EncodingType],
) -> EncodingType {
    // skip compression for media types
    if (order.is_empty()
        || mime.type_() == mime::IMAGE
        || mime.type_() == mime::AUDIO
        || mime.type_() == mime::VIDEO)
        && *mime != mime::IMAGE_SVG
    {
        return EncodingType::None;
    }
    for enc in order {
        if !enc.as_str().is_empty() && accept.contains(enc.as_str()) {
            return enc.clone();
        }
    }
    EncodingType::None
}

fn encode_brotli<T: AsRef<[u8]>>(
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

fn encode_zstd<T: AsRef<[u8]>>(input: T, level: i32) -> std::io::Result<Bytes> {
    let mut out = vec![];
    zstd::stream::copy_encode(std::io::Cursor::new(input.as_ref()), &mut out, level)?;
    Ok(Bytes::from(out))
}

fn encode_gzip<T: AsRef<[u8]>>(input: T, level: u32) -> std::io::Result<Bytes> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut out = vec![];
    let mut encoder = GzEncoder::new(&mut out, Compression::new(level));
    std::io::copy(&mut std::io::Cursor::new(input.as_ref()), &mut encoder)?;
    encoder.finish()?;
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use moka::sync::Cache;

    use crate::network::http::{
        file::{serve, EncodingType, FileInfo}, h1::{H1Service, H1ServiceFactory}, session::Session
    };
    use std::{
        io::{Read, Write}, sync::OnceLock,
    };

    struct FileServer<T>(pub T);

    struct FileService;

    static FILE_CACHE: OnceLock<Cache<String, FileInfo>> = OnceLock::new();
    fn get_cache() -> &'static Cache<String, FileInfo> {
        FILE_CACHE.get_or_init(|| {
            Cache::builder()
                .max_capacity(128)
                .build()
        })
    }

    impl H1Service for FileService {
        fn call<S: Read + Write>(&mut self, session: &mut Session<S>) -> std::io::Result<()> {
            serve(session,"/Users/pooyaeimandar/Desktop/k6.js", get_cache().clone(), 
            &[
                    EncodingType::Zstd { level: 3 },
                    EncodingType::Br {
                        buffer_size: 4096,
                        quality: 4,
                        lgwindow: 19,
                    },
                    EncodingType::Gzip { level: 4 },
                    EncodingType::None,
                ]
            );
            Ok(())
        }
    }

    impl H1ServiceFactory for FileServer<FileService> {
        type Service = FileService;

        fn service(&self, _id: usize) -> FileService {
            FileService
        }
    }

    #[test]
    fn file_server() {
        // Print number of CPU cores
        let cpus = num_cpus::get();
        // Pick a port and start the server
        let addr = "0.0.0.0:8080";
        let mut threads = Vec::with_capacity(cpus);

        for _ in 0..cpus {
            let handle = std::thread::spawn(move || {
                let id = std::thread::current().id();
                println!("Listening {addr} on thread: {id:?}");
                FileServer(FileService)
                    .start(addr, cpus, 0)
                    .unwrap_or_else(|_| panic!("file server failed to start for thread {id:?}"))
                    .join()
                    .unwrap_or_else(|_| panic!("file server failed to joining thread {id:?}"));
            });
            threads.push(handle);
        }

        // Wait for all threads to complete (they won’t unless crashed)
        for handle in threads {
            handle.join().expect("Thread panicked");
        }
    }

}


