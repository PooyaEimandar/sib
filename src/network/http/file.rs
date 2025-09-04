use crate::network::http::{
    session::Session,
    util::{HttpHeader, Status},
};
use bytes::Bytes;
use dashmap::DashMap;
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

pub fn serve<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut Vec<(HttpHeader, String)>,
    encoding_order: &[EncodingType],
    min_max_compress_thresholds: (u64, u64),
) -> std::io::Result<()> {
    let min_bytes_on_the_fly_size = min_max_compress_thresholds.0;
    let max_bytes_on_the_fly_size = min_max_compress_thresholds.1;

    // canonicalise
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            eprintln!("File server failed to canonicalize path: {path}");
            session
                .status_code(Status::NotFound)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
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
            session
                .status_code(Status::NotFound)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
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
            session
                .status_code(Status::InternalServerError)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
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

    let range_requested = session.req_header(&HttpHeader::Range).is_ok();
    let encoding = match session.req_header(&HttpHeader::AcceptEncoding) {
        Ok(val) => {
            let mime_type: Mime = file_info
                .mime_type
                .parse()
                .unwrap_or(mime::APPLICATION_OCTET_STREAM);
            choose_encoding(val, &mime_type, encoding_order)
        }
        Err(_) => EncodingType::None,
    };

    let mut applied_encoding: Option<&'static str> = None;
    let (file_path, total_size) = match encoding {
        EncodingType::None => {
            // Serve file directly
            (file_info.path.clone(), file_info.size)
        }
        EncodingType::NotAcceptable => {
            session
                .status_code(Status::NotAcceptable)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
        }
        EncodingType::Br {
            buffer_size,
            quality,
            lgwindow,
        } => {
            if let Some(br_info) = file_info.br_info {
                // we already have the br info in the cache
                rsp_headers.push((HttpHeader::ContentEncoding, "br".to_string()));
                applied_encoding = Some("br");
                br_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    compress_then_respond(
                        session,
                        rsp_headers,
                        &file_info.path,
                        file_info.mime_type.as_ref(),
                        &file_info.etag,
                        "br",
                        |b| encode_brotli(b, buffer_size, quality, lgwindow),
                    );
                    return Ok(());
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Gzip { level } => {
            if let Some(gz_info) = file_info.gz_info {
                // we already have the gz info in the cache
                rsp_headers.push((HttpHeader::ContentEncoding, "gzip".to_string()));
                applied_encoding = Some("gzip");
                gz_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    compress_then_respond(
                        session,
                        rsp_headers,
                        &file_info.path,
                        file_info.mime_type.as_ref(),
                        &file_info.etag,
                        "gzip",
                        |b| encode_gzip(b, level),
                    );
                    return Ok(());
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
        EncodingType::Zstd { level } => {
            if let Some(zstd_info) = file_info.zstd_info {
                // we already have the zstd info in the cache
                rsp_headers.push((HttpHeader::ContentEncoding, "zstd".to_string()));
                applied_encoding = Some("zstd");
                zstd_info
            } else {
                // On-the-fly only if size is within [min,max] AND not a Range request
                if file_info.size >= min_bytes_on_the_fly_size
                    && file_info.size <= max_bytes_on_the_fly_size
                    && !range_requested
                {
                    compress_then_respond(
                        session,
                        rsp_headers,
                        &file_info.path,
                        file_info.mime_type.as_ref(),
                        &file_info.etag,
                        "zstd",
                        |b| encode_zstd(b, level),
                    );
                    return Ok(());
                } else {
                    // fall back to original file
                    (file_info.path.clone(), file_info.size)
                }
            }
        }
    };

    let range: Option<Range<u64>> = session
        .req_header(&HttpHeader::Range)
        .ok()
        .and_then(|h| parse_byte_range(h, total_size));

    let etag_to_send = rep_etag(&file_info.etag, applied_encoding);
    if let Ok(inm) = session.req_header(&HttpHeader::IfNoneMatch) {
        if if_none_match_contains(&inm, &etag_to_send) {
            if let Some(enc) = applied_encoding {
                rsp_headers.push((HttpHeader::ContentEncoding, enc.to_string()));
            }
            rsp_headers.extend([
                (HttpHeader::ContentLength, "0".to_owned()),
                (HttpHeader::Etag, etag_to_send),
                (
                    HttpHeader::LastModified,
                    file_info.last_modified_str.clone(),
                ),
                (HttpHeader::Vary, "Accept-Encoding".to_owned()),
            ]);
            session
                .status_code(Status::NotModified)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
        }
    }
    rsp_headers.extend([
        (HttpHeader::ContentType, file_info.mime_type.clone()),
        (
            HttpHeader::LastModified,
            file_info.last_modified_str.clone(),
        ),
        (HttpHeader::ContentDisposition, "inline".to_owned()),
        (HttpHeader::Etag, etag_to_send),
        (HttpHeader::Vary, "Accept-Encoding".to_owned()),
    ]);

    let (status, start, end) = if let Some(r) = range {
        let content_length = r.end - r.start;
        rsp_headers.extend([
            (
                HttpHeader::ContentRange,
                format!("bytes {}-{}/{}", r.start, r.end - 1, total_size),
            ),
            (HttpHeader::ContentLength, content_length.to_string()),
        ]);

        (Status::PartialContent, r.start, r.end)
    } else {
        rsp_headers.push((HttpHeader::ContentLength, total_size.to_string()));
        (Status::Ok, 0, total_size)
    };
    rsp_headers.push((HttpHeader::AcceptRanges, "bytes".to_string()));

    if session.req_method() == Some("HEAD") {
        session
            .status_code(status)
            .headers_vec(rsp_headers)?
            .body_static("")
            .eom();
        return Ok(());
    }

    let mmap = match std::fs::File::open(&file_path) {
        Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
            Ok(mmap) => mmap,
            Err(e) => {
                eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                session
                    .status_code(Status::InternalServerError)
                    .headers_vec(rsp_headers)?
                    .body_static("")
                    .eom();
                return Ok(());
            }
        },
        Err(e) => {
            eprintln!("Failed to open file: {}: {}", file_path.display(), e);
            session
                .status_code(Status::InternalServerError)
                .headers_vec(rsp_headers)?
                .body_static("")
                .eom();
            return Ok(());
        }
    };

    if session.is_h3() {
        session
            .status_code(status)
            .headers_vec(rsp_headers)?
            .body_mmap(std::sync::Arc::new(mmap), start as usize, end as usize)
            .eom();
    } else {
        session
            .status_code(status)
            .headers_vec(rsp_headers)?
            .body_slice(&mmap[start as usize..end as usize])
            .eom();
    }

    Ok(())
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
fn if_none_match_contains(header: &str, target: &str) -> bool {
    if header.trim() == "*" {
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

    header
        .split(',')
        .map(|s| s.trim())
        .any(|tag| tag == t_strong || tag == t_weak)
}

pub fn load_file_cache(capacity: usize) -> FileCache {
    DashMap::with_capacity(capacity)
}

fn compress_then_respond<S: Session>(
    session: &mut S,
    headers: &mut Vec<(HttpHeader, String)>,
    src_path: &PathBuf,
    mime_type: &str,
    etag: &str,
    encoding_name: &str,
    compress_fn: impl Fn(&[u8]) -> std::io::Result<Bytes>,
) {
    let res = (|| {
        let f = std::fs::File::open(src_path)?;
        let mmap = unsafe { memmap2::Mmap::map(&f) }
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        compress_fn(&mmap[..])
    })();

    match res {
        Ok(compressed) => {
            let etag_val = rep_etag(etag, Some(encoding_name));
            headers.extend([
                (HttpHeader::ContentEncoding, encoding_name.to_string()),
                (HttpHeader::ContentLength, compressed.len().to_string()),
                (HttpHeader::ContentType, mime_type.to_owned()),
                (HttpHeader::Etag, etag_val),
                (HttpHeader::ContentDisposition, "inline".to_owned()),
                (HttpHeader::Vary, "Accept-Encoding".to_owned()),
            ]);
            match session.status_code(Status::Ok).headers_vec(headers) {
                Ok(session) => session.body(&compressed).eom(),
                Err(_) => session
                    .status_code(Status::InternalServerError)
                    .body_static("")
                    .eom(),
            }
        }
        Err(e) => {
            eprintln!(
                "Compression failed ({encoding_name}) for {}: {e}",
                src_path.display()
            );
            let _ = session
                .status_code(Status::InternalServerError)
                .headers_vec(headers)
                .map(|s| s.body_static("").eom());
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
    let mime_type = mime_guess::from_path(&canonical)
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
fn choose_encoding(accept: &str, mime: &Mime, order: &[EncodingType]) -> EncodingType {
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

    let has_header = !accept.trim().is_empty();
    let mut prefs: std::collections::HashMap<String, Pref> = std::collections::HashMap::new();
    let mut star_q: Option<f32> = None;
    let mut identity_q: Option<f32> = None;

    for item in accept.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.split(';');
        let token_raw = parts.next().unwrap().trim();
        let token = token_raw.to_ascii_lowercase();
        let mut q: f32 = 1.0;
        for p in parts {
            let p = p.trim();
            if let Some(v) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                if let Ok(val) = v.trim().parse::<f32>() {
                    q = val;
                }
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

#[cfg(test)]
mod tests {
    use crate::network::http::{
        file::{EncodingType, FileInfo, serve},
        server::HFactory,
        session::{HService, Session},
    };
    use dashmap::DashMap;
    use std::sync::OnceLock;

    struct FileServer<T>(pub T);

    struct FileService;

    static FILE_CACHE: OnceLock<DashMap<String, FileInfo>> = OnceLock::new();
    fn get_cache() -> &'static DashMap<String, FileInfo> {
        FILE_CACHE.get_or_init(|| DashMap::with_capacity(128))
    }

    impl HService for FileService {
        fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
            use crate::network::http::file::HttpHeader;

            let mut rsp_headers: Vec<(HttpHeader, String)> = if session.is_h3() {
                Vec::new()
            } else {
                vec![
                    (HttpHeader::Connection, "close".to_string()),
                    (HttpHeader::AltSvc, "h3=\":8080\"; ma=86400".to_string()),
                ]
            };

            const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
            const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB

            let rel_file = file!();
            serve(
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

    impl HFactory for FileServer<FileService> {
        type Service = FileService;

        fn service(&self, _id: usize) -> FileService {
            FileService
        }
    }

    fn create_self_signed_tls_pems() -> (String, String) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd,
        };
        let mut params: CertificateParams = Default::default();
        params.not_before = rcgen::date_time_ymd(1975, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sib");
        params.distinguished_name.push(DnType::CommonName, "Sib");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn file_server() {
        const NUMBER_OF_WORKERS: usize = 2;
        const STACK_SIZE: usize = 2 * 1024 * 1024;
        crate::init(NUMBER_OF_WORKERS, STACK_SIZE);

        // Pick a port and start the server
        let addr = "0.0.0.0:8080";
        let mut threads = Vec::new();

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        let cert_path = "/tmp/cert.pem";
        let key_path = "/tmp/key.pem";

        std::fs::write(cert_path, certs.0.clone()).unwrap();
        std::fs::write(key_path, certs.1.clone()).unwrap();

        for _ in 0..NUMBER_OF_WORKERS {
            let cert_pem = certs.0.clone();
            let key_pem = certs.1.clone();
            let h1_handle = std::thread::spawn(move || {
                let id = std::thread::current().id();
                let ssl = crate::network::http::util::SSL {
                    cert_pem: cert_pem.as_bytes(),
                    key_pem: key_pem.as_bytes(),
                    chain_pem: None,
                    min_version: crate::network::http::util::SSLVersion::TLS1_2,
                    max_version: crate::network::http::util::SSLVersion::TLS1_3,
                    io_timeout: std::time::Duration::from_secs(10),
                };
                println!("Starting H1 server on {addr} with thread: {id:?}");
                FileServer(FileService)
                    .start_h1_tls(addr, &ssl, STACK_SIZE, None)
                    .unwrap_or_else(|_| panic!("file server failed to start for thread {id:?}"))
                    .join()
                    .unwrap_or_else(|_| panic!("file server failed to joining thread {id:?}"));
            });
            threads.push(h1_handle);
        }

        let h3_handle = std::thread::spawn(move || {
            let id = std::thread::current().id();
            println!("Starting H3 server on {addr} with thread: {id:?}");
            FileServer(FileService)
                .start_h3_tls(
                    addr,
                    (cert_path, key_path),
                    std::time::Duration::from_secs(10),
                    false,
                    (STACK_SIZE, NUMBER_OF_WORKERS),
                    false,
                )
                .unwrap_or_else(|_| panic!("file server failed to start for thread {id:?}"));
        });
        threads.push(h3_handle);

        // Wait for all threads to complete (they won’t unless crashed)
        for handle in threads {
            handle.join().expect("Thread panicked");
        }
    }
}
