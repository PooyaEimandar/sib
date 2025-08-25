use std::{fs::Metadata, io::Read, ops::Range, path::PathBuf, time::SystemTime};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use mime::Mime;
use crate::network::http::{util::{HttpHeader, Status}, session::Session};

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

pub type FileCache = DashMap<String, FileInfo>;

pub fn serve<S: Session>(
    session: &mut S,
    path: &str,
    file_cache: &FileCache,
    rsp_headers: &mut Vec<(HttpHeader, String)>,
    encoding_order: &[EncodingType],
) -> std::io::Result<()> {
    // canonicalise
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            eprintln!(
                "File server failed to canonicalize path: {path}"
            );
            session.status_code(Status::NotFound).headers_vec(rsp_headers)?.body_static("").eom();
            return Ok(()); 
        }
    };
     // meta
    let meta = match std::fs::metadata(&canonical)
    {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("File server failed to get metadata for path: {}: {}", canonical.display(), e);
            session.status_code(Status::NotFound).headers_vec(rsp_headers)?.body_static("").eom();
            return Ok(()); 
        }
    };

    // look or fill cache
    let key = canonical.to_string_lossy().to_string();

    // Get modified time once
    let modified = match meta.modified() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read modified time for: {}: {}", canonical.display(), e);
            session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
            return Ok(()); 
        }
    };

    // file cache lookup
    let file_info = if let Some(info) = file_cache.get(&key) {
        if modified <= info.modified {
            info.clone()
        } else {
            // outdated cache entry, fall through to regeneration
            generate_file_info(&key, canonical, &meta, modified, file_cache)
        }
    } else {
        // cache miss, generate and insert
        generate_file_info(&key, canonical, &meta, modified, file_cache)
    };

    // check ‘If-None-Match’ header
    if let Ok(p_header_val) = session.req_header(&HttpHeader::IfNoneMatch) {
        if p_header_val == file_info.etag {
            rsp_headers.extend([
                (HttpHeader::ContentLength, "0".to_owned()),
                (HttpHeader::Etag, file_info.etag),
                (HttpHeader::LastModified, httpdate::HttpDate::from(file_info.modified).to_string()),
            ]);
            session.status_code(Status::NotModified).headers_vec(rsp_headers)?.body_static("").eom();
            return Ok(()); 
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

    let mut meta_opt: Option<Metadata> = None;
    let mut file_path = file_info.path.clone();
    if file_info.size > MIN_BYTES_ON_THE_FLY_SIZE {
        let parent = match file_info.path.parent() {
            Some(parent) => parent,
            None => {
                eprintln!("File server failed to get parent directory for path: {}", file_info.path.display());
                session.status_code(Status::NotFound).headers_vec(rsp_headers)?.body_static("").eom();
                return Ok(()); 
            }
        };
        let file_name_osstr = match file_info.path.file_name() {
            Some(name) => name,
            None => {
                eprintln!("File server failed to get file name for path: {}", file_info.path.display());
                session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
                return Ok(()); 
            }
        };

        let filename = match file_name_osstr.to_str() {
            Some(name) => name,
            None => {
                eprintln!("File server failed to convert file name to string for path: {}", file_info.path.display());
                session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
                return Ok(()); 
            }
        };

        (file_path, meta_opt) = match encoding {
            EncodingType::Gzip{level} => {
                let com_file = parent.join("gz").join(format!("{filename}.gz"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    rsp_headers.push((
                        HttpHeader::ContentEncoding,
                        "gzip".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {  
                    respond_with_compressed(
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
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Br{buffer_size, quality, lgwindow} => {
                let com_file = parent.join("br").join(format!("{filename}.br"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    rsp_headers.push((
                        HttpHeader::ContentEncoding,
                        "br".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {
                    respond_with_compressed(
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
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::Zstd{level} => {
                let com_file = parent.join("zstd").join(format!("{filename}.zstd"));
                let com_meta_res = std::fs::metadata(&com_file);
                if let Ok(com_meta) = com_meta_res {
                    rsp_headers.push((
                        HttpHeader::ContentEncoding,
                        "zstd".to_string(),
                    ));
                    (com_file, Some(com_meta))
                } else if file_info.size <= MAX_BYTES_ON_THE_FLY_SIZE {
                    respond_with_compressed(
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
                    (file_info.path.clone(), None)
                }
            }
            EncodingType::None => (file_info.path.clone(), None),
        };
    }

    let meta = if let Some(m) = meta_opt { m } else {
        match std::fs::metadata(&file_path) {
            Ok(m) => m,
            Err(err) => {
                eprintln!("Failed to stat {}: {err}", file_path.display());
                session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
                return Ok(())
            }
        }
    };
    let total_size = meta.len();

    let range: Option<Range<u64>> = session
    .req_header(&HttpHeader::Range)
    .ok()
    .and_then(|h| parse_byte_range(h, total_size));

    rsp_headers.extend([
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
        rsp_headers.extend([
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
        rsp_headers.push((
            HttpHeader::ContentLength,
            total_size.to_string(),
        ));
        (Status::Ok, 0, total_size)
    };

    if session.req_method() == Some("HEAD") {
        session.status_code(status).headers_vec(rsp_headers)?.body_static("").eom();
        return Ok(());
    }

    // #[cfg(target_os = "linux")]
    // {
    //     match read_file_uring_range(file_path.to_str().unwrap(), start, (end - start) as usize) {
    //         Ok(buf) => {
    //             session.status_code(status)
    //                 .headers_vec(&rsp_headers)?
    //                 .body_slice(&buf)
    //                 .eom();
    //         }
    //         Err(e) => {
    //             eprintln!("io_uring read failed: {e}");
    //             session.status_code(Status::InternalServerError)
    //                 .headers_vec(&rsp_headers)?
    //                 .body_static("")
    //                 .eom();
    //         }
    //     }
    // }
    // #[cfg(not(target_os = "linux"))]
    // {
        let mmap = match std::fs::File::open(&file_path) {
            Ok(std_file) => match unsafe { memmap2::Mmap::map(&std_file) } {
                Ok(mmap) => mmap,
                Err(e) => {
                    eprintln!("Failed to memory-map file: {}: {}", file_path.display(), e);
                    session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
                    return Ok(());
                }
            },
            Err(e) => {
                eprintln!("Failed to open file: {}: {}", file_path.display(), e);
                session.status_code(Status::InternalServerError).headers_vec(rsp_headers)?.body_static("").eom();
                return Ok(());
            }
        };
        session.status_code(status).headers_vec(rsp_headers)?.body_slice(&mmap[start as usize..end as usize]).eom();
    // }
    Ok(())
}

pub fn load_file_cache(capacity: usize) -> FileCache {
    DashMap::with_capacity(capacity)
}

// #[cfg(target_os = "linux")]
// fn read_file_uring_range(path: &str, offset: u64, len: usize) -> std::io::Result<Bytes> {
//     use io_uring::{IoUring, opcode, types};
//     use nix::sys::uio::IoVec;
//     use std::{fs::File, os::unix::io::AsRawFd};

//     let file = File::open(path)?;
//     let fd = file.as_raw_fd();
//     let mut buf = vec![0u8; len];
//     let mut ring = IoUring::new(4)?;

//     unsafe {
//         let iovec = [IoVec::from_mut_slice(&mut buf)];
//         let read_e = opcode::Readv::new(types::Fd(fd), iovec.as_ptr(), 1)
//             .offset(offset as i64)
//             .build()
//             .user_data(0x42);

//         ring.submission().push(&read_e).unwrap();
//         ring.submit_and_wait(1)?;

//         let cqe = ring.completion().next().unwrap();
//         if cqe.result() < 0 {
//             return Err(std::io::Error::from_raw_os_error(-cqe.result()));
//         }
//         buf.truncate(cqe.result() as usize);
//         Ok(Bytes::from(buf))
//     }
// }

fn respond_with_compressed<S: Session>(session: &mut S,
                               headers: &mut Vec<(HttpHeader, String)>,
                               file_path: &PathBuf,
                               mime_type: &str,
                               etag: &str,
                               encoding_name: &str,
                               compress_fn: impl Fn(Bytes) -> std::io::Result<Bytes>) {
    match get_file_buffer(file_path).and_then(compress_fn) {
        Ok(compressed) => {
            headers.extend(
                [
                    (HttpHeader::ContentEncoding, encoding_name.to_string()),
                    (HttpHeader::ContentLength, compressed.len().to_string()),
                    (HttpHeader::ContentType, mime_type.to_owned()),
                    (HttpHeader::Etag, etag.to_owned()),
                    (HttpHeader::ContentDisposition, "inline".to_owned()),
                ]);
            match session.status_code(Status::Ok).headers_vec(headers)
            {
                Ok(session) => {
                    session.body(&compressed).eom();
                }
                Err(e) => 
                {
                    eprintln!(
                        "Compression failed ({encoding_name}) while sending headers for {}: {e}",
                        file_path.display()
                    );
                    session.status_code(Status::InternalServerError).body_static("").eom();
                }
            }
        }
        Err(e) => {
            eprintln!(
                "Compression failed ({encoding_name}) for {}: {e}",
                file_path.display()
            );
            match session.status_code(Status::InternalServerError).headers_vec(headers)
            {
                Ok(session) => {
                    session.body_static("").eom();
                }
                Err(_) => 
                {
                    session.status_code(Status::InternalServerError).body_static("").eom();
                }
            }
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
        file::{serve, EncodingType, FileInfo}, server::HFactory, session::{HService, Session}
    };
    use dashmap::DashMap;
    use std::{
        sync::OnceLock,
    };

    struct FileServer<T>(pub T);

    struct FileService;

    static FILE_CACHE: OnceLock<DashMap<String, FileInfo>> = OnceLock::new();
    fn get_cache() -> &'static DashMap<String, FileInfo> {
        FILE_CACHE.get_or_init(|| {
            DashMap::with_capacity(128)
        })
    }

    impl HService for FileService {
        fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
            use crate::network::http::file::HttpHeader;

            let mut rsp_headers: Vec<(HttpHeader, String)> = if session.is_h3()
            {
                Vec::new()
            } else {
                vec![
                    (HttpHeader::Connection, "close".to_string()),
                    (HttpHeader::AltSvc, "h3=\":8080\"; ma=86400".to_string()),
                ]
            };

            serve(session,"/Users/pooyaeimandar/Desktop/k6.js", get_cache(),
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
                ]
            )
        }
    }

    #[cfg(feature = "net-h3-server")]
    impl crate::network::http::session::HServiceWebTransport for FileService {}

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
        const NUMBER_OF_WORKERS: usize = 1;
        const STACK_SIZE: usize = 2 * 1024 * 1024;
        crate::init(NUMBER_OF_WORKERS, STACK_SIZE);

        // Pick a port and start the server
        let addr = "0.0.0.0:8080";
        let mut threads = Vec::with_capacity(2);

        // create self-signed TLS certificates
        let certs = create_self_signed_tls_pems();
        let cert_path = "/tmp/cert.pem";
        let key_path = "/tmp/key.pem";

        std::fs::write(cert_path, certs.0.clone()).unwrap();
        std::fs::write(key_path, certs.1.clone()).unwrap();

        let cert_pem = certs.0.clone();
        let key_pem = certs.1.clone();

        let h1_handle = std::thread::spawn(move || {

            let id = std::thread::current().id();
            let ssl = crate::network::http::util::SSL
            {
                cert_pem: cert_pem.as_bytes(),
                key_pem: key_pem.as_bytes(),
                chain_pem: None,
                min_version: crate::network::http::util::SSLVersion::TLS1_2,
                max_version: crate::network::http::util::SSLVersion::TLS1_3,
                io_timeout: std::time::Duration::from_secs(10)
            };
            println!("Starting H1 server on {addr} with thread: {id:?}");
            FileServer(FileService)
                .start_h1_tls(addr, &ssl, STACK_SIZE, None)
                .unwrap_or_else(|_| panic!("file server failed to start for thread {id:?}"))
                .join()
                .unwrap_or_else(|_| panic!("file server failed to joining thread {id:?}"));
        });
        threads.push(h1_handle);

        let h3_handle = std::thread::spawn(move || {
            let id = std::thread::current().id();
            println!("Starting H3 server on {addr} with thread: {id:?}");
            FileServer(FileService)
                .start_h3_tls(addr, (cert_path, key_path), std::time::Duration::from_secs(10), false, STACK_SIZE, None)
                .unwrap_or_else(|_| panic!("file server failed to start for thread {id:?}"));
        });
        threads.push(h3_handle);

        // Wait for all threads to complete (they won’t unless crashed)
        for handle in threads {
            handle.join().expect("Thread panicked");
        }
    }
}


