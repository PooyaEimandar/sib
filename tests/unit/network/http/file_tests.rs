#[cfg(feature = "net-h1-server")]
use crate::network::http::server::H1Config;
use crate::network::http::session::Session;
use crate::network::http::{
    file::{EncodingType, FileInfo},
    server::HFactory,
};
use dashmap::DashMap;
use std::sync::OnceLock;

struct FileServer<T>(pub T);

struct FileService;

static FILE_CACHE: OnceLock<DashMap<String, FileInfo>> = OnceLock::new();
fn get_cache() -> &'static DashMap<String, FileInfo> {
    FILE_CACHE.get_or_init(|| DashMap::with_capacity(128))
}

#[test]
fn ktx2_uses_the_registered_image_media_type() {
    let mime = super::mime_for_path(std::path::Path::new("runtime/sky.KTX2"));
    assert_eq!(mime.essence_str(), "image/ktx2");
}

#[cfg(feature = "net-h2-server")]
#[test]
fn cached_file_refresh_does_not_deadlock() {
    use crate::network::http::{file, h1_session_async::H1SessionAsync};
    use bytes::Bytes;
    use http::{HeaderMap, Method, Uri, Version};
    use std::{
        fs::{File, FileTimes},
        path::PathBuf,
        sync::mpsc,
        time::{Duration, SystemTime},
    };
    use tokio::io::AsyncReadExt;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn response(path: &PathBuf, cache: &file::FileCache) -> String {
        // The small response fits in the buffer without a concurrent reader.
        let (mut server, mut client) = tokio::io::duplex(16 * 1024);
        let mut session = H1SessionAsync::new(
            "127.0.0.1".parse().unwrap(),
            &mut server,
            (Method::GET, Version::HTTP_11),
            Uri::from_static("/asset.txt"),
            (HeaderMap::new(), Bytes::new()),
            false,
            false,
        );
        file::serve_h1_async(
            &mut session,
            path,
            cache,
            &[EncodingType::None],
            (0, 8192),
            (8192, 1024),
            ("inline", true),
        )
        .await
        .unwrap();
        drop(session);
        drop(server);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    }

    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sib-file-cache-refresh-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    // Keep cleanup on the test thread, including when the worker times out.
    let fixture = Fixture(root);
    let path = fixture.0.join("asset.txt");
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cache = file::FileCache::new();
                for (version, body) in ["original", "updated asset contents"].iter().enumerate() {
                    std::fs::write(&path, body).unwrap();
                    // Explicit times avoid sleeps and filesystem timestamp precision races.
                    let modified = SystemTime::UNIX_EPOCH
                        + Duration::from_secs(1_700_000_000 + version as u64 * 2);
                    File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_times(FileTimes::new().set_modified(modified))
                        .unwrap();

                    // Exercise insertion/refresh, followed by an unchanged cache hit.
                    for _ in 0..2 {
                        let response = response(&path, &cache).await;
                        let (headers, received_body) = response.split_once("\r\n\r\n").unwrap();
                        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
                        assert_eq!(received_body, *body);
                        assert!(headers.lines().any(|line| {
                            line.eq_ignore_ascii_case(&format!("content-length: {}", body.len()))
                        }));
                    }
                }
            });
        done_tx.send(()).unwrap();
    });

    // A Tokio timeout cannot interrupt a synchronous DashMap lock on its own thread.
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("serving a changed cached file must complete without deadlocking");
    worker.join().unwrap();
}

#[cfg(feature = "net-h1-server")]
impl crate::network::http::session::HService for FileService {
    fn call<S: Session>(&self, session: &mut S) -> std::io::Result<()> {
        const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
        const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
        const H1_STREAM_THRESHOLD: u64 = 256 * 1024; // 256 KB
        const H1_STREAM_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

        // session.header(
        //     http::header::CONNECTION,
        //     http::HeaderValue::from_static("close"),
        // )?;

        use crate::network::http::file::serve_h1;
        serve_h1(
            session,
            &std::path::PathBuf::from(file!()),
            get_cache(),
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
            (H1_STREAM_THRESHOLD, H1_STREAM_CHUNK_SIZE),
            ("inline", true),
        )
    }
}

#[cfg(any(
    feature = "net-h2-server",
    all(feature = "net-h3-server", target_os = "linux")
))]
#[async_trait::async_trait(?Send)]
impl crate::network::http::session::HAsyncService for FileService {
    async fn call<SE: Session>(&self, session: &mut SE) -> std::io::Result<()> {
        const MIN_BYTES_ON_THE_FLY_SIZE: u64 = 1024;
        const MAX_BYTES_ON_THE_FLY_SIZE: u64 = 512 * 1024; // 512 KB
        const H2_STREAM_THRESHOLD: u64 = 128 * 1024; // 128 KB
        const H2_STREAM_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

        if session.req_http_version() == http::Version::HTTP_3 {
            #[cfg(all(feature = "net-h3-server", target_os = "linux"))]
            if let Err(e) = crate::network::http::file::serve_h3(
                session,
                &std::path::PathBuf::from(file!()),
                get_cache(),
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
                (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
            )
            .await
            {
                tracing::error!("H3 FileService failed: {e}");
                return session
                    .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(bytes::Bytes::new())
                    .eom_async()
                    .await;
            };
        } else if session.req_http_version() == http::Version::HTTP_2 {
            let _ = session.header(
                http::header::ALT_SVC,
                http::HeaderValue::from_static("h3=\":8082\"; ma=86400"),
            );

            #[cfg(feature = "net-h2-server")]
            if let Err(e) = crate::network::http::file::serve_h2(
                session,
                &std::path::PathBuf::from(file!()),
                get_cache(),
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
                (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
                ("inline", true),
            )
            .await
            {
                tracing::error!("H2 FileService failed: {e}");
                return session
                    .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(bytes::Bytes::new())
                    .eom();
            };
        } else {
            let _ = session.header(
                http::header::ALT_SVC,
                http::HeaderValue::from_static("h3=\":8082\"; ma=86400"),
            );

            #[cfg(feature = "net-h2-server")]
            if let Err(e) = crate::network::http::file::serve_h1_async(
                session,
                &std::path::PathBuf::from(file!()),
                get_cache(),
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
                (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
                ("inline", true),
            )
            .await
            {
                tracing::error!("H2 FileService failed: {e}");
                return session
                    .status_code(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(bytes::Bytes::new())
                    .eom();
            };
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[cfg(feature = "net-wt-server")]
struct UnusedWtService;

#[cfg(feature = "net-wt-server")]
#[async_trait::async_trait(?Send)]
impl crate::network::http::wt::WtService for UnusedWtService {
    async fn call(
        &mut self,
        _session: &mut crate::network::http::wt::WtSession,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "unused wt service in file server test",
        ))
    }
}

impl HFactory for FileServer<FileService> {
    #[cfg(feature = "net-h1-server")]
    type Service = FileService;

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    type HAsyncService = FileService;

    #[cfg(feature = "net-wt-server")]
    type WtService = UnusedWtService;

    #[cfg(feature = "net-h1-server")]
    fn service(&self, _id: usize) -> Self::Service {
        FileService
    }

    #[cfg(any(
        feature = "net-h2-server",
        all(feature = "net-h3-server", target_os = "linux")
    ))]
    fn async_service(&self, _id: usize) -> Self::HAsyncService {
        FileService
    }

    #[cfg(feature = "net-wt-server")]
    fn wt_service(&self, _id: usize) -> Self::WtService {
        UnusedWtService
    }
}
#[test]
#[ignore = "legacy network integration test uses fixed ports and long-running servers"]
fn file_server() {
    // Pick a port and start the server
    let mut threads = Vec::new();

    // create self-signed TLS certificates
    let mtls = crate::MtlsIdentity::generate(&[], &[], false).expect("generate mTLS identity");

    cfg_if::cfg_if! {
        if #[cfg(feature = "net-h1-server")] {
            const NUMBER_OF_WORKERS: usize = 2;
            const STACK_SIZE: usize = 2 * 1024 * 1024;
            crate::init_global_poller(NUMBER_OF_WORKERS, STACK_SIZE);

            for _ in 0..NUMBER_OF_WORKERS {
                let addr = "0.0.0.0:8080";
                let cert_pem = mtls.server_cert_pem.clone();
                let key_pem = mtls.server_key_pem.clone();
                let h1_handle = std::thread::spawn(move || {
                    let id = std::thread::current().id();
                    tracing::info!("Starting H1 server on {addr} with thread: {id:?}");
                    FileServer(FileService)
                        .start_h1_tls(
                            addr,
                            (None, cert_pem.as_bytes(), key_pem.as_bytes()),
                            H1Config::default(),
                        )
                        .unwrap_or_else(|_| panic!("H1 file server failed to start for thread {id:?}"))
                        .join()
                        .unwrap_or_else(|_| panic!("H1 file server failed to joining thread {id:?}"));
                });
                threads.push(h1_handle);
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "net-h2-server")] {
            let cert_pem = mtls.server_cert_pem.clone();
            let key_pem = mtls.server_key_pem.clone();
            let cancel = tokio_util::sync::CancellationToken::new();
            let h2_handle = std::thread::spawn(move || {
                use crate::network::http::server::H2Config;
                let addr = "0.0.0.0:8081";
                let cert_pem = cert_pem.as_bytes();
                let key_pem = key_pem.as_bytes();
                let id = std::thread::current().id();
                tracing::info!("Starting H2 server on {addr} with thread: {id:?}");
                FileServer(FileService)
                    .start_h2_tls(addr, (None, cert_pem, key_pem), H2Config::default(), cancel.clone())
                    .unwrap_or_else(|_| panic!("H2 file server failed to start for thread {id:?}"));
            });
            threads.push(h2_handle);
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "net-h3-server", target_os = "linux"))] {
            let cert_h3_pem = mtls.server_cert_pem.clone();
            let key_h3_pem = mtls.server_key_pem.clone();
            let h3_handle = std::thread::spawn(move || {
                use crate::network::http::server::H3Config;
                let addr = "0.0.0.0:8082";
                let cert_pem = cert_h3_pem.as_bytes();
                let key_pem = key_h3_pem.as_bytes();
                let id = std::thread::current().id();
                tracing::info!("Starting H3 server on {addr} with thread: {id:?}");
                FileServer(FileService)
                    .start_h3_tls(addr, (None, cert_pem, key_pem), H3Config::default())
                    .unwrap_or_else(|_| panic!("H3 file server failed to start for thread {id:?}"));
            });
            threads.push(h3_handle);
        }
    }

    // Wait for all threads to complete (they won’t unless crashed)
    for handle in threads {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn parse_byte_range_clamps_and_never_overflows() {
    use super::{ByteRange::*, parse_byte_range};
    use http::HeaderValue;

    for (header, total, expected) in [
        ("bytes=0-18446744073709551615", 1000, Satisfiable(0..1000)),
        ("bytes=0-18446744073709551616", 1000, Satisfiable(0..1000)),
        ("bytes=10-20", 1000, Satisfiable(10..21)),
        ("bytes=0-5000", 1000, Satisfiable(0..1000)),
        ("bytes=990-", 1000, Satisfiable(990..1000)),
        ("bytes=-500", 1000, Satisfiable(500..1000)),
        ("bytes=-5000", 1000, Satisfiable(0..1000)),
        ("bytes=-18446744073709551616", 1000, Satisfiable(0..1000)),
        ("BYTES=0-0", 1000, Satisfiable(0..1)),
        ("bytes=0001-0002", 1000, Satisfiable(1..3)),
        ("bytes=1000-1001", 1000, Unsatisfiable),
        ("bytes=1000-", 1000, Unsatisfiable),
        ("bytes=18446744073709551616-", 1000, Unsatisfiable),
        ("bytes=-0", 1000, Unsatisfiable),
        ("bytes=0-0", 0, Unsatisfiable),
        ("bytes=0-", 0, Unsatisfiable),
        ("bytes=-1", 0, Ignored),
        ("bytes=-0", 0, Unsatisfiable),
        (
            "bytes=18446744073709551614-18446744073709551615",
            u64::MAX,
            Satisfiable((u64::MAX - 1)..u64::MAX),
        ),
    ] {
        assert_eq!(
            parse_byte_range(&HeaderValue::from_str(header).unwrap(), total),
            expected,
            "{header}"
        );
    }
}

#[test]
fn malformed_and_unsupported_ranges_are_ignored() {
    use super::{ByteRange, parse_byte_range};
    use http::HeaderValue;

    for header in [
        "bytes=10-bad",
        "bytes=bad-10",
        "bytes=10-9",
        "bytes=10--20",
        "bytes=+1-2",
        "bytes=1-+2",
        "bytes=-+2",
        "bytes=1 -2",
        "bytes=1- 2",
        "bytes=-",
        "bytes=",
        "bytes=1",
        "bytes=0-1,4-5",
        "items=0-1",
    ] {
        assert_eq!(
            parse_byte_range(&HeaderValue::from_str(header).unwrap(), 1000),
            ByteRange::Ignored,
            "{header}"
        );
    }
}

#[test]
fn safe_join_confines_to_root() {
    use crate::network::http::file::safe_join;
    use std::path::{Path, PathBuf};

    let root = Path::new("/srv/www");

    assert_eq!(
        safe_join(root, "/index.html"),
        Some(PathBuf::from("/srv/www/index.html"))
    );
    assert_eq!(
        safe_join(root, "a/b/c.txt"),
        Some(PathBuf::from("/srv/www/a/b/c.txt"))
    );
    assert_eq!(
        safe_join(root, "/a/./b"),
        Some(PathBuf::from("/srv/www/a/b"))
    );
    // Descend then come back up within root is fine.
    assert_eq!(
        safe_join(root, "/a/b/../c"),
        Some(PathBuf::from("/srv/www/a/c"))
    );

    // Traversal above root is rejected.
    assert_eq!(safe_join(root, "/../etc/passwd"), None);
    assert_eq!(safe_join(root, "a/../../etc/passwd"), None);
    // Absolute component cannot replace the root.
    assert_eq!(
        safe_join(root, "/a//etc"),
        Some(PathBuf::from("/srv/www/a/etc"))
    );
    // NUL byte rejected.
    assert_eq!(safe_join(root, "a\0b"), None);
}

#[test]
fn if_match_parses_opaque_tags_and_rejects_weak_or_malformed_matches() {
    use http::{HeaderMap, HeaderValue, header};
    assert!(super::if_match_satisfied(&HeaderMap::new(), "\"current\""));
    for (value, target, expected) in [
        ("*", "W/\"current\"", true),
        ("\"current\"", "W/\"current\"", false),
        ("W/\"current\"", "\"current\"", false),
        ("\"\"", "\"\"", true),
        ("\"Current\"", "\"current\"", false),
        (" ,\t\"current\",, ", "\"current\"", true),
        (r#""a,b\c", "other""#, r#""a,b\c""#, true),
        ("\"étag\"", "\"étag\"", true),
        ("\"current\" garbage", "\"current\"", false),
        ("\"current\", W/\"unfinished", "\"current\"", false),
        ("\"current\", \"bad tag\"", "\"current\"", false),
        ("\"current\", *", "\"current\"", false),
        (",,", "\"current\"", false),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
        assert_eq!(
            super::if_match_satisfied(&headers, target),
            expected,
            "{value:?} vs {target:?}"
        );
    }
}
