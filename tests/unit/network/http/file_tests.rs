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
            #[cfg(all(
                all(feature = "net-h3-server", target_os = "linux"),
                feature = "rt-glommio",
                target_os = "linux"
            ))]
            if let Err(e) = crate::network::http::file::serve_h3(
                session,
                file!(),
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
                (H2_STREAM_THRESHOLD, H2_STREAM_CHUNK_SIZE),
            )
            .await
            {
                error!("H3 FileService failed: {e}");
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
    let mtls = crate::MtlsIdentity::generate(&[], &[], false);

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
            let cert_h3_pem = cert.clone();
            let key_h3_pem = key.clone();
            let h3_handle = std::thread::spawn(move || {
                use crate::network::http::server::H3Config;
                let addr = "0.0.0.0:8082";
                let cert_pem = cert_h3_pem.as_bytes();
                let key_pem = key_h3_pem.as_bytes();
                let id = std::thread::current().id();
                tracing::info!("Starting H2 server on {addr} with thread: {id:?}");
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
