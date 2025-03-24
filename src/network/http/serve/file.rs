use bytes::BytesMut;
use http::{HeaderValue, StatusCode};
use mime_guess::{Mime, mime};
use std::time::SystemTime;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, BufReader},
};

use crate::network::http::session::{HTTPMethod, Session};

const CHUNK_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
enum EncodingType {
    None,
    Gzip,
    Br,
    Zstd,
}

pub async fn serve(session: &mut Session, path: &str) -> anyhow::Result<()> {
    // Normalize and canonicalize the path
    let canonical = match fs::canonicalize(path).await {
        Ok(p) => p,
        Err(_) => return session.send_status_eom(StatusCode::BAD_REQUEST).await,
    };

    // check if it's a regular file
    let meta = match fs::metadata(&canonical).await {
        Ok(meta) => meta,
        _ => return session.send_status_eom(StatusCode::NOT_FOUND).await,
    };

    // ETag from last modified + file size
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let etag = format!(
        "\"{}-{}\"",
        modified.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
        meta.len()
    );

    // Handle ETAG
    if let Some(p_header_val) = session.read_req_header(http::header::IF_NONE_MATCH) {
        if p_header_val == &etag {
            return session.send_status_eom(StatusCode::NOT_MODIFIED).await;
        }
    }

    // Determine MIME type
    let mime_type = mime_guess::from_path(&canonical).first_or_octet_stream();

    // Determine compression encoding
    let encoding = get_encoding(
        session.read_req_header(http::header::ACCEPT_ENCODING),
        &mime_type,
    );

    const MIN_BYTES: u64 = 1024;
    let mut file_path = canonical.clone();
    if meta.len() > MIN_BYTES {
        let parent = canonical.parent().unwrap();
        let filename = canonical.file_name().unwrap().to_str().unwrap();
        let file_ext = canonical
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        file_path = match encoding {
            EncodingType::Gzip => parent.join("gz").join(format!("{filename}.{file_ext}.gz")),
            EncodingType::Br => parent.join("gz").join(format!("{filename}.{file_ext}.br")),
            EncodingType::Zstd => parent.join("gz").join(format!("{filename}.{file_ext}.zst")),
            EncodingType::None => canonical.clone(),
        };

        // If compressed file does not exist, fall back to original
        if fs::metadata(&file_path).await.is_err() {
            file_path = canonical.clone();
        }
    }

    session.append_headers(&[
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(mime_type.as_ref())?,
        ),
        (http::header::ETAG, HeaderValue::from_str(&etag)?),
    ]);

    // Add Content-Encoding if applicable
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

    if session.get_method() == &HTTPMethod::Head {
        session.send_status_eom(StatusCode::OK).await?;
        return Ok(());
    }

    // Try to open the file
    let file = match File::open(&file_path).await {
        Ok(file) => file,
        Err(_) => {
            return session
                .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                .await;
        }
    };

    session.send_status(StatusCode::OK).await?;

    let mut reader = BufReader::new(file);

    // Read & send chunks via pre-allocate buffer
    let mut buffer = BytesMut::with_capacity(CHUNK_SIZE);
    loop {
        buffer.resize(CHUNK_SIZE, 0);

        let num_read_bytes = match reader.read(&mut buffer).await {
            Ok(0) => break, // EOF
            Ok(num) => num,
            Err(_) => {
                return session
                    .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                    .await;
            }
        };

        let is_last_chunk = num_read_bytes < CHUNK_SIZE;

        let chunk = buffer.split_to(num_read_bytes).freeze();

        session.send_body(chunk, is_last_chunk).await?;

        // Cooperative multitasking
        tokio::task::yield_now().await;
    }

    session.send_eom().await
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
