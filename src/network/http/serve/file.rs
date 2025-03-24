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

    // ETag from last modified
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

    //Determine compression encoding
    let encoding = get_encoding(
        session.read_req_header(http::header::ACCEPT_ENCODING),
        &mime_type,
    );

    const MIN_BYTES: u64 = 1024;
    let file_path = if meta.len() > MIN_BYTES {
        let parent = canonical.parent().unwrap();
        let filename = canonical.file_name().unwrap().to_str().unwrap();
        let file_ext = canonical
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        match encoding {
            EncodingType::None => canonical,
            EncodingType::Gzip => {
                session.append_header(
                    &http::header::CONTENT_ENCODING,
                    HeaderValue::from_static("gzip"),
                );
                parent.join("gz").join(format!("{filename}.{file_ext}.gz"))
            }
            EncodingType::Br => {
                session.append_header(
                    &http::header::CONTENT_ENCODING,
                    HeaderValue::from_static("br"),
                );
                parent.join("br").join(format!("{filename}.{file_ext}.br"))
            }
            EncodingType::Zstd => {
                session.append_header(
                    &http::header::CONTENT_ENCODING,
                    HeaderValue::from_static("zstd"),
                );
                parent.join("zs").join(format!("{filename}.{file_ext}.zs"))
            }
        }
    } else {
        canonical
    };

    session.append_headers(&[
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(mime_type.as_ref())?,
        ),
        (http::header::ETAG, HeaderValue::from_str(&etag)?),
    ]);

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
        // Resize buffer to read into it
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

        // Freeze the buffer into an immutable `Bytes` slice
        let chunk = buffer.split_to(num_read_bytes).freeze();

        session.send_body(chunk, is_last_chunk).await?;

        // yield to the Tokio scheduler after sending each chunk makes the file streamer more friendly in high concurrency environments
        tokio::task::yield_now().await;
    }

    // Finally, send the end of the message
    session.send_eom().await
}

fn get_encoding(accept_encoding: Option<&HeaderValue>, mime: &Mime) -> EncodingType {
    // Skip compression for already compressed media types (except SVG)
    if (mime.type_() == mime::IMAGE || mime.type_() == mime::AUDIO || mime.type_() == mime::VIDEO)
        && *mime != mime::IMAGE_SVG
    {
        return EncodingType::None;
    }

    let header = match accept_encoding.and_then(|h| h.to_str().ok()) {
        Some(value) => value,
        None => return EncodingType::None,
    };

    // Convert to lowercase once and use efficient substring search
    let header = header.to_ascii_lowercase();

    // go for the encoding type in order
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
