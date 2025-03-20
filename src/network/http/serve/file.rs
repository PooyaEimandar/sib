use bytes::BytesMut;
use http::StatusCode;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, BufReader},
};

use crate::network::http::session::Session;

const CHUNK_SIZE: usize = 16 * 1024;

pub async fn serve(session: &mut Session, path: &str) -> anyhow::Result<()> {
    // check file existence
    let meta_res = fs::metadata(path).await;
    if meta_res.is_err() {
        return session.send_status_eom(StatusCode::NOT_FOUND).await;
    }

    // first, open the file
    let file = match File::open(path).await {
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
    }

    // Finally, send the end of the message
    session.send_eom().await
}
