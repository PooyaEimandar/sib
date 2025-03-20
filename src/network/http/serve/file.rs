use http::StatusCode;
use tokio::io::AsyncReadExt;

use crate::network::http::session::Session;

const CHUNK_SIZE: usize = 4096;

pub async fn serve(session: &mut Session, path: &str) -> anyhow::Result<()> {
    // check file existence
    let meta_res = tokio::fs::metadata(path).await;
    if meta_res.is_err() {
        return session.send_status_eom(StatusCode::NOT_FOUND).await;
    }

    // first, open the file
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(_) => {
            return session
                .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                .await;
        }
    };

    session.send_status(StatusCode::OK).await?;

    // Then, send the chunks
    let chunk_size = 4096;
    let mut buffer = vec![0; CHUNK_SIZE];

    // Then, send the chunks
    loop {
        let num_read_bytes: usize = match file.read(&mut buffer).await {
            Ok(num) => num,
            Err(_) => {
                return session
                    .send_status_eom(StatusCode::INTERNAL_SERVER_ERROR)
                    .await;
            }
        };

        if num_read_bytes == 0 {
            break;
        }

        let chunk = buffer[..num_read_bytes].to_vec();
        let is_last_chunk = num_read_bytes < chunk_size;

        session.send_body(chunk.into(), is_last_chunk).await?;

        println!("Sending chunk of size: {}", num_read_bytes);
    }

    // Finally, send the end of the message
    session.send_eom().await
}
