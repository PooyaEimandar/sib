use crate::network::http::server::H2Config;
use crate::network::http::session::HAsyncService;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_lite::io::{AsyncRead, AsyncWrite};
use h2::server::Builder;
use std::net::SocketAddr;
use tokio::io::{AsyncRead as TAsyncRead, AsyncWrite as TAsyncWrite, ReadBuf};

struct TokioStream<S>(pub S);

impl<S: AsyncRead + Unpin> TAsyncRead for TokioStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match Pin::new(&mut self.0).poll_read(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> TAsyncWrite for TokioStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

pub(crate) async fn serve<S, T>(
    stream: S,
    mut service: T,
    config: &H2Config,
    peer: SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
    T: HAsyncService + Send + 'static,
{
    let mut builder = Builder::new();
    builder
        .max_header_list_size(config.max_header_list_size)
        .max_concurrent_streams(config.max_concurrent_streams)
        .initial_window_size(config.initial_window_size)
        .initial_connection_window_size(config.initial_connection_window_size)
        .max_frame_size(config.max_frame_size);
    if config.enable_connect_protocol {
        builder.enable_connect_protocol();
    }

    let mut conn: h2::server::Connection<TokioStream<S>, bytes::Bytes> = builder
        .handshake::<TokioStream<S>, bytes::Bytes>(TokioStream(stream))
        .await
        .map_err(|e| std::io::Error::other(format!("h2 error: {}", e)))?;

    while let Some(r) = conn.accept().await {
        let (request, respond) = match r {
            Ok(x) => x,
            Err(e) => {
                // Protocol / IO close.
                if e.is_io() {
                    return Ok(());
                }
                break;
            }
        };

        use crate::network::http::h2_session::H2Session;
        if let Err(e) = service
            .call(&mut H2Session::new(peer, request, respond))
            .await
        {
            eprintln!("h2 service got an error: {}", e);
            if e.kind() == std::io::ErrorKind::ConnectionAborted {
                // only abort if the service explicitly wants hard close
                conn.graceful_shutdown();
            }
        }
    }

    Ok(())
}
