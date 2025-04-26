use async_trait::async_trait;
use pingora::apps::HttpServerApp;
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
// use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::session::Session;
// use crate::{network::ratelimit::RateLimit, s_error};
use crate::s_error;

const READ_H1_HEADERS_TIMEOUT: Duration = Duration::from_secs(1);

pub type HandlerFn =
    Arc<dyn Fn(Session) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

pub fn service(
    // rate_limiter: Option<Arc<RateLimit>>,
    handler: Option<HandlerFn>,
) -> Service<H2Handler> {
    Service::new(
        "Sib http service handler".to_string(),
        H2Handler {
            // rate_limiter,
            handler,
        },
    )
}

pub struct H2Handler {
    // rate_limiter: Option<Arc<RateLimit>>,
    handler: Option<HandlerFn>,
}

#[async_trait]
impl HttpServerApp for H2Handler {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // If HTTP/1.1, force to read the headers
        if !session.is_http2() {
            match pingora::time::timeout(READ_H1_HEADERS_TIMEOUT, session.read_request()).await {
                Ok(result) => {
                    if let Err(err) = result {
                        s_error!("Session timeout while reading headers for HTTP/1.1 {}", err);
                        return None;
                    }
                }
                Err(e) => {
                    s_error!("Error while reading headers for HTTP/1.1: {:?}", e);
                    return None;
                }
            }
        }

        // // check rate limit
        // if let Some(limiter) = &self.rate_limiter {
        //     if let Some(peer_addr) = session.client_addr() {
        //         if let Some(ip) = peer_addr
        //             .to_socket_addrs()
        //             .ok()
        //             .and_then(|mut addrs| addrs.next().map(|addr| addr.ip()))
        //         {
        //             if !limiter.allow(ip) {
        //                 s_warn!("H2 Rate limit exceeded for {ip}");
        //                 return None;
        //             }
        //         }
        //     }
        // }

        if let Some(p_handler) = &self.handler {
            match Session::new_h2(session).await {
                Ok(session) => {
                    if let Err(e) = p_handler(session).await {
                        s_error!("H2/H1 session handler encountered an error: {:?}", e);
                    }
                }
                Err(err) => {
                    s_error!("Failed to build H2/H1 session: {:?}", err);
                }
            }
        } else {
            s_error!("No handler defined for incoming session.");
        }

        None
    }
}
