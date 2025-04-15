use async_trait::async_trait;
use pingora::apps::HttpServerApp;
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use std::pin::Pin;
use std::sync::Arc;

use crate::s_error;

use super::session::Session;

pub type HandlerFn =
    Arc<dyn Fn(Session) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

pub fn service(handler: Option<HandlerFn>) -> Service<H2Handler> {
    Service::new(
        "Sib http service handler".to_string(),
        H2Handler { handler },
    )
}

pub struct H2Handler {
    handler: Option<HandlerFn>,
}

#[async_trait]
impl HttpServerApp for H2Handler {
    async fn process_new_http(
        self: &Arc<Self>,
        p_session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        if let Some(p_handler) = &self.handler {
            match Session::new_h2(p_session).await {
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
