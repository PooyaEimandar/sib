use async_trait::async_trait;
use pingora::apps::HttpServerApp;
use pingora::http::ResponseHeader;
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::param::Param;

pub type HandlerFn = Arc<
    dyn Fn(
            Param,
            Vec<(String, String)>,
            Option<bytes::Bytes>,
            bool,
        ) -> Pin<
            Box<
                dyn Future<Output = (http::StatusCode, Vec<(String, String)>, bytes::Bytes)> + Send,
            >,
        > + Send
        + Sync,
>;

pub fn service(handler: Option<HandlerFn>) -> Service<H2Handler> {
    Service::new(
        "Sib HTTP Service handler".to_string(),
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
        mut p_session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let req_summary = p_session.request_summary();
        let param = super::param::Param::parse(&req_summary).ok()?;

        // Convert headers to Vec<String, String>
        let parsed_headers: Vec<(String, String)> = p_session
            .req_header()
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let read_timeout = Duration::from_secs(2);
        let body = match pingora_timeout::timeout(read_timeout, p_session.read_request_body()).await
        {
            Ok(Ok(b)) => b,
            _ => {
                eprintln!("Error reading request body or timeout occurred.");
                return None;
            }
        };

        // Call the shared handler
        let (status_code, response_headers, response_body) = if let Some(p_handler) = &self.handler
        {
            p_handler(param, parsed_headers, body, false).await
        } else {
            (
                http::StatusCode::OK,
                Vec::<(String, String)>::new(),
                bytes::Bytes::new(),
            )
        };

        // Build HTTP/2 response headers
        let mut response = ResponseHeader::build_no_case(status_code, None).ok()?;
        for (key, value) in response_headers {
            response.append_header(key, value).ok()?;
        }

        // Send response headers
        p_session
            .write_response_header(Box::new(response))
            .await
            .ok()?;

        // Send response body
        p_session
            .write_response_body(response_body.clone(), false)
            .await
            .ok()?;

        p_session.finish().await.ok()?;

        None
    }
}
