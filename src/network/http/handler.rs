use async_trait::async_trait;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::apps::HttpServerApp;
use pingora::http::ResponseHeader;
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use wasmer::Module;

pub static WASMS: Lazy<Arc<RwLock<HashMap<String, Module>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

pub fn service() -> Service<H2Handler> {
    Service::new("Sib HTTP Service handler".to_string(), H2Handler)
}

pub struct H2Handler;

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
        let (status_code, response_headers, response_body) =
            shared_handler(param, parsed_headers, body, false).await;

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

// fn host_function(n: i32) -> Result<i32, RuntimeError> {
//     println!("Host function called with: {}", n);
//     Ok(n * 2)
// }

pub async fn shared_handler(
    param: super::param::Param,
    headers: Vec<(String, String)>,
    body: Option<bytes::Bytes>,
    is_h3: bool,
) -> (StatusCode, Vec<(String, String)>, bytes::Bytes) {
    println!(
        "Received request: {:?}, Headers: {:?}, Body: {:?}",
        param, headers, body
    );

    let status = StatusCode::OK;

    let mut response_headers = Vec::new();
    if is_h3 {
        let status = StatusCode::OK;
        response_headers.push((":status".to_string(), status.as_str().to_owned()));
    }

    response_headers.append(&mut vec![
        ("Alt-Svc".to_string(), "h3=\":8443\"; ma=86400".to_string()),
        ("content-type".to_string(), "text/plain".to_string()),
    ]);

    let response_body = bytes::Bytes::from(format!(
        "Hello from Sib via {}",
        if is_h3 { "H3" } else { "H2" }
    ));

    // let key = format!("{} {}", h_param.method(), h_param.path());

    // let module_opt = {
    //     let wasms_lock = WASMS.read().ok()?;
    //     wasms_lock.get(&key).cloned()
    // };

    // let module = module_opt?;

    // // Prepare memory buffer before async call
    // let summary_bytes = req_summary.as_bytes().to_vec();
    // let headers_bytes: Vec<u8> = p_session
    //     .req_header()
    //     .headers
    //     .iter()
    //     .flat_map(|(name, value)| {
    //         let mut header_vec = Vec::new();
    //         header_vec.extend_from_slice(name.as_str().as_bytes());
    //         header_vec.extend_from_slice(b": ");
    //         header_vec.extend_from_slice(value.as_bytes());
    //         header_vec.push(b'\n');
    //         header_vec
    //     })
    //     .collect();

    // let body_bytes = body.to_vec();
    // let total_size = (summary_bytes.len() + headers_bytes.len() + body_bytes.len()) as i32;

    // // Offload the Wasm execution to a blocking thread
    // let result = task::spawn_blocking(move || {
    //     let mut store = Store::default();
    //     let import_object = imports! {
    //         "env" => {
    //             "host_function" => Function::new_typed(&mut store, host_function),
    //         }
    //     };

    //     let instance = Instance::new(&mut store, &module, &import_object).ok()?;

    //     let alloc_fn = instance
    //         .exports
    //         .get_typed_function::<i32, i32>(&store, "allocate")
    //         .ok()?;
    //     let ptr = alloc_fn.call(&mut store, total_size).ok()?;

    //     let memory = instance.exports.get_memory("memory").ok()?;
    //     let memory_view = memory.view(&store);

    //     let mut offset = ptr as u64;

    //     // Write into Wasm memory
    //     memory_view.write(offset, &summary_bytes).ok()?;
    //     offset += summary_bytes.len() as u64;

    //     memory_view.write(offset, &headers_bytes).ok()?;
    //     offset += headers_bytes.len() as u64;

    //     memory_view.write(offset, &body_bytes).ok()?;

    //     let wasm_entry = instance
    //         .exports
    //         .get_typed_function::<(i32, i32), i32>(&mut store, "wasm_entry")
    //         .ok()?;

    //     let result = wasm_entry.call(&mut store, ptr, total_size).unwrap_or(-1);

    //     if let Ok(free_fn) = instance
    //         .exports
    //         .get_typed_function::<(i32, i32), ()>(&mut store, "free")
    //     {
    //         free_fn.call(&mut store, ptr, total_size).ok()?;
    //     }

    //     Some(result)
    // })
    // .await
    // .unwrap_or(None);

    (status, response_headers, response_body)
}
