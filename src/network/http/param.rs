// use crate::s_trace;
// use memchr::memchr;
// use std::collections::HashMap;

// #[derive(Debug, Clone)]
// pub struct Param {
//     method: String,
//     path: String,
//     host: String,
//     query: String,
//     query_params: Option<HashMap<String, String>>,
// }

// impl Param {
//     pub fn new(method: String, path: String, host: String) -> Self {
//         Self {
//             method,
//             path,
//             host,
//             query: "".to_owned(),
//             query_params: None,
//         }
//     }

//     pub fn parse(p_request: &str) -> anyhow::Result<Self> {
//         let mut parts = p_request.splitn(2, ", ");

//         let request_line = parts
//             .next()
//             .ok_or_else(|| s_trace!("Missing request line"))?;
//         let host = parts
//             .next()
//             .ok_or_else(|| s_trace!("Missing host part"))?
//             .strip_prefix("Host: ")
//             .ok_or_else(|| s_trace!("Invalid host part"))?;

//         // Extract method and path/query
//         let (method, path_query) = request_line
//             .split_once(' ')
//             .ok_or_else(|| s_trace!("Invalid method and path/query part"))?;

//         // Extract path and query parameters
//         let (path, query) = match memchr(b'?', path_query.as_bytes()) {
//             Some(pos) => (&path_query[..pos], &path_query[pos + 1..]),
//             None => (path_query, ""),
//         };

//         Ok(Self {
//             method: method.to_string(),
//             path: path.to_string(),
//             host: host.to_string(),
//             query: query.to_string(),
//             query_params: None,
//         })
//     }

//     pub fn method(&self) -> &str {
//         &self.method
//     }

//     pub fn path(&self) -> &str {
//         &self.path
//     }

//     pub fn host(&self) -> &str {
//         &self.host
//     }

//     pub fn query(&self) -> &str {
//         &self.query
//     }

//     pub fn query_params(&mut self) -> &Option<HashMap<String, String>> {
//         if self.query_params.is_none() {
//             let params: HashMap<String, String> = self
//                 .query
//                 .split('&')
//                 .filter_map(|pair| {
//                     let mut kv = pair.splitn(2, '=');
//                     Some((kv.next()?.to_string(), kv.next()?.to_string()))
//                 })
//                 .collect();
//             self.query_params = Some(params);
//         }
//         &self.query_params
//     }
// }
