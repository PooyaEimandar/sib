use bytes::Bytes;
use futures::SinkExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use pingora::{http::ResponseHeader, protocols::http::ServerSession};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio_quiche::{
    buf_factory::BufFactory,
    http3::{
        H3AuditStats,
        driver::{InboundFrameStream, OutboundFrame, OutboundFrameSender},
    },
    quiche::h3::{self, NameValue},
};

pub struct H3Session {
    _stream_id: u64,
    headers: HeaderMap,
    in_frame: InboundFrameStream,
    out_frame: OutboundFrameSender,
    read_fin: bool,
    _h3_audit_stats: Arc<H3AuditStats>,
}

pub struct Session {
    method: String,
    path: String,
    host: String,
    res_headers: Option<http::HeaderMap>,
    h2: Option<ServerSession>,
    h3: Option<H3Session>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            method: "".to_owned(),
            path: "".to_owned(),
            host: "".to_owned(),
            res_headers: None,
            h2: None,
            h3: None,
        }
    }
}

impl Session {
    pub(crate) fn new_h2(session: ServerSession) -> Self {
        let req_summary = session.request_summary();
        let mut parts = req_summary.split(", ");
        // Extract Method and Path (first part)
        let mut first_part = parts.next().unwrap_or("").split_whitespace();
        let method = first_part.next().unwrap_or("");
        let path = first_part.next().unwrap_or("");

        // Extract Host header (second part)
        let host = parts
            .find(|s| s.starts_with("Host: "))
            .map(|s| s.trim_start_matches("Host: ").trim())
            .unwrap_or("");

        Self {
            method: method.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            h2: Some(session),
            ..Default::default()
        }
    }

    pub(crate) fn new_h3(
        stream_id: u64,
        headers: Vec<h3::Header>,
        send: OutboundFrameSender,
        recv: InboundFrameStream,
        read_fin: bool,
        h3_audit_stats: Arc<H3AuditStats>,
    ) -> Self {
        let mut method: String = "".to_owned();
        let mut path: String = "".to_owned();
        let mut host: String = "".to_owned();
        let mut http_headers = HeaderMap::new();

        for header in headers {
            // Extract pseudo-headers
            match header.name() {
                b":method" => method = String::from_utf8_lossy(header.value()).to_string(),
                b":path" => path = String::from_utf8_lossy(header.value()).to_string(),
                b"host" => host = String::from_utf8_lossy(header.value()).to_string(),
                b":authority" if host.is_empty() => {
                    host = String::from_utf8_lossy(header.value()).to_string();
                }
                _ => {
                    // Parse header name safely
                    let name = match HeaderName::from_bytes(header.name()) {
                        Ok(n) => n,
                        Err(_) => {
                            eprintln!("Invalid header name: {:?}", header.name());
                            continue; // Skip invalid headers
                        }
                    };

                    // Parse header value safely
                    let value = match HeaderValue::from_bytes(header.value()) {
                        Ok(v) => v,
                        Err(_) => {
                            eprintln!("Invalid header value for {:?}: {:?}", name, header.value());
                            continue; // Skip invalid headers
                        }
                    };

                    http_headers.insert(name, value.clone());
                }
            }
        }

        Self {
            method,
            path,
            host,
            h3: Some(H3Session {
                _stream_id: stream_id,
                headers: http_headers,
                in_frame: recv,
                out_frame: send,
                read_fin,
                _h3_audit_stats: h3_audit_stats,
            }),
            ..Default::default()
        }
    }

    pub fn get_method(&self) -> &str {
        self.method.as_str()
    }

    pub fn get_path(&self) -> &str {
        self.path.as_str()
    }

    pub fn get_host(&self) -> &str {
        self.host.as_str()
    }

    pub fn get_is_h3(&self) -> bool {
        self.h3.is_some()
    }

    pub fn get_req_header(&self, key: http::HeaderName) -> Option<&http::HeaderValue> {
        if let Some(h2) = &self.h2 {
            return h2.get_header(key);
        } else if let Some(h3) = &self.h3 {
            return h3.headers.get(&key);
        }
        None
    }

    pub fn get_req_headers(&self) -> Option<&http::HeaderMap> {
        if let Some(h2) = &self.h2 {
            return Some(&h2.req_header().headers);
        } else if let Some(h3) = &self.h3 {
            return Some(&h3.headers);
        }
        None
    }

    pub async fn get_req_body(&mut self, timeout: Duration) -> anyhow::Result<Option<Bytes>> {
        if let Some(h2) = &mut self.h2 {
            let body = match pingora_timeout::timeout(timeout, h2.read_request_body()).await {
                Ok(Ok(b)) => b,
                _ => {
                    anyhow::bail!("Got timeout while reading h2 request body");
                }
            };
            return Ok(body);
        } else if let Some(h3) = &mut self.h3 {
            // Properly read the h3 body in a non-blocking manner
            if !h3.read_fin {
                let body = match pingora_timeout::timeout(timeout, async move {
                    let mut body = bytes::BytesMut::new();
                    while let Some(chunk) = h3.in_frame.recv().await {
                        match chunk {
                            tokio_quiche::http3::driver::InboundFrame::Body(data, fin) => {
                                body.extend_from_slice(&data);
                                if fin {
                                    break; // End of stream
                                }
                            }
                            _ => break, // Stop on unexpected frame
                        }
                    }
                    body.freeze()
                })
                .await
                {
                    Ok(body) => body,
                    _ => {
                        anyhow::bail!("Got timeout while reading h3 request body");
                    }
                };

                return Ok(Some(body));
            }
        }
        Ok(None)
    }

    pub fn append_header(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        if self.res_headers.is_none() {
            self.res_headers = Some(http::HeaderMap::new());
        }
        if let Some(headers) = &mut self.res_headers {
            let header_name = HeaderName::from_str(key)?;
            let header_value = HeaderValue::from_str(value)?;
            headers.append(header_name, header_value);
        }
        Ok(())
    }

    pub fn append_headers(&mut self, items: &[(&str, &str)]) -> anyhow::Result<()> {
        if self.res_headers.is_none() {
            self.res_headers = Some(http::HeaderMap::new());
        }
        if let Some(headers) = &mut self.res_headers {
            for (key, value) in items {
                let header_name = HeaderName::from_str(key)?;
                let header_value = HeaderValue::from_str(value)?;
                headers.append(header_name, header_value);
            }
        }
        Ok(())
    }

    pub async fn send_status_eom(&mut self, status_code: http::StatusCode) -> anyhow::Result<()> {
        self.send_status(status_code).await?;
        self.send_eom().await
    }

    pub async fn send_status(&mut self, status_code: http::StatusCode) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            // Build HTTP/2 response headers
            let mut response = match ResponseHeader::build_no_case(status_code, None) {
                Ok(res) => res,
                Err(_) => anyhow::bail!("Failed to build response header"),
            };

            if let Some(h2_headers) = &self.res_headers {
                for (key, value) in h2_headers {
                    if response.append_header(key, value).is_err() {
                        anyhow::bail!("Failed to append header");
                    }
                }
            }

            // Send response headers
            if h2.write_response_header(Box::new(response)).await.is_err() {
                anyhow::bail!("Failed to send response headers");
            }
        } else if let Some(h3) = &mut self.h3 {
            let mut res_headers = Vec::<tokio_quiche::quiche::h3::Header>::new();
            res_headers.push(tokio_quiche::quiche::h3::Header::new(
                ":status".as_bytes(),
                status_code.as_str().as_bytes(),
            ));

            if let Some(h3_headers) = &self.res_headers {
                res_headers.extend(h3_headers.iter().filter_map(|(k, v)| {
                    v.to_str().ok().map(|v_str| {
                        tokio_quiche::quiche::h3::Header::new(
                            k.as_str().as_bytes(),
                            v_str.as_bytes(),
                        )
                    })
                }));
            }

            h3.out_frame
                .send(OutboundFrame::Headers(res_headers))
                .await?;
        }
        Ok(())
    }

    pub async fn send_body(&mut self, body: bytes::Bytes, finish: bool) -> anyhow::Result<()> {
        if let Some(h2) = &mut self.h2 {
            h2.write_response_body(body, false).await?;
        } else if let Some(h3) = &mut self.h3 {
            if let Err(e) = h3
                .out_frame
                .send(OutboundFrame::body(
                    BufFactory::buf_from_slice(&body),
                    finish,
                ))
                .await
            {
                anyhow::bail!("Failed to send response body: {:?}", e);
            }
        }
        Ok(())
    }

    pub async fn send_eom(&mut self) -> anyhow::Result<()> {
        if let Some(h2) = self.h2.take() {
            h2.finish().await.ok();
        } else if let Some(h3) = &mut self.h3 {
            h3.out_frame.close();
        }
        Ok(())
    }
}
