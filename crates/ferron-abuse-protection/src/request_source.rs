use crate::cloudflare::proxy_ip;
use abuse_core::{Limits, RequestInput};
use ferron_http::HttpContext;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTranslationError {
    MissingRequest,
    MissingClientIp,
    LimitExceeded,
    InvalidHeaderBytes,
}

pub fn request_input(
    context: &HttpContext,
    limits: &Limits,
) -> Result<RequestInput, RequestTranslationError> {
    let client_ip = context
        .remote_address
        .map(|address| address.ip().to_canonical())
        .ok_or(RequestTranslationError::MissingClientIp)?;
    let request = context
        .req
        .as_ref()
        .ok_or(RequestTranslationError::MissingRequest)?;
    let uri = context
        .original_uri
        .as_ref()
        .ok_or(RequestTranslationError::MissingRequest)?;
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| uri.path());
    let target = bounded_owned(target, limits.max_request_field_length)?;

    let method = bounded_owned(request.method().as_str(), limits.max_request_field_length)?;
    let host = if let Some(value) = request.headers().get("host") {
        bounded_header_text(value, limits.max_request_field_length)?
    } else if let Some(hostname) = context.hostname.as_deref() {
        bounded_owned(hostname, limits.max_request_field_length)?
    } else {
        String::new()
    };
    let user_agent = request
        .headers()
        .get("user-agent")
        .map(|value| bounded_header_text(value, limits.max_request_field_length))
        .transpose()?
        .unwrap_or_default();
    if request.headers().len() > limits.max_request_headers {
        return Err(RequestTranslationError::LimitExceeded);
    }
    let mut duplicate_counts = HashMap::<String, usize>::new();
    let mut headers = Vec::with_capacity(request.headers().len());
    for (name, value) in request.headers() {
        if name.as_str().len() > limits.max_header_name_length {
            return Err(RequestTranslationError::LimitExceeded);
        }
        let value = bounded_header_text(value, limits.max_header_value_length)?;
        let name = name.as_str().to_owned();
        let count = duplicate_counts.entry(name.clone()).or_default();
        *count += 1;
        if *count > limits.max_header_value_count {
            return Err(RequestTranslationError::LimitExceeded);
        }
        headers.push((name, value));
    }
    let request_bytes = request
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(RequestInput {
        client_ip,
        proxy_ip: proxy_ip(context),
        method,
        host,
        target,
        user_agent,
        headers,
        request_bytes,
        body_sha256: None,
    })
}

pub fn malformed_input(client_ip: IpAddr) -> RequestInput {
    RequestInput {
        client_ip,
        proxy_ip: None,
        method: "GET".to_owned(),
        host: String::new(),
        target: "/".to_owned(),
        user_agent: String::new(),
        headers: Vec::new(),
        request_bytes: 0,
        body_sha256: None,
    }
}

fn bounded_header_text(
    value: &http::HeaderValue,
    max: usize,
) -> Result<String, RequestTranslationError> {
    let value = value
        .to_str()
        .map_err(|_| RequestTranslationError::InvalidHeaderBytes)?;
    bounded_owned(value, max)
}

fn bounded_owned(value: &str, max: usize) -> Result<String, RequestTranslationError> {
    if value.len() > max {
        return Err(RequestTranslationError::LimitExceeded);
    }
    Ok(value.to_owned())
}
