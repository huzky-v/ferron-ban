use crate::config::Limits;
use crate::error::{CoreError, Result};
use crate::model::{
    BoundedValue, RequestInput, RequestView, is_header_name_byte, is_sensitive_name,
    normalize_header_name,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    pub raw_path: BoundedValue,
    pub path: BoundedValue,
    pub query_for_match: BoundedValue,
    pub query_for_audit: BoundedValue,
}

/// Split, decode once, and normalize an HTTP target. The matching query and
/// audit query are intentionally separate so audit redaction never changes a
/// definition's matching semantics.
pub fn normalize_target(target: &str, limits: &Limits) -> Result<NormalizedTarget> {
    validate_limits(limits)?;
    if target.len() > limits.max_request_field_length {
        return Err(CoreError::InvalidRequest(
            "target exceeds raw request limit".to_owned(),
        ));
    }
    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let raw_path = if raw_path.is_empty() { "/" } else { raw_path };
    let decoded_path = percent_decode(raw_path)?;
    let path = normalize_path(&decoded_path)?;
    let query_for_match = bounded_text(
        &percent_decode(raw_query)?,
        limits.max_request_field_length,
        "query",
    )?;
    let query_for_audit = redact_query(&query_for_match, limits.max_request_field_length);

    Ok(NormalizedTarget {
        raw_path: bounded_text(raw_path, limits.max_request_field_length, "raw path")?,
        path: bounded_text(&path, limits.max_request_field_length, "path")?,
        query_for_match,
        query_for_audit,
    })
}

pub fn normalize_request(input: RequestInput, limits: &Limits) -> Result<RequestView> {
    let target = normalize_target(&input.target, limits)?;
    if input.headers.len() > limits.max_request_headers {
        return Err(CoreError::InvalidRequest(
            "raw header count exceeds configured limit".to_owned(),
        ));
    }
    let method = bounded_text(&input.method, limits.max_request_field_length, "method")?;
    let host = bounded_text(&input.host, limits.max_request_field_length, "host")?;
    let user_agent = bounded_text(
        &input.user_agent,
        limits.max_request_field_length,
        "user-agent",
    )?;
    let mut headers: BTreeMap<String, Vec<BoundedValue>> = BTreeMap::new();
    for (name, value) in input.headers {
        if name.len() > limits.max_header_name_length {
            return Err(CoreError::InvalidRequest(
                "header name exceeds configured limit".to_owned(),
            ));
        }
        let name = normalize_header_name(&name);
        if name.is_empty() || !name.is_ascii() || !name.bytes().all(is_header_name_byte) {
            return Err(CoreError::InvalidRequest(
                "header name must be a valid non-empty ASCII token".to_owned(),
            ));
        }
        let value = bounded_text(&value, limits.max_header_value_length, "header value")?;
        let values = headers.entry(name).or_default();
        if values.len() >= limits.max_header_value_count {
            return Err(CoreError::InvalidRequest(
                "duplicate header value count exceeds configured limit".to_owned(),
            ));
        }
        values.push(value);
    }

    let body_sha256 = input
        .body_sha256
        .map(|digest| {
            if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(digest.to_ascii_lowercase())
            } else {
                Err(CoreError::InvalidRequest(
                    "body_sha256 must be a 64-character hexadecimal digest".to_owned(),
                ))
            }
        })
        .transpose()?;

    Ok(RequestView {
        client_ip: input.client_ip,
        proxy_ip: input.proxy_ip,
        method,
        host,
        raw_path: target.raw_path,
        path: target.path,
        query_for_match: target.query_for_match,
        query_for_audit: target.query_for_audit,
        user_agent,
        headers,
        request_bytes: input.request_bytes,
        body_sha256,
    })
}

fn validate_limits(limits: &Limits) -> Result<()> {
    limits
        .validate()
        .map_err(|error| CoreError::InvalidRequest(error.to_string()))
}

fn normalize_path(path: &str) -> Result<String> {
    if !path.starts_with('/') {
        return Err(CoreError::InvalidRequest(
            "request path must start with '/'".to_owned(),
        ));
    }
    if path
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(CoreError::InvalidRequest(
            "request path contains a control character".to_owned(),
        ));
    }

    let trailing_slash = path.ends_with('/');
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    let mut normalized = String::from("/");
    normalized.push_str(&segments.join("/"));
    if trailing_slash && normalized != "/" {
        normalized.push('/');
    }
    Ok(normalized)
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(CoreError::InvalidRequest(
                    "malformed percent escape".to_owned(),
                ));
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| CoreError::InvalidRequest("percent-decoded value is not UTF-8".to_owned()))
}

fn hex_value(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(CoreError::InvalidRequest(
            "malformed percent escape".to_owned(),
        )),
    }
}

fn bounded_text(value: &str, max: usize, field: &str) -> Result<BoundedValue> {
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(CoreError::InvalidRequest(format!(
            "{field} contains a control character"
        )));
    }
    if value.len() <= max {
        return Ok(BoundedValue::new(value, true));
    }
    Ok(BoundedValue::new(truncate_utf8(value, max), false))
}

fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn redact_query(query: &BoundedValue, max: usize) -> BoundedValue {
    let mut output = String::new();
    for (index, component) in query.value.split('&').enumerate() {
        if index != 0 {
            output.push('&');
        }
        let (key, value) = component.split_once('=').unwrap_or((component, ""));
        output.push_str(key);
        if component.contains('=') {
            output.push('=');
            if is_sensitive_name(key) {
                output.push_str("<redacted>");
            } else {
                output.push_str(value);
            }
        }
        if output.len() >= max {
            break;
        }
    }
    BoundedValue::new(
        truncate_utf8(&output, max),
        query.complete && output.len() <= max,
    )
}

/// Construct a bounded, deliberately incomplete request view for auditing a
/// malformed request from an already banned client. It performs no decoding,
/// matching, or I/O and therefore cannot turn malformed input into a rule hit.
pub(crate) fn degraded_request_view(input: &RequestInput, limits: &Limits) -> RequestView {
    let (raw_path, raw_query) = input.target.split_once('?').unwrap_or((&input.target, ""));
    let raw_path = if raw_path.is_empty() { "/" } else { raw_path };
    let query = BoundedValue::new(
        truncate_utf8(raw_query, limits.max_request_field_length),
        false,
    );
    let mut headers = BTreeMap::new();
    for (name, value) in input.headers.iter().take(limits.max_request_headers) {
        let name = normalize_header_name(name);
        let name = if name.is_empty() {
            "invalid-header".to_owned()
        } else {
            truncate_utf8(&name, limits.max_header_name_length)
        };
        headers
            .entry(name)
            .or_insert_with(Vec::new)
            .push(BoundedValue::new(
                truncate_utf8(value, limits.max_header_value_length),
                false,
            ));
    }
    RequestView {
        client_ip: input.client_ip,
        proxy_ip: input.proxy_ip,
        method: BoundedValue::new(
            truncate_utf8(&input.method, limits.max_request_field_length),
            false,
        ),
        host: BoundedValue::new(
            truncate_utf8(&input.host, limits.max_request_field_length),
            false,
        ),
        raw_path: BoundedValue::new(
            truncate_utf8(raw_path, limits.max_request_field_length),
            false,
        ),
        path: BoundedValue::new(
            truncate_utf8(raw_path, limits.max_request_field_length),
            false,
        ),
        query_for_match: BoundedValue::new(String::new(), false),
        query_for_audit: redact_untrusted_query(&query, limits.max_request_field_length),
        user_agent: BoundedValue::new(
            truncate_utf8(&input.user_agent, limits.max_request_field_length),
            false,
        ),
        headers,
        request_bytes: input.request_bytes,
        body_sha256: None,
    }
}

fn redact_untrusted_query(query: &BoundedValue, max: usize) -> BoundedValue {
    let mut output = String::new();
    for (index, component) in query.value.split('&').enumerate() {
        if index != 0 {
            output.push('&');
        }
        if component.contains('=') {
            output.push_str("<redacted>=<redacted>");
        } else {
            output.push_str("<redacted>");
        }
        if output.len() >= max {
            break;
        }
    }
    BoundedValue::new(truncate_utf8(&output, max), false)
}
