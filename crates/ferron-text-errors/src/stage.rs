//! Plain-text error response pipeline stage.
//!
//! Generates a one-line `"<status> <reason>"` body (e.g. `404 Not Found`)
//! for HTTP 4xx/5xx error responses instead of the built-in HTML error
//! page.

use async_trait::async_trait;
use bytes::Bytes;
use ferron_core::pipeline::{PipelineError, Stage};
use ferron_core::registry::StageConstraint;
use ferron_http::HttpErrorContext;
use http::StatusCode;
use http::{HeaderValue, Response, header};
use http_body_util::{BodyExt, Full};

/// Reason phrase for an arbitrary status code, matching the built-in HTML
/// error pages (`Unknown` when the code has no canonical reason).
pub fn status_reason(status: u16) -> &'static str {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("Unknown")
}

/// Build the response body for an error status code.
fn body_for(status: u16) -> Bytes {
    Bytes::from(format!("{status} {}\n", status_reason(status)))
}

/// Pipeline stage that generates plain-text error responses.
pub struct TextErrorStage;

impl Default for TextErrorStage {
    #[inline]
    fn default() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl Stage<HttpErrorContext> for TextErrorStage {
    #[inline]
    fn name(&self) -> &str {
        "text_error"
    }

    #[inline]
    fn constraints(&self) -> Vec<StageConstraint> {
        vec![
            // Keep the built-in JSON error module (when compiled in) in
            // charge, and beat the file-based `error_page` stage.
            StageConstraint::Before("error_page".to_string()),
        ]
    }

    #[inline]
    fn is_applicable(
        &self,
        config: Option<&ferron_core::config::ServerConfigurationBlock>,
    ) -> bool {
        let Some(config) = config else {
            return false;
        };
        config.has_directive("text_errors")
    }

    async fn run(&self, ctx: &mut HttpErrorContext) -> Result<bool, PipelineError> {
        // Never override an already-rendered response.
        if ctx.res.is_some() {
            return Ok(true);
        }

        if !ctx.configuration.get_flag("text_errors", true) {
            return Ok(true);
        }

        let status = ctx.error_code;
        let bytes = body_for(status);

        let mut builder = Response::builder()
            .status(status)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )
            .header(header::CONTENT_LENGTH, bytes.len());

        if let Some(ref headers) = ctx.headers {
            for (name, value) in headers.iter() {
                builder = builder.header(name.clone(), value.clone());
            }
        }

        let response = builder
            .body(Full::new(bytes).map_err(|e| match e {}).boxed_unsync())
            .map_err(|e| PipelineError::custom(e.to_string()))?;

        ctx.res = Some(response);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::layer::LayeredConfiguration;
    use ferron_core::config::{
        ServerConfigurationBlock, ServerConfigurationDirectiveEntry, ServerConfigurationValue,
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;

    fn layered_flag(enabled: Option<bool>) -> LayeredConfiguration {
        let mut directives = rustc_hash::FxHashMap::default();
        let args = match enabled {
            Some(value) => vec![ServerConfigurationValue::Boolean(value, None)],
            None => vec![],
        };
        directives.insert(
            "text_errors".to_owned(),
            vec![ServerConfigurationDirectiveEntry {
                args,
                children: None,
                span: None,
            }],
        );
        let mut config = LayeredConfiguration::new();
        config.add_layer(Arc::new(ServerConfigurationBlock {
            directives: Arc::new(directives),
            matchers: rustc_hash::FxHashMap::default(),
            span: None,
        }));
        config
    }

    async fn rendered_body(mut ctx: HttpErrorContext) -> Vec<u8> {
        TextErrorStage
            .run(&mut ctx)
            .await
            .expect("text error stage should not fail");
        let response = ctx.res.take().expect("response should be set");
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn context(code: u16, enabled: Option<bool>) -> HttpErrorContext {
        let mut ctx = HttpErrorContext::default();
        ctx.error_code = code;
        ctx.configuration = layered_flag(enabled);
        ctx
    }

    #[tokio::test]
    async fn emits_status_line_for_common_codes() {
        for (code, expected) in [
            (400u16, "400 Bad Request\n"),
            (403, "403 Forbidden\n"),
            (404, "404 Not Found\n"),
            (429, "429 Too Many Requests\n"),
            (500, "500 Internal Server Error\n"),
            (503, "503 Service Unavailable\n"),
        ] {
            assert_eq!(
                rendered_body(context(code, None)).await,
                expected.as_bytes(),
                "code {code}"
            );
        }
    }

    #[tokio::test]
    async fn honors_disabled_flag() {
        let mut ctx = context(404, Some(false));
        TextErrorStage
            .run(&mut ctx)
            .await
            .expect("text error stage should not fail");
        assert!(ctx.res.is_none());
    }

    #[tokio::test]
    async fn keeps_existing_response() {
        let mut ctx = context(404, None);
        ctx.res = Some(
            Response::builder()
                .status(404)
                .body(
                    Full::new(Bytes::new())
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap(),
        );
        TextErrorStage
            .run(&mut ctx)
            .await
            .expect("text error stage should not fail");
        assert_eq!(ctx.res.as_ref().unwrap().status().as_u16(), 404);
    }

    #[tokio::test]
    async fn preserves_extra_headers() {
        let mut ctx = context(429, None);
        ctx.headers = Some({
            let mut headers = http::HeaderMap::new();
            headers.insert("retry-after", HeaderValue::from_static("42"));
            headers
        });
        TextErrorStage
            .run(&mut ctx)
            .await
            .expect("text error stage should not fail");
        let response = ctx.res.take().expect("response should be set");
        assert_eq!(response.headers().get("retry-after").unwrap(), "42");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH).unwrap(),
            "22"
        );
    }

    #[test]
    fn unknown_status_falls_back() {
        assert_eq!(status_reason(599), "Unknown");
        assert_eq!(status_reason(999), "Unknown");
    }
}
