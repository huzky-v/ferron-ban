use std::fmt;

/// Errors returned by startup validation, offline database tooling, and the
/// pure request-domain components.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid limits: {0}")]
    InvalidLimits(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid definition {id}: {message}")]
    InvalidDefinition { id: i64, message: String },
    #[error("invalid allowlist entry {id}: {message}")]
    InvalidAllowlist { id: i64, message: String },
    #[error("invalid database schema: {0}")]
    InvalidSchema(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database file error: {0}")]
    DatabaseFile(#[from] std::io::Error),
    #[error("regular expression error: {0}")]
    Regex(#[from] regex::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("audit record exceeds configured limit")]
    AuditRecordTooLarge,
}

impl CoreError {
    pub(crate) fn definition(id: i64, message: impl Into<String>) -> Self {
        Self::InvalidDefinition {
            id,
            message: message.into(),
        }
    }

    pub(crate) fn allowlist(id: i64, message: impl Into<String>) -> Self {
        Self::InvalidAllowlist {
            id,
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

/// Keep error construction useful to callers without exposing implementation
/// details from the individual modules.
impl From<fmt::Error> for CoreError {
    fn from(_: fmt::Error) -> Self {
        Self::InvalidRequest("formatting failed".to_owned())
    }
}
