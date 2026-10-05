//! Ferron-independent foundation for the abuse-protection module.
//!
//! The crate deliberately contains no Ferron types and no request-path I/O.
//! SQLite loading and schema initialization are startup/offline operations; the
//! policy engine only operates on an immutable [`DefinitionSnapshot`].

mod audit;
mod ban;
mod config;
mod error;
mod honeypot;
mod ipban;
mod matcher;
mod metrics;
mod model;
mod normalize;
mod policy;
mod schema;
mod seed;
mod template;

pub use audit::{
    AuditEnqueueResult, AuditQueue, AuditRecord, AuditWriter, HeaderMap, REDACTED_VALUE,
    ResponseMode, rfc3339,
};
pub use ban::{
    BanEntry, BanError, BanInsertResult, BanRegistry, BanTrigger, Clock, ClockReading,
    DeterministicIncidentIdGenerator, IncidentIdGenerator, ManualClock, ProcessIncidentIdGenerator,
    SystemClock,
};
pub use config::{
    ConfigError, Fail2banPolicy, HARD_MAX_ALLOWLIST_ROWS, HARD_MAX_AUDIT_HEADERS,
    HARD_MAX_AUDIT_LINE_BYTES, HARD_MAX_AUDIT_QUEUE, HARD_MAX_AUDIT_RETENTION,
    HARD_MAX_AUDIT_VALUE_LENGTH, HARD_MAX_BAN_DURATION, HARD_MAX_BANS,
    HARD_MAX_COMPILED_REGEX_BYTES_TOTAL, HARD_MAX_DEFINITIONS, HARD_MAX_HEADER_NAME_LENGTH,
    HARD_MAX_HEADER_VALUE_COUNT, HARD_MAX_HEADER_VALUE_LENGTH, HARD_MAX_HONEYPOT_BODY_BYTES,
    HARD_MAX_MATCHES, HARD_MAX_METRIC_QUEUE, HARD_MAX_PATTERN_BYTES_TOTAL,
    HARD_MAX_REGEX_DFA_BYTES, HARD_MAX_REGEX_LENGTH, HARD_MAX_REGEX_PROGRAM_BYTES,
    HARD_MAX_REQUEST_FIELD_LENGTH, HARD_MAX_REQUEST_HEADERS, HARD_MAX_SQLITE_BYTES, Limits,
    ProtectionConfig, canonicalize_ban_extensions,
};
pub use error::{CoreError, Result};
pub use honeypot::HoneypotResponse;
pub use ipban::{IpBanSet, MAX_IPBAN_ENTRIES};
pub use matcher::{
    CompiledDefinition, DefinitionSnapshot, MatchResult, SnapshotLoader, SnapshotSummary,
};
pub use metrics::{
    MetricEvent, MetricEventReceiver, MetricEventSender, MetricSink, MetricSnapshot, Metrics,
};
pub use model::{
    AttackType, BoundedValue, Definition, DefinitionField, DefinitionMatcher, IpCidr, RequestInput,
    RequestView,
};
pub use normalize::{NormalizedTarget, normalize_request, normalize_target};
pub use policy::{PolicyAction, PolicyDecision, PolicyEngine};
pub use schema::{
    SCHEMA_VERSION, SNAPSHOT_VERSION_KEY, initialize_database, initialize_schema,
    validate_database_schema,
};
pub use seed::{DefinitionListing, list_definitions, seed_initial_definitions};
pub use template::TemplateCatalog;
