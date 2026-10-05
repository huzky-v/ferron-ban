use crate::config::Limits;
use crate::error::{CoreError, Result};
use crate::model::{
    AttackType, BoundedValue, Definition, DefinitionField, DefinitionMatcher, IpCidr, RequestView,
};
use crate::schema::{read_database, readonly_connection};
use regex::Regex;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CompiledDefinition {
    definition: Definition,
    regex: Option<Regex>,
    header_name: Option<String>,
}

impl CompiledDefinition {
    pub fn definition(&self) -> &Definition {
        &self.definition
    }

    pub fn id(&self) -> i64 {
        self.definition.id
    }

    pub fn name(&self) -> &str {
        &self.definition.name
    }
}

#[derive(Debug, Clone)]
struct SnapshotInner {
    snapshot_version: u64,
    definitions: Vec<CompiledDefinition>,
    allowlist: Vec<IpCidr>,
    limits: Limits,
}

/// Immutable, startup-built matcher state. There is no SQLite or filesystem
/// reference in this value, so it is safe to share on a request path.
#[derive(Debug, Clone)]
pub struct DefinitionSnapshot {
    inner: Arc<SnapshotInner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub snapshot_version: u64,
    pub definition_count: usize,
    pub allowlist_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub matched_definition_ids: Vec<i64>,
    pub matched_attack_types: Vec<AttackType>,
    pub truncated: bool,
    pub selected_id_leak_name: Option<String>,
    /// A harmless request marker. It never triggers a ban or matched log.
    pub no_log: bool,
}

impl MatchResult {
    pub fn is_match(&self) -> bool {
        !self.matched_attack_types.is_empty()
    }

    pub fn has_id_leak(&self) -> bool {
        self.selected_id_leak_name.is_some()
    }
}

impl DefinitionSnapshot {
    pub fn load(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        SnapshotLoader::new(limits)?.load(path.as_ref())
    }

    pub(crate) fn from_connection(connection: &Connection, limits: Limits) -> Result<Self> {
        limits
            .validate()
            .map_err(|error| CoreError::InvalidConfiguration(error.to_string()))?;
        let loaded = read_database(connection, &limits)?;
        let mut definitions = Vec::new();
        let mut compiled_regex_budget = 0usize;
        for definition in loaded.definitions {
            if !definition.enabled {
                continue;
            }
            let regex = if definition.matcher == DefinitionMatcher::Regex {
                // Reserve the full configured automata/program ceilings for
                // every compiled regex. This is intentionally conservative:
                // many short patterns must not bypass the memory budget.
                let reserve = limits
                    .max_regex_program_bytes
                    .saturating_add(limits.max_regex_dfa_bytes);
                compiled_regex_budget =
                    compiled_regex_budget.checked_add(reserve).ok_or_else(|| {
                        CoreError::InvalidSchema("compiled regex budget overflow".to_owned())
                    })?;
                if compiled_regex_budget > limits.max_compiled_regex_bytes_total {
                    return Err(CoreError::InvalidSchema(
                        "cumulative compiled regex budget exceeded".to_owned(),
                    ));
                }
                Some(compile_regex(
                    &definition.pattern,
                    definition.case_sensitive,
                    &limits,
                )?)
            } else {
                None
            };
            let header_name = definition.normalized_header_name();
            definitions.push(CompiledDefinition {
                definition,
                regex,
                header_name,
            });
        }
        Ok(Self {
            inner: Arc::new(SnapshotInner {
                snapshot_version: loaded.snapshot_version,
                definitions,
                allowlist: loaded.allowlist,
                limits,
            }),
        })
    }

    pub fn summary(&self) -> SnapshotSummary {
        SnapshotSummary {
            snapshot_version: self.inner.snapshot_version,
            definition_count: self.inner.definitions.len(),
            allowlist_count: self.inner.allowlist.len(),
        }
    }

    pub fn snapshot_version(&self) -> u64 {
        self.inner.snapshot_version
    }

    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    pub fn definitions(&self) -> &[CompiledDefinition] {
        &self.inner.definitions
    }

    pub fn is_allowlisted(&self, ip: std::net::IpAddr) -> bool {
        self.inner
            .allowlist
            .iter()
            .any(|network| network.contains(ip))
    }

    pub fn match_request(&self, request: &RequestView) -> MatchResult {
        self.match_request_for_site(request, false)
    }

    pub fn match_request_for_site(
        &self,
        request: &RequestView,
        wordpress_site: bool,
    ) -> MatchResult {
        let mut matched_definition_ids = Vec::with_capacity(self.inner.limits.max_matches);
        let mut matched_attack_types = Vec::new();
        let mut truncated = false;
        let mut selected_id_leak_name = None;
        let mut no_log = false;
        for definition in &self.inner.definitions {
            if wordpress_site && definition.definition.attack_type == AttackType::WpBan {
                continue;
            }
            if matches_definition(
                definition,
                request,
                self.inner.limits.max_request_field_length,
            ) {
                if definition.definition.attack_type == AttackType::NoLog {
                    no_log = true;
                    continue;
                }
                if definition.definition.attack_type.is_id_leak() && selected_id_leak_name.is_none()
                {
                    selected_id_leak_name = Some(definition.name().to_owned());
                }
                if matched_definition_ids.len() < self.inner.limits.max_matches {
                    matched_definition_ids.push(definition.id());
                } else {
                    truncated = true;
                }
                if !matched_attack_types.contains(&definition.definition.attack_type) {
                    matched_attack_types.push(definition.definition.attack_type);
                }
            }
        }
        MatchResult {
            matched_definition_ids,
            matched_attack_types,
            truncated,
            selected_id_leak_name,
            no_log,
        }
    }
}

/// Startup-only loader. A loader owns no mutable snapshot state and performs
/// one read-only SQLite load per invocation.
#[derive(Debug, Clone)]
pub struct SnapshotLoader {
    limits: Limits,
}

impl SnapshotLoader {
    pub fn new(limits: Limits) -> Result<Self> {
        limits
            .validate()
            .map_err(|error| CoreError::InvalidConfiguration(error.to_string()))?;
        Ok(Self { limits })
    }

    pub fn load(&self, path: &Path) -> Result<DefinitionSnapshot> {
        let connection = readonly_connection(path, &self.limits)?;
        DefinitionSnapshot::from_connection(&connection, self.limits.clone())
    }

    pub fn load_connection(&self, connection: &Connection) -> Result<DefinitionSnapshot> {
        DefinitionSnapshot::from_connection(connection, self.limits.clone())
    }
}

fn matches_definition(definition: &CompiledDefinition, request: &RequestView, max: usize) -> bool {
    let value = match definition.definition.field {
        DefinitionField::Path => &request.path,
        DefinitionField::UserAgent => &request.user_agent,
        DefinitionField::Header => {
            let Some(name) = definition.header_name.as_deref() else {
                return false;
            };
            let Some(value) = request.header(name) else {
                return false;
            };
            return value
                .iter()
                .any(|value| matches_value(definition, &bounded(value, max)));
        }
        DefinitionField::Method => &request.method,
        DefinitionField::Host => &request.host,
        DefinitionField::Query => &request.query_for_match,
    };
    matches_value(definition, &bounded(value, max))
}

fn matches_value(definition: &CompiledDefinition, value: &BoundedValue) -> bool {
    match definition.definition.matcher {
        DefinitionMatcher::Exact => {
            if !value.complete {
                return false;
            }
            if definition.definition.case_sensitive {
                value.value == definition.definition.pattern
            } else {
                value
                    .value
                    .eq_ignore_ascii_case(&definition.definition.pattern)
            }
        }
        DefinitionMatcher::Prefix => {
            if definition.definition.case_sensitive {
                value.value.starts_with(&definition.definition.pattern)
            } else {
                starts_with_ascii_case_insensitive(&value.value, &definition.definition.pattern)
            }
        }
        DefinitionMatcher::Regex => {
            value.complete
                && definition
                    .regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(&value.value))
        }
    }
}

fn bounded(value: &BoundedValue, max: usize) -> BoundedValue {
    if value.value.len() <= max {
        return value.clone();
    }
    let mut end = max;
    while !value.value.is_char_boundary(end) {
        end -= 1;
    }
    BoundedValue::new(&value.value[..end], false)
}

fn compile_regex(pattern: &str, case_sensitive: bool, limits: &Limits) -> Result<Regex> {
    Ok(regex::RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .unicode(false)
        .size_limit(limits.max_regex_program_bytes)
        .dfa_size_limit(limits.max_regex_dfa_bytes)
        .build()?)
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value.len() >= prefix.len()
        && value.as_bytes()[..prefix.len()]
            .iter()
            .zip(prefix.as_bytes())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}
