use crate::config::Limits;
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A bounded value retains whether the complete source value was available.
/// Exact and regex matchers must reject `complete == false`; prefix matchers
/// may safely use a known leading prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedValue {
    pub value: String,
    pub complete: bool,
}

impl BoundedValue {
    pub fn new(value: impl Into<String>, complete: bool) -> Self {
        Self {
            value: value.into(),
            complete,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn is_truncated(&self) -> bool {
        !self.complete
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    IdLeak,
    VulnerabilityProbe,
    CredentialAttack,
    Scanner,
    WpBan,
    NoLog,
    ResourceAbuse,
    Unknown,
}

impl AttackType {
    pub fn is_id_leak(self) -> bool {
        self == Self::IdLeak
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "id_leak" => Self::IdLeak,
            "vulnerability_probe" => Self::VulnerabilityProbe,
            "credential_attack" => Self::CredentialAttack,
            "scanner" => Self::Scanner,
            "wp_ban" => Self::WpBan,
            "no_log" => Self::NoLog,
            "resource_abuse" => Self::ResourceAbuse,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinitionField {
    Path,
    UserAgent,
    Header,
    Method,
    Host,
    Query,
}

impl DefinitionField {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "path" => Self::Path,
            "user_agent" => Self::UserAgent,
            "header" => Self::Header,
            "method" => Self::Method,
            "host" => Self::Host,
            "query" => Self::Query,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinitionMatcher {
    Exact,
    Prefix,
    Regex,
}

impl DefinitionMatcher {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "exact" => Self::Exact,
            "prefix" => Self::Prefix,
            "regex" => Self::Regex,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub field: DefinitionField,
    pub header_name: Option<String>,
    pub matcher: DefinitionMatcher,
    pub pattern: String,
    pub case_sensitive: bool,
    pub attack_type: AttackType,
    pub priority: i64,
    pub description: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Definition {
    pub fn validate(&self, limits: &Limits) -> Result<()> {
        let invalid = |message: &str| CoreError::definition(self.id, message);
        if self.id <= 0 {
            return Err(invalid("id must be positive"));
        }
        if self.name.trim().is_empty() || self.name.len() > limits.max_request_field_length {
            return Err(invalid("name must be non-empty and bounded"));
        }
        if self.pattern.is_empty() || self.pattern.len() > limits.max_request_field_length {
            return Err(invalid("pattern must be non-empty and bounded"));
        }
        if self.matcher == DefinitionMatcher::Regex {
            if self.pattern.len() > limits.max_regex_length {
                return Err(invalid("regular expression is too long"));
            }
            regex::RegexBuilder::new(&self.pattern)
                .case_insensitive(!self.case_sensitive)
                .unicode(false)
                .size_limit(limits.max_regex_program_bytes)
                .dfa_size_limit(limits.max_regex_dfa_bytes)
                .build()
                .map_err(|error| invalid(&format!("invalid regular expression: {error}")))?;
        }
        if self.field == DefinitionField::Header {
            let Some(name) = self.header_name.as_ref() else {
                return Err(invalid("header_name is required for header definitions"));
            };
            if name.trim().is_empty() || !name.is_ascii() {
                return Err(invalid("header_name must be a non-empty ASCII name"));
            }
            if name.len() > limits.max_header_name_length || !name.bytes().all(is_header_name_byte)
            {
                return Err(invalid("header_name contains invalid characters"));
            }
        } else if self.header_name.is_some() {
            return Err(invalid(
                "header_name must be null for non-header definitions",
            ));
        }
        if self.version <= 0 {
            return Err(invalid("version must be positive"));
        }
        if self.created_at.is_empty() || self.updated_at.is_empty() {
            return Err(invalid("timestamps must be non-empty"));
        }
        if self.description.len() > limits.max_request_field_length {
            return Err(invalid("description is too long"));
        }
        Ok(())
    }

    pub(crate) fn normalized_header_name(&self) -> Option<String> {
        self.header_name.as_deref().map(normalize_header_name)
    }
}

/// Input supplied by an adapter. It contains no body bytes; callers provide a
/// bounded byte count and an already computed digest when they have one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInput {
    pub client_ip: IpAddr,
    pub proxy_ip: Option<IpAddr>,
    pub method: String,
    pub host: String,
    pub target: String,
    pub user_agent: String,
    pub headers: Vec<(String, String)>,
    pub request_bytes: u64,
    pub body_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    pub client_ip: IpAddr,
    pub proxy_ip: Option<IpAddr>,
    pub method: BoundedValue,
    pub host: BoundedValue,
    pub raw_path: BoundedValue,
    pub path: BoundedValue,
    pub query_for_match: BoundedValue,
    pub query_for_audit: BoundedValue,
    pub user_agent: BoundedValue,
    pub headers: BTreeMap<String, Vec<BoundedValue>>,
    pub request_bytes: u64,
    pub body_sha256: Option<String>,
}

impl RequestView {
    pub fn header(&self, name: &str) -> Option<&[BoundedValue]> {
        self.headers
            .get(&normalize_header_name(name))
            .map(Vec::as_slice)
    }

    pub fn has_truncated_input(&self) -> bool {
        !self.method.complete
            || !self.host.complete
            || !self.raw_path.complete
            || !self.path.complete
            || !self.query_for_match.complete
            || !self.query_for_audit.complete
            || !self.user_agent.complete
            || self.headers.values().flatten().any(|value| !value.complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    address: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| CoreError::InvalidRequest("CIDR requires a prefix length".to_owned()))?;
        let address: IpAddr = address
            .parse()
            .map_err(|_| CoreError::InvalidRequest("invalid CIDR address".to_owned()))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| CoreError::InvalidRequest("invalid CIDR prefix".to_owned()))?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CoreError::InvalidRequest(
                "CIDR prefix is out of range".to_owned(),
            ));
        }
        let network = mask_ip(address, prefix_len);
        if network != address {
            return Err(CoreError::InvalidRequest(
                "CIDR address contains host bits and is not canonical".to_owned(),
            ));
        }
        Ok(Self {
            address: network,
            prefix_len,
        })
    }

    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                mask_v4(candidate, self.prefix_len) == network
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                mask_v6(candidate, self.prefix_len) == network
            }
            _ => false,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix_len)
    }
}

pub(crate) fn normalize_header_name(name: &str) -> String {
    name.trim()
        .bytes()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

/// Shared conservative classifier used for both query keys and header names.
pub(crate) fn is_sensitive_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name == "auth"
        || name == "authorization"
        || name == "cookie"
        || name == "set-cookie"
        || name == "proxy-authorization"
        || name.contains("auth")
        || name.contains("credential")
        || name.contains("secret")
        || name.contains("token")
        || name.contains("password")
        || name.contains("passwd")
        || name.contains("private")
        || name.contains("api-key")
        || name.contains("api_key")
        || name.ends_with("-key")
        || name.ends_with("_key")
        || name == "key"
}

pub(crate) fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn mask_ip(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(value) => IpAddr::V4(mask_v4(value, prefix_len)),
        IpAddr::V6(value) => IpAddr::V6(mask_v6(value, prefix_len)),
    }
}

fn mask_v4(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(address);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(address: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(address);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}
