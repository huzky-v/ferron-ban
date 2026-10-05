//! Immutable version-1 decoy catalog. Strings use `${name}` references (also
//! inside format expressions and JSON object keys); `$$` emits a literal `$`.
//! There are no request, env,
//! file, or machine-state substitutions. Every named expression is evaluated
//! exactly once per response and cached, regardless of reference order.
use crate::config::Limits;
use crate::error::{CoreError, Result};
use crate::honeypot::{DecoyRng, HoneypotResponse, pkcs8_rsa_pem};
use crate::matcher::DefinitionSnapshot;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::Path;

const MAX_FILE: usize = 64 * 1024;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 1024;
const MAX_DEPTH: usize = 32;
// Conservative fixed-size bound for the PKCS#8 generator in honeypot.rs.
// The current DER is 1213 bytes (1620 Base64 chars + 26 line breaks + PEM
// framing), i.e. 1700 UTF-8 bytes. The 2048/2200 bounds leave margin for
// framing and JSON newline escaping without relying on a random sample.
const PEM_BYTES_BOUND: usize = 2048;
const PEM_JSON_BOUND: usize = 2200;

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::InvalidConfiguration(format!("honeypot template: {}", message.into()))
}

fn replace_literal(from: &str) -> Result<&str> {
    // Search strings are static and nonempty. Dynamic references could resolve
    // to empty (for example, a choice arm), invalidating the expansion bound.
    if from.is_empty() || from.contains('$') {
        return Err(invalid(
            "replace.from must be a nonempty literal without dollar syntax",
        ));
    }
    Ok(from)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u8,
    name: String,
    restype: Restype,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    variables: BTreeMap<String, Expression>,
    #[serde(default)]
    fields: Option<serde_yaml::Value>,
    #[serde(default)]
    template: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Restype {
    Json,
    Normal,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Expression {
    Format {
        value: String,
    },
    Chars {
        alphabet: String,
        min: usize,
        #[serde(default)]
        max: Option<usize>,
    },
    Integer {
        min: u64,
        max: u64,
        #[serde(default)]
        width: Option<usize>,
    },
    Choice {
        values: Vec<String>,
    },
    BytesBase64 {
        length: usize,
    },
    Base64 {
        value: String,
    },
    Replace {
        value: String,
        from: String,
        to: String,
    },
    UrlEncode {
        value: String,
    },
    Pkcs8RsaPem,
}

#[derive(Debug)]
enum Node {
    Scalar(Value),
    Text(String),
    List(Vec<Node>),
    Object(Vec<(String, Node)>),
}

#[derive(Debug)]
struct Template {
    variables: BTreeMap<String, Expression>,
    fields: Option<Node>,
    template: Option<String>,
    content_type: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct Bound {
    bytes: usize,
    json: usize, // escaped JSON string content, excluding surrounding quotes
}

impl Bound {
    fn add(self, other: Self, limit: usize) -> Result<Self> {
        let bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or_else(|| invalid("size overflow"))?;
        let json = self
            .json
            .checked_add(other.json)
            .ok_or_else(|| invalid("JSON size overflow"))?;
        if bytes > limit || json > limit {
            return Err(invalid("worst-case value exceeds body limit"));
        }
        Ok(Self { bytes, json })
    }

    fn literal(s: &str) -> Self {
        Self {
            bytes: s.len(),
            json: json_escaped_len(s),
        }
    }
}

fn json_escaped_len(s: &str) -> usize {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len(); // YAML source size is capped at 64 KiB.
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, s).expect("counting JSON string bytes cannot fail");
    counter.0 - 2 // remove the string's opening and closing quotes
}

fn cap(n: Option<usize>, limit: usize) -> Result<usize> {
    let n = n.ok_or_else(|| invalid("size overflow"))?;
    if n > limit {
        Err(invalid("worst-case output exceeds body limit"))
    } else {
        Ok(n)
    }
}

fn open_source(path: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(std::fs::File::open(path)?)
    }
}

#[derive(Debug)]
pub struct TemplateCatalog {
    templates: HashMap<String, Template>,
    limits: Limits,
}

impl TemplateCatalog {
    /// Read startup-only YAML files. Every enabled id_leak name must have
    /// exactly one file; no unrecognized/retired response is silently loaded.
    pub fn load(directory: impl AsRef<Path>, snapshot: &DefinitionSnapshot) -> Result<Self> {
        let limits = snapshot.limits().clone();
        let dir = directory.as_ref();
        // The root directory and its ancestors are operator-trusted. Only the
        // final file component is untrusted; on Unix O_NOFOLLOW binds the
        // opened descriptor to a regular file without a symlink-swap race.
        if !std::fs::symlink_metadata(dir)?.file_type().is_dir() {
            return Err(invalid("catalog directory must be a real directory"));
        }
        let expected: HashSet<&str> = snapshot
            .definitions()
            .iter()
            .filter(|definition| definition.definition().attack_type.is_id_leak())
            .map(|definition| definition.name())
            .collect();
        let mut templates = HashMap::new();
        let mut total = 0usize;
        let mut count = 0usize;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            count += 1;
            if count > MAX_FILES.min(limits.max_definitions) {
                return Err(invalid("file count limit exceeded"));
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yaml")
                || !entry.file_type()?.is_file()
            {
                return Err(invalid(format!(
                    "not a regular .yaml file: {}",
                    path.display()
                )));
            }
            let file = open_source(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(invalid("not a regular YAML source file"));
            }
            if metadata.len() > MAX_FILE as u64 {
                return Err(invalid("file size limit exceeded"));
            }
            let mut bytes = Vec::new();
            file.take((MAX_FILE + 1) as u64).read_to_end(&mut bytes)?;
            if bytes.len() > MAX_FILE {
                return Err(invalid("file size limit exceeded"));
            }
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("aggregate size overflow"))?;
            if total > MAX_TOTAL {
                return Err(invalid("aggregate size limit exceeded"));
            }
            let source: Source =
                serde_yaml::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
            if source.version != 1 {
                return Err(invalid("unsupported version"));
            }
            if !expected.contains(source.name.as_str()) {
                return Err(invalid(format!("unknown definition name {}", source.name)));
            }
            if path.file_stem().and_then(|s| s.to_str()) != Some(source.name.as_str()) {
                return Err(invalid("filename must equal definition name"));
            }
            let name = source.name.clone();
            let template = Template::parse(source, &limits)?;
            if templates.insert(name, template).is_some() {
                return Err(invalid("duplicate definition name"));
            }
        }
        for name in expected {
            if !templates.contains_key(name) {
                return Err(invalid(format!("missing template for {name}")));
            }
        }
        Ok(Self { templates, limits })
    }

    pub fn render(&self, definition_name: &str) -> Result<HoneypotResponse> {
        let template = self
            .templates
            .get(definition_name)
            .ok_or_else(|| invalid("missing response template"))?;
        template.render(&self.limits)
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn covers(&self, snapshot: &DefinitionSnapshot) -> bool {
        self.limits == *snapshot.limits()
            && snapshot
                .definitions()
                .iter()
                .filter(|d| d.definition().attack_type.is_id_leak())
                .all(|d| self.templates.contains_key(d.name()))
    }
}

impl Template {
    fn parse(source: Source, limits: &Limits) -> Result<Self> {
        let (fields, template, content_type) = match source.restype {
            Restype::Json => {
                if source.template.is_some()
                    || source.content_type.is_some()
                    || source.fields.is_none()
                {
                    return Err(invalid("json requires fields only"));
                }
                (
                    Some(Node::parse(source.fields.as_ref().unwrap(), 0)?),
                    None,
                    "application/json",
                )
            }
            Restype::Normal => {
                if source.fields.is_some() || source.template.is_none() {
                    return Err(invalid("normal requires template only"));
                }
                let content_type = match source
                    .content_type
                    .as_deref()
                    .unwrap_or("text/plain; charset=utf-8")
                {
                    "text/plain; charset=utf-8" => "text/plain; charset=utf-8",
                    "application/yaml; charset=utf-8" => "application/yaml; charset=utf-8",
                    _ => return Err(invalid("unsafe content type")),
                };
                (None, source.template, content_type)
            }
        };
        if source.variables.len() > 256 {
            return Err(invalid("too many variables"));
        }
        for (name, expr) in &source.variables {
            if !valid_name(name) {
                return Err(invalid(format!("invalid variable name {name}")));
            }
            expr.validate(limits)?;
        }
        let result = Self {
            variables: source.variables,
            fields,
            template,
            content_type,
        };
        // Check every reference, including all choice arms, not just the one
        // sampled. The same DFS also rejects cycles before serving traffic.
        for name in result.variables.keys() {
            result.check_name(name, &mut HashSet::new(), &mut HashSet::new())?;
        }
        result.check_node_references()?;
        result.validate_maximum(limits.max_honeypot_body_bytes)?;
        Ok(result)
    }

    fn validate_maximum(&self, limit: usize) -> Result<()> {
        let mut memo = HashMap::new();
        for name in self.variables.keys() {
            self.variable_bound(name, &mut memo, limit)?;
        }
        if let Some(fields) = &self.fields {
            let n = fields.json_bound(self, &mut memo, limit, 0)?;
            cap(n.checked_add(1), limit)?; // final newline
        } else {
            let s = self
                .template
                .as_deref()
                .ok_or_else(|| invalid("missing template"))?;
            self.format_bound(s, &mut memo, limit)?;
        }
        Ok(())
    }

    fn variable_bound(
        &self,
        name: &str,
        memo: &mut HashMap<String, Bound>,
        limit: usize,
    ) -> Result<Bound> {
        if let Some(bound) = memo.get(name) {
            return Ok(*bound);
        }
        // Dependencies and cycles were checked first. Each result is cached.
        let expr = self
            .variables
            .get(name)
            .ok_or_else(|| invalid("unknown variable"))?;
        let bound = match expr {
            Expression::Format { value } => self.format_bound(value, memo, limit)?,
            Expression::Chars { alphabet, min, max } => {
                let length = max.unwrap_or(*min);
                let escaped_unit = if alphabet.contains('"') || alphabet.contains('\\') {
                    2
                } else {
                    1
                };
                Bound {
                    bytes: cap(Some(length), limit)?,
                    json: cap(length.checked_mul(escaped_unit), limit)?,
                }
            }
            Expression::Integer { max, width, .. } => {
                let n = width.unwrap_or(0).max(max.to_string().len());
                Bound {
                    bytes: cap(Some(n), limit)?,
                    json: cap(Some(n), limit)?,
                }
            }
            Expression::Choice { values } => {
                let mut max = Bound { bytes: 0, json: 0 };
                for value in values {
                    let b = self.format_bound(value, memo, limit)?;
                    max.bytes = max.bytes.max(b.bytes);
                    max.json = max.json.max(b.json);
                }
                max
            }
            Expression::BytesBase64 { length } => {
                let n = cap(
                    length
                        .checked_add(2)
                        .map(|n| n / 3)
                        .and_then(|n| n.checked_mul(4)),
                    limit,
                )?;
                Bound { bytes: n, json: n }
            }
            Expression::Base64 { value } => {
                let input = self.format_bound(value, memo, limit)?;
                let n = cap(
                    input
                        .bytes
                        .checked_add(2)
                        .map(|n| n / 3)
                        .and_then(|n| n.checked_mul(4)),
                    limit,
                )?;
                Bound { bytes: n, json: n }
            }
            Expression::Replace { value, from, to } => {
                let input = self.format_bound(value, memo, limit)?;
                self.format_bound(replace_literal(from)?, memo, limit)?;
                let replacement = self.format_bound(to, memo, limit)?;
                // `from` is a nonempty literal: no more than one replacement
                // can occur per input byte.
                let bytes = cap(input.bytes.checked_mul(replacement.bytes.max(1)), limit)?;
                Bound {
                    bytes,
                    json: cap(bytes.checked_mul(6), limit)?,
                }
            }
            Expression::UrlEncode { value } => {
                let input = self.format_bound(value, memo, limit)?;
                let n = cap(input.bytes.checked_mul(3), limit)?;
                Bound { bytes: n, json: n }
            }
            Expression::Pkcs8RsaPem => Bound {
                bytes: cap(Some(PEM_BYTES_BOUND), limit)?,
                json: cap(Some(PEM_JSON_BOUND), limit)?,
            },
        };
        memo.insert(name.to_owned(), bound);
        Ok(bound)
    }

    fn format_bound(
        &self,
        text: &str,
        memo: &mut HashMap<String, Bound>,
        limit: usize,
    ) -> Result<Bound> {
        let mut result = Bound { bytes: 0, json: 0 };
        let mut rest = text;
        while let Some(start) = rest.find('$') {
            result = result.add(Bound::literal(&rest[..start]), limit)?;
            rest = &rest[start..];
            if rest.starts_with("$$") {
                result = result.add(Bound::literal("$"), limit)?;
                rest = &rest[2..];
            } else {
                let end = rest
                    .find('}')
                    .ok_or_else(|| invalid("unterminated placeholder"))?;
                result = result.add(self.variable_bound(&rest[2..end], memo, limit)?, limit)?;
                rest = &rest[end + 1..];
            }
        }
        result.add(Bound::literal(rest), limit)
    }

    fn check_name(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
        done: &mut HashSet<String>,
    ) -> Result<()> {
        if done.contains(name) {
            return Ok(());
        }
        let expr = self
            .variables
            .get(name)
            .ok_or_else(|| invalid(format!("unresolved variable {name}")))?;
        if !visiting.insert(name.to_owned()) {
            return Err(invalid(format!("cyclic variable {name}")));
        }
        let mut refs = Vec::new();
        expr.strings(&mut refs);
        for text in refs {
            for dep in references(text)? {
                self.check_name(dep, visiting, done)?;
            }
        }
        visiting.remove(name);
        done.insert(name.to_owned());
        Ok(())
    }

    fn check_node_references(&self) -> Result<()> {
        let mut strings = Vec::new();
        if let Some(fields) = &self.fields {
            fields.strings(&mut strings);
        }
        if let Some(template) = &self.template {
            strings.push(template);
        }
        for text in strings {
            for name in references(text)? {
                if !self.variables.contains_key(name) {
                    return Err(invalid(format!("unresolved variable {name}")));
                }
            }
        }
        Ok(())
    }

    fn render(&self, limits: &Limits) -> Result<HoneypotResponse> {
        let mut ctx = Context {
            variables: &self.variables,
            values: HashMap::new(),
            rng: DecoyRng::new(),
            limit: limits.max_honeypot_body_bytes,
        };
        let body = if let Some(fields) = &self.fields {
            let mut writer = BoundedWriter::new(ctx.limit);
            fields.write_json(&mut ctx, &mut writer, 0)?;
            writer.push("\n")?;
            String::from_utf8(writer.body).map_err(|_| invalid("invalid rendered UTF-8"))?
        } else {
            ctx.format(
                self.template
                    .as_deref()
                    .ok_or_else(|| invalid("missing template"))?,
            )?
        };
        Ok(HoneypotResponse {
            status_code: 200,
            content_type: self.content_type,
            body,
        })
    }
}

impl Node {
    fn parse(value: &serde_yaml::Value, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(invalid("JSON nesting limit exceeded"));
        }
        match value {
            serde_yaml::Value::Null => Ok(Self::Scalar(Value::Null)),
            serde_yaml::Value::Bool(b) => Ok(Self::Scalar(Value::Bool(*b))),
            serde_yaml::Value::Number(n) => {
                let v = serde_json::to_value(n).map_err(|e| invalid(e.to_string()))?;
                if !v.is_number() {
                    return Err(invalid("invalid JSON number"));
                }
                Ok(Self::Scalar(v))
            }
            serde_yaml::Value::String(s) => Ok(Self::Text(s.clone())),
            serde_yaml::Value::Sequence(items) => Ok(Self::List(
                items
                    .iter()
                    .map(|v| Self::parse(v, depth + 1))
                    .collect::<Result<_>>()?,
            )),
            serde_yaml::Value::Mapping(map) => {
                let mut entries = Vec::new();
                for (key, val) in map {
                    let serde_yaml::Value::String(key) = key else {
                        return Err(invalid("JSON keys must be strings"));
                    };
                    entries.push((key.clone(), Self::parse(val, depth + 1)?));
                }
                Ok(Self::Object(entries))
            }
            _ => Err(invalid("YAML tags are unsupported")),
        }
    }
    fn strings<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Text(s) => out.push(s),
            Self::List(v) => {
                for node in v {
                    node.strings(out);
                }
            }
            Self::Object(v) => {
                for (key, node) in v {
                    out.push(key);
                    node.strings(out);
                }
            }
            Self::Scalar(_) => {}
        }
    }
    fn json_bound(
        &self,
        template: &Template,
        memo: &mut HashMap<String, Bound>,
        limit: usize,
        depth: usize,
    ) -> Result<usize> {
        fn add(sum: &mut usize, n: usize, limit: usize) -> Result<()> {
            *sum = cap(sum.checked_add(n), limit)?;
            Ok(())
        }
        match self {
            Self::Scalar(v) => {
                let n = match v {
                    Value::Null => 4,
                    Value::Bool(true) => 4,
                    Value::Bool(false) => 5,
                    Value::Number(n) => n.to_string().len(),
                    _ => unreachable!("parsed JSON scalar"),
                };
                cap(Some(n), limit)
            }
            Self::Text(s) => cap(
                template.format_bound(s, memo, limit)?.json.checked_add(2),
                limit,
            ),
            Self::List(v) => {
                let mut n = 1;
                for (index, item) in v.iter().enumerate() {
                    if index > 0 {
                        add(&mut n, 1, limit)?;
                    } // comma
                    add(&mut n, 1 + 2 * (depth + 1), limit)?; // newline + indentation
                    add(
                        &mut n,
                        item.json_bound(template, memo, limit, depth + 1)?,
                        limit,
                    )?;
                }
                if !v.is_empty() {
                    add(&mut n, 1 + 2 * depth, limit)?;
                }
                add(&mut n, 1, limit)?; // closing bracket
                Ok(n)
            }
            Self::Object(v) => {
                let mut n = 1;
                let mut fixed = HashSet::new();
                for (index, (key, node)) in v.iter().enumerate() {
                    let key_bound = template.format_bound(key, memo, limit)?;
                    if !references(key)?.is_empty() {
                        // Even correlated generators or a choice arm could
                        // collide with another key. The sole-key rule proves
                        // collisions impossible without sampling RNG values.
                        if v.len() != 1 {
                            return Err(invalid(
                                "dynamic JSON key must be the sole key in its object",
                            ));
                        }
                    } else {
                        let static_key = key.replace("$$", "$");
                        if !fixed.insert(static_key) {
                            return Err(invalid("duplicate rendered JSON key"));
                        }
                    }
                    if index > 0 {
                        add(&mut n, 1, limit)?;
                    }
                    add(&mut n, 1 + 2 * (depth + 1), limit)?;
                    add(&mut n, key_bound.json + 4, limit)?; // quotes, colon, space
                    add(
                        &mut n,
                        node.json_bound(template, memo, limit, depth + 1)?,
                        limit,
                    )?;
                }
                if !v.is_empty() {
                    add(&mut n, 1 + 2 * depth, limit)?;
                }
                add(&mut n, 1, limit)?;
                Ok(n)
            }
        }
    }

    fn write_json(
        &self,
        ctx: &mut Context<'_>,
        writer: &mut BoundedWriter,
        depth: usize,
    ) -> Result<()> {
        match self {
            Self::Scalar(v) => writer.json(v)?,
            Self::Text(s) => writer.json(&ctx.format(s)?)?,
            Self::List(items) => {
                writer.push("[")?;
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        writer.push(",")?;
                    }
                    writer.indent(depth + 1)?;
                    item.write_json(ctx, writer, depth + 1)?;
                }
                if !items.is_empty() {
                    writer.indent(depth)?;
                }
                writer.push("]")?;
            }
            Self::Object(items) => {
                writer.push("{")?;
                for (index, (key, item)) in items.iter().enumerate() {
                    if index != 0 {
                        writer.push(",")?;
                    }
                    writer.indent(depth + 1)?;
                    writer.json(&ctx.format(key)?)?;
                    writer.push(": ")?;
                    item.write_json(ctx, writer, depth + 1)?;
                }
                if !items.is_empty() {
                    writer.indent(depth)?;
                }
                writer.push("}")?;
            }
        }
        Ok(())
    }
}

struct BoundedWriter {
    body: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            body: Vec::new(),
            limit,
        }
    }
    fn push(&mut self, part: &str) -> Result<()> {
        if part.len() > self.limit.saturating_sub(self.body.len()) {
            return Err(invalid("rendered output exceeds limit"));
        }
        self.body.extend_from_slice(part.as_bytes());
        Ok(())
    }
    fn json<T: serde::Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        serde_json::to_writer(self, value).map_err(|_| invalid("JSON output exceeds limit"))
    }
    fn indent(&mut self, depth: usize) -> Result<()> {
        self.push("\n")?;
        for _ in 0..depth {
            self.push("  ")?;
        }
        Ok(())
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.limit.saturating_sub(self.body.len()) {
            return Err(std::io::Error::other("honeypot body limit exceeded"));
        }
        // serde_json may split UTF-8 code points across write calls.
        self.body.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn references(text: &str) -> Result<Vec<&str>> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('$') {
        rest = &rest[start..];
        if rest.starts_with("$$") {
            rest = &rest[2..];
            continue;
        }
        if !rest.starts_with("${") {
            return Err(invalid("unknown placeholder syntax"));
        }
        let end = rest
            .find('}')
            .ok_or_else(|| invalid("unterminated placeholder"))?;
        let name = &rest[2..end];
        if !valid_name(name) {
            return Err(invalid("invalid placeholder"));
        }
        refs.push(name);
        rest = &rest[end + 1..];
    }
    Ok(refs)
}

impl Expression {
    fn strings<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Format { value } | Self::Base64 { value } | Self::UrlEncode { value } => {
                out.push(value)
            }
            Self::Replace { value, from, to } => {
                out.extend([value.as_str(), from, to]);
            }
            Self::Choice { values } => out.extend(values.iter().map(String::as_str)),
            Self::Chars { alphabet, .. } => out.push(alphabet),
            _ => {}
        }
    }
    fn validate(&self, limits: &Limits) -> Result<()> {
        let max = limits.max_honeypot_body_bytes;
        match self {
            Self::Chars {
                alphabet,
                min,
                max: upper,
            } => {
                let upper = upper.unwrap_or(*min);
                // Alphabets are static too: rejecting `$` forbids references.
                if alphabet.is_empty()
                    || !alphabet.is_ascii()
                    || alphabet
                        .bytes()
                        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'$')
                    || *min == 0
                    || upper < *min
                    || upper > max
                {
                    return Err(invalid("invalid chars expression"));
                }
            }
            Self::Integer {
                min,
                max: upper,
                width,
            } => {
                if upper < min || width.is_some_and(|w| w == 0 || w > max) {
                    return Err(invalid("invalid integer expression"));
                }
            }
            Self::Choice { values } => {
                if values.is_empty() || values.len() > 256 {
                    return Err(invalid("invalid choice expression"));
                }
            }
            Self::BytesBase64 { length } => {
                if *length == 0 || *length > max / 4 * 3 {
                    return Err(invalid("invalid bytes length"));
                }
            }
            Self::Replace { from, .. } => {
                replace_literal(from)?;
            }
            _ => {}
        }
        Ok(())
    }
}

struct Context<'a> {
    variables: &'a BTreeMap<String, Expression>,
    values: HashMap<String, String>,
    rng: DecoyRng,
    limit: usize,
}

impl Context<'_> {
    fn bounded(&self, value: String) -> Result<String> {
        if value.len() > self.limit {
            Err(invalid("rendered value exceeds limit"))
        } else {
            Ok(value)
        }
    }
    fn append(&self, output: &mut String, value: &str) -> Result<()> {
        if value.len() > self.limit.saturating_sub(output.len()) {
            return Err(invalid("rendered value exceeds limit"));
        }
        output.push_str(value);
        Ok(())
    }
    fn format(&mut self, text: &str) -> Result<String> {
        let mut output = String::new();
        let mut rest = text;
        while let Some(start) = rest.find('$') {
            self.append(&mut output, &rest[..start])?;
            rest = &rest[start..];
            if rest.starts_with("$$") {
                self.append(&mut output, "$")?;
                rest = &rest[2..];
                continue;
            }
            if !rest.starts_with("${") {
                return Err(invalid("invalid placeholder"));
            }
            let end = rest
                .find('}')
                .ok_or_else(|| invalid("unterminated placeholder"))?;
            let value = self.value(&rest[2..end])?;
            self.append(&mut output, &value)?;
            rest = &rest[end + 1..];
        }
        self.append(&mut output, rest)?;
        Ok(output)
    }
    fn value(&mut self, name: &str) -> Result<String> {
        if let Some(value) = self.values.get(name) {
            return Ok(value.clone());
        }
        let expr = self
            .variables
            .get(name)
            .ok_or_else(|| invalid("unknown variable"))?;
        // Cycles were rejected at startup, so recursion is bounded by the 256
        // variable limit. No request-time user input enters this graph.
        let value = match expr {
            Expression::Format { value } => self.format(value)?,
            Expression::Chars { alphabet, min, max } => {
                let alphabet = self.format(alphabet)?;
                if alphabet.is_empty() || !alphabet.is_ascii() {
                    return Err(invalid("invalid alphabet"));
                }
                let length = *min + self.rng.below(max.unwrap_or(*min) - *min + 1);
                if length > self.limit {
                    return Err(invalid("random value exceeds limit"));
                }
                (0..length)
                    .map(|_| alphabet.as_bytes()[self.rng.below(alphabet.len())] as char)
                    .collect()
            }
            Expression::Integer { min, max, width } => {
                let n =
                    *min + (self.rng.next_u64() as u128 % (*max as u128 - *min as u128 + 1)) as u64;
                if width.unwrap_or(0).max(n.to_string().len()) > self.limit {
                    return Err(invalid("integer value exceeds limit"));
                }
                match width {
                    Some(w) => format!("{n:0w$}"),
                    None => n.to_string(),
                }
            }
            Expression::Choice { values } => {
                let index = self.rng.below(values.len());
                self.format(&values[index])?
            }
            Expression::BytesBase64 { length } => {
                cap(
                    length
                        .checked_add(2)
                        .map(|n| n / 3)
                        .and_then(|n| n.checked_mul(4)),
                    self.limit,
                )?;
                let mut bytes = vec![0; *length];
                self.rng.fill(&mut bytes);
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }
            Expression::Base64 { value } => {
                let input = self.format(value)?;
                cap(
                    input
                        .len()
                        .checked_add(2)
                        .map(|n| n / 3)
                        .and_then(|n| n.checked_mul(4)),
                    self.limit,
                )?;
                base64::engine::general_purpose::STANDARD.encode(input)
            }
            Expression::Replace { value, from, to } => {
                let value = self.format(value)?;
                let from = replace_literal(from)?;
                let to = self.format(to)?;
                let count = value.matches(from).count();
                let size = count
                    .checked_mul(from.len())
                    .and_then(|removed| value.len().checked_sub(removed))
                    .and_then(|n| count.checked_mul(to.len()).and_then(|r| n.checked_add(r)));
                cap(size, self.limit)?;
                value.replace(from, &to)
            }
            Expression::UrlEncode { value } => {
                let value = self.format(value)?;
                let mut encoded = String::new();
                for b in value.bytes() {
                    if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                        if encoded.len() >= self.limit {
                            return Err(invalid("URL value exceeds limit"));
                        }
                        encoded.push(b as char);
                    } else {
                        if self.limit.saturating_sub(encoded.len()) < 3 {
                            return Err(invalid("URL value exceeds limit"));
                        }
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        encoded.push('%');
                        encoded.push(HEX[(b >> 4) as usize] as char);
                        encoded.push(HEX[(b & 15) as usize] as char);
                    }
                }
                encoded
            }
            Expression::Pkcs8RsaPem => {
                cap(Some(PEM_BYTES_BOUND), self.limit)?;
                pkcs8_rsa_pem(&mut self.rng)
            }
        };
        let value = self.bounded(value)?;
        self.values.insert(name.to_owned(), value.clone());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PolicyAction, PolicyEngine, ProtectionConfig, RequestInput, SnapshotLoader,
        initialize_database, normalize_request,
    };
    use rusqlite::Connection;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn setup() -> (TempDir, DefinitionSnapshot) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("templates")).unwrap();
        let db = dir.path().join("rules.sqlite");
        initialize_database(&db).unwrap();
        let connection = Connection::open(&db).unwrap();
        connection
            .execute_batch(
                "INSERT INTO attack_definitions
            (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
             priority,description,version,created_at,updated_at)
            VALUES (1,'decoy',1,'path',NULL,'exact','/old',1,'id_leak',10,'',1,'now','now');",
            )
            .unwrap();
        let snapshot = SnapshotLoader::new(Limits::default())
            .unwrap()
            .load(&db)
            .unwrap();
        (dir, snapshot)
    }

    fn write(dir: &TempDir, body: &str) {
        std::fs::write(dir.path().join("templates/decoy.yaml"), body).unwrap();
    }

    const VALID: &str = "version: 1\nname: decoy\nrestype: normal\ntemplate: 'hello'\n";

    #[test]
    fn schema_rejects_unknown_duplicate_missing_and_malformed() {
        let (dir, snapshot) = setup();
        assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err());
        for bad in [
            "version: 2\nname: decoy\nrestype: normal\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\ntemplate: ok\nunknown: 1\n",
            "version: 1\nname: decoy\nrestype: normal\ntemplate: ok\ntemplate: again\n",
            "version: 1\nname: decoy\nrestype: normal\nfields: {}\n",
            "version: 1\nname: decoy\nrestype: json\nfields: {x: 1}\ntemplate: hi\n",
            "version: 1\nname: decoy\nrestype: normal\ncontent_type: text/html\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\ntemplate: '${not_known}'\n",
            "version: 1\nname: decoy\nrestype: normal\ntemplate: '$oops'\n",
            "version: 1\nname: decoy\nrestype: json\nfields: {a: !unsafe hi}\n",
            "version: 1\nname: decoy\nrestype: json\nfields: {a: 1, a: 2}\n",
            "version: 1\nname: decoy\nrestype: json\nfields: {a: '${undefined}'}\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: command, value: hi}}\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: integer, min: 1, max: 2, unknown: yes}}\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: choice, values: [ok, '${undefined}']}}\ntemplate: '${a}'\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: format, value: '${b}'}, b: {op: format, value: '${a}'}}\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: chars, alphabet: ab, min: 0}}\ntemplate: ok\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: replace, value: foo, from: '', to: bar}}\ntemplate: '${a}'\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {needle: {op: choice, values: ['', foo]}, a: {op: replace, value: foo, from: '${needle}', to: bar}}\ntemplate: '${a}'\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {needle: {op: format, value: foo}, a: {op: replace, value: foo, from: '${needle}', to: bar}}\ntemplate: '${a}'\n",
            "version: 1\nname: decoy\nrestype: normal\nvariables: {a: {op: replace, value: foo, from: '$$foo', to: bar}}\ntemplate: '${a}'\n",
        ] {
            write(&dir, bad);
            assert!(
                TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err(),
                "accepted {bad}"
            );
        }
        write(&dir, VALID);
        assert_eq!(
            TemplateCatalog::load(dir.path().join("templates"), &snapshot)
                .unwrap()
                .len(),
            1
        );
        std::fs::write(dir.path().join("templates/other.yaml"), VALID).unwrap();
        assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err());
    }

    #[test]
    fn replace_search_is_nonempty_static_literal() {
        let (dir, snapshot) = setup();
        for from in ["''", "'${needle}'", "'$$needle'", "'$needle'"] {
            write(
                &dir,
                &format!(
                    "version: 1\nname: decoy\nrestype: normal\nvariables:\n  needle: {{op: choice, values: ['', foo]}}\n  replaced: {{op: replace, value: foo, from: {from}, to: bar}}\ntemplate: '${{replaced}}'\n"
                ),
            );
            let error = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap_err();
            assert!(
                error.to_string().contains("replace.from"),
                "{from}: {error}"
            );
        }
    }

    #[test]
    fn operations_json_types_escaping_and_named_reuse() {
        let (dir, snapshot) = setup();
        write(
            &dir,
            r#"version: 1
name: decoy
restype: json
variables:
  raw: {op: format, value: '"\\\n${n}'}
  n: {op: integer, min: 7, max: 7, width: 3}
  ranged: {op: integer, min: 3, max: 8}
  choice: {op: choice, values: ['selected']}
  chars: {op: chars, alphabet: 'ab', min: 2, max: 3}
  replaced: {op: replace, value: 'a-a', from: '-', to: '_'}
  url: {op: url_encode, value: 'a b@c'}
  encoded: {op: base64, value: '${choice}:${n}'}
  bytes: {op: bytes_base64, length: 12}
  key: {op: pkcs8_rsa_pem}
fields:
  outer:
    - {first: '${raw}', second: '${raw}', numeric: 23, bool: true, nil: null}
    - '${chars}'
  dynamic: {'${replaced}': '${url}'}
  encoded: '${encoded}'
  ranged: '${ranged}'
  bytes: '${bytes}'
  key: '${key}'
"#,
        );
        let catalog = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap();
        let response = catalog.render("decoy").unwrap();
        let json: Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(json["outer"][0]["first"], json["outer"][0]["second"]);
        assert!(json["outer"][0]["first"].as_str().unwrap().contains('"'));
        assert_eq!(json["outer"][0]["numeric"], 23);
        assert_eq!(json["outer"][0]["bool"], true);
        assert!(json["outer"][0]["nil"].is_null());
        assert_eq!(json["dynamic"]["a_a"], "a%20b%40c");
        assert!((3..=8).contains(&json["ranged"].as_str().unwrap().parse::<u64>().unwrap()));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(json["encoded"].as_str().unwrap())
                .unwrap(),
            b"selected:007"
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(json["bytes"].as_str().unwrap())
                .unwrap()
                .len(),
            12
        );
        assert!(
            json["key"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!((2..=3).contains(&json["outer"][1].as_str().unwrap().len()));
    }

    #[test]
    fn deterministic_worst_case_rejects_random_max_choice_and_expansion() {
        let (dir, snapshot) = setup();
        let db = dir.path().join("rules.sqlite");
        let small = SnapshotLoader::new(Limits {
            max_honeypot_body_bytes: 128,
            ..Limits::default()
        })
        .unwrap()
        .load(&db)
        .unwrap();
        for (variables, body) in [
            (
                "value: {op: chars, alphabet: a, min: 1, max: 100}",
                "${value}${value}".to_owned(),
            ),
            (
                "value: {op: choice, values: [ok, oversized]}",
                "${value}".repeat(20),
            ),
            (
                "value: {op: format, value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}",
                "${value}${value}".to_owned(),
            ),
            (
                "value: {op: replace, value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', from: a, to: xx}",
                "${value}".to_owned(),
            ),
            (
                "value: {op: base64, value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}",
                "${value}".to_owned(),
            ),
            (
                "value: {op: url_encode, value: '                                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}",
                "${value}".to_owned(),
            ),
        ] {
            write(
                &dir,
                &format!(
                    "version: 1\nname: decoy\nrestype: normal\nvariables:\n  {variables}\ntemplate: '{body}'\n"
                ),
            );
            assert!(
                TemplateCatalog::load(dir.path().join("templates"), &small).is_err(),
                "accepted {variables}"
            );
        }
        // Literal JSON source text fits, but escaping repeated quotes does not.
        write(
            &dir,
            &format!(
                "version: 1\nname: decoy\nrestype: json\nfields: {{a: '{}'}}\n",
                "\\\"".repeat(55)
            ),
        );
        assert!(TemplateCatalog::load(dir.path().join("templates"), &small).is_err());
        // The ordinary limit accepts this source: only the 128-byte limit is
        // responsible for rejecting it, not YAML syntax or a random draw.
        assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_ok());

        // Container punctuation and indentation count too, not just strings.
        write(
            &dir,
            &format!(
                "version: 1\nname: decoy\nrestype: json\nfields:\n  list: [{}]\n",
                vec!["1"; 30].join(", ")
            ),
        );
        assert!(TemplateCatalog::load(dir.path().join("templates"), &small).is_err());
    }

    #[test]
    fn pem_generator_fits_its_static_upper_bound() {
        for _ in 0..8 {
            let pem = pkcs8_rsa_pem(&mut DecoyRng::new());
            assert_eq!(pem.len(), 1700);
            assert!(pem.len() <= PEM_BYTES_BOUND);
            assert!(json_escaped_len(&pem) <= PEM_JSON_BOUND);
        }
    }

    #[test]
    fn dynamic_json_keys_must_be_unambiguous() {
        let (dir, snapshot) = setup();
        for fields in ["{'${key}': x, fixed: y}", "{'${key}': x, '${other}': y}"] {
            write(
                &dir,
                &format!(
                    "version: 1\nname: decoy\nrestype: json\nvariables:\n  key: {{op: choice, values: [fixed, other]}}\n  other: {{op: format, value: '${{key}}'}}\nfields: {fields}\n"
                ),
            );
            assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err());
        }
        write(
            &dir,
            "version: 1\nname: decoy\nrestype: json\nvariables:\n  key: {op: choice, values: [one, two]}\nfields: {outer: {'${key}': 1}}\n",
        );
        assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_ok());
    }

    #[test]
    fn runtime_format_replace_and_json_writer_stop_at_budget() {
        let (dir, snapshot) = setup();
        let small = Limits {
            max_honeypot_body_bytes: 128,
            ..Limits::default()
        };
        for template in ["${v}${v}${v}", "${expanded}"] {
            write(
                &dir,
                &format!(
                    "version: 1\nname: decoy\nrestype: normal\nvariables:\n  v: {{op: format, value: '{}'}}\n  expanded: {{op: replace, value: '${{v}}', from: a, to: xxxxx}}\ntemplate: '{template}'\n",
                    "a".repeat(100)
                ),
            );
            let catalog = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap();
            assert!(catalog.templates["decoy"].render(&small).is_err());
        }
        write(
            &dir,
            &format!(
                "version: 1\nname: decoy\nrestype: json\nfields:\n  a: '{}'\n",
                "\\\"".repeat(110)
            ),
        );
        let catalog = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap();
        assert!(catalog.templates["decoy"].render(&small).is_err());
        let mut writer = BoundedWriter::new(128);
        assert!(writer.json(&"\"".repeat(110)).is_err());
        assert!(writer.body.len() <= 128);

        write(
            &dir,
            "version: 1\nname: decoy\nrestype: normal\nvariables:\n  n: {op: integer, min: 1, max: 1, width: 200}\ntemplate: '${n}'\n",
        );
        let catalog = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap();
        assert!(catalog.templates["decoy"].render(&small).is_err());
    }

    #[test]
    fn bounds_symlink_and_runtime_failure_are_closed() {
        let (dir, snapshot) = setup();
        write(
            &dir,
            &format!(
                "version: 1\nname: decoy\nrestype: normal\ntemplate: '{}'\n",
                "x".repeat(129)
            ),
        );
        let limits = Limits {
            max_honeypot_body_bytes: 128,
            ..Limits::default()
        };
        let db = dir.path().join("rules.sqlite");
        let small = SnapshotLoader::new(limits).unwrap().load(&db).unwrap();
        assert!(TemplateCatalog::load(dir.path().join("templates"), &small).is_err());
        write(&dir, &format!("{VALID}{}", " ".repeat(MAX_FILE)));
        assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err());
        write(&dir, VALID);
        #[cfg(unix)]
        {
            let link = dir.path().join("templates/link.yaml");
            std::os::unix::fs::symlink(dir.path().join("templates/decoy.yaml"), &link).unwrap();
            assert!(open_source(&link).is_err()); // O_NOFOLLOW, not merely pre-open metadata
            assert!(TemplateCatalog::load(dir.path().join("templates"), &snapshot).is_err());
            std::fs::remove_file(link).unwrap();
        }
        let mut catalog = TemplateCatalog::load(dir.path().join("templates"), &snapshot).unwrap();
        catalog.templates.get_mut("decoy").unwrap().template = Some("${missing}".to_owned());
        let config = ProtectionConfig {
            ban_mode: false,
            honeypot_mode: true,
            wordpress_site: false,
            ban_duration: std::time::Duration::from_secs(60),
            definitions_db: db.clone(),
            definitions_url: None,
            audit_log: db.with_extension("ndjson"),
            limits: Limits::default(),
            fail2ban: Default::default(),
            ban_extensions: Vec::new(),
        };
        let engine =
            PolicyEngine::with_catalog(config, snapshot.clone(), std::sync::Arc::new(catalog))
                .unwrap();
        let request = normalize_request(
            RequestInput {
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                proxy_ip: None,
                method: "GET".into(),
                host: "example.invalid".into(),
                target: "/old".into(),
                user_agent: "test".into(),
                headers: vec![],
                request_bytes: 0,
                body_sha256: None,
            },
            snapshot.limits(),
        )
        .unwrap();
        let decision = engine.evaluate(&request, SystemTime::now());
        assert_eq!(
            decision.matches.selected_id_leak_name.as_deref(),
            Some("decoy")
        );
        assert_eq!(decision.action, PolicyAction::NotFound);
        assert_eq!(engine.metrics().snapshot().honeypot_responses, 0);
    }
}
