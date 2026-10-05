use crate::config::Limits;
use crate::error::{CoreError, Result};
use crate::model::{AttackType, Definition, DefinitionField, DefinitionMatcher, IpCidr};
use rusqlite::{Connection, OpenFlags, Row};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 2;
pub const SNAPSHOT_VERSION_KEY: &str = "snapshot_version";

pub(crate) struct LoadedDatabase {
    pub definitions: Vec<Definition>,
    pub allowlist: Vec<IpCidr>,
    pub snapshot_version: u64,
}

/// Create the definition schema. This is an offline/install-time operation, not
/// something called by the request path.
pub fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attack_definitions (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            field TEXT NOT NULL CHECK (
                field IN ('path', 'user_agent', 'header', 'method', 'host', 'query')
            ),
            header_name TEXT,
            matcher TEXT NOT NULL CHECK (matcher IN ('exact', 'prefix', 'regex')),
            pattern TEXT NOT NULL CHECK (length(pattern) > 0),
            case_sensitive INTEGER NOT NULL DEFAULT 1 CHECK (case_sensitive IN (0, 1)),
            attack_type TEXT NOT NULL CHECK (
                attack_type IN (
                    'id_leak', 'vulnerability_probe', 'credential_attack', 'scanner',
                     'resource_abuse', 'unknown', 'wp_ban', 'no_log'
                )
            ),
            priority INTEGER NOT NULL DEFAULT 100,
            description TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            CHECK ((field = 'header' AND header_name IS NOT NULL AND length(header_name) > 0)
                OR (field <> 'header' AND header_name IS NULL))
        );

        CREATE INDEX IF NOT EXISTS attack_definitions_enabled_priority
            ON attack_definitions (enabled, priority, id);

        CREATE TABLE IF NOT EXISTS ip_allowlist (
            id INTEGER PRIMARY KEY,
            cidr TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )?;
    // In-place migration from the previous v1 schema: the per-definition
    // honeypot provider table is obsolete because responses are now keyed by
    // definition name. Dropping it is a no-op on new
    // databases and keeps older v1 databases loadable without re-initialization.
    connection.execute_batch("DROP TABLE IF EXISTS honeypot_metadata;")?;
    connection.execute(
        "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?1, ?2)",
        [SNAPSHOT_VERSION_KEY, "1"],
    )?;
    if meta_value(connection, "schema_version")? == "1" {
        connection.execute_batch(include_str!(
            "../../../docs/database/attack-definitions-schema-v1-to-v2.sql"
        ))?;
    }
    validate_database_schema(connection)
}

pub fn initialize_database(path: &Path) -> Result<()> {
    let connection = Connection::open(path)?;
    initialize_schema(&connection)
}

pub fn validate_database_schema(connection: &Connection) -> Result<()> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(CoreError::InvalidSchema(format!(
            "SQLite integrity_check failed: {integrity}"
        )));
    }
    for table in ["schema_meta", "attack_definitions"] {
        if !table_exists(connection, table)? {
            return Err(CoreError::InvalidSchema(format!(
                "required table {table:?} is missing"
            )));
        }
    }
    require_columns(connection, "schema_meta", &["key", "value"])?;
    require_columns(
        connection,
        "attack_definitions",
        &[
            "id",
            "name",
            "enabled",
            "field",
            "header_name",
            "matcher",
            "pattern",
            "case_sensitive",
            "attack_type",
            "priority",
            "description",
            "version",
            "created_at",
            "updated_at",
        ],
    )?;
    if table_exists(connection, "ip_allowlist")? {
        require_columns(
            connection,
            "ip_allowlist",
            &[
                "id",
                "cidr",
                "description",
                "enabled",
                "created_at",
                "updated_at",
            ],
        )?;
    }
    let schema_version = meta_value(connection, "schema_version")?
        .parse::<i64>()
        .map_err(|_| CoreError::InvalidSchema("schema_version is not an integer".to_owned()))?;
    if schema_version != SCHEMA_VERSION {
        return Err(CoreError::InvalidSchema(format!(
            "unsupported schema_version {schema_version}"
        )));
    }
    let snapshot_version = meta_value(connection, SNAPSHOT_VERSION_KEY)?
        .parse::<u64>()
        .map_err(|_| {
            CoreError::InvalidSchema("snapshot_version is not a positive integer".to_owned())
        })?;
    if snapshot_version == 0 {
        return Err(CoreError::InvalidSchema(
            "snapshot_version must be positive".to_owned(),
        ));
    }
    validate_required_types_and_keys(connection)?;
    Ok(())
}

fn require_columns(connection: &Connection, table: &str, required: &[&str]) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut statement = connection.prepare(&pragma)?;
    let mut columns = std::collections::HashSet::new();
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        columns.insert(row?);
    }
    if let Some(missing) = required.iter().find(|column| !columns.contains(**column)) {
        return Err(CoreError::InvalidSchema(format!(
            "table {table:?} is missing column {missing:?}"
        )));
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?)
}

fn validate_required_types_and_keys(connection: &Connection) -> Result<()> {
    validate_table_layout(
        connection,
        "schema_meta",
        &[("key", "TEXT", false, true), ("value", "TEXT", true, false)],
    )?;
    validate_table_layout(
        connection,
        "attack_definitions",
        &[
            ("id", "INTEGER", false, true),
            ("name", "TEXT", true, false),
            ("enabled", "INTEGER", true, false),
            ("field", "TEXT", true, false),
            ("header_name", "TEXT", false, false),
            ("matcher", "TEXT", true, false),
            ("pattern", "TEXT", true, false),
            ("case_sensitive", "INTEGER", true, false),
            ("attack_type", "TEXT", true, false),
            ("priority", "INTEGER", true, false),
            ("description", "TEXT", true, false),
            ("version", "INTEGER", true, false),
            ("created_at", "TEXT", true, false),
            ("updated_at", "TEXT", true, false),
        ],
    )?;
    if table_exists(connection, "ip_allowlist")? {
        validate_table_layout(
            connection,
            "ip_allowlist",
            &[
                ("id", "INTEGER", false, true),
                ("cidr", "TEXT", true, false),
                ("description", "TEXT", true, false),
                ("enabled", "INTEGER", true, false),
                ("created_at", "TEXT", true, false),
                ("updated_at", "TEXT", true, false),
            ],
        )?;
    }
    {
        let column = "name";
        let duplicate: bool = connection.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM attack_definitions GROUP BY {column} HAVING COUNT(*) > 1)"
            ),
            [],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(CoreError::InvalidSchema(format!(
                "attack_definitions contains duplicate {column} values"
            )));
        }
    }
    let index_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'attack_definitions_enabled_priority')",
        [],
        |row| row.get(0),
    )?;
    if !index_exists {
        return Err(CoreError::InvalidSchema(
            "attack_definitions_enabled_priority index is missing".to_owned(),
        ));
    }
    let mut statement =
        connection.prepare("PRAGMA index_info(attack_definitions_enabled_priority)")?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get(2))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns != ["enabled", "priority", "id"] {
        return Err(CoreError::InvalidSchema(
            "attack_definitions_enabled_priority has unexpected columns".to_owned(),
        ));
    }
    let mut statement = connection.prepare("PRAGMA index_list(attack_definitions)")?;
    let indexes = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)? != 0))
    })?;
    let mut unique_name_index = false;
    for index in indexes {
        let (name, unique) = index?;
        if !unique {
            continue;
        }
        let pragma = format!("PRAGMA index_info({name})");
        let mut info = connection.prepare(&pragma)?;
        let columns: Vec<String> = info
            .query_map([], |row| row.get(2))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if columns == ["name"] {
            unique_name_index = true;
            break;
        }
    }
    if !unique_name_index {
        return Err(CoreError::InvalidSchema(
            "attack_definitions.name unique index is missing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_table_layout(
    connection: &Connection,
    table: &str,
    required: &[(&str, &str, bool, bool)],
) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut statement = connection.prepare(&pragma)?;
    let mut columns = HashMap::new();
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    for row in rows {
        let (name, sql_type, not_null, primary_key) = row?;
        columns.insert(name, (sql_type, not_null != 0, primary_key != 0));
    }
    for (name, expected_type, required_not_null, primary_key) in required {
        let Some((actual_type, not_null, actual_primary_key)) = columns.get(*name) else {
            return Err(CoreError::InvalidSchema(format!(
                "table {table:?} is missing column {name:?}"
            )));
        };
        if actual_type.to_ascii_uppercase() != *expected_type
            || (*required_not_null && !not_null)
            || (*primary_key != *actual_primary_key)
        {
            return Err(CoreError::InvalidSchema(format!(
                "table {table:?} column {name:?} has invalid declaration"
            )));
        }
    }
    Ok(())
}

pub(crate) fn read_database(connection: &Connection, limits: &Limits) -> Result<LoadedDatabase> {
    validate_database_schema(connection)?;
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM attack_definitions", [], |row| {
            row.get(0)
        })?;
    if count < 0 || count as usize > limits.max_definitions {
        return Err(CoreError::InvalidSchema(format!(
            "definition count {count} exceeds configured limit {}",
            limits.max_definitions
        )));
    }
    let mut pattern_budget = 0usize;
    let mut definition_ids = HashSet::new();
    let mut definition_names = HashSet::new();

    let mut statement = connection.prepare(
        "SELECT id, name, enabled, field, header_name, matcher, pattern, case_sensitive,
                attack_type, priority, description, version, created_at, updated_at
         FROM attack_definitions ORDER BY priority ASC, id ASC",
    )?;
    let rows = statement.query_map([], definition_from_row)?;
    let mut definitions = Vec::with_capacity(count as usize);
    for row in rows {
        let definition = row?;
        if !definition_ids.insert(definition.id) {
            return Err(CoreError::InvalidSchema(format!(
                "duplicate definition id {}",
                definition.id
            )));
        }
        if !definition_names.insert(definition.name.clone()) {
            return Err(CoreError::InvalidSchema(format!(
                "duplicate definition name {:?}",
                definition.name
            )));
        }
        pattern_budget = pattern_budget
            .checked_add(definition.pattern.len())
            .ok_or_else(|| CoreError::InvalidSchema("pattern budget overflow".to_owned()))?;
        if pattern_budget > limits.max_pattern_bytes_total {
            return Err(CoreError::InvalidSchema(
                "aggregate pattern budget exceeded".to_owned(),
            ));
        }
        definition.validate(limits)?;
        definitions.push(definition);
    }

    let mut allowlist = Vec::new();
    if table_exists(connection, "ip_allowlist")? {
        let allowlist_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM ip_allowlist", [], |row| row.get(0))?;
        if allowlist_count < 0 || allowlist_count as usize > limits.max_allowlist_rows {
            return Err(CoreError::InvalidSchema(
                "allowlist row limit exceeded".to_owned(),
            ));
        }
        let mut statement =
            connection.prepare("SELECT id, cidr, enabled FROM ip_allowlist ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let cidr: String = row.get(1)?;
            let enabled: i64 = row.get(2)?;
            Ok((id, cidr, enabled))
        })?;
        for row in rows {
            let (id, cidr, enabled) = row?;
            if id <= 0 {
                return Err(CoreError::allowlist(id, "id must be positive"));
            }
            if enabled != 0 && enabled != 1 {
                return Err(CoreError::allowlist(id, "enabled must be 0 or 1"));
            }
            if cidr.len() > limits.max_request_field_length {
                return Err(CoreError::allowlist(id, "CIDR value is too long"));
            }
            let network = IpCidr::parse(&cidr)
                .map_err(|error| CoreError::allowlist(id, error.to_string()))?;
            if enabled == 1 {
                allowlist.push(network);
            }
        }
    }

    let snapshot_version = meta_value(connection, SNAPSHOT_VERSION_KEY)?
        .parse::<u64>()
        .map_err(|_| CoreError::InvalidSchema("snapshot_version is not positive".to_owned()))?;
    Ok(LoadedDatabase {
        definitions,
        allowlist,
        snapshot_version,
    })
}

pub(crate) fn readonly_connection(path: &Path, limits: &Limits) -> Result<Connection> {
    let size = std::fs::metadata(path)?.len();
    if size > limits.max_sqlite_bytes {
        return Err(CoreError::InvalidSchema(format!(
            "database is {size} bytes, exceeding limit {}",
            limits.max_sqlite_bytes
        )));
    }
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)?;
    if &header != b"SQLite format 3\0" {
        return Err(CoreError::InvalidSchema(
            "database does not have a valid SQLite header".to_owned(),
        ));
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection)
}

fn meta_value(connection: &Connection, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                CoreError::InvalidSchema(format!("schema_meta is missing {key}"))
            }
            other => CoreError::Database(other),
        })
}

fn definition_from_row(row: &Row<'_>) -> rusqlite::Result<Definition> {
    let id: i64 = row.get(0)?;
    let field: String = row.get(3)?;
    let matcher: String = row.get(5)?;
    let attack_type: String = row.get(8)?;
    Ok(Definition {
        id,
        name: row.get(1)?,
        enabled: read_bool(row.get(2)?, "enabled")?,
        field: DefinitionField::parse(&field).ok_or_else(|| invalid_value("field"))?,
        header_name: row.get(4)?,
        matcher: DefinitionMatcher::parse(&matcher).ok_or_else(|| invalid_value("matcher"))?,
        pattern: row.get(6)?,
        case_sensitive: read_bool(row.get(7)?, "case_sensitive")?,
        attack_type: AttackType::parse(&attack_type).ok_or_else(|| invalid_value("attack_type"))?,
        priority: row.get(9)?,
        description: row.get(10)?,
        version: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn read_bool(value: i64, field: &str) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_value(field)),
    }
}

fn invalid_value(field: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {field}"),
        )),
    )
}
