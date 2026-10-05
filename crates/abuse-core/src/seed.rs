use crate::error::Result;
use crate::schema::validate_database_schema;
use rusqlite::Connection;

/// A definition as currently stored in SQLite, including disabled rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionListing {
    pub name: String,
    pub attack_type: String,
    pub field: String,
    pub matcher: String,
    pub pattern: String,
    pub enabled: bool,
}

/// List definitions from the database, not from a compiled catalog.
pub fn list_definitions(connection: &Connection) -> Result<Vec<DefinitionListing>> {
    validate_database_schema(connection)?;
    let mut statement = connection.prepare(
        "SELECT name, attack_type, field, matcher, pattern, enabled
         FROM attack_definitions ORDER BY priority, id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(DefinitionListing {
            name: row.get(0)?,
            attack_type: row.get(1)?,
            field: row.get(2)?,
            matcher: row.get(3)?,
            pattern: row.get(4)?,
            enabled: row.get::<_, i64>(5)? == 1,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Legacy API retained for existing consumers. It only validates the schema;
/// it never inserts, updates, or removes definition rows.
pub fn seed_initial_definitions(connection: &mut Connection) -> Result<()> {
    validate_database_schema(connection)
}
