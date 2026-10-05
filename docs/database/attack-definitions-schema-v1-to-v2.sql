-- Apply once to schema_version 1 databases before adding wp_ban/no_log rows.
-- initialize_schema also runs this migration when invoked on an existing v1 DB.
BEGIN TRANSACTION;
ALTER TABLE attack_definitions RENAME TO attack_definitions_v1;
CREATE TABLE attack_definitions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    field TEXT NOT NULL CHECK (field IN ('path', 'user_agent', 'header', 'method', 'host', 'query')),
    header_name TEXT,
    matcher TEXT NOT NULL CHECK (matcher IN ('exact', 'prefix', 'regex')),
    pattern TEXT NOT NULL CHECK (length(pattern) > 0),
    case_sensitive INTEGER NOT NULL DEFAULT 1 CHECK (case_sensitive IN (0, 1)),
    attack_type TEXT NOT NULL CHECK (
        attack_type IN ('id_leak', 'vulnerability_probe', 'credential_attack', 'scanner',
                        'resource_abuse', 'unknown', 'wp_ban', 'no_log')
    ),
    priority INTEGER NOT NULL DEFAULT 100,
    description TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((field = 'header' AND header_name IS NOT NULL AND length(header_name) > 0)
        OR (field <> 'header' AND header_name IS NULL))
);
INSERT INTO attack_definitions SELECT * FROM attack_definitions_v1;
DROP TABLE attack_definitions_v1;
CREATE INDEX attack_definitions_enabled_priority
    ON attack_definitions (enabled, priority, id);
UPDATE schema_meta SET value = '2' WHERE key = 'schema_version';
COMMIT;
