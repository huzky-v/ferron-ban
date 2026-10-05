use abuse_core::{initialize_schema, list_definitions};
use rusqlite::Connection;
use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(env::args_os().skip(1), &mut io::stdout())
}

fn run(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: abuse-definitions-init <sqlite-path> | --list-definitions <sqlite-path>";
    let mut args = args.into_iter();
    let first = args.next().ok_or(usage)?;
    let list = first == "--list-definitions";
    if first.to_string_lossy().starts_with('-') && !list {
        return Err(usage.into());
    }
    let path = if list {
        args.next().ok_or(usage)?
    } else {
        first
    };
    if args.next().is_some() {
        return Err(usage.into());
    }
    if path.to_string_lossy().starts_with('-') {
        return Err(usage.into());
    }
    let path = PathBuf::from(path);
    if list {
        // Read-only: listing must neither create a missing DB nor modify its rows.
        let connection =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        writeln!(
            output,
            "name\tattack_type\tfield\tmatcher\tpattern\tenabled"
        )?;
        for entry in list_definitions(&connection)? {
            writeln!(
                output,
                "{}\t{}\t{}\t{}\t{}\t{}",
                entry.name,
                entry.attack_type,
                entry.field,
                entry.matcher,
                entry.pattern,
                entry.enabled
            )?;
        }
    } else {
        let connection = Connection::open(path)?;
        initialize_schema(&connection)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_does_not_insert_and_listing_reflects_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.sqlite");
        let args = || vec![path.clone().into_os_string()];
        run(args(), &mut Vec::new()).unwrap();
        run(args(), &mut Vec::new()).unwrap();
        let connection = Connection::open(&path).unwrap();
        assert!(list_definitions(&connection).unwrap().is_empty());
        connection.execute_batch("INSERT INTO attack_definitions
            (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
             priority,description,version,created_at,updated_at)
            VALUES (77,'db-only-rule',1,'path',NULL,'exact','/db-only',1,'scanner',1,'',1,'now','now');").unwrap();
        run(args(), &mut Vec::new()).unwrap();
        let mut output = Vec::new();
        run(
            vec!["--list-definitions".into(), path.into_os_string()],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "name\tattack_type\tfield\tmatcher\tpattern\tenabled\ndb-only-rule\tscanner\tpath\texact\t/db-only\ttrue\n"
        );
    }

    #[test]
    fn list_requires_existing_db_path_and_does_not_create_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.sqlite");
        assert!(
            run(
                vec!["--list-definitions".into(), path.clone().into_os_string()],
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(!path.exists());
        assert!(run(vec!["--list-seeds".into()], &mut Vec::new()).is_err());
        assert!(!dir.path().join("--list-seeds").exists());
    }
}
