//! One-shot, fail-closed ZIP source. Nothing is installed into an operator cache.
use crate::definition_source::{DefinitionDownloader, ReqwestDefinitionDownloader};
use abuse_core::{DefinitionSnapshot, Limits, SnapshotLoader, TemplateCatalog};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use zip::ZipArchive;

pub const DEFAULT_BUNDLE: &str = "/var/lib/ferron/abuse-bundle.zip";
// DB (64 MiB by default) + 8 MiB templates + ZIP headers/metadata margin.
const MAX_ARCHIVE: u64 = 80 * 1024 * 1024;
const MAX_ENTRIES: usize = 1026;
const MAX_PATH: usize = 255;
const MAX_TEMPLATE: u64 = 64 * 1024;
const MAX_TEMPLATES_TOTAL: u64 = 8 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> String {
    format!("invalid definitions_bundle: {}", message.into())
}

pub fn load(
    source: &str,
    limits: &Limits,
    honeypot: bool,
) -> Result<(DefinitionSnapshot, Option<Arc<TemplateCatalog>>), String> {
    limits.validate().map_err(|e| invalid(e.to_string()))?;
    load_with_downloader(source, limits, honeypot, None)
}

fn load_with_downloader(
    source: &str,
    limits: &Limits,
    honeypot: bool,
    downloader: Option<&dyn DefinitionDownloader>,
) -> Result<(DefinitionSnapshot, Option<Arc<TemplateCatalog>>), String> {
    limits.validate().map_err(|e| invalid(e.to_string()))?;
    let directory = tempfile::tempdir().map_err(|e| invalid(e.to_string()))?;
    let source = if source == "default" {
        DEFAULT_BUNDLE
    } else {
        source
    };
    let remote;
    let path = if source.starts_with("https://") {
        let client;
        let downloader = match downloader {
            Some(downloader) => downloader,
            None => {
                client = ReqwestDefinitionDownloader::new().map_err(|e| invalid(e.to_string()))?;
                &client
            }
        };
        remote = downloader
            .download(source, directory.path(), MAX_ARCHIVE)
            .map_err(|e| invalid(e.to_string()))?;
        remote.path()
    } else if source.contains("://") {
        return Err(invalid("URL must use HTTPS"));
    } else {
        Path::new(source)
    };
    extract(path, &directory, limits, honeypot)?;
    let snapshot = SnapshotLoader::new(limits.clone())
        .and_then(|loader| loader.load(&directory.path().join("definitions.sqlite")))
        .map_err(|e| invalid(e.to_string()))?;
    let catalog = if honeypot {
        Some(Arc::new(
            TemplateCatalog::load(directory.path().join("honeypot-responses"), &snapshot)
                .map_err(|e| invalid(e.to_string()))?,
        ))
    } else {
        None
    };
    Ok((snapshot, catalog))
}

fn safe_archive_path(raw: &str) -> bool {
    if raw.len() > MAX_PATH || raw.starts_with('/') || raw.ends_with("//") {
        return false;
    }
    raw.trim_end_matches('/').split('/').all(|part| {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part
                .bytes()
                .any(|byte| byte <= 0x1f || b"\\:*?\"<>|".contains(&byte))
        {
            return false;
        }
        let basename = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
            return false;
        }
        !["COM", "LPT"].iter().any(|prefix| {
            basename.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    })
}

// zip 2.x indexes entries by name, silently collapsing *exact* duplicates.
// Count raw central-directory records before iterating its name-indexed API.
fn check_central_entry_count(
    mut file: File,
    start: u64,
    length: u64,
    count: usize,
) -> Result<(), String> {
    file.seek(SeekFrom::Start(start))
        .map_err(|e| invalid(e.to_string()))?;
    let mut records = 0usize;
    loop {
        let mut signature = [0; 4];
        file.read_exact(&mut signature)
            .map_err(|e| invalid(e.to_string()))?;
        if signature != [0x50, 0x4b, 0x01, 0x02] {
            break;
        }
        records += 1;
        if records > MAX_ENTRIES {
            return Err(invalid("entry count limit exceeded"));
        }
        let mut header = [0; 42];
        file.read_exact(&mut header)
            .map_err(|e| invalid(e.to_string()))?;
        let variable_length = [24, 26, 28]
            .into_iter()
            .map(|offset| u16::from_le_bytes([header[offset], header[offset + 1]]) as u64)
            .sum::<u64>();
        let next = file
            .stream_position()
            .map_err(|e| invalid(e.to_string()))?
            .checked_add(variable_length)
            .ok_or_else(|| invalid("central directory overflow"))?;
        if next > length {
            return Err(invalid("truncated central directory"));
        }
        file.seek(SeekFrom::Start(next))
            .map_err(|e| invalid(e.to_string()))?;
    }
    if records != count {
        return Err(invalid("duplicate ZIP entry or invalid central directory"));
    }
    Ok(())
}

fn extract(path: &Path, temp: &TempDir, limits: &Limits, honeypot: bool) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| invalid(e.to_string()))?;
    let size = file.metadata().map_err(|e| invalid(e.to_string()))?;
    if !size.is_file() || size.len() > MAX_ARCHIVE {
        return Err(invalid(
            "archive is not a regular file or exceeds size limit",
        ));
    }
    let central_file = file.try_clone().map_err(|e| invalid(e.to_string()))?;
    let mut archive = ZipArchive::new(file).map_err(|e| invalid(e.to_string()))?;
    check_central_entry_count(
        central_file,
        archive.central_directory_start(),
        size.len(),
        archive.len(),
    )?;
    if archive.len() > MAX_ENTRIES {
        return Err(invalid("entry count limit exceeded"));
    }
    let mut names = HashSet::new();
    let mut db = false;
    let mut templates = 0usize;
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| invalid(e.to_string()))?;
        if entry.encrypted()
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err(invalid("encrypted or unsupported ZIP entry"));
        }
        let raw = std::str::from_utf8(entry.name_raw()).map_err(|_| invalid("non-UTF-8 path"))?;
        if !safe_archive_path(raw) {
            return Err(invalid("unsafe archive path"));
        }
        let canonical = raw.trim_end_matches('/').to_ascii_lowercase();
        if !names.insert(canonical) {
            return Err(invalid("duplicate or case-colliding path"));
        }
        let is_dir = raw == "honeypot-responses/";
        let is_db = raw == "definitions.sqlite";
        let template = raw
            .strip_prefix("honeypot-responses/")
            .is_some_and(|name| !name.is_empty() && !name.contains('/') && name.ends_with(".yaml"));
        if !(is_dir || is_db || template) || entry.is_dir() != is_dir {
            return Err(invalid("unexpected entry or entry type"));
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != if is_dir { 0o040000 } else { 0o100000 } {
                return Err(invalid("symlink or special file"));
            }
        }
        if is_dir {
            if entry.size() != 0 {
                return Err(invalid("nonempty directory entry"));
            }
            // Read through the decoder to EOF: the ZIP API checks CRC only on
            // read, not when metadata is inspected or an entry is dropped.
            let read = io::copy(&mut entry.by_ref().take(1), &mut io::sink())
                .map_err(|e| invalid(e.to_string()))?;
            if read != 0 {
                return Err(invalid("nonempty directory entry"));
            }
            continue;
        }
        let max = if is_db {
            limits.max_sqlite_bytes
        } else {
            MAX_TEMPLATE
        };
        if entry.size() > max {
            return Err(invalid("entry exceeds size limit"));
        }
        if is_db {
            db = true;
        } else {
            templates += 1;
            total = total
                .checked_add(entry.size())
                .ok_or_else(|| invalid("size overflow"))?;
            if templates > 1024.min(limits.max_definitions) || total > MAX_TEMPLATES_TOTAL {
                return Err(invalid("template count or total size exceeded"));
            }
        }
        // Even with honeypot disabled, inspect the ZIP structure and decompress
        // bounded entries so CRC/truncation and ZIP bombs cannot go unnoticed.
        let destination = temp.path().join(raw);
        if template {
            fs::create_dir_all(temp.path().join("honeypot-responses"))
                .map_err(|e| invalid(e.to_string()))?;
        }
        let mut output = if honeypot || is_db {
            Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(destination)
                    .map_err(|e| invalid(e.to_string()))?,
            )
        } else {
            None
        };
        let cap = max
            .checked_add(1)
            .ok_or_else(|| invalid("entry size limit overflow"))?;
        let read = io::copy(
            &mut entry.by_ref().take(cap),
            &mut output
                .as_mut()
                .map(|f| f as &mut dyn Write)
                .unwrap_or(&mut io::sink()),
        )
        .map_err(|e| invalid(e.to_string()))?;
        if read > max || read != entry.size() {
            return Err(invalid("entry size mismatch"));
        }
    }
    if !db {
        return Err(invalid("missing definitions.sqlite"));
    }
    if honeypot {
        fs::create_dir_all(temp.path().join("honeypot-responses"))
            .map_err(|e| invalid(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition_source::SourceError;
    use abuse_core::initialize_database;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;
    use zip::write::SimpleFileOptions;

    const YAML: &str = "version: 1\nname: decoy\nrestype: normal\ntemplate: 'hello'\n";

    fn database(dir: &TempDir) -> Vec<u8> {
        let db = dir.path().join("source.sqlite");
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
        drop(connection);
        fs::read(db).unwrap()
    }

    fn bundle(dir: &TempDir, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        let path = dir.path().join("bundle.zip");
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for &(name, contents) in entries {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    fn run(
        path: &Path,
        honeypot: bool,
    ) -> Result<(DefinitionSnapshot, Option<Arc<TemplateCatalog>>), String> {
        load(path.to_str().unwrap(), &Limits::default(), honeypot)
    }

    #[test]
    fn valid_bundle_and_optional_templates() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(
            &dir,
            &[
                ("definitions.sqlite", &db),
                ("honeypot-responses/decoy.yaml", YAML.as_bytes()),
            ],
        );
        let (snapshot, catalog) = run(&path, true).unwrap();
        assert_eq!(snapshot.definitions().len(), 1);
        assert_eq!(catalog.unwrap().len(), 1);
        let path = bundle(
            &dir,
            &[
                ("definitions.sqlite", &db),
                ("honeypot-responses/decoy.yaml", b"invalid yaml"),
            ],
        );
        assert!(run(&path, false).unwrap().1.is_none());
        assert!(run(&path, true).is_err());
        let path = bundle(&dir, &[("definitions.sqlite", &db)]);
        assert!(run(&path, false).is_ok());
        assert!(run(&path, true).is_err());
    }

    #[test]
    fn missing_invalid_and_unsafe_entries_fail() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        for entries in [
            vec![("honeypot-responses/decoy.yaml", YAML.as_bytes())],
            vec![("definitions.sqlite", b"not sqlite".as_slice())],
            vec![("definitions.sqlite", db.as_slice()), ("../escape", b"bad")],
            vec![
                ("definitions.sqlite", db.as_slice()),
                ("Definitions.sqlite", db.as_slice()),
            ],
            vec![
                ("definitions.sqlite", db.as_slice()),
                ("honeypot-responses/../bad.yaml", b"bad"),
            ],
            vec![
                ("definitions.sqlite", db.as_slice()),
                ("honeypot-responses\\bad.yaml", b"bad"),
            ],
        ] {
            assert!(run(&bundle(&dir, &entries), false).is_err());
        }
        let limits = Limits {
            max_sqlite_bytes: 1024,
            ..Limits::default()
        };
        assert!(
            load(
                bundle(&dir, &[("definitions.sqlite", &db)])
                    .to_str()
                    .unwrap(),
                &limits,
                false
            )
            .is_err()
        );
        let path = bundle(
            &dir,
            &[
                ("definitions.sqlite", &db),
                ("honeypot-responses/decoy.yaml", &vec![b'x'; 65537]),
            ],
        );
        assert!(run(&path, false).is_err());
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 30);
        fs::write(&path, bytes).unwrap();
        assert!(run(&path, false).is_err());
    }

    #[test]
    fn rejects_symlinks_and_unexpected_directories() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(&dir, &[("definitions.sqlite", &db), ("other/", b"")]);
        assert!(run(&path, false).is_err());
        let path = dir.path().join("bundle.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.start_file("definitions.sqlite", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&db).unwrap();
        zip.add_symlink(
            "honeypot-responses/decoy.yaml",
            "../../escape",
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.finish().unwrap();
        assert!(run(&path, false).is_err());
    }

    #[test]
    fn rejects_exact_duplicate_central_records() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(
            &dir,
            &[
                ("definitions.sqlite", &db),
                ("honeypot-responses/a.yaml", b"one"),
                ("honeypot-responses/b.yaml", b"two"),
            ],
        );
        // ZipWriter disallows duplicate names. Change both the local and the
        // central name of its second template, preserving lengths and offsets.
        let mut bytes = fs::read(&path).unwrap();
        let old = b"honeypot-responses/b.yaml";
        let positions: Vec<_> = bytes
            .windows(old.len())
            .enumerate()
            .filter_map(|(index, window)| (window == old).then_some(index))
            .collect();
        assert_eq!(positions.len(), 2);
        for position in positions {
            bytes[position + "honeypot-responses/".len()] = b'a';
        }
        fs::write(&path, bytes).unwrap();
        assert!(
            run(&path, false)
                .unwrap_err()
                .contains("duplicate ZIP entry")
        );
    }

    #[test]
    fn rejects_nonportable_windows_paths() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        for name in [
            "CON.yaml",
            "nUl.yaml",
            "COM1.yaml",
            "Lpt9.yaml",
            "COM¹.yaml",
            "bad:name.yaml",
            "bad?.yaml",
        ] {
            let name = format!("honeypot-responses/{name}");
            assert!(!safe_archive_path(&name), "{name}");
            assert!(
                run(
                    &bundle(&dir, &[("definitions.sqlite", &db), (&name, b"bad")]),
                    false
                )
                .is_err()
            );
        }
        for name in [
            "honeypot-responses/bad.",
            "honeypot-responses/bad ",
            "honeypot-responses/aux.txt",
        ] {
            assert!(!safe_archive_path(name), "{name}");
        }
    }

    #[test]
    fn rejects_nonempty_and_corrupted_directories() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(
            &dir,
            &[
                ("definitions.sqlite", &db),
                ("honeypot-responses/", b"payload"),
            ],
        );
        assert!(run(&path, false).is_err());

        let path = dir.path().join("bundle.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.add_directory("honeypot-responses/", SimpleFileOptions::default())
            .unwrap();
        zip.start_file("definitions.sqlite", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&db).unwrap();
        zip.finish().unwrap();
        assert!(run(&path, false).is_ok());
        let central = ZipArchive::new(File::open(&path).unwrap())
            .unwrap()
            .by_index(0)
            .unwrap()
            .central_header_start();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(central + 16)).unwrap(); // central header CRC-32
        file.write_all(&1u32.to_le_bytes()).unwrap();
        assert!(run(&path, false).is_err());
    }

    #[test]
    fn invalid_limits_fail_before_download_or_extraction_and_cap_overflow_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(&dir, &[("definitions.sqlite", &db)]);
        let limits = Limits {
            max_sqlite_bytes: u64::MAX,
            ..Limits::default()
        };
        assert!(
            load(path.to_str().unwrap(), &limits, false)
                .unwrap_err()
                .contains("max_sqlite_bytes")
        );
        assert!(
            load_with_downloader(
                "https://example.invalid/bundle.zip",
                &limits,
                false,
                Some(&FailedDownload)
            )
            .unwrap_err()
            .contains("max_sqlite_bytes")
        );
        assert!(
            extract(&path, &tempfile::tempdir().unwrap(), &limits, false)
                .unwrap_err()
                .contains("overflow")
        );
    }

    #[test]
    fn rejects_encrypted_and_unsupported_methods() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let path = bundle(&dir, &[("definitions.sqlite", &db)]);
        let central = ZipArchive::new(File::open(&path).unwrap())
            .unwrap()
            .by_index(0)
            .unwrap()
            .central_header_start() as usize;
        let original = fs::read(&path).unwrap();
        let mut encrypted = original.clone();
        encrypted[6] |= 1; // local general purpose flag
        encrypted[central + 8] |= 1; // central general purpose flag
        fs::write(&path, encrypted).unwrap();
        assert!(run(&path, false).is_err());

        let mut unsupported = original;
        unsupported[8..10].copy_from_slice(&12u16.to_le_bytes()); // bzip2 (not enabled)
        unsupported[central + 10..central + 12].copy_from_slice(&12u16.to_le_bytes());
        fs::write(&path, unsupported).unwrap();
        assert!(run(&path, false).is_err());
    }

    #[test]
    fn rejects_archive_count_path_and_compressed_size_limits() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let long_name = format!("honeypot-responses/{}.yaml", "a".repeat(240));
        assert!(
            run(
                &bundle(&dir, &[("definitions.sqlite", &db), (&long_name, b"")]),
                false
            )
            .is_err()
        );

        let path = dir.path().join("bundle.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.start_file("definitions.sqlite", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&db).unwrap();
        for i in 0..MAX_ENTRIES {
            zip.start_file(
                format!("honeypot-responses/{i}.yaml"),
                SimpleFileOptions::default(),
            )
            .unwrap();
        }
        zip.finish().unwrap();
        assert!(run(&path, false).is_err());

        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_ARCHIVE + 1)
            .unwrap();
        assert!(run(&path, false).is_err());
    }

    struct FailedDownload;
    impl DefinitionDownloader for FailedDownload {
        fn download(&self, _: &str, _: &Path, _: u64) -> Result<NamedTempFile, SourceError> {
            Err(SourceError::Status(503))
        }
    }

    struct InvalidDownload;
    impl DefinitionDownloader for InvalidDownload {
        fn download(
            &self,
            _: &str,
            directory: &Path,
            _: u64,
        ) -> Result<NamedTempFile, SourceError> {
            let mut file = NamedTempFile::new_in(directory)?;
            file.write_all(b"invalid ZIP")?;
            Ok(file)
        }
    }

    #[test]
    fn remote_failure_never_falls_back_to_local() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(&dir);
        let _local = bundle(&dir, &[("definitions.sqlite", &db)]);
        assert!(
            load_with_downloader(
                "https://example.invalid/bundle.zip",
                &Limits::default(),
                false,
                Some(&FailedDownload)
            )
            .is_err()
        );
        assert!(
            load_with_downloader(
                "https://example.invalid/bundle.zip",
                &Limits::default(),
                false,
                Some(&InvalidDownload)
            )
            .is_err()
        );
        assert!(
            load(
                "http://example.invalid/bundle.zip",
                &Limits::default(),
                false
            )
            .is_err()
        );
        assert_eq!(DEFAULT_BUNDLE, "/var/lib/ferron/abuse-bundle.zip");
    }
}
