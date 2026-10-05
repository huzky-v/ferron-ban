use abuse_core::{
    DefinitionSnapshot, MetricEvent, MetricEventSender, MetricSink, ProtectionConfig,
    SnapshotLoader,
};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::{Attempt, Policy};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use tempfile::NamedTempFile;

pub trait DefinitionDownloader: Send + Sync {
    fn download(
        &self,
        url: &str,
        directory: &Path,
        max_bytes: u64,
    ) -> Result<NamedTempFile, SourceError>;
}

pub struct ReqwestDefinitionDownloader {
    client: Client,
}

impl ReqwestDefinitionDownloader {
    pub fn new() -> Result<Self, SourceError> {
        Self::build_client(None, Duration::from_secs(5), Duration::from_secs(30))
    }

    pub fn new_with_root_certificate(certificate_der: &[u8]) -> Result<Self, SourceError> {
        Self::build_client(
            Some(reqwest::Certificate::from_der(certificate_der)?),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
    }

    pub fn new_with_root_certificate_and_timeout(
        certificate_der: &[u8],
        timeout: Duration,
    ) -> Result<Self, SourceError> {
        Self::build_client(
            Some(reqwest::Certificate::from_der(certificate_der)?),
            timeout,
            timeout,
        )
    }

    fn build_client(
        certificate: Option<reqwest::Certificate>,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, SourceError> {
        let redirect = Policy::custom(|attempt: Attempt<'_>| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many definition redirects");
            }
            if attempt.url().scheme() != "https" {
                return attempt.error("definition redirects must remain HTTPS");
            }
            attempt.follow()
        });
        let mut builder = Client::builder()
            .no_proxy()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .redirect(redirect);
        if let Some(certificate) = certificate {
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build()?;
        Ok(Self { client })
    }
}

impl DefinitionDownloader for ReqwestDefinitionDownloader {
    fn download(
        &self,
        url: &str,
        directory: &Path,
        max_bytes: u64,
    ) -> Result<NamedTempFile, SourceError> {
        let parsed = Url::parse(url).map_err(|_| SourceError::InvalidUrl)?;
        if parsed.scheme() != "https" {
            return Err(SourceError::InvalidUrl);
        }
        let response = self.client.get(parsed).send()?;
        copy_response(response, directory, max_bytes)
    }
}

fn copy_response(
    mut response: Response,
    directory: &Path,
    max_bytes: u64,
) -> Result<NamedTempFile, SourceError> {
    if !response.status().is_success() {
        return Err(SourceError::Status(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes)
    {
        return Err(SourceError::TooLarge);
    }
    copy_reader(&mut response, directory, max_bytes)
}

fn copy_reader<R: Read>(
    reader: &mut R,
    directory: &Path,
    max_bytes: u64,
) -> Result<NamedTempFile, SourceError> {
    let mut temp = NamedTempFile::new_in(directory)?;
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(SourceError::TooLarge)?;
        if total > max_bytes {
            return Err(SourceError::TooLarge);
        }
        temp.write_all(&buffer[..read])?;
    }
    temp.as_file_mut().flush()?;
    temp.as_file().sync_all()?;
    Ok(temp)
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("definitions URL must be HTTPS")]
    InvalidUrl,
    #[error("definitions source returned HTTP status {0}")]
    Status(u16),
    #[error("definitions source exceeded configured size limit")]
    TooLarge,
    #[error("definitions source install failed: {0}")]
    Install(String),
    #[error("definitions source validation failed: {0}")]
    Validation(String),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tempfile(#[from] tempfile::PersistError),
}

pub fn resolve_snapshot(
    config: &ProtectionConfig,
    downloader: &dyn DefinitionDownloader,
    metric_sender: &MetricEventSender,
) -> Result<DefinitionSnapshot, SourceError> {
    let loader = SnapshotLoader::new(config.limits.clone())
        .map_err(|error| SourceError::Validation(error.to_string()))?;
    let Some(url) = config.definitions_url.as_deref() else {
        return loader
            .load(&config.definitions_db)
            .map_err(|error| SourceError::Validation(error.to_string()));
    };
    let directory = config
        .definitions_db
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match downloader.download(url, directory, config.limits.max_sqlite_bytes) {
        Ok(temp) => {
            match loader
                .load(temp.path())
                .map_err(|error| SourceError::Validation(error.to_string()))
                .and_then(|snapshot| install_cache(temp, &config.definitions_db).map(|()| snapshot))
            {
                Ok(snapshot) => Ok(snapshot),
                Err(remote_error) => {
                    fallback_local(&loader, &config.definitions_db, remote_error, metric_sender)
                }
            }
        }
        Err(remote_error) => {
            fallback_local(&loader, &config.definitions_db, remote_error, metric_sender)
        }
    }
}

pub fn resolve_snapshot_startup(
    config: &ProtectionConfig,
    metric_sender: &MetricEventSender,
) -> Result<DefinitionSnapshot, SourceError> {
    if config.definitions_url.is_none() {
        return SnapshotLoader::new(config.limits.clone())
            .map_err(|error| SourceError::Validation(error.to_string()))?
            .load(&config.definitions_db)
            .map_err(|error| SourceError::Validation(error.to_string()));
    }
    match ReqwestDefinitionDownloader::new() {
        Ok(downloader) => resolve_snapshot(config, &downloader, metric_sender),
        Err(remote_error) => {
            let loader = SnapshotLoader::new(config.limits.clone())
                .map_err(|error| SourceError::Validation(error.to_string()))?;
            fallback_local(&loader, &config.definitions_db, remote_error, metric_sender)
        }
    }
}

fn fallback_local(
    loader: &SnapshotLoader,
    local_path: &Path,
    remote_error: SourceError,
    metric_sender: &MetricEventSender,
) -> Result<DefinitionSnapshot, SourceError> {
    let _ = metric_sender.try_record(MetricEvent::InvalidDefinitionSource);
    ferron_core::log_warn!(
        "ferron abuse definitions remote source unavailable; using validated local database"
    );
    loader.load(local_path).map_err(|local_error| {
        SourceError::Validation(format!(
            "remote source failed ({remote_error}); local source failed ({local_error})"
        ))
    })
}

fn install_cache(temp: NamedTempFile, destination: &Path) -> Result<(), SourceError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(SourceError::Install(
                "definitions_db destination is not a regular file".to_owned(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SourceError::Io(error)),
        Ok(_) => {}
    }
    temp.persist(destination).map_err(SourceError::Tempfile)?;
    #[cfg(unix)]
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abuse_core::{DefinitionSnapshot, Limits, initialize_database};
    use rcgen::generate_simple_self_signed;
    use rusqlite::Connection;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Once;
    use std::thread;
    use tempfile::tempdir;

    static RUSTLS_PROVIDER: Once = Once::new();

    fn install_rustls_provider() {
        RUSTLS_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    struct FixtureDownloader {
        source: PathBuf,
    }

    impl DefinitionDownloader for FixtureDownloader {
        fn download(
            &self,
            _url: &str,
            directory: &Path,
            _max_bytes: u64,
        ) -> Result<NamedTempFile, SourceError> {
            let mut temp = NamedTempFile::new_in(directory)?;
            let bytes = fs::read(&self.source)?;
            temp.write_all(&bytes)?;
            temp.as_file_mut().flush()?;
            Ok(temp)
        }
    }

    struct FailingDownloader(SourceError);

    impl DefinitionDownloader for FailingDownloader {
        fn download(
            &self,
            _url: &str,
            _directory: &Path,
            _max_bytes: u64,
        ) -> Result<NamedTempFile, SourceError> {
            Err(match &self.0 {
                SourceError::Status(code) => SourceError::Status(*code),
                SourceError::TooLarge => SourceError::TooLarge,
                SourceError::InvalidUrl => SourceError::InvalidUrl,
                SourceError::Install(message) => SourceError::Install(message.clone()),
                SourceError::Validation(message) => SourceError::Validation(message.clone()),
                SourceError::Request(error) => SourceError::Validation(error.to_string()),
                SourceError::Io(error) => SourceError::Validation(error.to_string()),
                SourceError::Tempfile(error) => SourceError::Validation(error.to_string()),
            })
        }
    }

    struct PanicDownloader;

    impl DefinitionDownloader for PanicDownloader {
        fn download(
            &self,
            _url: &str,
            _directory: &Path,
            _max_bytes: u64,
        ) -> Result<NamedTempFile, SourceError> {
            panic!("local-only resolution must not call downloader");
        }
    }

    fn config(path: PathBuf, url: Option<String>) -> ProtectionConfig {
        ProtectionConfig {
            ban_mode: true,
            honeypot_mode: false,
            wordpress_site: false,
            ban_duration: Duration::from_secs(60),
            definitions_db: path,
            definitions_url: url,
            audit_log: PathBuf::from("audit.ndjson"),
            limits: Limits::default(),
            fail2ban: Default::default(),
            ban_extensions: Vec::new(),
        }
    }

    fn insert_test_definition(connection: &Connection) {
        connection
            .execute_batch(
                "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (9133,'operator-scanner',1,'path',NULL,'exact','/operator-check',1,
                     'scanner',1,'test rule',1,'now','now');",
            )
            .unwrap();
    }

    fn assert_operator_rule(snapshot: &DefinitionSnapshot) {
        let definitions = snapshot.definitions();
        assert_eq!(definitions.len(), 1);
        let definition = definitions[0].definition();
        assert_eq!(definition.id, 9133);
        assert_eq!(definition.name, "operator-scanner");
        assert_eq!(definition.pattern, "/operator-check");
    }

    fn tls_server(
        body: Vec<u8>,
        headers: &str,
        delay: Option<Duration>,
    ) -> (String, Vec<u8>, thread::JoinHandle<()>) {
        tls_server_status("200 OK", body, headers, delay)
    }

    fn tls_server_status(
        status: &str,
        body: Vec<u8>,
        headers: &str,
        delay: Option<Duration>,
    ) -> (String, Vec<u8>, thread::JoinHandle<()>) {
        install_rustls_provider();
        let status = status.to_owned();
        let headers = headers.to_owned();
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate_der = certified.cert.der().to_vec();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(certificate_der.clone())], key)
            .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if let Some(delay) = delay {
                thread::sleep(delay);
            }
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\n{}Connection: close\r\n\r\n",
                headers
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        });
        (
            format!("https://localhost:{}/definitions.sqlite", address.port()),
            certificate_der,
            join,
        )
    }

    #[test]
    fn valid_remote_candidate_is_installed_after_validation() {
        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate.sqlite");
        initialize_database(&candidate).unwrap();
        let connection = Connection::open(&candidate).unwrap();
        insert_test_definition(&connection);
        connection
            .execute(
                "UPDATE schema_meta SET value = '7' WHERE key = 'snapshot_version'",
                [],
            )
            .unwrap();
        drop(connection);
        let local = directory.path().join("active.sqlite");
        let config = config(local.clone(), Some("https://example.invalid/db".to_owned()));
        let sender = MetricEventSender::from_limits(&config.limits).unwrap().0;
        let snapshot =
            resolve_snapshot(&config, &FixtureDownloader { source: candidate }, &sender).unwrap();
        assert_operator_rule(&snapshot);
        assert_eq!(snapshot.snapshot_version(), 7);
        assert!(local.is_file());
        let installed = SnapshotLoader::new(Limits::default())
            .unwrap()
            .load(&local)
            .unwrap();
        assert_operator_rule(&installed);
        assert_eq!(installed.snapshot_version(), 7);
    }

    #[test]
    fn production_client_rejects_http_before_network() {
        let downloader = ReqwestDefinitionDownloader::new().unwrap();
        let directory = tempdir().unwrap();
        let error = downloader
            .download(
                "http://example.invalid/definitions.sqlite",
                directory.path(),
                1024,
            )
            .unwrap_err();
        assert!(matches!(error, SourceError::InvalidUrl));
    }

    #[test]
    fn production_downloader_streams_local_tls_sqlite() {
        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate.sqlite");
        initialize_database(&candidate).unwrap();
        let connection = Connection::open(&candidate).unwrap();
        insert_test_definition(&connection);
        drop(connection);
        let bytes = fs::read(&candidate).unwrap();
        let (url, certificate, server) = tls_server(
            bytes.clone(),
            &format!("Content-Length: {}\r\n", bytes.len()),
            None,
        );
        let downloader =
            ReqwestDefinitionDownloader::new_with_root_certificate(&certificate).unwrap();
        let temp = downloader
            .download(&url, directory.path(), 64 * 1024 * 1024)
            .unwrap();
        assert_eq!(fs::read(temp.path()).unwrap(), bytes);
        server.join().unwrap();
    }

    #[test]
    fn production_downloader_rejects_downgrade_and_enforces_timeout() {
        let directory = tempdir().unwrap();
        let (url, certificate, server) = tls_server_status(
            "302 Found",
            Vec::new(),
            "Location: http://127.0.0.1:1/definitions.sqlite\r\n",
            None,
        );
        let downloader =
            ReqwestDefinitionDownloader::new_with_root_certificate(&certificate).unwrap();
        let error = downloader
            .download(&url, directory.path(), 1024)
            .unwrap_err();
        assert!(matches!(error, SourceError::Request(_)));
        server.join().unwrap();

        let (url, certificate, server) =
            tls_server(Vec::new(), "", Some(Duration::from_millis(200)));
        let downloader = ReqwestDefinitionDownloader::new_with_root_certificate_and_timeout(
            &certificate,
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(downloader.download(&url, directory.path(), 1024).is_err());
        server.join().unwrap();
    }

    #[test]
    fn production_downloader_enforces_chunked_actual_bytes_without_length() {
        let directory = tempdir().unwrap();
        let (url, certificate, server) = tls_server(vec![7u8; 128], "", None);
        let downloader =
            ReqwestDefinitionDownloader::new_with_root_certificate(&certificate).unwrap();
        assert!(matches!(
            downloader.download(&url, directory.path(), 32),
            Err(SourceError::TooLarge)
        ));
        server.join().unwrap();
    }

    #[test]
    fn chunked_body_limit_is_enforced_without_content_length() {
        let directory = tempdir().unwrap();
        let mut body = std::io::Cursor::new(vec![0u8; 33]);
        assert!(matches!(
            copy_reader(&mut body, directory.path(), 32),
            Err(SourceError::TooLarge)
        ));
    }

    #[test]
    fn invalid_remote_falls_back_and_preserves_local_cache() {
        let directory = tempdir().unwrap();
        let local = directory.path().join("active.sqlite");
        initialize_database(&local).unwrap();
        let connection = Connection::open(&local).unwrap();
        insert_test_definition(&connection);
        drop(connection);
        let before = fs::read(&local).unwrap();
        let config = config(local.clone(), Some("https://example.invalid/db".to_owned()));
        let (sender, receiver) = MetricEventSender::from_limits(&config.limits).unwrap();
        let invalid = directory.path().join("invalid.sqlite");
        fs::write(&invalid, b"not sqlite").unwrap();
        let snapshot =
            resolve_snapshot(&config, &FixtureDownloader { source: invalid }, &sender).unwrap();
        assert_operator_rule(&snapshot);
        assert_eq!(before, fs::read(local).unwrap());
        assert_eq!(
            receiver.try_recv(),
            Some(MetricEvent::InvalidDefinitionSource)
        );
    }

    #[test]
    fn non_success_and_oversize_failures_use_valid_local_source() {
        let directory = tempdir().unwrap();
        let local = directory.path().join("active.sqlite");
        initialize_database(&local).unwrap();
        let connection = Connection::open(&local).unwrap();
        insert_test_definition(&connection);
        drop(connection);
        let config = config(local, Some("https://example.invalid/db".to_owned()));
        for failure in [SourceError::Status(503), SourceError::TooLarge] {
            let (sender, receiver) = MetricEventSender::from_limits(&config.limits).unwrap();
            let snapshot = resolve_snapshot(&config, &FailingDownloader(failure), &sender).unwrap();
            assert_operator_rule(&snapshot);
            assert_eq!(
                receiver.try_recv(),
                Some(MetricEvent::InvalidDefinitionSource)
            );
        }
    }

    #[test]
    fn missing_local_and_failed_remote_fails_closed() {
        let directory = tempdir().unwrap();
        let local = directory.path().join("missing.sqlite");
        let config = config(local, Some("https://example.invalid/db".to_owned()));
        let (sender, _receiver) = MetricEventSender::from_limits(&config.limits).unwrap();
        assert!(
            resolve_snapshot(
                &config,
                &FailingDownloader(SourceError::Status(500)),
                &sender
            )
            .is_err()
        );
    }

    #[test]
    fn local_only_resolution_does_not_call_downloader() {
        let directory = tempdir().unwrap();
        let local = directory.path().join("local.sqlite");
        initialize_database(&local).unwrap();
        let connection = Connection::open(&local).unwrap();
        insert_test_definition(&connection);
        drop(connection);
        let config = config(local, None);
        let (sender, _receiver) = MetricEventSender::from_limits(&config.limits).unwrap();
        let snapshot = resolve_snapshot(&config, &PanicDownloader, &sender).unwrap();
        assert_operator_rule(&snapshot);
    }

    #[cfg(unix)]
    #[test]
    fn remote_install_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.sqlite");
        initialize_database(&target).unwrap();
        let connection = Connection::open(&target).unwrap();
        insert_test_definition(&connection);
        drop(connection);
        let local = directory.path().join("active.sqlite");
        symlink(&target, &local).unwrap();
        let config = config(local.clone(), Some("https://example.invalid/db".to_owned()));
        let (sender, _receiver) = MetricEventSender::from_limits(&config.limits).unwrap();
        let candidate = directory.path().join("candidate.sqlite");
        fs::copy(&target, &candidate).unwrap();
        let snapshot =
            resolve_snapshot(&config, &FixtureDownloader { source: candidate }, &sender).unwrap();
        assert_operator_rule(&snapshot);
        assert!(local.is_symlink());
    }
}
