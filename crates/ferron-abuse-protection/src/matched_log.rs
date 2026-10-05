use abuse_core::{AttackType, PolicyAction, PolicyDecision, PolicyEngine};
use chrono::{DateTime, Utc};
use ferron_http::HttpContext;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

pub struct MatchedLog {
    sender: SyncSender<String>,
    join: JoinHandle<()>,
}

impl MatchedLog {
    pub fn spawn(mut file: File) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<String>(1024);
        let join = thread::Builder::new()
            .name("abuse-matched-writer".to_owned())
            .spawn(move || {
                for line in receiver {
                    if let Err(error) = file.write_all(line.as_bytes()) {
                        ferron_core::log_error!("ferron abuse matched_log write failed: {}", error);
                        break;
                    }
                }
            })?;
        Ok(Self { sender, join })
    }

    pub fn record(&self, line: String) {
        if let Err(TrySendError::Full(_)) = self.sender.try_send(line) {
            ferron_core::log_error!("ferron abuse matched_log queue full; entry dropped");
        }
    }

    pub fn shutdown_and_join(self) -> thread::Result<()> {
        drop(self.sender);
        self.join.join()
    }
}

pub fn rule_names(decision: &PolicyDecision, policy: &PolicyEngine) -> Option<String> {
    if decision.matches.no_log {
        return None;
    }
    if decision.extension_match {
        return Some("extban".to_owned());
    }
    let names: Vec<_> = decision
        .matches
        .matched_definition_ids
        .iter()
        .filter_map(|id| {
            policy
                .snapshot()
                .definitions()
                .iter()
                .find(|d| d.id() == *id)
        })
        .map(|definition| {
            if definition.definition().attack_type == AttackType::WpBan {
                "wp-ban"
            } else {
                definition.name()
            }
        })
        .collect();
    if names.is_empty() {
        None
    } else {
        let mut names = names;
        names.dedup();
        Some(names.join(","))
    }
}

pub fn status(action: &PolicyAction) -> Option<u16> {
    match action {
        PolicyAction::Fail2ban { status_code, .. } => Some(*status_code),
        PolicyAction::Honeypot(response) => Some(response.status_code),
        PolicyAction::NotFound => Some(404),
        PolicyAction::Continue => None,
    }
}

/// Apache combined format, followed by the proxy IP, request host and matching definition name(s) or extban.
pub fn format_line(context: &HttpContext, now: SystemTime, status: u16, rule: &str) -> String {
    let ip = context
        .remote_address
        .map(|address| address.ip().to_canonical().to_string())
        .unwrap_or_else(|| "-".to_owned());
    let proxy_ip = crate::cloudflare::proxy_ip(context)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let timestamp: DateTime<Utc> = now.into();
    let request = context.req.as_ref();
    let method = request.map(|req| req.method().as_str()).unwrap_or("-");
    let uri = context
        .original_uri
        .as_ref()
        .map(|uri| {
            uri.path_and_query()
                .map(|path| path.as_str())
                .unwrap_or_else(|| uri.path())
        })
        .unwrap_or("/");
    let version = request
        .map(|req| match req.version() {
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2.0",
            http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        })
        .unwrap_or("HTTP/1.1");
    let header = |name| {
        request
            .and_then(|req| req.headers().get(name))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
    };
    let host = request
        .and_then(|req| req.headers().get("host"))
        .and_then(|value| value.to_str().ok())
        .or(context.hostname.as_deref())
        .unwrap_or("-");
    format!(
        "{} - - [{}] \"{} {} {}\" {} - \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"\n",
        ip,
        timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
        escape(method),
        escape(uri),
        version,
        status,
        escape(header("referer")),
        escape(header("user-agent")),
        proxy_ip,
        escape(host),
        escape(rule),
    )
}

fn escape(value: &str) -> String {
    // ipban runs before request normalization: bound attacker-controlled fields
    // here rather than building an unbounded log line for a rejected request.
    const MAX_LOG_FIELD_CHARS: usize = 8_192;
    value
        .chars()
        .take(MAX_LOG_FIELD_CHARS)
        .flat_map(|c| match c {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '"' => "\\\"".chars().collect(),
            '\\' => "\\\\".chars().collect(),
            c if c.is_control() => "?".chars().collect(),
            c => vec![c],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use abuse_core::{
        DefinitionSnapshot, Limits, ProtectionConfig, RequestInput, TemplateCatalog,
        initialize_database,
    };
    use bytes::Bytes;
    use ferron_http::HttpRequest;
    use http::Request;
    use http_body_util::{BodyExt, Empty};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn reports_definition_names_and_only_current_extension_hits() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("definitions.sqlite");
        initialize_database(&db).unwrap();
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute_batch(
                "INSERT INTO attack_definitions
            (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
             priority,description,version,created_at,updated_at) VALUES
             (101,'scan-probe',1,'path',NULL,'exact','/probe',1,'scanner',1,'',1,'now','now'),
             (102,'id-leak-dotenv',1,'path',NULL,'exact','/.env',1,'id_leak',2,'',1,'now','now'),
             (103,'wp-ban-login',1,'path',NULL,'exact','/wp-login.php',1,'wp_ban',3,'',1,'now','now'),
             (104,'no-log-favicon',1,'path',NULL,'exact','/favicon.ico',1,'no_log',0,'',1,'now','now');",
            )
            .unwrap();
        let snapshot = DefinitionSnapshot::load(&db, Limits::default()).unwrap();
        let config = ProtectionConfig {
            ban_mode: true,
            honeypot_mode: false,
            wordpress_site: false,
            ban_extensions: vec!["php".to_owned()],
            ban_duration: Duration::from_secs(60),
            definitions_db: db,
            definitions_url: None,
            audit_log: dir.path().join("audit.ndjson"),
            limits: Limits::default(),
            fail2ban: Default::default(),
        };
        let engine = PolicyEngine::new(config.clone(), snapshot.clone()).unwrap();
        let request = |target: &str| RequestInput {
            client_ip: "198.51.100.7".parse().unwrap(),
            proxy_ip: None,
            method: "GET".to_owned(),
            host: String::new(),
            target: target.to_owned(),
            user_agent: String::new(),
            headers: Vec::new(),
            request_bytes: 0,
            body_sha256: None,
        };
        let now = UNIX_EPOCH + Duration::from_secs(100_000);
        let scan = engine.evaluate_input(request("/probe"), now);
        assert_eq!(rule_names(&scan, &engine).as_deref(), Some("scan-probe"));
        assert_eq!(status(&scan.action), Some(403));
        let extension = engine.evaluate_input(request("/secret.PHP"), now);
        assert_eq!(rule_names(&extension, &engine).as_deref(), Some("extban"));
        let unmatched = engine.evaluate_input(request("/ordinary"), now);
        assert_eq!(rule_names(&unmatched, &engine), None);
        let wp = engine.evaluate_input(request("/wp-login.php"), now);
        assert!(!wp.extension_match);
        assert_eq!(rule_names(&wp, &engine).as_deref(), Some("wp-ban"));
        let favicon = engine.evaluate_input(request("/favicon.ico"), now);
        assert!(favicon.audit.is_none());
        assert_eq!(rule_names(&favicon, &engine), None);

        let templates = dir.path().join("templates");
        std::fs::create_dir(&templates).unwrap();
        std::fs::write(
            templates.join("id-leak-dotenv.yaml"),
            "version: 1\nname: id-leak-dotenv\nrestype: normal\ntemplate: 'decoy'\n",
        )
        .unwrap();
        let catalog = std::sync::Arc::new(TemplateCatalog::load(&templates, &snapshot).unwrap());
        let mut honeypot_config = config;
        honeypot_config.honeypot_mode = true;
        let honeypot_engine =
            PolicyEngine::with_catalog(honeypot_config, snapshot, catalog).unwrap();
        let honeypot = honeypot_engine.evaluate_input(request("/.env"), now);
        assert!(matches!(honeypot.action, PolicyAction::Honeypot(_)));
        assert_eq!(
            rule_names(&honeypot, &honeypot_engine).as_deref(),
            Some("id-leak-dotenv")
        );
        assert_eq!(status(&honeypot.action), Some(200));
    }

    #[test]
    fn combined_log_escapes_untrusted_fields_and_includes_host() {
        let request: HttpRequest = Request::builder()
            .method("GET")
            .header("user-agent", "probe\"\\next")
            .header("referer", "https://example.invalid/")
            .header("host", "example.invalid:8080")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let mut context = HttpContext::default();
        context.req = Some(request);
        context.original_uri = Some("/secret.php?x=1".parse().unwrap());
        context.remote_address = Some("198.51.100.7:1234".parse().unwrap());
        let line = format_line(&context, UNIX_EPOCH + Duration::from_secs(0), 429, "extban");
        assert_eq!(
            line,
            "198.51.100.7 - - [01/Jan/1970:00:00:00 +0000] \"GET /secret.php?x=1 HTTP/1.1\" 429 - \"https://example.invalid/\" \"probe\\\"\\\\next\" \"-\" \"example.invalid:8080\" \"extban\"\n"
        );
        assert_eq!(line.lines().count(), 1);
        context.insert::<crate::cloudflare::ProxyIpKey>("172.69.223.81".parse().unwrap());
        assert!(
            format_line(&context, UNIX_EPOCH, 429, "extban")
                .contains("\"172.69.223.81\" \"example.invalid:8080\"")
        );
        assert_eq!(escape("x\ny\rz"), "x\\ny\\rz");
        assert_eq!(escape(&"x".repeat(10_000)).len(), 8_192);
        context.hostname = Some("fallback.invalid".to_owned());
        context.req.as_mut().unwrap().headers_mut().remove("host");
        assert!(
            format_line(&context, UNIX_EPOCH, 429, "extban")
                .ends_with("\"fallback.invalid\" \"extban\"\n")
        );
    }

    #[test]
    fn writer_drains_queued_entries_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("matched.log");
        let writer = MatchedLog::spawn(File::create(&path).unwrap()).unwrap();
        writer.record("one\n".to_owned());
        writer.record("two\n".to_owned());
        writer.shutdown_and_join().unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "one\ntwo\n");
    }
}
