use crate::audit::{AuditEnqueueResult, AuditQueue, AuditRecord, ResponseMode};
use crate::ban::{BanEntry, BanInsertResult, BanRegistry, BanTrigger, ClockReading};
use crate::config::ProtectionConfig;
use crate::error::{CoreError, Result};
use crate::honeypot::HoneypotResponse;
use crate::matcher::{DefinitionSnapshot, MatchResult};
use crate::metrics::{MetricDispatcher, MetricEvent, MetricEventSender, MetricSink, Metrics};
use crate::model::{AttackType, RequestInput, RequestView};
use crate::normalize::{degraded_request_view, normalize_request};
use crate::template::TemplateCatalog;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Continue,
    Fail2ban {
        status_code: u16,
        retry_after_seconds: u64,
        capacity_exhausted: bool,
        normalization_error: bool,
    },
    Honeypot(HoneypotResponse),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub matches: MatchResult,
    /// This request matched a configured ban extension (not just an existing ban).
    pub extension_match: bool,
    pub ban: Option<BanEntry>,
    pub audit: Option<AuditEnqueueResult>,
}

pub struct PolicyEngine {
    config: ProtectionConfig,
    snapshot: DefinitionSnapshot,
    registry: BanRegistry,
    audit_queue: Arc<AuditQueue>,
    metrics: Arc<Metrics>,
    metric_sink: Arc<dyn MetricSink>,
    coordination: Vec<Mutex<()>>,
    catalog: Option<Arc<TemplateCatalog>>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyEngine")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot.summary())
            .field("registry_capacity", &self.registry.capacity())
            .finish_non_exhaustive()
    }
}

impl PolicyEngine {
    pub fn new(config: ProtectionConfig, snapshot: DefinitionSnapshot) -> Result<Self> {
        config
            .validate()
            .map_err(|error| CoreError::InvalidConfiguration(error.to_string()))?;
        let registry = BanRegistry::new(config.limits.max_bans)
            .map_err(|error| CoreError::InvalidConfiguration(error.to_owned()))?;
        let audit_queue = Arc::new(AuditQueue::new(config.limits.max_audit_queue)?);
        Self::with_components(
            config,
            snapshot,
            registry,
            audit_queue,
            Arc::new(Metrics::default()),
        )
    }

    pub fn with_catalog(
        config: ProtectionConfig,
        snapshot: DefinitionSnapshot,
        catalog: Arc<TemplateCatalog>,
    ) -> Result<Self> {
        let registry = BanRegistry::new(config.limits.max_bans)
            .map_err(|error| CoreError::InvalidConfiguration(error.to_owned()))?;
        let audit_queue = Arc::new(AuditQueue::new(config.limits.max_audit_queue)?);
        Self::with_metric_sink_and_catalog(
            config,
            snapshot,
            registry,
            audit_queue,
            Arc::new(Metrics::default()),
            None,
            Some(catalog),
        )
    }

    pub fn with_components(
        config: ProtectionConfig,
        snapshot: DefinitionSnapshot,
        registry: BanRegistry,
        audit_queue: Arc<AuditQueue>,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        Self::with_metric_sink_and_catalog(
            config,
            snapshot,
            registry,
            audit_queue,
            metrics,
            None,
            None,
        )
    }

    pub fn with_metric_sink_and_catalog(
        config: ProtectionConfig,
        snapshot: DefinitionSnapshot,
        registry: BanRegistry,
        audit_queue: Arc<AuditQueue>,
        metrics: Arc<Metrics>,
        sink: Option<Arc<MetricEventSender>>,
        catalog: Option<Arc<TemplateCatalog>>,
    ) -> Result<Self> {
        config
            .validate()
            .map_err(|error| CoreError::InvalidConfiguration(error.to_string()))?;
        if snapshot.limits() != &config.limits {
            return Err(CoreError::InvalidConfiguration(
                "snapshot and policy limits differ".to_owned(),
            ));
        }
        if registry.capacity() != config.limits.max_bans {
            return Err(CoreError::InvalidConfiguration(
                "ban registry capacity differs from policy limits".to_owned(),
            ));
        }
        if audit_queue.capacity() != config.limits.max_audit_queue {
            return Err(CoreError::InvalidConfiguration(
                "audit queue capacity differs from policy limits".to_owned(),
            ));
        }
        if let Some(sink) = &sink
            && sink.capacity() != config.limits.max_metric_queue
        {
            return Err(CoreError::InvalidConfiguration(
                "metric event queue capacity differs from policy limits".to_owned(),
            ));
        }
        if config.honeypot_mode && !catalog.as_ref().is_some_and(|c| c.covers(&snapshot)) {
            return Err(CoreError::InvalidConfiguration(
                "honeypot mode requires a validated catalog covering the snapshot".to_owned(),
            ));
        }
        let coordination = (0..256).map(|_| Mutex::new(())).collect();
        let metric_sink: Arc<dyn MetricSink> =
            Arc::new(MetricDispatcher::new(metrics.clone(), sink));
        Ok(Self {
            config,
            snapshot,
            registry,
            audit_queue,
            metrics,
            metric_sink,
            coordination,
            catalog,
        })
    }

    pub fn with_metric_sink(
        config: ProtectionConfig,
        snapshot: DefinitionSnapshot,
        registry: BanRegistry,
        audit_queue: Arc<AuditQueue>,
        metrics: Arc<Metrics>,
        sink: Option<Arc<MetricEventSender>>,
    ) -> Result<Self> {
        Self::with_metric_sink_and_catalog(
            config,
            snapshot,
            registry,
            audit_queue,
            metrics,
            sink,
            None,
        )
    }

    pub fn snapshot(&self) -> &DefinitionSnapshot {
        &self.snapshot
    }

    pub fn registry(&self) -> &BanRegistry {
        &self.registry
    }

    pub fn audit_queue(&self) -> &Arc<AuditQueue> {
        &self.audit_queue
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Normalize at the adapter boundary. Malformed input is explicitly
    /// fail-closed for the current request and never enters the matcher.
    pub fn evaluate_input(&self, input: RequestInput, wall_time: SystemTime) -> PolicyDecision {
        // Disabled protection is a true no-op: do not normalize, decode, or
        // reject anything when neither mode can change the pipeline.
        if !self.config.ban_mode && !self.config.honeypot_mode {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }
        // Allowlist is checked against the canonical adapter-supplied IP
        // before parsing any attacker-controlled request fields.
        if self.snapshot.is_allowlisted(input.client_ip) {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }
        let fallback_input = input.clone();
        match normalize_request(input, &self.config.limits) {
            Ok(request) => self.evaluate(&request, wall_time),
            Err(_) => self.evaluate_malformed_input(fallback_input, wall_time),
        }
    }

    pub fn evaluate_malformed_input(
        &self,
        input: RequestInput,
        wall_time: SystemTime,
    ) -> PolicyDecision {
        if !self.config.ban_mode && !self.config.honeypot_mode
            || self.snapshot.is_allowlisted(input.client_ip)
        {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }
        self.record_metric(MetricEvent::NormalizationError);
        if !self.config.ban_mode {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }
        let lock_index = coordination_index(input.client_ip);
        let _guard = self.coordination[lock_index]
            .lock()
            .expect("policy coordination mutex poisoned");
        let reading = self.registry.clock_reading();
        let Some(ban) = self.registry.get_at(
            input.client_ip,
            ClockReading {
                wall_time,
                monotonic: reading.monotonic,
            },
        ) else {
            return PolicyDecision {
                action: self.fail2ban(false, true),
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        };
        let degraded = degraded_request_view(&input, &self.config.limits);
        let original_id_leak = ban
            .triggering_attack_types
            .iter()
            .any(|attack_type| attack_type.is_id_leak());
        let action = if self.config.honeypot_mode && original_id_leak {
            PolicyAction::NotFound
        } else {
            self.fail2ban(false, true)
        };
        let response_mode = response_mode(&action);
        let audit = Some(self.enqueue_audit(&ban, &degraded, wall_time, response_mode));
        PolicyDecision {
            action,
            matches: empty_match_result(),
            extension_match: false,
            ban: Some(ban),
            audit,
        }
    }

    pub fn evaluate(&self, request: &RequestView, wall_time: SystemTime) -> PolicyDecision {
        let lock_index = coordination_index(request.client_ip);
        let _guard = self.coordination[lock_index]
            .lock()
            .expect("policy coordination mutex poisoned");
        let mut reading = self.registry.clock_reading();
        reading.wall_time = wall_time;
        self.evaluate_locked(request, reading)
    }

    pub fn evaluate_at(&self, request: &RequestView, reading: ClockReading) -> PolicyDecision {
        let lock_index = coordination_index(request.client_ip);
        let _guard = self.coordination[lock_index]
            .lock()
            .expect("policy coordination mutex poisoned");
        self.evaluate_locked(request, reading)
    }

    fn evaluate_locked(&self, request: &RequestView, reading: ClockReading) -> PolicyDecision {
        if !self.config.ban_mode && !self.config.honeypot_mode {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }
        // Allowlist is deliberately before both matching and enforcement.
        if self.snapshot.is_allowlisted(request.client_ip) {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches: empty_match_result(),
                extension_match: false,
                ban: None,
                audit: None,
            };
        }

        // Match first so no_log suppresses logging even for extension hits.
        let matches = self
            .snapshot
            .match_request_for_site(request, self.config.wordpress_site);
        // A configured extension takes priority over actionable snapshot matches,
        // honeypots, and any active ban's original response mode.
        if self.config.ban_mode
            && !matches.matched_attack_types.contains(&AttackType::WpBan)
            && self.is_ban_extension_path(request)
        {
            let expired_before = self.registry.expired_count();
            // -1 is reserved for the synthetic extension trigger (DB IDs are positive).
            let insert = self.registry.try_ban_at(
                request.client_ip,
                reading,
                self.config.ban_duration,
                BanTrigger {
                    definition_ids: vec![-1],
                    attack_types: vec![AttackType::Scanner],
                    original_request_summary: request_summary(request),
                },
            );
            for _ in 0..self.registry.expired_count().saturating_sub(expired_before) {
                self.record_metric(MetricEvent::BanExpired);
            }
            let (ban, capacity_exhausted) = match insert {
                Ok(BanInsertResult::Created(ban)) => {
                    self.record_metric(MetricEvent::BanCreated);
                    (Some(ban), false)
                }
                Ok(BanInsertResult::Existing(ban)) => (Some(ban), false),
                Ok(BanInsertResult::CapacityExhausted) => {
                    self.record_metric(MetricEvent::BanCapacityExhausted);
                    (None, true)
                }
                Err(_) => (None, false),
            };
            return PolicyDecision {
                action: self.fail2ban(capacity_exhausted, false),
                matches: MatchResult {
                    no_log: matches.no_log,
                    ..empty_match_result()
                },
                extension_match: true,
                ban,
                audit: None,
            };
        }

        if matches.is_match() {
            self.record_metric(MetricEvent::KnownRuleMatch);
        }

        if !self.config.ban_mode {
            let action = if self.config.honeypot_mode && matches.has_id_leak() {
                self.honeypot_action(&matches)
            } else {
                PolicyAction::Continue
            };
            return PolicyDecision {
                action,
                matches,
                extension_match: false,
                ban: None,
                audit: None,
            };
        }

        let expired_before = self.registry.expired_count();
        let active_ban = self.registry.get_at(request.client_ip, reading);
        let expired_after = self.registry.expired_count();
        for _ in 0..expired_after.saturating_sub(expired_before) {
            self.record_metric(MetricEvent::BanExpired);
        }
        if let Some(ban) = active_ban {
            let original_id_leak = ban
                .triggering_attack_types
                .iter()
                .any(|attack_type| attack_type.is_id_leak());
            let action = if self.config.honeypot_mode && matches.has_id_leak() {
                self.honeypot_action(&matches)
            } else if self.config.honeypot_mode && !matches.is_match() && original_id_leak {
                PolicyAction::NotFound
            } else {
                self.fail2ban(false, false)
            };
            let audit = if !matches.is_match() && !matches.no_log {
                Some(self.enqueue_audit(&ban, request, reading.wall_time, response_mode(&action)))
            } else {
                None
            };
            return PolicyDecision {
                action,
                matches,
                extension_match: false,
                ban: Some(ban),
                audit,
            };
        }

        if !matches.is_match() {
            return PolicyDecision {
                action: PolicyAction::Continue,
                matches,
                extension_match: false,
                ban: None,
                audit: None,
            };
        }

        let insert = self.registry.try_ban_at(
            request.client_ip,
            reading,
            self.config.ban_duration,
            BanTrigger {
                definition_ids: matches.matched_definition_ids.clone(),
                attack_types: matches.matched_attack_types.clone(),
                original_request_summary: request_summary(request),
            },
        );
        match insert {
            Ok(BanInsertResult::Created(ban)) => {
                self.record_metric(MetricEvent::BanCreated);
                let action = if self.config.honeypot_mode && matches.has_id_leak() {
                    self.honeypot_action(&matches)
                } else {
                    self.fail2ban(false, false)
                };
                PolicyDecision {
                    action,
                    matches,
                    extension_match: false,
                    ban: Some(ban),
                    audit: None,
                }
            }
            Ok(BanInsertResult::Existing(ban)) => {
                let action = if self.config.honeypot_mode && matches.has_id_leak() {
                    self.honeypot_action(&matches)
                } else {
                    self.fail2ban(false, false)
                };
                PolicyDecision {
                    action,
                    matches,
                    extension_match: false,
                    ban: Some(ban),
                    audit: None,
                }
            }
            Ok(BanInsertResult::CapacityExhausted) => {
                self.record_metric(MetricEvent::BanCapacityExhausted);
                let action = if self.config.honeypot_mode && matches.has_id_leak() {
                    // A decoy is still the required current-request response;
                    // capacity only prevents future enforcement for this IP.
                    self.honeypot_action(&matches)
                } else {
                    self.fail2ban(true, false)
                };
                PolicyDecision {
                    action,
                    matches,
                    extension_match: false,
                    ban: None,
                    audit: None,
                }
            }
            Err(_) => PolicyDecision {
                action: self.fail2ban(false, false),
                matches,
                extension_match: false,
                ban: None,
                audit: None,
            },
        }
    }

    fn is_ban_extension_path(&self, request: &RequestView) -> bool {
        // A truncated path cannot safely establish its final extension.
        if !request.path.complete {
            return false;
        }
        let segment = request.path.as_str().rsplit('/').next().unwrap_or("");
        let Some((stem, extension)) = segment.rsplit_once('.') else {
            return false;
        };
        !stem.is_empty()
            && self.config.ban_extensions.iter().any(|configured| {
                !(self.config.wordpress_site && configured == "php")
                    && extension.eq_ignore_ascii_case(configured)
            })
    }

    fn enqueue_audit(
        &self,
        ban: &BanEntry,
        request: &RequestView,
        now: SystemTime,
        response_mode: ResponseMode,
    ) -> AuditEnqueueResult {
        self.record_metric(MetricEvent::UnmatchedBannedRequest);
        let record = AuditRecord::unmatched(
            now,
            ban,
            self.snapshot.snapshot_version(),
            request,
            response_mode,
            &self.config.limits,
        );
        let record = if record
            .to_json_line(self.config.limits.max_audit_line_bytes)
            .is_ok()
        {
            record
        } else {
            self.record_metric(MetricEvent::AuditMinimalFallback);
            let minimal = record.minimal();
            if minimal
                .to_json_line(self.config.limits.max_audit_line_bytes)
                .is_err()
            {
                self.record_metric(MetricEvent::DroppedAuditRecord);
                return AuditEnqueueResult::FullDrop;
            }
            minimal
        };
        let result = self.audit_queue.try_enqueue(record);
        match result {
            AuditEnqueueResult::MinimalFallback => {
                self.record_metric(MetricEvent::AuditMinimalFallback)
            }
            AuditEnqueueResult::FullDrop => self.record_metric(MetricEvent::DroppedAuditRecord),
            AuditEnqueueResult::Normal => {}
        }
        result
    }

    fn fail2ban(&self, capacity_exhausted: bool, normalization_error: bool) -> PolicyAction {
        PolicyAction::Fail2ban {
            status_code: self.config.fail2ban.status_code,
            retry_after_seconds: self.config.fail2ban.retry_after.as_secs(),
            capacity_exhausted,
            normalization_error,
        }
    }

    fn honeypot_action(&self, matches: &MatchResult) -> PolicyAction {
        let response = matches
            .selected_id_leak_name
            .as_deref()
            .and_then(|name| self.catalog.as_ref()?.render(name).ok());
        match response {
            Some(response) => {
                self.record_metric(MetricEvent::HoneypotResponse);
                PolicyAction::Honeypot(response)
            }
            None => PolicyAction::NotFound,
        }
    }

    fn record_metric(&self, event: MetricEvent) {
        let _ = self.metric_sink.try_record(event);
    }
}

fn empty_match_result() -> MatchResult {
    MatchResult {
        matched_definition_ids: Vec::new(),
        matched_attack_types: Vec::new(),
        truncated: false,
        selected_id_leak_name: None,
        no_log: false,
    }
}

fn response_mode(action: &PolicyAction) -> ResponseMode {
    match action {
        PolicyAction::Honeypot(_) => ResponseMode::Honeypot,
        PolicyAction::NotFound => ResponseMode::NotFound,
        _ => ResponseMode::Fail2ban,
    }
}

fn request_summary(request: &RequestView) -> String {
    let mut summary = format!(
        "{} {}{}",
        request.method.as_str(),
        request.host.as_str(),
        request.path.as_str()
    );
    if summary.len() > 512 {
        let mut end = 512;
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
    }
    summary
}

fn coordination_index(ip: IpAddr) -> usize {
    let value = match ip {
        IpAddr::V4(ip) => u32::from(ip) as u64,
        IpAddr::V6(ip) => (u128::from(ip) ^ (u128::from(ip) >> 64)) as u64,
    };
    (value as usize) & 255
}
