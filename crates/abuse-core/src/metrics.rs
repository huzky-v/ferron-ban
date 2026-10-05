use crate::config::Limits;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

pub const HARD_MAX_METRIC_QUEUE: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricEvent {
    BanCreated,
    BanExpired,
    BanCapacityExhausted,
    HoneypotResponse,
    KnownRuleMatch,
    UnmatchedBannedRequest,
    AuditMinimalFallback,
    DroppedAuditRecord,
    AuditWriterError,
    InvalidDefinition,
    InvalidDefinitionSource,
    NormalizationError,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricSnapshot {
    pub bans_created: u64,
    pub bans_expired: u64,
    pub bans_capacity_exhausted: u64,
    pub honeypot_responses: u64,
    pub known_rule_matches: u64,
    pub unmatched_banned_requests: u64,
    pub audit_minimal_fallbacks: u64,
    pub dropped_audit_records: u64,
    pub audit_writer_errors: u64,
    pub invalid_definitions: u64,
    pub invalid_definition_sources: u64,
    pub normalization_errors: u64,
}

pub trait MetricSink: Send + Sync {
    /// Must be a bounded, nonblocking operation. Implementations used by the
    /// policy engine must never perform disk, network, or mutex-contended I/O.
    fn try_record(&self, event: MetricEvent) -> bool;
}

pub struct MetricEventSender {
    tx: SyncSender<MetricEvent>,
    capacity: usize,
    dropped: AtomicU64,
}

pub struct MetricEventReceiver {
    rx: Receiver<MetricEvent>,
}

impl MetricEventSender {
    pub fn from_limits(limits: &Limits) -> Result<(Arc<Self>, MetricEventReceiver), &'static str> {
        Self::channel(limits.max_metric_queue)
    }

    pub fn channel(capacity: usize) -> Result<(Arc<Self>, MetricEventReceiver), &'static str> {
        if capacity == 0 || capacity > HARD_MAX_METRIC_QUEUE {
            return Err("metric queue capacity is outside hard limits");
        }
        let (tx, rx) = mpsc::sync_channel(capacity);
        Ok((
            Arc::new(Self {
                tx,
                capacity,
                dropped: AtomicU64::new(0),
            }),
            MetricEventReceiver { rx },
        ))
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl MetricSink for MetricEventSender {
    fn try_record(&self, event: MetricEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

impl MetricEventReceiver {
    pub fn try_recv(&self) -> Option<MetricEvent> {
        self.rx.try_recv().ok()
    }
}

pub struct MetricDispatcher {
    metrics: std::sync::Arc<Metrics>,
    sink: Option<Arc<MetricEventSender>>,
}

impl MetricDispatcher {
    pub fn new(metrics: std::sync::Arc<Metrics>, sink: Option<Arc<MetricEventSender>>) -> Self {
        Self { metrics, sink }
    }
}

impl MetricSink for MetricDispatcher {
    fn try_record(&self, event: MetricEvent) -> bool {
        self.metrics.record(event);
        if let Some(sink) = &self.sink {
            return sink.try_record(event);
        }
        true
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    bans_created: AtomicU64,
    bans_expired: AtomicU64,
    bans_capacity_exhausted: AtomicU64,
    honeypot_responses: AtomicU64,
    known_rule_matches: AtomicU64,
    unmatched_banned_requests: AtomicU64,
    audit_minimal_fallbacks: AtomicU64,
    dropped_audit_records: AtomicU64,
    audit_writer_errors: AtomicU64,
    invalid_definitions: AtomicU64,
    invalid_definition_sources: AtomicU64,
    normalization_errors: AtomicU64,
}

impl MetricSink for Metrics {
    fn try_record(&self, event: MetricEvent) -> bool {
        let counter = match event {
            MetricEvent::BanCreated => &self.bans_created,
            MetricEvent::BanExpired => &self.bans_expired,
            MetricEvent::BanCapacityExhausted => &self.bans_capacity_exhausted,
            MetricEvent::HoneypotResponse => &self.honeypot_responses,
            MetricEvent::KnownRuleMatch => &self.known_rule_matches,
            MetricEvent::UnmatchedBannedRequest => &self.unmatched_banned_requests,
            MetricEvent::AuditMinimalFallback => &self.audit_minimal_fallbacks,
            MetricEvent::DroppedAuditRecord => &self.dropped_audit_records,
            MetricEvent::AuditWriterError => &self.audit_writer_errors,
            MetricEvent::InvalidDefinition => &self.invalid_definitions,
            MetricEvent::InvalidDefinitionSource => &self.invalid_definition_sources,
            MetricEvent::NormalizationError => &self.normalization_errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        true
    }
}

impl Metrics {
    pub fn record(&self, event: MetricEvent) {
        let _ = <Self as MetricSink>::try_record(self, event);
    }

    pub fn snapshot(&self) -> MetricSnapshot {
        MetricSnapshot {
            bans_created: self.bans_created.load(Ordering::Relaxed),
            bans_expired: self.bans_expired.load(Ordering::Relaxed),
            bans_capacity_exhausted: self.bans_capacity_exhausted.load(Ordering::Relaxed),
            honeypot_responses: self.honeypot_responses.load(Ordering::Relaxed),
            known_rule_matches: self.known_rule_matches.load(Ordering::Relaxed),
            unmatched_banned_requests: self.unmatched_banned_requests.load(Ordering::Relaxed),
            audit_minimal_fallbacks: self.audit_minimal_fallbacks.load(Ordering::Relaxed),
            dropped_audit_records: self.dropped_audit_records.load(Ordering::Relaxed),
            audit_writer_errors: self.audit_writer_errors.load(Ordering::Relaxed),
            invalid_definitions: self.invalid_definitions.load(Ordering::Relaxed),
            invalid_definition_sources: self.invalid_definition_sources.load(Ordering::Relaxed),
            normalization_errors: self.normalization_errors.load(Ordering::Relaxed),
        }
    }
}
