use crate::ban::BanEntry;
use crate::config::Limits;
use crate::error::{CoreError, Result};
use crate::model::{
    AttackType, BoundedValue, RequestView, is_sensitive_name, normalize_header_name,
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type HeaderMap = BTreeMap<String, Vec<String>>;
pub const REDACTED_VALUE: &str = "<redacted>";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Fail2ban,
    Honeypot,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    timestamp: String,
    incident_id: String,
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_ip: Option<String>,
    ban_expires_at: String,
    definition_snapshot_version: u64,
    triggering_definition_ids: Vec<i64>,
    triggering_attack_types: Vec<AttackType>,
    host: String,
    method: String,
    path: String,
    query: String,
    user_agent: String,
    headers: HeaderMap,
    content_length_bytes: u64,
    response_mode: ResponseMode,
    degraded: bool,
}

impl AuditRecord {
    /// Build the detailed record for the only event that belongs in this log:
    /// an unmatched request from an active, non-allowlisted ban.
    pub fn unmatched(
        now: SystemTime,
        ban: &BanEntry,
        snapshot_version: u64,
        request: &RequestView,
        response_mode: ResponseMode,
        limits: &Limits,
    ) -> Self {
        Self {
            timestamp: rfc3339(now),
            incident_id: ban.incident_id.clone(),
            ip: ban.ip.to_string(),
            proxy_ip: request.proxy_ip.map(|ip| ip.to_string()),
            ban_expires_at: rfc3339(ban.expires_at),
            definition_snapshot_version: snapshot_version,
            triggering_definition_ids: ban.triggering_definition_ids.clone(),
            triggering_attack_types: ban.triggering_attack_types.clone(),
            host: bounded(&request.host, limits.max_audit_value_length),
            method: bounded(&request.method, limits.max_audit_value_length),
            path: bounded(&request.path, limits.max_audit_value_length),
            query: bounded(&request.query_for_audit, limits.max_audit_value_length),
            user_agent: bounded(&request.user_agent, limits.max_audit_value_length),
            headers: redact_headers(&request.headers, limits),
            content_length_bytes: request.request_bytes,
            response_mode,
            degraded: request.has_truncated_input(),
        }
    }

    /// The emergency lane deliberately keeps the same valid JSON schema while
    /// removing optional forensic values. It never performs I/O.
    pub fn minimal(&self) -> Self {
        let mut minimal = self.clone();
        minimal.host = bounded_text(&minimal.host, 64);
        minimal.method = bounded_text(&minimal.method, 8);
        minimal.path = bounded_text(&minimal.path, 64);
        minimal.query = REDACTED_VALUE.to_owned();
        minimal.user_agent = REDACTED_VALUE.to_owned();
        minimal.headers.clear();
        minimal.degraded = true;
        minimal
    }

    pub fn validate(&self) -> Result<()> {
        if self.definition_snapshot_version == 0 {
            return Err(CoreError::InvalidRequest(
                "audit snapshot version must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn to_json_line(&self, max_bytes: usize) -> Result<String> {
        self.validate()?;
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        if line.len() > max_bytes {
            return Err(CoreError::AuditRecordTooLarge);
        }
        Ok(line)
    }

    pub fn minimal_json_line(&self, max_bytes: usize) -> Result<String> {
        self.minimal().to_json_line(max_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEnqueueResult {
    Normal,
    MinimalFallback,
    FullDrop,
}

struct QueueState {
    normal: VecDeque<AuditRecord>,
    emergency: VecDeque<AuditRecord>,
    shutdown: bool,
}

/// Two bounded nonblocking lanes. Producers never wait on disk and the
/// eventual writer can block on `wait_dequeue` without polling.
pub struct AuditQueue {
    state: Mutex<QueueState>,
    wake: Condvar,
    normal_capacity: usize,
    emergency_capacity: usize,
    dropped: AtomicU64,
    failed: AtomicU64,
}

impl std::fmt::Debug for AuditQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditQueue")
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

impl AuditQueue {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity < 2 {
            return Err(CoreError::InvalidConfiguration(
                "audit queue capacity must reserve normal and emergency lanes".to_owned(),
            ));
        }
        let emergency_capacity = (capacity / 4).max(1);
        let normal_capacity = capacity - emergency_capacity;
        Ok(Self {
            state: Mutex::new(QueueState {
                normal: VecDeque::with_capacity(normal_capacity),
                emergency: VecDeque::with_capacity(emergency_capacity),
                shutdown: false,
            }),
            wake: Condvar::new(),
            normal_capacity,
            emergency_capacity,
            dropped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        })
    }

    pub fn capacity(&self) -> usize {
        self.normal_capacity + self.emergency_capacity
    }

    pub fn try_enqueue(&self, record: AuditRecord) -> AuditEnqueueResult {
        let mut state = self.state.lock().expect("audit queue mutex poisoned");
        if record.validate().is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return AuditEnqueueResult::FullDrop;
        }
        if state.shutdown || self.failed.load(Ordering::Relaxed) != 0 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return AuditEnqueueResult::FullDrop;
        }
        if state.normal.len() < self.normal_capacity {
            state.normal.push_back(record);
            self.wake.notify_one();
            return AuditEnqueueResult::Normal;
        }
        if state.emergency.len() < self.emergency_capacity {
            state.emergency.push_back(record.minimal());
            self.wake.notify_one();
            return AuditEnqueueResult::MinimalFallback;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        AuditEnqueueResult::FullDrop
    }

    /// Emergency records have priority so a full normal lane cannot starve the
    /// minimal preservation lane.
    pub fn try_dequeue(&self) -> Option<AuditRecord> {
        let mut state = self.state.lock().expect("audit queue mutex poisoned");
        state
            .emergency
            .pop_front()
            .or_else(|| state.normal.pop_front())
    }

    /// Create the only public consumer seam. The returned receiver is intended
    /// for a dedicated OS/blocking worker thread; never call `recv` directly
    /// from an async runtime worker.
    fn blocking_receiver(&self) -> AuditQueueReceiver<'_> {
        AuditQueueReceiver { queue: self }
    }

    fn wait_dequeue(&self) -> Option<AuditRecord> {
        let mut state = self.state.lock().expect("audit queue mutex poisoned");
        loop {
            if let Some(record) = state
                .emergency
                .pop_front()
                .or_else(|| state.normal.pop_front())
            {
                return Some(record);
            }
            if state.shutdown {
                return None;
            }
            state = self.wake.wait(state).expect("audit queue mutex poisoned");
        }
    }

    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("audit queue mutex poisoned");
        state.shutdown = true;
        self.wake.notify_all();
    }

    pub fn fail(&self) {
        self.failed.store(1, Ordering::Release);
        let mut state = self.state.lock().expect("audit queue mutex poisoned");
        state.shutdown = true;
        self.wake.notify_all();
    }

    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire) != 0
    }

    pub fn is_shutdown(&self) -> bool {
        self.state
            .lock()
            .expect("audit queue mutex poisoned")
            .shutdown
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

struct AuditQueueReceiver<'a> {
    queue: &'a AuditQueue,
}

/// Owned blocking writer lifecycle for Ferron adapters. This always spawns
/// a dedicated OS thread; Ferron async secondary tasks must manage this handle
/// but must not call `recv` themselves.
#[must_use = "call shutdown_and_join on the owned audit writer"]
pub struct AuditWriter {
    queue: std::sync::Arc<AuditQueue>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditWriter")
            .finish_non_exhaustive()
    }
}

impl AuditWriter {
    pub fn spawn_until<F>(queue: std::sync::Arc<AuditQueue>, handler: F) -> std::io::Result<Self>
    where
        F: FnMut(AuditRecord) -> bool + Send + 'static,
    {
        let worker_queue = std::sync::Arc::clone(&queue);
        let join = thread::Builder::new()
            .name("abuse-audit-writer".to_owned())
            .spawn(move || {
                let receiver = worker_queue.blocking_receiver();
                let mut handler = handler;
                while let Some(record) = receiver.recv() {
                    if !handler(record) {
                        worker_queue.fail();
                        break;
                    }
                }
            })?;
        Ok(Self {
            queue,
            join: Some(join),
        })
    }

    /// Run the owned blocking consumer on the current OS/blocking worker.
    /// Async adapters should invoke this through their runtime's dedicated
    /// blocking facility rather than calling it from an async task directly.
    pub fn run_blocking<F>(queue: std::sync::Arc<AuditQueue>, mut handler: F)
    where
        F: FnMut(AuditRecord),
    {
        let receiver = queue.blocking_receiver();
        while let Some(record) = receiver.recv() {
            handler(record);
        }
    }

    pub fn run_blocking_until<F>(queue: std::sync::Arc<AuditQueue>, mut handler: F)
    where
        F: FnMut(AuditRecord) -> bool,
    {
        let receiver = queue.blocking_receiver();
        while let Some(record) = receiver.recv() {
            if !handler(record) {
                queue.fail();
                break;
            }
        }
    }

    pub fn spawn<F>(queue: std::sync::Arc<AuditQueue>, handler: F) -> std::io::Result<Self>
    where
        F: FnMut(AuditRecord) + Send + 'static,
    {
        let worker_queue = std::sync::Arc::clone(&queue);
        let join = thread::Builder::new()
            .name("abuse-audit-writer".to_owned())
            .spawn(move || {
                let receiver = worker_queue.blocking_receiver();
                let mut handler = handler;
                while let Some(record) = receiver.recv() {
                    handler(record);
                }
            })?;
        Ok(Self {
            queue,
            join: Some(join),
        })
    }

    /// Signals shutdown, drains queued records, and joins the dedicated OS
    /// thread. Call this from an explicit module shutdown path.
    pub fn shutdown_and_join(mut self) -> thread::Result<()> {
        self.queue.shutdown();
        let join = self.join.take().expect("audit writer already joined");
        if join.thread().id() == thread::current().id() {
            return Ok(());
        }
        join.join()
    }
}

impl Drop for AuditWriter {
    fn drop(&mut self) {
        self.queue.shutdown();
        let Some(join) = self.join.take() else { return };
        if join.thread().id() == thread::current().id() {
            return;
        }
        let _ = thread::Builder::new()
            .name("abuse-audit-reaper".to_owned())
            .spawn(move || {
                let _ = join.join();
            });
    }
}

impl AuditQueueReceiver<'_> {
    /// Blocks without polling until a record is available or the queue has
    /// been shut down and drained. Run this only on a blocking worker.
    fn recv(&self) -> Option<AuditRecord> {
        self.queue.wait_dequeue()
    }
}

pub fn redact_headers(headers: &BTreeMap<String, Vec<BoundedValue>>, limits: &Limits) -> HeaderMap {
    let mut output = HeaderMap::new();
    for (name, values) in headers {
        if output.len() >= limits.max_audit_headers {
            break;
        }
        let name = normalize_header_name(name);
        let entry = output.entry(name.clone()).or_default();
        for value in values {
            if entry.len() >= limits.max_header_value_count {
                break;
            }
            entry.push(if is_sensitive_name(&name) {
                REDACTED_VALUE.to_owned()
            } else {
                bounded(value, limits.max_audit_value_length)
            });
        }
    }
    output
}

fn bounded(value: &BoundedValue, max: usize) -> String {
    bounded_text(&value.value, max)
}

fn bounded_text(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// RFC-3339 UTC formatting without a clock/file dependency.
pub fn rfc3339(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_date(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        day_seconds / 3_600,
        (day_seconds / 60) % 60,
        day_seconds % 60,
        duration.subsec_nanos()
    )
}

// Howard Hinnant's civil-from-days algorithm, with the Unix epoch offset.
fn civil_date(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (y + if month <= 2 { 1 } else { 0 }, month, day)
}
