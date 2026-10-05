use crate::model::AttackType;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct ClockReading {
    pub wall_time: SystemTime,
    pub monotonic: Instant,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> ClockReading;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> ClockReading {
        ClockReading {
            wall_time: SystemTime::now(),
            monotonic: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct ManualClock {
    reading: Mutex<ClockReading>,
}

impl ManualClock {
    pub fn new(wall_time: SystemTime) -> Self {
        Self {
            reading: Mutex::new(ClockReading {
                wall_time,
                monotonic: Instant::now(),
            }),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut reading = self.reading.lock().expect("manual clock mutex poisoned");
        reading.wall_time = reading
            .wall_time
            .checked_add(duration)
            .unwrap_or(reading.wall_time);
        reading.monotonic = reading
            .monotonic
            .checked_add(duration)
            .unwrap_or(reading.monotonic);
    }

    pub fn set(&self, reading: ClockReading) {
        *self.reading.lock().expect("manual clock mutex poisoned") = reading;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> ClockReading {
        *self.reading.lock().expect("manual clock mutex poisoned")
    }
}

pub trait IncidentIdGenerator: Send + Sync {
    fn next_id(&self) -> String;
}

#[derive(Debug)]
pub struct DeterministicIncidentIdGenerator {
    prefix: String,
    next: AtomicU64,
}

impl DeterministicIncidentIdGenerator {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            next: AtomicU64::new(1),
        }
    }
}

impl IncidentIdGenerator for DeterministicIncidentIdGenerator {
    fn next_id(&self) -> String {
        format!(
            "{}-{}",
            self.prefix,
            self.next.fetch_add(1, AtomicOrdering::Relaxed)
        )
    }
}

#[derive(Debug)]
pub struct ProcessIncidentIdGenerator {
    prefix: String,
}

static NEXT_PROCESS_INCIDENT: AtomicU64 = AtomicU64::new(1);

impl Default for ProcessIncidentIdGenerator {
    fn default() -> Self {
        static PROCESS_NONCE: OnceLock<String> = OnceLock::new();
        let nonce = PROCESS_NONCE.get_or_init(|| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("{}-{nanos}", std::process::id())
        });
        Self {
            prefix: format!("inc-{nonce}"),
        }
    }
}

impl IncidentIdGenerator for ProcessIncidentIdGenerator {
    fn next_id(&self) -> String {
        format!(
            "{}-{}",
            self.prefix,
            NEXT_PROCESS_INCIDENT.fetch_add(1, AtomicOrdering::Relaxed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    pub incident_id: String,
    pub ip: IpAddr,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub triggering_definition_ids: Vec<i64>,
    pub triggering_attack_types: Vec<AttackType>,
    pub original_request_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanTrigger {
    pub definition_ids: Vec<i64>,
    pub attack_types: Vec<AttackType>,
    pub original_request_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanInsertResult {
    Created(BanEntry),
    Existing(BanEntry),
    CapacityExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BanError {
    #[error("ban duration must be positive and bounded")]
    InvalidDuration,
    #[error("ban deadline overflow")]
    DeadlineOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpiryIndex {
    deadline: Instant,
    sequence: u64,
    ip: IpAddr,
}

impl Ord for ExpiryIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for ExpiryIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct StoredBan {
    entry: BanEntry,
    deadline: Instant,
    sequence: u64,
}

#[derive(Debug, Default)]
struct RegistryState {
    entries: HashMap<IpAddr, StoredBan>,
    expiry: BinaryHeap<ExpiryIndex>,
    next_sequence: u64,
    expired: u64,
}

#[derive(Clone)]
pub struct BanRegistry {
    state: Arc<Mutex<RegistryState>>,
    capacity: usize,
    clock: Arc<dyn Clock>,
    incident_ids: Arc<dyn IncidentIdGenerator>,
}

impl std::fmt::Debug for BanRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BanRegistry")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl BanRegistry {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        Self::with_components(
            capacity,
            Arc::new(SystemClock),
            Arc::new(ProcessIncidentIdGenerator::default()),
        )
    }

    pub fn with_clock(capacity: usize, clock: Arc<dyn Clock>) -> Result<Self, &'static str> {
        Self::with_components(
            capacity,
            clock,
            Arc::new(ProcessIncidentIdGenerator::default()),
        )
    }

    pub fn with_components(
        capacity: usize,
        clock: Arc<dyn Clock>,
        incident_ids: Arc<dyn IncidentIdGenerator>,
    ) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("ban registry capacity must be positive");
        }
        Ok(Self {
            state: Arc::new(Mutex::new(RegistryState::default())),
            capacity,
            clock,
            incident_ids,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clock_reading(&self) -> ClockReading {
        self.clock.now()
    }

    pub fn len(&self) -> usize {
        self.len_at(self.clock.now())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len_at(&self, reading: ClockReading) -> usize {
        let mut state = self.state.lock().expect("ban registry mutex poisoned");
        reclaim_expired(&mut state, reading.monotonic);
        state.entries.len()
    }

    pub fn get(&self, ip: IpAddr) -> Option<BanEntry> {
        self.get_at(ip, self.clock.now())
    }

    pub fn get_at(&self, ip: IpAddr, reading: ClockReading) -> Option<BanEntry> {
        let mut state = self.state.lock().expect("ban registry mutex poisoned");
        reclaim_expired(&mut state, reading.monotonic);
        state.entries.get(&ip).map(|stored| stored.entry.clone())
    }

    pub fn expired_count(&self) -> u64 {
        self.state
            .lock()
            .expect("ban registry mutex poisoned")
            .expired
    }

    pub(crate) fn try_ban_at(
        &self,
        ip: IpAddr,
        reading: ClockReading,
        duration: Duration,
        trigger: BanTrigger,
    ) -> Result<BanInsertResult, BanError> {
        if duration.is_zero() {
            return Err(BanError::InvalidDuration);
        }
        let deadline = reading
            .monotonic
            .checked_add(duration)
            .ok_or(BanError::DeadlineOverflow)?;
        let expires_at = reading
            .wall_time
            .checked_add(duration)
            .ok_or(BanError::DeadlineOverflow)?;
        let mut state = self.state.lock().expect("ban registry mutex poisoned");
        reclaim_expired(&mut state, reading.monotonic);
        if let Some(existing) = state.entries.get(&ip) {
            return Ok(BanInsertResult::Existing(existing.entry.clone()));
        }
        if state.entries.len() >= self.capacity {
            return Ok(BanInsertResult::CapacityExhausted);
        }
        state.next_sequence = state.next_sequence.wrapping_add(1);
        let sequence = state.next_sequence;
        let entry = BanEntry {
            incident_id: self.incident_ids.next_id(),
            ip,
            created_at: reading.wall_time,
            expires_at,
            triggering_definition_ids: trigger.definition_ids,
            triggering_attack_types: trigger.attack_types,
            original_request_summary: trigger.original_request_summary,
        };
        state.entries.insert(
            ip,
            StoredBan {
                entry: entry.clone(),
                deadline,
                sequence,
            },
        );
        state.expiry.push(ExpiryIndex {
            deadline,
            sequence,
            ip,
        });
        Ok(BanInsertResult::Created(entry))
    }
}

fn reclaim_expired(state: &mut RegistryState, now: Instant) {
    while let Some(index) = state.expiry.peek().copied() {
        if index.deadline > now {
            break;
        }
        state.expiry.pop();
        let should_remove = state
            .entries
            .get(&index.ip)
            .is_some_and(|stored| stored.sequence == index.sequence && stored.deadline <= now);
        if should_remove {
            state.entries.remove(&index.ip);
            state.expired = state.expired.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger() -> BanTrigger {
        BanTrigger {
            definition_ids: vec![1],
            attack_types: vec![AttackType::Scanner],
            original_request_summary: "GET /".to_owned(),
        }
    }

    #[test]
    fn internal_registry_mutation_is_clocked_and_bounded() {
        let clock = Arc::new(ManualClock::new(UNIX_EPOCH));
        let ids = Arc::new(DeterministicIncidentIdGenerator::new("test"));
        let registry = BanRegistry::with_components(1, clock.clone(), ids).unwrap();
        let first = registry
            .try_ban_at(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                clock.now(),
                Duration::from_secs(10),
                trigger(),
            )
            .unwrap();
        assert!(matches!(first, BanInsertResult::Created(_)));
        let second = registry
            .try_ban_at(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
                clock.now(),
                Duration::from_secs(10),
                trigger(),
            )
            .unwrap();
        assert_eq!(second, BanInsertResult::CapacityExhausted);
        assert!(matches!(
            registry.try_ban_at(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 3)),
                clock.now(),
                Duration::MAX,
                trigger(),
            ),
            Err(BanError::DeadlineOverflow)
        ));
        clock.advance(Duration::from_secs(10));
        assert!(registry.is_empty());
    }
}
