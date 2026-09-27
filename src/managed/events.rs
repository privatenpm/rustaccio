//! Durable usage-event reporting to the control plane.
//!
//! Events are fsynced to an append-only spool on enqueue and never dropped
//! silently. A background worker batches the spool into `POST /v1/events`
//! calls and retries a failed batch — same `event_id`s — until the control
//! plane answers 2xx. Only then is the batch removed. When the spool's byte
//! bound is hit, the newest event is dropped and
//! `rustaccio_events_dropped_total` is incremented.
//!
//! Metadata (packument) cache hits are aggregated per
//! (registry, credential, package, minute) and emitted as one `metadata`
//! event when the minute closes.

use super::client::{ControlPlaneClient, EventRange, ManagedEvent};
use super::spool::{AppendOutcome, EventSpool};
use crate::error::RegistryError;
use axum::http::HeaderMap;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};
use tracing::{debug, warn};

pub const EVENT_DOWNLOAD: &str = "download";
pub const EVENT_PUBLISH: &str = "publish";
pub const EVENT_METADATA: &str = "metadata";

pub const STATUS_COMPLETE: &str = "complete";
pub const STATUS_PARTIAL: &str = "partial";
pub const STATUS_ABORTED: &str = "aborted";
pub const STATUS_REDIRECTED: &str = "redirected";

pub const FORMAT_NPM: &str = "npm";

const FLUSH_BATCH: usize = 50;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

const MAX_USER_AGENT: usize = 1024;
const MAX_NPM_COMMAND: usize = 64;
const MAX_NPM_SESSION: usize = 64;
const MAX_HOST: usize = 255;
const MAX_REQUEST_ID: usize = 255;
const MAX_FILE: usize = 512;
const MAX_ID: usize = 60;

/// Fleet capabilities advertised once the corresponding bridge features exist.
pub const CAPABILITY_EVENTS_V2: &str = "events_v2";
pub const CAPABILITY_UPSTREAM_FORWARD: &str = "upstream_forward";

#[derive(Debug, Clone)]
pub struct EventReporterConfig {
    pub spool_dir: PathBuf,
    pub max_bytes: u64,
    pub flush_interval: Duration,
    pub flush_batch: usize,
}

impl EventReporterConfig {
    pub fn new(spool_dir: PathBuf, max_bytes: u64) -> Self {
        Self {
            spool_dir,
            max_bytes,
            flush_interval: FLUSH_INTERVAL,
            flush_batch: FLUSH_BATCH,
        }
    }
}

#[derive(Clone)]
pub struct EventReporter {
    inner: Arc<ReporterInner>,
}

struct ReporterInner {
    spool: EventSpool,
    client: Arc<ControlPlaneClient>,
    notify: Notify,
    shutdown: AtomicBool,
    dropped: AtomicU64,
    metadata: std::sync::Mutex<MetadataAggregator>,
    flush_interval: Duration,
    flush_batch: usize,
    worker: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

/// One packument cache hit to fold into the current minute window.
#[derive(Debug, Clone)]
pub struct MetadataObservation {
    pub tenant_id: String,
    pub registry_id: String,
    pub credential_id: String,
    pub package: String,
    pub bytes: u64,
    pub not_modified: bool,
    pub at: chrono::DateTime<chrono::Utc>,
}

impl EventReporter {
    pub async fn start(
        client: Arc<ControlPlaneClient>,
        config: EventReporterConfig,
    ) -> Result<Self, RegistryError> {
        let spool = EventSpool::open(&config.spool_dir, config.max_bytes)?;
        let inner = Arc::new(ReporterInner {
            spool,
            client,
            notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            metadata: std::sync::Mutex::new(MetadataAggregator::default()),
            flush_interval: config.flush_interval,
            flush_batch: config.flush_batch.max(1),
            worker: tokio::sync::Mutex::new(None),
        });
        let worker = tokio::spawn(event_worker(Arc::clone(&inner)));
        *inner.worker.lock().await = Some(worker);
        Ok(Self { inner })
    }

    /// Persist one event. Returns after the spool fsync. A full spool drops
    /// this event (the newest) and increments the dropped counter.
    pub async fn report(&self, event: ManagedEvent) {
        let event_id = event.event_id.clone();
        let appended = tokio::task::spawn_blocking({
            let spool = self.inner.spool.clone();
            move || spool.append(&event)
        })
        .await;
        match appended {
            Ok(Ok(AppendOutcome::Stored)) => self.inner.notify.notify_one(),
            Ok(Ok(AppendOutcome::Dropped)) => {
                self.note_dropped(&event_id, "managed event spool full; dropping newest event")
            }
            Ok(Err(error)) => {
                self.note_dropped(&event_id, "failed to spool managed event; dropping event");
                warn!(event_id = %event_id, error = ?error, "event spool write failed");
            }
            Err(error) => {
                self.note_dropped(&event_id, "failed to spool managed event; dropping event");
                warn!(event_id = %event_id, error = ?error, "event spool task failed");
            }
        }
    }

    pub fn observe_metadata(&self, observation: MetadataObservation) {
        if observation.tenant_id.trim().is_empty() || observation.package.trim().is_empty() {
            return;
        }
        let mut aggregator = self
            .inner
            .metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        aggregator.observe(observation);
    }

    pub fn dropped_total(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Prometheus text for `rustaccio_events_dropped_total`. Always emitted,
    /// including zero, so an alert can load the series before the first drop.
    pub fn render_metrics(&self) -> String {
        let dropped = self.dropped_total();
        format!(
            "# HELP rustaccio_events_dropped_total Usage events dropped because the durable spool could not accept them.\n# TYPE rustaccio_events_dropped_total counter\nrustaccio_events_dropped_total {dropped}\n"
        )
    }

    /// Stop the worker. Pending events stay on the spool for the next start.
    pub async fn shutdown(&self) {
        self.signal_shutdown();
        if let Some(handle) = self.inner.worker.lock().await.take() {
            let _ = handle.await;
        }
    }

    fn signal_shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Guard held by the bridge. Dropping it stops the worker without waiting;
    /// clones of [`EventReporter`] do not carry it, so in-flight reports do not
    /// shut the worker down.
    pub fn shutdown_guard(&self) -> EventShutdown {
        EventShutdown {
            inner: Arc::clone(&self.inner),
        }
    }

    fn note_dropped(&self, event_id: &str, message: &str) {
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
        warn!(event_id = %event_id, metric = "rustaccio_events_dropped_total", "{message}");
    }

    pub fn event(
        kind: &str,
        tenant_id: Option<&str>,
        package: &str,
        version: Option<&str>,
        bytes: u64,
        credential_id: Option<&str>,
    ) -> ManagedEvent {
        ManagedEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            kind: kind.to_string(),
            tenant_id: tenant_id.unwrap_or_default().to_string(),
            package: package.to_string(),
            version: version.map(ToOwned::to_owned),
            credential_id: credential_id.map(ToOwned::to_owned),
            bytes,
            occurred_at: chrono::Utc::now().to_rfc3339(),
            ..ManagedEvent::default()
        }
    }
}

/// Signals the event worker to stop when the bridge is dropped.
pub struct EventShutdown {
    inner: Arc<ReporterInner>,
}

impl Drop for EventShutdown {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }
}

async fn event_worker(inner: Arc<ReporterInner>) {
    let mut backoff = INITIAL_BACKOFF;
    let mut startup = true;
    let mut waiting_since: Option<tokio::time::Instant> = None;
    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            flush_all_metadata(&inner).await;
            break;
        }
        flush_closed_metadata(&inner).await;
        let Some(batch) = read_pending(&inner).await else {
            if wait(&inner, backoff).await {
                break;
            }
            continue;
        };
        if batch.events.is_empty() {
            startup = false;
            waiting_since = None;
            if wait(&inner, inner.flush_interval).await {
                break;
            }
            continue;
        }
        if !startup && batch.events.len() < inner.flush_batch {
            let since = waiting_since.get_or_insert_with(tokio::time::Instant::now);
            let elapsed = since.elapsed();
            if elapsed < inner.flush_interval {
                if wait(&inner, inner.flush_interval.saturating_sub(elapsed)).await {
                    break;
                }
                continue;
            }
        }
        waiting_since = None;
        startup = false;
        match inner.client.send_events(&batch.events).await {
            Ok(()) => {
                if ack_pending(&inner, batch.end_offset, batch.generation).await {
                    debug!(accepted = batch.events.len(), "delivered managed events");
                }
                backoff = INITIAL_BACKOFF;
            }
            Err(error) => {
                warn!(
                    events = batch.events.len(),
                    error = ?error,
                    "failed to deliver managed events; leaving batch spooled"
                );
                if wait(&inner, backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn read_pending(inner: &ReporterInner) -> Option<super::spool::PendingBatch> {
    let spool = inner.spool.clone();
    let limit = inner.flush_batch;
    match tokio::task::spawn_blocking(move || spool.read_batch(limit)).await {
        Ok(Ok(batch)) => Some(batch),
        Ok(Err(error)) => {
            warn!(error = ?error, "failed to read managed event spool");
            None
        }
        Err(error) => {
            warn!(error = ?error, "event spool read task failed");
            None
        }
    }
}

async fn ack_pending(inner: &ReporterInner, end_offset: u64, generation: u64) -> bool {
    let spool = inner.spool.clone();
    match tokio::task::spawn_blocking(move || spool.ack(end_offset, generation)).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            warn!(error = ?error, "failed to acknowledge managed event batch");
            false
        }
        Err(error) => {
            warn!(error = ?error, "event spool ack task failed");
            false
        }
    }
}

async fn flush_all_metadata(inner: &ReporterInner) {
    let events = {
        let mut aggregator = inner
            .metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        aggregator.flush_all()
    };
    spool_metadata(inner, events).await;
}

async fn flush_closed_metadata(inner: &ReporterInner) {
    let events = {
        let mut aggregator = inner
            .metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        aggregator.flush_closed(chrono::Utc::now())
    };
    spool_metadata(inner, events).await;
}

async fn spool_metadata(inner: &ReporterInner, events: Vec<ManagedEvent>) {
    if events.is_empty() {
        return;
    }
    let count = events.len() as u64;
    let spool = inner.spool.clone();
    let appended = tokio::task::spawn_blocking(move || {
        let mut dropped = 0u64;
        for event in &events {
            match spool.append(event) {
                Ok(AppendOutcome::Stored) => {}
                Ok(AppendOutcome::Dropped) => {
                    dropped = dropped.saturating_add(1);
                    warn!(
                        event_id = %event.event_id,
                        metric = "rustaccio_events_dropped_total",
                        "managed event spool full; dropping newest metadata aggregate"
                    );
                }
                Err(error) => {
                    dropped = dropped.saturating_add(1);
                    warn!(
                        event_id = %event.event_id,
                        error = ?error,
                        metric = "rustaccio_events_dropped_total",
                        "failed to spool metadata aggregate"
                    );
                }
            }
        }
        dropped
    })
    .await;
    let dropped = match appended {
        Ok(dropped) => dropped,
        Err(error) => {
            warn!(error = ?error, "metadata aggregate spool task failed");
            count
        }
    };
    if dropped > 0 {
        inner.dropped.fetch_add(dropped, Ordering::Relaxed);
    }
}

/// Wait up to `duration`, or until shutdown / a new enqueue. Returns whether
/// the worker should stop.
async fn wait(inner: &ReporterInner, duration: Duration) -> bool {
    if inner.shutdown.load(Ordering::SeqCst) {
        return true;
    }
    tokio::select! {
        _ = inner.notify.notified() => inner.shutdown.load(Ordering::SeqCst),
        _ = tokio::time::sleep(duration) => inner.shutdown.load(Ordering::SeqCst),
    }
}

/// Client facts taken from the request. `client_ip` is the trusted edge
/// address (Fly `Fly-Client-IP`, else Cloudflare `CF-Connecting-IP`). A
/// client-supplied `X-Forwarded-For` is ignored.
pub struct ClientFacts {
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub npm_command: Option<String>,
    pub npm_session: Option<String>,
    pub ci: Option<bool>,
}

pub fn client_facts(headers: &HeaderMap) -> ClientFacts {
    let user_agent = header_text(headers, "user-agent", MAX_USER_AGENT);
    let ci = user_agent
        .as_deref()
        .map(user_agent_marked_ci)
        .or(Some(false));
    ClientFacts {
        client_ip: trusted_client_ip(headers),
        user_agent,
        npm_command: header_text(headers, "npm-command", MAX_NPM_COMMAND),
        npm_session: header_text(headers, "npm-session", MAX_NPM_SESSION),
        ci,
    }
}

/// npm appends a `ci/<name>` token; pip and twine carry `"ci":true`.
pub fn user_agent_marked_ci(user_agent: &str) -> bool {
    let lower = user_agent.to_ascii_lowercase();
    lower.contains(" ci/") || lower.contains("\"ci\":true")
}

pub fn trusted_client_ip(headers: &HeaderMap) -> Option<String> {
    for name in ["fly-client-ip", "cf-connecting-ip"] {
        let Some(value) = header_text(headers, name, 64) else {
            continue;
        };
        if value.parse::<IpAddr>().is_ok() {
            return Some(value);
        }
    }
    None
}

pub fn header_text(headers: &HeaderMap, name: &str, max_bytes: usize) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    bounded_text(value, max_bytes)
}

pub fn bounded_text(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.len() <= max_bytes {
        return Some(value.to_string());
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    Some(value[..end].to_string()).filter(|truncated| !truncated.is_empty())
}

pub fn bounded_id(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ID {
        return None;
    }
    Some(value.to_string())
}

/// Fields a download or publish already knows, plus the request's client facts.
pub struct TransferFacts<'a> {
    pub registry_id: &'a str,
    pub file: &'a str,
    pub declared_bytes: u64,
    pub status: &'a str,
    pub range: Option<EventRange>,
    pub host: &'a str,
    pub request_id: &'a str,
    pub headers: &'a HeaderMap,
}

pub fn apply_transfer(event: &mut ManagedEvent, facts: TransferFacts<'_>) {
    event.registry_id = bounded_id(facts.registry_id);
    event.format = Some(FORMAT_NPM.to_string());
    event.file = bounded_text(facts.file, MAX_FILE);
    event.declared_bytes = Some(facts.declared_bytes);
    event.status = Some(facts.status.to_string());
    event.range = facts.range.filter(|range| range.end >= range.start);
    event.host = bounded_text(facts.host, MAX_HOST);
    event.request_id = bounded_text(facts.request_id, MAX_REQUEST_ID);
    let client = client_facts(facts.headers);
    event.client_ip = client.client_ip;
    event.user_agent = client.user_agent;
    event.npm_command = client.npm_command;
    event.npm_session = client.npm_session;
    event.ci = client.ci;
}

pub fn parse_content_range(value: &str) -> Option<EventRange> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (span, _) = rest.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let end = end.trim().parse().ok()?;
    (end >= start).then_some(EventRange { start, end })
}

#[derive(Default)]
struct MetadataAggregator {
    windows: HashMap<MetaKey, MetaTotals>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MetaKey {
    registry_id: String,
    credential_id: String,
    package: String,
    minute_unix: i64,
}

struct MetaTotals {
    tenant_id: String,
    count: u64,
    bytes: u64,
    not_modified: u64,
}

impl MetadataAggregator {
    fn observe(&mut self, observation: MetadataObservation) {
        let key = MetaKey {
            registry_id: observation.registry_id,
            credential_id: observation.credential_id,
            package: observation.package,
            minute_unix: observation.at.timestamp().div_euclid(60) * 60,
        };
        let entry = self.windows.entry(key).or_insert_with(|| MetaTotals {
            tenant_id: observation.tenant_id.clone(),
            count: 0,
            bytes: 0,
            not_modified: 0,
        });
        entry.count = entry.count.saturating_add(1);
        entry.bytes = entry.bytes.saturating_add(observation.bytes);
        if observation.not_modified {
            entry.not_modified = entry.not_modified.saturating_add(1);
        }
    }

    /// Emit one event per window whose minute has ended.
    fn flush_closed(&mut self, now: chrono::DateTime<chrono::Utc>) -> Vec<ManagedEvent> {
        let current = now.timestamp().div_euclid(60) * 60;
        let ready: Vec<MetaKey> = self
            .windows
            .keys()
            .filter(|key| key.minute_unix < current)
            .cloned()
            .collect();
        ready.into_iter().filter_map(|key| self.emit(key)).collect()
    }

    /// Emit every window, including the one still open. Tests and shutdown use this.
    fn flush_all(&mut self) -> Vec<ManagedEvent> {
        let keys: Vec<MetaKey> = self.windows.keys().cloned().collect();
        keys.into_iter().filter_map(|key| self.emit(key)).collect()
    }

    fn emit(&mut self, key: MetaKey) -> Option<ManagedEvent> {
        let totals = self.windows.remove(&key)?;
        let occurred_at = chrono::DateTime::from_timestamp(key.minute_unix, 0)?.to_rfc3339();
        Some(ManagedEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            kind: EVENT_METADATA.to_string(),
            tenant_id: totals.tenant_id,
            package: key.package,
            version: None,
            credential_id: bounded_id(&key.credential_id),
            bytes: totals.bytes,
            occurred_at,
            registry_id: bounded_id(&key.registry_id),
            format: Some(FORMAT_NPM.to_string()),
            count: Some(totals.count),
            not_modified: Some(totals.not_modified),
            ..ManagedEvent::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::time::Duration;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        headers
    }

    #[test]
    fn trusted_client_ip_ignores_forwarded_for() {
        let headers = header_map(&[
            ("x-forwarded-for", "203.0.113.9, 10.0.0.1"),
            ("fly-client-ip", "198.51.100.7"),
            ("cf-connecting-ip", "203.0.113.4"),
        ]);
        assert_eq!(trusted_client_ip(&headers).as_deref(), Some("198.51.100.7"));

        let cloudflare = header_map(&[
            ("x-forwarded-for", "203.0.113.9"),
            ("cf-connecting-ip", "2001:db8::1"),
        ]);
        assert_eq!(
            trusted_client_ip(&cloudflare).as_deref(),
            Some("2001:db8::1")
        );

        let spoofed = header_map(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(trusted_client_ip(&spoofed), None);

        let garbage = header_map(&[("fly-client-ip", "not-an-ip")]);
        assert_eq!(trusted_client_ip(&garbage), None);
    }

    #[test]
    fn ci_marker_matches_npm_pip_and_twine() {
        assert!(user_agent_marked_ci(
            "npm/10.8.1 node/v22.4.0 linux x64 ci/github-actions"
        ));
        assert!(user_agent_marked_ci("twine/5.1.1 {\"ci\":true}"));
        assert!(!user_agent_marked_ci("npm/10.8.1 node/v22.4.0 linux x64"));
        assert!(!user_agent_marked_ci("ci/github"));
    }

    #[test]
    fn apply_transfer_fills_download_fields_and_ignores_forwarded_for() {
        let headers = header_map(&[
            (
                "user-agent",
                "npm/10.8.1 node/v22.4.0 linux x64 ci/github-actions",
            ),
            ("npm-command", "install"),
            ("npm-session", "sess-1"),
            ("fly-client-ip", "198.51.100.7"),
            ("x-forwarded-for", "203.0.113.9"),
        ]);
        let mut event = ManagedEvent::default();
        apply_transfer(
            &mut event,
            TransferFacts {
                registry_id: "reg_1",
                file: "demo-1.0.0.tgz",
                declared_bytes: 18,
                status: STATUS_REDIRECTED,
                range: None,
                host: "npm.example.test",
                request_id: "req-1",
                headers: &headers,
            },
        );
        assert_eq!(event.registry_id.as_deref(), Some("reg_1"));
        assert_eq!(event.format.as_deref(), Some(FORMAT_NPM));
        assert_eq!(event.file.as_deref(), Some("demo-1.0.0.tgz"));
        assert_eq!(event.declared_bytes, Some(18));
        assert_eq!(event.status.as_deref(), Some(STATUS_REDIRECTED));
        assert_eq!(event.client_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            event.user_agent.as_deref(),
            Some("npm/10.8.1 node/v22.4.0 linux x64 ci/github-actions")
        );
        assert_eq!(event.npm_command.as_deref(), Some("install"));
        assert_eq!(event.npm_session.as_deref(), Some("sess-1"));
        assert_eq!(event.ci, Some(true));
        assert_eq!(event.host.as_deref(), Some("npm.example.test"));
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert!(event.range.is_none());
        assert!(
            event.cache.is_none(),
            "hosted transfers do not invent an upstream cache outcome"
        );
    }

    #[test]
    fn content_range_parses_bounds() {
        assert_eq!(
            parse_content_range("bytes 0-4/512"),
            Some(EventRange { start: 0, end: 4 })
        );
        assert_eq!(parse_content_range("bytes */512"), None);
    }

    #[test]
    fn metadata_aggregation_emits_one_event_per_minute_window() {
        let mut aggregator = MetadataAggregator::default();
        let minute = chrono::DateTime::parse_from_rfc3339("2026-09-27T12:00:30Z")
            .expect("time")
            .with_timezone(&chrono::Utc);
        let next = minute + chrono::Duration::seconds(60);
        let observe = |aggregator: &mut MetadataAggregator, at, bytes, not_modified| {
            aggregator.observe(MetadataObservation {
                tenant_id: "org_1".to_string(),
                registry_id: "reg_1".to_string(),
                credential_id: "ntok_1".to_string(),
                package: "demo".to_string(),
                bytes,
                not_modified,
                at,
            });
        };
        observe(&mut aggregator, minute, 100, false);
        observe(
            &mut aggregator,
            minute + chrono::Duration::seconds(10),
            50,
            true,
        );
        observe(&mut aggregator, next, 10, false);

        let closed = aggregator.flush_closed(next);
        assert_eq!(closed.len(), 1, "one event for the closed minute");
        assert_eq!(closed[0].kind, EVENT_METADATA);
        assert_eq!(closed[0].count, Some(2));
        assert_eq!(closed[0].bytes, 150);
        assert_eq!(closed[0].not_modified, Some(1));
        assert_eq!(closed[0].package, "demo");
        assert_eq!(closed[0].registry_id.as_deref(), Some("reg_1"));
        assert_eq!(closed[0].credential_id.as_deref(), Some("ntok_1"));
        assert_eq!(closed[0].occurred_at, "2026-09-27T12:00:00+00:00");

        let open = aggregator.flush_all();
        assert_eq!(open.len(), 1, "the next minute is its own event");
        assert_eq!(open[0].count, Some(1));
        assert_eq!(open[0].bytes, 10);
        assert_ne!(open[0].event_id, closed[0].event_id);
    }

    fn sample(id: &str) -> ManagedEvent {
        ManagedEvent {
            event_id: id.to_string(),
            kind: EVENT_DOWNLOAD.to_string(),
            tenant_id: "org_1".to_string(),
            package: "demo".to_string(),
            bytes: 4,
            occurred_at: "2026-09-27T12:00:00Z".to_string(),
            ..ManagedEvent::default()
        }
    }

    #[tokio::test]
    async fn spool_bound_drops_newest_and_bumps_metric() {
        let dir = tempfile::tempdir().expect("tempdir");
        let older = sample("evt-older");
        let probe = EventSpool::open(dir.path(), u64::MAX).expect("probe");
        assert_eq!(probe.append(&older).expect("append"), AppendOutcome::Stored);
        let bound = probe.read_batch(1).expect("size").end_offset;
        drop(probe);

        let client =
            Arc::new(ControlPlaneClient::new("http://127.0.0.1:1", "node").expect("client"));
        let reporter = EventReporter::start(
            client,
            EventReporterConfig {
                spool_dir: dir.path().to_path_buf(),
                max_bytes: bound,
                flush_interval: Duration::from_secs(60),
                flush_batch: 50,
            },
        )
        .await
        .expect("reporter");
        reporter.report(sample("evt-newest")).await;
        assert_eq!(reporter.dropped_total(), 1);
        assert!(
            reporter
                .render_metrics()
                .contains("rustaccio_events_dropped_total 1")
        );
        let pending = reporter.inner.spool.pending_ids().expect("pending");
        assert_eq!(pending, vec!["evt-older".to_string()]);
        assert!(!pending.iter().any(|id| id == "evt-newest"));
        reporter.shutdown().await;
    }

    #[tokio::test]
    async fn spool_replays_the_same_event_ids_after_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dead = Arc::new(ControlPlaneClient::new("http://127.0.0.1:1", "node").expect("client"));
        let reporter = EventReporter::start(
            dead,
            EventReporterConfig {
                spool_dir: dir.path().to_path_buf(),
                max_bytes: 8 * 1024 * 1024,
                flush_interval: Duration::from_millis(50),
                flush_batch: 50,
            },
        )
        .await
        .expect("reporter");
        reporter.report(sample("evt-stable")).await;
        reporter.shutdown().await;

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/registry/v1/events"))
            .respond_with(wiremock::ResponseTemplate::new(202))
            .mount(&server)
            .await;
        let live = Arc::new(ControlPlaneClient::new(&server.uri(), "node").expect("client"));
        let restarted = EventReporter::start(
            live,
            EventReporterConfig {
                spool_dir: dir.path().to_path_buf(),
                max_bytes: 8 * 1024 * 1024,
                flush_interval: Duration::from_millis(50),
                flush_batch: 50,
            },
        )
        .await
        .expect("restart");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut delivered = None;
        while tokio::time::Instant::now() < deadline {
            if let Some(requests) = server.received_requests().await {
                for request in requests {
                    if request.url.path() != "/api/registry/v1/events" {
                        continue;
                    }
                    if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) {
                        let matched = body["events"].as_array().is_some_and(|events| {
                            events.iter().any(|event| event["event_id"] == "evt-stable")
                        });
                        if matched {
                            delivered = Some(body);
                            break;
                        }
                    }
                }
            }
            if delivered.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let body = delivered.expect("replayed event was not delivered");
        let events = body["events"].as_array().expect("events");
        assert!(
            events.iter().all(|event| event["event_id"] == "evt-stable"),
            "retries keep the original event id"
        );
        restarted.shutdown().await;
    }
}
