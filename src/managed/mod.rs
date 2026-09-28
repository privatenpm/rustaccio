//! Managed data-plane bridge.
//!
//! When `RUSTACCIO_METADATA_BACKEND=managed`, Rustaccio runs as a pure data
//! plane for the Go control plane (see `docs/contracts/managed-v1.md`):
//! authorization, metadata and publish session state live upstream; this node
//! decodes publish bodies, hashes and uploads tarballs to control-plane
//! issued presigned URLs, redirects or proxies downloads, and reports usage
//! events. All control-plane failures fail closed (502), never falling back
//! to upstream registries or local policy for private operations.

pub mod cache;
pub mod client;
pub mod dispatch;
pub mod events;
pub mod extract;
pub mod fleet;
mod pending;
mod spool;

use crate::config::{Config, TarballStorageBackend};
use crate::error::RegistryError;
use axum::http::StatusCode;
use std::{path::PathBuf, sync::Arc};
use tracing::debug;

/// How tarball downloads are served in managed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMode {
    /// 302 redirect to the control-plane issued presigned URL (default).
    Redirect,
    /// Stream the presigned URL through this node.
    Proxy,
}

impl DownloadMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redirect => "redirect",
            Self::Proxy => "proxy",
        }
    }
}

/// Configuration for the managed data-plane bridge.
#[derive(Debug, Clone)]
pub struct ManagedConfig {
    /// Control-plane base URL (`RUSTACCIO_CONTROL_PLANE_URL`).
    pub control_plane_url: String,
    /// Node credential (`RUSTACCIO_CONTROL_PLANE_TOKEN`).
    pub token: String,
    /// Origin packuments/metadata writes are proxied to
    /// (`RUSTACCIO_MANAGED_METADATA_ORIGIN`, default = control-plane URL).
    pub metadata_origin: String,
    /// Download serving mode (`RUSTACCIO_MANAGED_DOWNLOAD_MODE`).
    pub download_mode: DownloadMode,
    /// Node identity (`RUSTACCIO_DATA_PLANE_ID`, default: hostname).
    pub identity: String,
    /// Fail startup unless the control plane placed this node
    /// (`RUSTACCIO_REQUIRE_PLACEMENT`).
    pub require_placement: bool,
    /// Capabilities reported in fleet heartbeats.
    pub capabilities: Vec<String>,
    /// Decision/download cache bounds and local TTL ceiling (clamped to the
    /// control-plane `expires_at`).
    pub decision_cache_max_entries: usize,
    pub decision_cache_ttl_ms: u64,
    /// Optional packument cache (default off).
    pub metadata_cache_ttl_ms: u64,
    pub metadata_cache_max_entries: usize,
    pub metadata_cache_max_bytes: usize,
    /// Bound for the metadata portion of a publish document (pre-scan and
    /// tail), and for buffered packument proxying.
    pub max_metadata_bytes: usize,
    /// Presigned upload timeout.
    pub upload_timeout_ms: u64,
    /// Optional directory for durable pending events; None uses memory. Distinct from
    /// `spool_dir`, which holds publish tarball bytes and is swept on startup.
    pub event_spool_dir: Option<PathBuf>,
    /// Byte bound of the event spool. A new event that would exceed it is
    /// dropped and counted in `rustaccio_events_dropped_total`.
    pub event_spool_max_bytes: u64,
    /// Directory tarball payloads are spooled to between reserve and upload.
    pub spool_dir: PathBuf,
}

impl ManagedConfig {
    pub fn from_env(data_dir: &std::path::Path) -> Result<Self, RegistryError> {
        let control_plane_url = std::env::var("RUSTACCIO_CONTROL_PLANE_URL")
            .ok()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        if control_plane_url.is_empty() {
            return Err(misconfigured(
                "RUSTACCIO_METADATA_BACKEND=managed requires RUSTACCIO_CONTROL_PLANE_URL",
            ));
        }
        let token = std::env::var("RUSTACCIO_CONTROL_PLANE_TOKEN")
            .ok()
            .unwrap_or_default()
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(misconfigured(
                "RUSTACCIO_METADATA_BACKEND=managed requires RUSTACCIO_CONTROL_PLANE_TOKEN",
            ));
        }

        let metadata_origin = std::env::var("RUSTACCIO_MANAGED_METADATA_ORIGIN")
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| control_plane_url.clone());

        let download_mode = match std::env::var("RUSTACCIO_MANAGED_DOWNLOAD_MODE")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("redirect") => DownloadMode::Redirect,
            Some("proxy") => DownloadMode::Proxy,
            Some(other) => {
                return Err(misconfigured(format!(
                    "unsupported RUSTACCIO_MANAGED_DOWNLOAD_MODE: {other} (expected redirect|proxy)"
                )));
            }
        };

        let identity = std::env::var("RUSTACCIO_DATA_PLANE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                std::env::var("HOSTNAME")
                    .ok()
                    .map(|value| value.trim().to_string())
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustaccio-data-plane".to_string());

        let spool_dir = data_dir.join("managed-spool");
        let event_spool_dir = std::env::var("RUSTACCIO_MANAGED_EVENT_SPOOL_DIR")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        if event_spool_dir.as_ref() == Some(&spool_dir) {
            return Err(misconfigured(
                "RUSTACCIO_MANAGED_EVENT_SPOOL_DIR must not be the publish spool directory",
            ));
        }

        Ok(Self {
            control_plane_url,
            token,
            metadata_origin,
            download_mode,
            identity,
            require_placement: parse_bool_env("RUSTACCIO_REQUIRE_PLACEMENT", false),
            capabilities: bridge_capabilities(download_mode),
            decision_cache_max_entries: parse_usize_env(
                "RUSTACCIO_MANAGED_DECISION_CACHE_MAX_ENTRIES",
                10_000,
            ),
            decision_cache_ttl_ms: parse_u64_env("RUSTACCIO_MANAGED_DECISION_CACHE_TTL_MS", 30_000),
            metadata_cache_ttl_ms: parse_u64_env("RUSTACCIO_MANAGED_METADATA_CACHE_TTL_MS", 0),
            metadata_cache_max_entries: parse_usize_env(
                "RUSTACCIO_MANAGED_METADATA_CACHE_MAX_ENTRIES",
                128,
            ),
            metadata_cache_max_bytes: parse_usize_env(
                "RUSTACCIO_MANAGED_METADATA_CACHE_MAX_BYTES",
                4 * 1024 * 1024,
            ),
            max_metadata_bytes: parse_usize_env(
                "RUSTACCIO_MANAGED_MAX_METADATA_BYTES",
                8 * 1024 * 1024,
            ),
            upload_timeout_ms: parse_u64_env("RUSTACCIO_MANAGED_UPLOAD_TIMEOUT_MS", 300_000),
            event_spool_dir,
            event_spool_max_bytes: parse_u64_env(
                "RUSTACCIO_MANAGED_EVENT_SPOOL_MAX_BYTES",
                64 * 1024 * 1024,
            ),
            spool_dir,
        })
    }
}

/// Capabilities advertised on fleet heartbeats. `events_v2` and
/// `upstream_forward` mark a node that spools the expanded event contract and
/// can reverse-proxy names the control plane classifies as upstream.
pub fn bridge_capabilities(download_mode: DownloadMode) -> Vec<String> {
    vec![
        "publish-bridge".to_string(),
        "metadata-proxy".to_string(),
        format!("download-{}", download_mode.as_str()),
        events::CAPABILITY_EVENTS_V2.to_string(),
        events::CAPABILITY_UPSTREAM_FORWARD.to_string(),
    ]
}

fn misconfigured(message: impl Into<String>) -> RegistryError {
    RegistryError::http(StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_usize_env(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

/// Whether `RUSTACCIO_METADATA_BACKEND=managed` selects the bridge.
pub fn managed_backend_enabled() -> bool {
    std::env::var("RUSTACCIO_METADATA_BACKEND")
        .ok()
        .map(|value| value.trim().eq_ignore_ascii_case("managed"))
        .unwrap_or(false)
}

/// Shared state for the managed data-plane bridge.
pub struct ManagedState {
    pub config: ManagedConfig,
    pub client: Arc<client::ControlPlaneClient>,
    pub decisions: cache::DecisionCache,
    pub downloads: cache::DownloadCache,
    pub metadata: cache::MetadataCache,
    pub registry_hosts: cache::RegistryHostCache,
    pub events: events::EventReporter,
    /// Stops the event worker when the bridge is dropped.
    pub event_shutdown: events::EventShutdown,
    pub fleet: fleet::FleetState,
}

impl ManagedState {
    /// Build the bridge from the process environment; returns `Ok(None)`
    /// unless `RUSTACCIO_METADATA_BACKEND=managed`.
    pub async fn from_config(config: &Config) -> Result<Option<Arc<Self>>, RegistryError> {
        if !managed_backend_enabled() {
            return Ok(None);
        }
        Self::validate_guardrails(config)?;
        let managed = ManagedConfig::from_env(&config.data_dir)?;
        Ok(Some(Arc::new(Self::new(managed).await?)))
    }

    /// Build the bridge from an explicit configuration (used by tests).
    pub async fn new(config: ManagedConfig) -> Result<Self, RegistryError> {
        if config.event_spool_dir.as_ref() == Some(&config.spool_dir) {
            return Err(misconfigured(
                "managed event spool directory must differ from the publish spool directory",
            ));
        }
        tokio::fs::create_dir_all(&config.spool_dir).await?;
        sweep_spool_dir(&config.spool_dir).await;
        let client = Arc::new(client::ControlPlaneClient::new(
            &config.control_plane_url,
            &config.token,
        )?);
        let events = events::EventReporter::start(
            Arc::clone(&client),
            events::EventReporterConfig::new(
                config.event_spool_dir.clone(),
                config.event_spool_max_bytes,
            ),
        )
        .await?;
        let event_shutdown = events.shutdown_guard();
        debug!(
            control_plane_url = config.control_plane_url,
            metadata_origin = config.metadata_origin,
            download_mode = config.download_mode.as_str(),
            identity = config.identity,
            require_placement = config.require_placement,
            metadata_cache_enabled = config.metadata_cache_ttl_ms > 0,
            "initialized managed data-plane bridge"
        );
        Ok(Self {
            events,
            event_shutdown,
            decisions: cache::DecisionCache::new(
                config.decision_cache_max_entries,
                config.decision_cache_ttl_ms,
            ),
            downloads: cache::DownloadCache::new(
                config.decision_cache_max_entries,
                config.decision_cache_ttl_ms,
            ),
            metadata: cache::MetadataCache::new(
                config.metadata_cache_max_entries,
                config.metadata_cache_ttl_ms,
                config.metadata_cache_max_bytes,
            ),
            registry_hosts: cache::RegistryHostCache::new(config.decision_cache_ttl_ms),
            fleet: fleet::FleetState::new(),
            config,
            client,
        })
    }

    /// Managed-mode startup guardrails (additive to the existing runtime
    /// profile checks): the bridge needs the S3 tarball backend so the
    /// deployment shape matches the control plane's create-only storage
    /// contract.
    fn validate_guardrails(config: &Config) -> Result<(), RegistryError> {
        if config.tarball_storage.backend != TarballStorageBackend::S3 {
            return Err(misconfigured(
                "RUSTACCIO_METADATA_BACKEND=managed requires RUSTACCIO_TARBALL_BACKEND=s3",
            ));
        }
        let bucket = config
            .tarball_storage
            .s3
            .as_ref()
            .map(|s3| s3.bucket.trim().to_string())
            .unwrap_or_default();
        if bucket.is_empty() {
            return Err(misconfigured(
                "RUSTACCIO_METADATA_BACKEND=managed requires the s3 tarball configuration (RUSTACCIO_S3_BUCKET)",
            ));
        }
        Ok(())
    }

    /// Startup: initial fleet heartbeat (with optional placement enforcement)
    /// and the background heartbeat loop.
    pub async fn start(self: &Arc<Self>) -> Result<(), RegistryError> {
        self.start_fleet().await
    }

    /// Flush every bridge-managed cache (admin endpoint).
    pub async fn invalidate_caches(&self) {
        self.decisions.invalidate().await;
        self.downloads.invalidate().await;
        self.metadata.invalidate().await;
    }

    /// Constant-time-free equality is acceptable here: the node credential is
    /// a high-entropy operator secret, not a user password.
    pub fn is_node_credential(&self, token: &str) -> bool {
        !token.is_empty() && token == self.config.token
    }
}

/// Remove spool files left behind by a crashed publish attempt.
async fn sweep_spool_dir(spool_dir: &PathBuf) {
    let mut entries = match tokio::fs::read_dir(spool_dir).await {
        Ok(entries) => entries,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Err(error) = tokio::fs::remove_file(entry.path()).await {
            debug!(error = ?error, "failed to remove stale publish spool file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_capabilities_advertise_events_v2_and_upstream_forward() {
        let caps = bridge_capabilities(DownloadMode::Redirect);
        assert!(caps.iter().any(|cap| cap == "publish-bridge"));
        assert!(caps.iter().any(|cap| cap == "download-redirect"));
        assert!(
            caps.iter().any(|cap| cap == events::CAPABILITY_EVENTS_V2),
            "heartbeats must advertise the expanded event contract"
        );
        assert!(
            caps.iter()
                .any(|cap| cap == events::CAPABILITY_UPSTREAM_FORWARD),
            "heartbeats must advertise upstream forwarding"
        );
    }
}
