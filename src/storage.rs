use crate::{
    auth::AuthHook,
    auth_plugin::HttpAuthPlugin,
    config::{Config, TarballStorageBackend},
    constants::{
        API_ERROR_MUST_BE_LOGGED, API_ERROR_NO_PACKAGE, API_ERROR_NO_SUCH_FILE,
        API_ERROR_PACKAGE_EXIST, API_ERROR_PARAMETERS_NOT_VALID, API_ERROR_REVISION_CONFLICT,
        API_ERROR_UNAUTHORIZED_ACCESS, API_ERROR_UNSUPPORTED_REGISTRY_CALL,
        API_ERROR_VERSION_NOT_EXIST, API_MESSAGE_PKG_CHANGED, API_MESSAGE_PKG_CREATED,
        API_MESSAGE_PKG_REMOVED, API_MESSAGE_TAG_ADDED, API_MESSAGE_TAG_REMOVED,
        API_MESSAGE_TARBALL_REMOVED,
    },
    error::RegistryError,
    models::{AuthIdentity, PackageRecord, PersistedState},
    state_coordination::StateWriteCoordinator,
    tarball_backend::TarballBackend,
};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{SecondsFormat, Utc};
use rand::Rng;
use serde_json::{Map, Value, json};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

#[derive(Default)]
pub struct StoreOptions {
    pub auth_hook: Option<Arc<dyn AuthHook>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageDiscoveryMode {
    SingleNode,
    MultiNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataBackend {
    Sidecar,
    Managed,
    TransactionalPreview,
}

impl MetadataBackend {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "sidecar" => Some(Self::Sidecar),
            "managed" => Some(Self::Managed),
            "transactional" | "db" | "database" => Some(Self::TransactionalPreview),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Managed => "managed",
            Self::TransactionalPreview => "transactional-preview",
        }
    }
}

impl PackageDiscoveryMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => "single-node",
            Self::MultiNode => "multi-node",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "single" | "single-node" | "single_node" | "local" => Some(Self::SingleNode),
            "multi" | "multi-node" | "multi_node" | "cluster" => Some(Self::MultiNode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct PackageCacheSettings {
    discovery_mode: PackageDiscoveryMode,
    max_entries: usize,
    record_ttl_ms: i64,
    prune_interval_ms: i64,
    negative_ttl_ms: i64,
    discovery_refresh_interval_ms: i64,
}

impl PackageCacheSettings {
    fn from_env(default_discovery_mode: PackageDiscoveryMode) -> Result<Self, RegistryError> {
        let discovery_mode = match std::env::var("RUSTACCIO_PACKAGE_DISCOVERY_MODE").ok() {
            None => default_discovery_mode,
            Some(raw) if raw.trim().is_empty() => default_discovery_mode,
            Some(raw) => PackageDiscoveryMode::parse(&raw).ok_or_else(|| {
                RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "unsupported RUSTACCIO_PACKAGE_DISCOVERY_MODE: {raw} (expected single-node|multi-node)"
                    ),
                )
            })?,
        };

        let (default_ttl_secs, default_negative_ttl_secs, default_refresh_secs) =
            match discovery_mode {
                PackageDiscoveryMode::SingleNode => (0_u64, 30_u64, 0_u64),
                PackageDiscoveryMode::MultiNode => (120_u64, 5_u64, 15_u64),
            };

        let max_entries = parse_usize_env("RUSTACCIO_PACKAGE_CACHE_MAX_ENTRIES", 5_000).max(100);
        let ttl_secs = parse_u64_env("RUSTACCIO_PACKAGE_CACHE_TTL_SECS", default_ttl_secs);
        let prune_interval_secs =
            parse_u64_env("RUSTACCIO_PACKAGE_CACHE_PRUNE_INTERVAL_SECS", 30).max(1);
        let negative_ttl_secs = parse_u64_env(
            "RUSTACCIO_PACKAGE_NEGATIVE_CACHE_TTL_SECS",
            default_negative_ttl_secs,
        );
        let refresh_secs = parse_u64_env(
            "RUSTACCIO_PACKAGE_DISCOVERY_REFRESH_SECS",
            default_refresh_secs,
        );

        Ok(Self {
            discovery_mode,
            max_entries,
            record_ttl_ms: (ttl_secs as i64).saturating_mul(1_000),
            prune_interval_ms: (prune_interval_secs as i64).saturating_mul(1_000),
            negative_ttl_ms: (negative_ttl_secs as i64).saturating_mul(1_000),
            discovery_refresh_interval_ms: (refresh_secs as i64).saturating_mul(1_000),
        })
    }
}

#[derive(Default)]
struct KnownPackagesIndex {
    initialized: bool,
    last_refresh_ms: i64,
    packages: HashSet<String>,
    missing: HashMap<String, i64>,
}

impl KnownPackagesIndex {
    fn prune_missing(&mut self, now_ms: i64) {
        self.missing
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
    }
}

pub struct Store {
    state: RwLock<PersistedState>,
    tarball_backend: TarballBackend,
    state_coordinator: StateWriteCoordinator,
    auth_plugin: Option<HttpAuthPlugin>,
    auth_hook: Option<Arc<dyn AuthHook>>,
    package_cache: PackageCacheSettings,
    metadata_backend: MetadataBackend,
    strict_revision_checks: bool,
    known_packages: RwLock<KnownPackagesIndex>,
    last_package_cache_prune_ms: AtomicI64,
    maintenance_started: AtomicBool,
}

#[derive(Default)]
struct MetadataOnlyMergeResult {
    tarballs_to_delete: HashSet<String>,
}

impl Store {
    #[instrument(skip(config), fields(data_dir = %config.data_dir.display(), auth_backend = config.auth_plugin.is_some()))]
    pub async fn open(config: &Config) -> Result<Self, RegistryError> {
        Self::open_with_options(config, StoreOptions::default()).await
    }

    #[instrument(skip(config, options), fields(data_dir = %config.data_dir.display(), auth_backend = config.auth_plugin.is_some(), embedded_auth_hook = options.auth_hook.is_some()))]
    pub async fn open_with_options(
        config: &Config,
        options: StoreOptions,
    ) -> Result<Self, RegistryError> {
        Self::ensure_sidecar_metadata_authority()?;
        tokio::fs::create_dir_all(&config.data_dir).await?;
        let tarball_backend = TarballBackend::from_config(config).await?;
        let state_coordinator = StateWriteCoordinator::from_env().await?;
        let metadata_backend = Self::metadata_backend_from_env()?;
        let default_discovery_mode = if managed_mode_enabled_from_env()
            || config.tarball_storage.backend == TarballStorageBackend::S3
        {
            PackageDiscoveryMode::MultiNode
        } else {
            PackageDiscoveryMode::SingleNode
        };
        let package_cache = PackageCacheSettings::from_env(default_discovery_mode)?;
        let strict_revision_checks = strict_revision_checks_from_env();

        let state = PersistedState::default();

        let auth_plugin = match config.auth_plugin.as_ref() {
            Some(plugin_cfg) => Some(HttpAuthPlugin::new(plugin_cfg)?),
            None => None,
        };

        let store = Self {
            state: RwLock::new(state),
            tarball_backend,
            state_coordinator,
            auth_plugin,
            auth_hook: options.auth_hook,
            package_cache: package_cache.clone(),
            metadata_backend,
            strict_revision_checks,
            known_packages: RwLock::new(KnownPackagesIndex::default()),
            last_package_cache_prune_ms: AtomicI64::new(0),
            maintenance_started: AtomicBool::new(false),
        };
        debug!(
            discovery_mode = package_cache.discovery_mode.as_str(),
            max_entries = package_cache.max_entries,
            cache_ttl_ms = package_cache.record_ttl_ms,
            prune_interval_ms = package_cache.prune_interval_ms,
            negative_ttl_ms = package_cache.negative_ttl_ms,
            discovery_refresh_interval_ms = package_cache.discovery_refresh_interval_ms,
            metadata_backend = metadata_backend.as_str(),
            strict_revision_checks,
            "store initialized"
        );
        Ok(store)
    }

    fn now_ms() -> i64 {
        Utc::now().timestamp_millis()
    }

    pub fn start_background_maintenance(self: &Arc<Self>) {
        let prune_enabled = self.package_cache.prune_interval_ms > 0;
        let refresh_enabled = self.package_cache.discovery_refresh_interval_ms > 0;
        if !prune_enabled && !refresh_enabled {
            return;
        }
        if self.maintenance_started.swap(true, AtomicOrdering::SeqCst) {
            return;
        }

        let interval_ms = [
            self.package_cache.prune_interval_ms,
            self.package_cache.discovery_refresh_interval_ms,
        ]
        .into_iter()
        .filter(|value| *value > 0)
        .min()
        .unwrap_or(30_000)
        .max(1_000);

        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                store.prune_package_cache_if_due(false).await;
                if let Err(error) = store.refresh_known_packages_if_due(false).await {
                    warn!(error = ?error, "failed to refresh known package index");
                }
            }
        });
    }

    fn authoritative_cache_entry_fresh(&self, record: &PackageRecord, now_ms: i64) -> bool {
        if record.cached_from_uplink {
            return true;
        }
        if self.package_cache.record_ttl_ms <= 0 {
            return false;
        }
        now_ms.saturating_sub(record.updated_at) <= self.package_cache.record_ttl_ms
    }

    async fn refresh_known_packages_if_due(&self, force: bool) -> Result<(), RegistryError> {
        let refresh_interval_ms = self.package_cache.discovery_refresh_interval_ms;
        if refresh_interval_ms <= 0 && !force {
            return Ok(());
        }

        let now_ms = Self::now_ms();
        {
            let known = self.known_packages.read().await;
            if !force
                && known.initialized
                && now_ms.saturating_sub(known.last_refresh_ms) < refresh_interval_ms
            {
                return Ok(());
            }
        }

        let packages = self.tarball_backend.list_packages().await?;
        let package_set = packages.into_iter().collect::<HashSet<_>>();
        let package_count = package_set.len();

        let mut known = self.known_packages.write().await;
        known.initialized = true;
        known.last_refresh_ms = now_ms;
        known.packages = package_set;
        let known_packages = known.packages.clone();
        known.missing.retain(|package, expires_at_ms| {
            *expires_at_ms > now_ms && !known_packages.contains(package)
        });

        debug!(
            package_count,
            discovery_mode = self.package_cache.discovery_mode.as_str(),
            "refreshed known package index"
        );
        Ok(())
    }

    async fn should_probe_authoritative_backend(&self, package_name: &str) -> bool {
        if let Err(error) = self.refresh_known_packages_if_due(false).await {
            warn!(error = ?error, "known package index refresh failed; falling back to direct probe");
        }

        let now_ms = Self::now_ms();
        let mut known = self.known_packages.write().await;
        known.prune_missing(now_ms);
        if known.packages.contains(package_name) {
            return true;
        }
        if known.missing.contains_key(package_name) {
            return false;
        }
        if self.package_cache.discovery_mode == PackageDiscoveryMode::MultiNode && known.initialized
        {
            if self.package_cache.negative_ttl_ms > 0 {
                known.missing.insert(
                    package_name.to_string(),
                    now_ms.saturating_add(self.package_cache.negative_ttl_ms),
                );
            }
            return false;
        }
        true
    }

    async fn mark_known_package(&self, package_name: &str) {
        let mut known = self.known_packages.write().await;
        known.packages.insert(package_name.to_string());
        known.missing.remove(package_name);
    }

    async fn mark_missing_package(&self, package_name: &str) {
        let mut known = self.known_packages.write().await;
        known.packages.remove(package_name);
        if self.package_cache.negative_ttl_ms > 0 {
            known.missing.insert(
                package_name.to_string(),
                Self::now_ms().saturating_add(self.package_cache.negative_ttl_ms),
            );
        } else {
            known.missing.remove(package_name);
        }
    }

    fn prune_package_cache_with_settings(
        state: &mut PersistedState,
        settings: &PackageCacheSettings,
        now_ms: i64,
    ) -> usize {
        let before = state.packages.len();
        if settings.record_ttl_ms > 0 {
            state.packages.retain(|_, record| {
                now_ms.saturating_sub(record.updated_at) <= settings.record_ttl_ms
            });
        }

        if settings.max_entries > 0 && state.packages.len() > settings.max_entries {
            let mut by_age = state
                .packages
                .iter()
                .map(|(name, record)| (name.clone(), record.updated_at))
                .collect::<Vec<_>>();
            by_age.sort_by_key(|(_, updated_at)| *updated_at);

            let remove_count = state.packages.len().saturating_sub(settings.max_entries);
            for (package_name, _) in by_age.into_iter().take(remove_count) {
                state.packages.remove(&package_name);
            }
        }

        before.saturating_sub(state.packages.len())
    }

    async fn prune_package_cache_now(&self, reason: &str) {
        let now_ms = Self::now_ms();
        let removed = {
            let mut state = self.state.write().await;
            Self::prune_package_cache_with_settings(&mut state, &self.package_cache, now_ms)
        };
        {
            let mut known = self.known_packages.write().await;
            known.prune_missing(now_ms);
        }
        self.last_package_cache_prune_ms
            .store(now_ms, AtomicOrdering::Relaxed);
        if removed > 0 {
            debug!(removed, reason, "pruned package cache");
        }
    }

    async fn prune_package_cache_if_due(&self, force: bool) {
        if self.package_cache.prune_interval_ms <= 0 && !force {
            return;
        }
        if !force {
            let now_ms = Self::now_ms();
            let last_prune_ms = self
                .last_package_cache_prune_ms
                .load(AtomicOrdering::Relaxed);
            if last_prune_ms > 0
                && now_ms.saturating_sub(last_prune_ms) < self.package_cache.prune_interval_ms
            {
                return;
            }
        }
        self.prune_package_cache_now("scheduled").await;
    }

    fn ensure_sidecar_metadata_authority() -> Result<(), RegistryError> {
        let Some(raw) = std::env::var("RUSTACCIO_PACKAGE_METADATA_AUTHORITY").ok() else {
            return Ok(());
        };
        let normalized = raw.trim().to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "" | "sidecar" | "sidecar_authoritative" | "sidecar-authoritative"
        ) {
            return Ok(());
        }
        Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "RUSTACCIO_PACKAGE_METADATA_AUTHORITY={raw} is unsupported; only `sidecar` is valid"
            ),
        ))
    }

    fn metadata_backend_from_env() -> Result<MetadataBackend, RegistryError> {
        let raw = std::env::var("RUSTACCIO_METADATA_BACKEND")
            .ok()
            .unwrap_or_else(|| "sidecar".to_string());
        let Some(backend) = MetadataBackend::parse(&raw) else {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unsupported RUSTACCIO_METADATA_BACKEND: {raw} (expected sidecar|managed)"),
            ));
        };
        if backend == MetadataBackend::TransactionalPreview {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_METADATA_BACKEND=transactional is not available yet; use sidecar or managed",
            ));
        }
        Ok(backend)
    }

    fn now_http() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    fn package_lock_scope(package_name: &str) -> String {
        format!("package:{package_name}")
    }

    async fn run_package_exclusive<T, F, Fut>(
        &self,
        package_name: &str,
        operation_name: &str,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, RegistryError>>,
    {
        let scope = Self::package_lock_scope(package_name);
        self.state_coordinator
            .run_exclusive_scoped(&scope, operation_name, operation)
            .await
    }

    async fn hydrate_from_tarball_backend(
        state: &mut PersistedState,
        tarball_backend: &TarballBackend,
    ) -> Result<bool, RegistryError> {
        let references = tarball_backend.list().await?;
        let discovered_packages = tarball_backend.list_packages().await?;
        let legacy_packages = tarball_backend
            .load_legacy_package_index()
            .await?
            .unwrap_or_default();

        let mut tarballs_by_package: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for reference in references {
            let Some(version) = Self::infer_version_from_filename(&reference.filename) else {
                continue;
            };
            tarballs_by_package
                .entry(reference.package)
                .or_default()
                .push((reference.filename, version));
        }

        let mut package_names = HashSet::new();
        package_names.extend(discovered_packages);
        package_names.extend(legacy_packages.iter().cloned());
        package_names.extend(tarballs_by_package.keys().cloned());

        if package_names.is_empty() {
            return Ok(false);
        }

        let mut ordered_packages = package_names.into_iter().collect::<Vec<_>>();
        ordered_packages.sort();

        let now_ms = Self::now_ms();
        let now_rfc3339 = Utc::now().to_rfc3339();
        let mut changed = false;
        let mut indexed_packages = 0usize;
        let mut indexed_versions = 0usize;
        let mut metadata_enriched_versions = 0usize;
        let before_package_count = state.packages.len();
        state.packages.retain(|package, record| {
            record.cached_from_uplink || ordered_packages.binary_search(package).is_ok()
        });
        let removed_stale_packages = before_package_count.saturating_sub(state.packages.len());
        if removed_stale_packages > 0 {
            changed = true;
        }
        let mut package_metadata_cache: HashMap<String, Option<Value>> = HashMap::new();

        for package_name in ordered_packages {
            if !package_metadata_cache.contains_key(&package_name) {
                let package_metadata = tarball_backend.read_package_metadata(&package_name).await?;
                package_metadata_cache.insert(package_name.clone(), package_metadata);
            }
            let package_metadata = package_metadata_cache
                .get(&package_name)
                .and_then(|value| value.as_ref());
            let package_tarballs = tarballs_by_package
                .remove(&package_name)
                .unwrap_or_default();

            if !state.packages.contains_key(&package_name) {
                let manifest = package_metadata
                    .cloned()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| {
                        Value::Object(Self::inferred_manifest_shell(&package_name, &now_rfc3339))
                    });
                state.packages.insert(
                    package_name.clone(),
                    PackageRecord {
                        manifest,
                        upstream_tarballs: HashMap::new(),
                        updated_at: now_ms,
                        cached_from_uplink: false,
                    },
                );
                indexed_packages += 1;
                changed = true;
            }

            let Some(record) = state.packages.get_mut(&package_name) else {
                continue;
            };
            let mut record_changed = false;
            if record.cached_from_uplink {
                record.cached_from_uplink = false;
                record_changed = true;
            }
            if let Some(metadata) = package_metadata.and_then(Value::as_object) {
                if !record.manifest.is_object() {
                    record.manifest = Value::Object(Map::new());
                    record_changed = true;
                }
                if let Some(manifest) = record.manifest.as_object_mut() {
                    for (key, value) in metadata {
                        if manifest.get(key) != Some(value) {
                            manifest.insert(key.clone(), value.clone());
                            record_changed = true;
                        }
                    }
                }
            } else if !record.manifest.is_object() {
                record.manifest =
                    Value::Object(Self::inferred_manifest_shell(&package_name, &now_rfc3339));
                record_changed = true;
            }

            let Some(manifest) = record.manifest.as_object_mut() else {
                continue;
            };

            if manifest.get("_id").and_then(Value::as_str) != Some(package_name.as_str()) {
                manifest.insert("_id".to_string(), Value::String(package_name.clone()));
                record_changed = true;
            }
            if manifest.get("name").and_then(Value::as_str) != Some(package_name.as_str()) {
                manifest.insert("name".to_string(), Value::String(package_name.clone()));
                record_changed = true;
            }
            if !manifest.contains_key("_rev") {
                manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));
                record_changed = true;
            }
            if let Some(metadata) = package_metadata
                && Self::merge_startup_manifest_metadata(manifest, metadata, &package_name)
            {
                record_changed = true;
            }

            {
                let versions = Self::ensure_object_field(manifest, "versions");
                for (filename, version) in &package_tarballs {
                    let was_known = versions.contains_key(version);
                    let payload = versions
                        .entry(version.clone())
                        .or_insert_with(|| Value::Object(Map::new()));
                    if !payload.is_object() {
                        *payload = Value::Object(Map::new());
                        record_changed = true;
                    }
                    if let Some(sidecar_version) =
                        Self::startup_metadata_for_version(package_metadata, version)
                        && let (Some(target), Some(source)) =
                            (payload.as_object_mut(), sidecar_version.as_object())
                    {
                        for (key, value) in source {
                            if target.get(key) != Some(value) {
                                target.insert(key.clone(), value.clone());
                                record_changed = true;
                            }
                        }
                    }
                    if let Some(target) = payload.as_object_mut() {
                        let expected_id = format!("{package_name}@{version}");
                        if target.get("_id").and_then(Value::as_str) != Some(expected_id.as_str()) {
                            target.insert("_id".to_string(), Value::String(expected_id));
                            record_changed = true;
                        }
                        if target.get("name").and_then(Value::as_str) != Some(package_name.as_str())
                        {
                            target.insert("name".to_string(), Value::String(package_name.clone()));
                            record_changed = true;
                        }
                        if target.get("version").and_then(Value::as_str) != Some(version.as_str()) {
                            target.insert("version".to_string(), Value::String(version.clone()));
                            record_changed = true;
                        }

                        let expected_tarball = Self::inferred_tarball_url(&package_name, filename);
                        let dist = target
                            .entry("dist".to_string())
                            .or_insert_with(|| Value::Object(Map::new()));
                        if !dist.is_object() {
                            *dist = Value::Object(Map::new());
                            record_changed = true;
                        }
                        if let Some(dist_obj) = dist.as_object_mut()
                            && dist_obj.get("tarball").and_then(Value::as_str)
                                != Some(expected_tarball.as_str())
                        {
                            dist_obj.insert("tarball".to_string(), Value::String(expected_tarball));
                            record_changed = true;
                        }
                    }
                    if !was_known {
                        indexed_versions += 1;
                        if Self::startup_metadata_for_version(package_metadata, version).is_some() {
                            metadata_enriched_versions += 1;
                        }
                    }
                }
            }

            let version_keys = manifest
                .get("versions")
                .and_then(Value::as_object)
                .map(|versions| versions.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let latest_version = manifest
                .get("versions")
                .and_then(Value::as_object)
                .and_then(Self::select_latest_version);

            let attachments = Self::ensure_object_field(manifest, "_attachments");
            for (filename, version) in &package_tarballs {
                let expected_attachment = json!({ "version": version });
                if attachments.get(filename) != Some(&expected_attachment) {
                    attachments.insert(filename.clone(), expected_attachment);
                    record_changed = true;
                }
            }

            let dist_tags = Self::ensure_object_field(manifest, "dist-tags");
            let latest_valid = dist_tags
                .get("latest")
                .and_then(Value::as_str)
                .is_some_and(|tag| version_keys.iter().any(|version| version == tag));
            if !latest_valid && let Some(latest) = latest_version {
                dist_tags.insert("latest".to_string(), Value::String(latest));
                record_changed = true;
            }

            if !manifest
                .get("maintainers")
                .is_some_and(serde_json::Value::is_array)
            {
                manifest.insert("maintainers".to_string(), Value::Array(Vec::new()));
                record_changed = true;
            }
            if !manifest
                .get("users")
                .is_some_and(serde_json::Value::is_object)
            {
                manifest.insert("users".to_string(), Value::Object(Map::new()));
                record_changed = true;
            }

            let time = Self::ensure_object_field(manifest, "time");
            if !time.contains_key("created") {
                time.insert("created".to_string(), Value::String(now_rfc3339.clone()));
                record_changed = true;
            }
            for version in version_keys {
                if !time.contains_key(&version) {
                    time.insert(version, Value::String(now_rfc3339.clone()));
                    record_changed = true;
                }
            }
            if !time.contains_key("modified") {
                time.insert("modified".to_string(), Value::String(now_rfc3339.clone()));
                record_changed = true;
            } else if record_changed {
                time.insert("modified".to_string(), Value::String(now_rfc3339.clone()));
            }

            if record_changed {
                record.updated_at = now_ms;
                changed = true;
            }
        }
        debug!(
            indexed_packages,
            indexed_versions,
            metadata_enriched_versions,
            legacy_seed_packages = legacy_packages.len(),
            removed_stale_packages,
            changed,
            "indexed tarball backend during startup"
        );
        Ok(changed)
    }

    fn inferred_manifest_shell(package_name: &str, now_rfc3339: &str) -> Map<String, Value> {
        let mut manifest = Map::new();
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        manifest.insert("name".to_string(), Value::String(package_name.to_string()));
        manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));
        manifest.insert("versions".to_string(), Value::Object(Map::new()));
        manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
        manifest.insert("_attachments".to_string(), Value::Object(Map::new()));
        manifest.insert("maintainers".to_string(), Value::Array(Vec::new()));
        manifest.insert("users".to_string(), Value::Object(Map::new()));
        manifest.insert(
            "time".to_string(),
            json!({
                "created": now_rfc3339,
                "modified": now_rfc3339,
            }),
        );
        manifest
    }

    fn ensure_object_field<'a>(
        manifest: &'a mut Map<String, Value>,
        key: &str,
    ) -> &'a mut Map<String, Value> {
        if !manifest.get(key).is_some_and(serde_json::Value::is_object) {
            manifest.insert(key.to_string(), Value::Object(Map::new()));
        }
        manifest
            .get_mut(key)
            .and_then(Value::as_object_mut)
            .expect("object field was initialized")
    }

    fn inferred_tarball_url(package_name: &str, filename: &str) -> String {
        format!(
            "http://localhost:4873/{}/-/{}",
            package_name_to_encoded(package_name),
            filename
        )
    }

    fn merge_startup_manifest_metadata(
        manifest: &mut Map<String, Value>,
        tarball_metadata: &Value,
        package_name: &str,
    ) -> bool {
        let Some(metadata) = tarball_metadata.as_object() else {
            return false;
        };

        let mut changed = false;
        if !manifest.contains_key("description")
            && let Some(description) = metadata.get("description")
            && description.is_string()
        {
            manifest.insert("description".to_string(), description.clone());
            changed = true;
        }
        if !manifest.contains_key("readme")
            && let Some(readme) = metadata.get("readme")
            && readme.is_string()
        {
            manifest.insert("readme".to_string(), readme.clone());
            changed = true;
        }

        let maintainers_empty = manifest
            .get("maintainers")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if maintainers_empty
            && let Some(maintainers) = metadata.get("maintainers")
            && maintainers.is_array()
        {
            manifest.insert("maintainers".to_string(), maintainers.clone());
            changed = true;
        }

        manifest.insert("name".to_string(), Value::String(package_name.to_string()));
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        changed
    }

    fn startup_metadata_for_version<'a>(
        package_metadata: Option<&'a Value>,
        version: &str,
    ) -> Option<&'a Value> {
        let metadata = package_metadata?;
        let from_versions = metadata
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(version))
            .filter(|value| value.is_object());
        if from_versions.is_some() {
            return from_versions;
        }

        if metadata.get("version").and_then(Value::as_str) == Some(version) && metadata.is_object()
        {
            return Some(metadata);
        }

        None
    }

    fn select_latest_version(versions: &Map<String, Value>) -> Option<String> {
        let mut latest: Option<String> = None;
        for version in versions.keys() {
            match latest.as_deref() {
                Some(current) if Self::compare_versions(version, current).is_gt() => {
                    latest = Some(version.clone());
                }
                None => latest = Some(version.clone()),
                _ => {}
            }
        }
        latest
    }

    fn infer_version_from_filename(filename: &str) -> Option<String> {
        let stem = filename
            .strip_suffix(".tgz")
            .or_else(|| filename.strip_suffix(".tar.gz"))?;
        let (_, version) = stem.rsplit_once('-')?;
        if version.is_empty() {
            return None;
        }
        if !version
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_digit())
        {
            return None;
        }
        Some(version.to_string())
    }

    fn semverish(version: &str) -> Option<([u64; 3], bool, String)> {
        let without_build = version.split('+').next().unwrap_or(version);
        let (core, prerelease) = without_build
            .split_once('-')
            .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((
            [major, minor, patch],
            prerelease.is_none(),
            prerelease.unwrap_or_default().to_string(),
        ))
    }

    fn compare_versions(candidate: &str, current: &str) -> Ordering {
        match (Self::semverish(candidate), Self::semverish(current)) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => candidate.cmp(current),
        }
    }

    fn random_token_hex(bytes: usize) -> String {
        let mut buf = vec![0_u8; bytes];
        rand::rng().fill_bytes(&mut buf);
        hex::encode(buf)
    }

    async fn load_authoritative_package_record(
        &self,
        package_name: &str,
    ) -> Result<Option<PackageRecord>, RegistryError> {
        let package_metadata = self
            .tarball_backend
            .read_package_metadata(package_name)
            .await?;
        let tarball_files = self
            .tarball_backend
            .list_package_tarballs(package_name)
            .await?;
        let mut tarballs = Vec::new();
        for filename in tarball_files {
            let Some(version) = Self::infer_version_from_filename(&filename) else {
                continue;
            };
            tarballs.push((filename, version));
        }

        if package_metadata.is_none() && tarballs.is_empty() {
            return Ok(None);
        }

        let now_rfc3339 = Utc::now().to_rfc3339();
        let mut manifest = package_metadata
            .clone()
            .filter(Value::is_object)
            .unwrap_or_else(|| {
                Value::Object(Self::inferred_manifest_shell(package_name, &now_rfc3339))
            });
        let Some(manifest_obj) = manifest.as_object_mut() else {
            return Ok(None);
        };

        if manifest_obj.get("_id").and_then(Value::as_str) != Some(package_name) {
            manifest_obj.insert("_id".to_string(), Value::String(package_name.to_string()));
        }
        if manifest_obj.get("name").and_then(Value::as_str) != Some(package_name) {
            manifest_obj.insert("name".to_string(), Value::String(package_name.to_string()));
        }
        if !manifest_obj.contains_key("_rev") {
            manifest_obj.insert("_rev".to_string(), Value::String(Self::initial_revision()));
        }
        if let Some(metadata) = package_metadata.as_ref() {
            let _ = Self::merge_startup_manifest_metadata(manifest_obj, metadata, package_name);
        }

        {
            let versions = Self::ensure_object_field(manifest_obj, "versions");
            for (filename, version) in &tarballs {
                let payload = versions
                    .entry(version.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                if !payload.is_object() {
                    *payload = Value::Object(Map::new());
                }
                if let Some(sidecar_version) =
                    Self::startup_metadata_for_version(package_metadata.as_ref(), version)
                    && let (Some(target), Some(source)) =
                        (payload.as_object_mut(), sidecar_version.as_object())
                {
                    for (key, value) in source {
                        target.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                }
                if let Some(target) = payload.as_object_mut() {
                    let expected_id = format!("{package_name}@{version}");
                    target
                        .entry("_id".to_string())
                        .or_insert_with(|| Value::String(expected_id));
                    target
                        .entry("name".to_string())
                        .or_insert_with(|| Value::String(package_name.to_string()));
                    target
                        .entry("version".to_string())
                        .or_insert_with(|| Value::String(version.clone()));
                    let expected_tarball = Self::inferred_tarball_url(package_name, filename);
                    let dist = target
                        .entry("dist".to_string())
                        .or_insert_with(|| Value::Object(Map::new()));
                    if !dist.is_object() {
                        *dist = Value::Object(Map::new());
                    }
                    if let Some(dist_obj) = dist.as_object_mut() {
                        dist_obj.insert("tarball".to_string(), Value::String(expected_tarball));
                    }
                }
            }
        }

        let attachments = Self::ensure_object_field(manifest_obj, "_attachments");
        for (filename, version) in &tarballs {
            let expected_attachment = json!({ "version": version });
            attachments
                .entry(filename.clone())
                .or_insert(expected_attachment);
        }

        let version_keys = manifest_obj
            .get("versions")
            .and_then(Value::as_object)
            .map(|versions| versions.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let latest_version = manifest_obj
            .get("versions")
            .and_then(Value::as_object)
            .and_then(Self::select_latest_version);
        let dist_tags = Self::ensure_object_field(manifest_obj, "dist-tags");
        let latest_valid = dist_tags
            .get("latest")
            .and_then(Value::as_str)
            .is_some_and(|tag| version_keys.iter().any(|version| version == tag));
        if !latest_valid && let Some(latest) = latest_version {
            dist_tags.insert("latest".to_string(), Value::String(latest));
        }

        if !manifest_obj
            .get("maintainers")
            .is_some_and(serde_json::Value::is_array)
        {
            manifest_obj.insert("maintainers".to_string(), Value::Array(Vec::new()));
        }
        if !manifest_obj
            .get("users")
            .is_some_and(serde_json::Value::is_object)
        {
            manifest_obj.insert("users".to_string(), Value::Object(Map::new()));
        }
        let time = Self::ensure_object_field(manifest_obj, "time");
        if !time.contains_key("created") {
            time.insert("created".to_string(), Value::String(now_rfc3339.clone()));
        }
        for version in version_keys {
            if !time.contains_key(&version) {
                time.insert(version, Value::String(now_rfc3339.clone()));
            }
        }
        if !time.contains_key("modified") {
            time.insert("modified".to_string(), Value::String(now_rfc3339));
        }

        Ok(Some(PackageRecord {
            manifest,
            upstream_tarballs: HashMap::new(),
            updated_at: Self::now_ms(),
            cached_from_uplink: false,
        }))
    }

    async fn refresh_package_from_authority_cache(
        &self,
        package_name: &str,
        retain_local_on_miss: bool,
    ) -> Result<(), RegistryError> {
        let authoritative = self.load_authoritative_package_record(package_name).await?;
        let authoritative_found = authoritative.is_some();
        let mut state = self.state.write().await;
        match authoritative {
            Some(record) => {
                state.packages.insert(package_name.to_string(), record);
            }
            None => {
                let keep_existing_local =
                    retain_local_on_miss && state.packages.contains_key(package_name);
                let keep_uplink = state
                    .packages
                    .get(package_name)
                    .is_some_and(|record| record.cached_from_uplink);
                if !keep_existing_local && !keep_uplink {
                    state.packages.remove(package_name);
                }
            }
        }
        drop(state);
        if authoritative_found {
            self.mark_known_package(package_name).await;
        } else {
            self.mark_missing_package(package_name).await;
        }
        self.prune_package_cache_if_due(false).await;
        Ok(())
    }

    async fn sync_all_package_sidecars(&self) -> Result<usize, RegistryError> {
        if self.metadata_backend != MetadataBackend::Sidecar {
            return Ok(0);
        }
        let package_manifests = {
            let state = self.state.read().await;
            state
                .packages
                .iter()
                .filter(|(_, record)| !record.cached_from_uplink && record.manifest.is_object())
                .map(|(package_name, record)| (package_name.clone(), record.manifest.clone()))
                .collect::<Vec<_>>()
        };

        let mut synced = 0usize;
        for (package_name, manifest) in package_manifests {
            self.tarball_backend
                .write_package_metadata(&package_name, &manifest)
                .await?;
            synced += 1;
        }
        Ok(synced)
    }

    async fn sync_package_sidecar(&self, package_name: &str) -> Result<(), RegistryError> {
        if self.metadata_backend != MetadataBackend::Sidecar {
            return Ok(());
        }
        let manifest = {
            let state = self.state.read().await;
            let Some(record) = state.packages.get(package_name) else {
                return Ok(());
            };
            if record.cached_from_uplink || !record.manifest.is_object() {
                return Ok(());
            }
            record.manifest.clone()
        };
        self.tarball_backend
            .write_package_metadata(package_name, &manifest)
            .await
    }

    async fn write_tarball_file(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        self.tarball_backend.put(package, filename, content).await
    }

    pub async fn read_local_tarball(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        self.tarball_backend.get(package, filename).await
    }

    pub async fn is_known_package(&self, package: &str) -> bool {
        {
            let state = self.state.read().await;
            if state.packages.contains_key(package) {
                return true;
            }
        }
        self.load_authoritative_package_record(package)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    pub async fn authenticate_request(
        &self,
        token: &str,
        method: &str,
        path: &str,
        request_id: Option<&str>,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        if let Some(hook) = &self.auth_hook {
            debug!(
                method,
                path, "attempting request auth via embedded auth hook"
            );
            if let Some(identity) = hook.authenticate_request(token, method, path).await? {
                debug!(
                    method,
                    path,
                    source = "embedded_auth_hook",
                    has_username = identity.username.is_some(),
                    group_count = identity.groups.len(),
                    "request auth accepted"
                );
                return Ok(Some(identity));
            }
        }
        if let Some(plugin) = &self.auth_plugin {
            debug!(
                method,
                path, "attempting request auth via external auth plugin"
            );
            if let Some(identity) = plugin
                .authenticate_request(token, method, path, request_id)
                .await?
            {
                debug!(
                    method,
                    path,
                    source = "external_auth_plugin",
                    has_username = identity.username.is_some(),
                    group_count = identity.groups.len(),
                    "request auth accepted"
                );
                return Ok(Some(identity));
            }
        }

        debug!(method, path, "request auth yielded no identity");
        Ok(None)
    }

    pub async fn allow_access(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
        request_id: Option<&str>,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook.allow_access(identity.cloned(), package_name).await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin
                .allow_access(identity.cloned(), package_name, request_id)
                .await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    pub async fn allow_publish(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
        request_id: Option<&str>,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook.allow_publish(identity.cloned(), package_name).await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin
                .allow_publish(identity.cloned(), package_name, request_id)
                .await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    pub async fn allow_unpublish(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
        request_id: Option<&str>,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook
                .allow_unpublish(identity.cloned(), package_name)
                .await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin
                .allow_unpublish(identity.cloned(), package_name, request_id)
                .await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    fn package_record<'a>(
        state: &'a mut PersistedState,
        package: &str,
    ) -> Result<&'a mut PackageRecord, RegistryError> {
        state
            .packages
            .get_mut(package)
            .ok_or_else(|| RegistryError::http(StatusCode::NOT_FOUND, API_ERROR_NO_PACKAGE))
    }

    fn bump_revision(manifest: &mut Map<String, Value>) {
        let next = manifest
            .get("_rev")
            .and_then(Value::as_str)
            .and_then(|rev| rev.split_once('-').map(|(n, _)| n))
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        manifest.insert("_rev".to_string(), Value::String(Self::revision(next)));
    }

    fn initial_revision() -> String {
        Self::revision(1)
    }

    fn ensure_revision_matches(
        manifest: &Map<String, Value>,
        expected_revision: Option<&str>,
    ) -> Result<(), RegistryError> {
        let Some(expected) = expected_revision else {
            return Ok(());
        };
        let current = manifest
            .get("_rev")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if current == expected {
            return Ok(());
        }
        Err(RegistryError::storage_conflict(format!(
            "{API_ERROR_REVISION_CONFLICT}: expected `{expected}`, current `{current}`"
        )))
    }

    fn revision(counter: u64) -> String {
        format!("{counter}-{}", Self::random_token_hex(16))
    }

    fn remove_attachment_data(value: &Value) -> Value {
        let mut obj = value.as_object().cloned().unwrap_or_default();
        obj.remove("data");
        Value::Object(obj)
    }

    fn now_rfc3339_timestamp() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    fn ensure_manifest_defaults(
        manifest: &mut Map<String, Value>,
        package_name: &str,
        username: &str,
    ) {
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        manifest.insert("name".to_string(), Value::String(package_name.to_string()));

        if manifest.get("maintainers").is_none() {
            manifest.insert(
                "maintainers".to_string(),
                json!([
                    {
                        "name": username,
                        "email": ""
                    }
                ]),
            );
        }

        if manifest.get("users").is_none() {
            manifest.insert("users".to_string(), Value::Object(Map::new()));
        }

        if manifest.get("dist-tags").is_none() {
            if let Some(versions) = manifest.get("versions").and_then(Value::as_object) {
                if let Some((first, _)) = versions.iter().next() {
                    manifest.insert("dist-tags".to_string(), json!({"latest": first}));
                } else {
                    manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
                }
            } else {
                manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
            }
        }

        let now = Self::now_rfc3339_timestamp();
        let time = manifest
            .entry("time")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(time_obj) = time.as_object_mut() {
            time_obj
                .entry("modified".to_string())
                .or_insert_with(|| Value::String(now.clone()));
            time_obj
                .entry("created".to_string())
                .or_insert_with(|| Value::String(now));
        }
    }

    fn has_attachment_data(body: &Value) -> bool {
        body.get("_attachments")
            .and_then(Value::as_object)
            .map(|attachments| {
                !attachments.is_empty()
                    && attachments
                        .values()
                        .all(|attachment| attachment.get("data").and_then(Value::as_str).is_some())
            })
            .unwrap_or(false)
    }

    fn attachment_basename(name: &str) -> Option<&str> {
        name.rsplit(['/', '\\']).find(|segment| !segment.is_empty())
    }

    fn normalized_attachment_filename(name: &str) -> Result<String, RegistryError> {
        let Some(filename) = Self::attachment_basename(name) else {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        };
        if filename == "." || filename == ".." {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        }
        Ok(filename.to_string())
    }

    fn normalized_attachment_names(
        attachments: &Map<String, Value>,
    ) -> Result<Vec<(String, String)>, RegistryError> {
        let mut names = Vec::with_capacity(attachments.len());
        let mut seen = HashSet::with_capacity(attachments.len());
        for raw_name in attachments.keys() {
            let normalized_name = Self::normalized_attachment_filename(raw_name)?;
            if !seen.insert(normalized_name.clone()) {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                ));
            }
            names.push((raw_name.clone(), normalized_name));
        }
        Ok(names)
    }

    fn normalize_version_dist_tarball(package_name: &str, payload: &mut Value) {
        let Some(dist_obj) = payload.get_mut("dist").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(raw_tarball) = dist_obj
            .get("tarball")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return;
        };
        let Some(raw_filename) = package_filename_from_tarball_url(&raw_tarball) else {
            return;
        };
        let Ok(filename) = Self::normalized_attachment_filename(&raw_filename) else {
            return;
        };
        let normalized_tarball = Self::inferred_tarball_url(package_name, &filename);
        if raw_tarball != normalized_tarball {
            dist_obj.insert("tarball".to_string(), Value::String(normalized_tarball));
        }
    }

    fn attachment_metadata_for_publish(
        versions: &Map<String, Value>,
        filename: &str,
        attachment: &Value,
    ) -> Value {
        let mut version_for_file: Option<String> = None;
        let mut shasum_for_file: Option<String> = None;

        for (version, payload) in versions {
            let Some(dist) = payload.get("dist").and_then(Value::as_object) else {
                continue;
            };
            let Some(tarball_filename) = dist
                .get("tarball")
                .and_then(Value::as_str)
                .and_then(package_filename_from_tarball_url)
            else {
                continue;
            };
            let Ok(normalized_tarball_filename) =
                Self::normalized_attachment_filename(&tarball_filename)
            else {
                continue;
            };
            if normalized_tarball_filename != filename {
                continue;
            }
            version_for_file = Some(version.clone());
            shasum_for_file = dist
                .get("shasum")
                .and_then(Value::as_str)
                .map(str::to_string);
            break;
        }

        let mut obj = Map::new();
        if let Some(shasum) = shasum_for_file {
            obj.insert("shasum".to_string(), Value::String(shasum));
        }
        if let Some(version) = version_for_file.or_else(|| {
            attachment
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        }) {
            obj.insert("version".to_string(), Value::String(version));
        }

        if obj.is_empty() {
            return Self::remove_attachment_data(attachment);
        }
        Value::Object(obj)
    }

    fn tarball_filename_from_version_payload(payload: &Value) -> Option<String> {
        payload
            .get("dist")
            .and_then(Value::as_object)
            .and_then(|dist| dist.get("tarball"))
            .and_then(Value::as_str)
            .and_then(package_filename_from_tarball_url)
    }

    fn merge_metadata_only_manifest(
        manifest: &mut Map<String, Value>,
        body: &Value,
    ) -> Result<MetadataOnlyMergeResult, RegistryError> {
        let mut result = MetadataOnlyMergeResult::default();
        let incoming_versions =
            body.get("versions")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    RegistryError::http(
                        StatusCode::BAD_REQUEST,
                        API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                    )
                })?;

        let dst_versions = manifest
            .entry("versions".to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(RegistryError::Internal)?;

        if incoming_versions
            .keys()
            .any(|version| !dst_versions.contains_key(version))
        {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        }

        let existing_versions: Vec<String> = dst_versions.keys().cloned().collect();
        let mut removed_versions = HashSet::new();
        for version in existing_versions {
            let Some(incoming_version) = incoming_versions.get(&version) else {
                if let Some(existing_payload) = dst_versions.get(&version)
                    && let Some(filename) =
                        Self::tarball_filename_from_version_payload(existing_payload)
                {
                    result.tarballs_to_delete.insert(filename);
                }
                dst_versions.remove(&version);
                removed_versions.insert(version);
                continue;
            };

            let Some(incoming_obj) = incoming_version.as_object() else {
                continue;
            };
            if !incoming_obj.contains_key("deprecated") {
                continue;
            }

            let Some(local_obj) = dst_versions
                .get_mut(&version)
                .and_then(Value::as_object_mut)
            else {
                return Err(RegistryError::Internal);
            };

            match incoming_obj.get("deprecated") {
                Some(Value::String(value)) if !value.is_empty() => {
                    local_obj.insert("deprecated".to_string(), Value::String(value.clone()));
                }
                Some(Value::String(_)) | Some(Value::Null) | None => {
                    local_obj.remove("deprecated");
                }
                Some(other) => {
                    local_obj.insert("deprecated".to_string(), other.clone());
                }
            }
        }

        if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
            for removed in &removed_versions {
                time_obj.remove(removed);
            }
        }

        if let Some(tags) = body.get("dist-tags").and_then(Value::as_object) {
            manifest.insert("dist-tags".to_string(), Value::Object(tags.clone()));
        }

        if let Some(users) = body.get("users") {
            manifest.insert("users".to_string(), users.clone());
        }
        if let Some(maintainers) = body.get("maintainers") {
            manifest.insert("maintainers".to_string(), maintainers.clone());
        }

        if let Some(attachments) = body.get("_attachments").and_then(Value::as_object) {
            let normalized_attachment_names = Self::normalized_attachment_names(attachments)?;
            let previous_attachment_names = manifest
                .get("_attachments")
                .and_then(Value::as_object)
                .map(|existing| existing.keys().cloned().collect::<HashSet<_>>())
                .unwrap_or_default();
            let mut new_attachments = Map::new();
            let mut new_attachment_names = HashSet::with_capacity(attachments.len());
            for (raw_name, normalized_name) in normalized_attachment_names {
                let Some(attachment) = attachments.get(&raw_name) else {
                    return Err(RegistryError::Internal);
                };
                new_attachments.insert(
                    normalized_name.clone(),
                    Self::remove_attachment_data(attachment),
                );
                new_attachment_names.insert(normalized_name);
            }
            for filename in &previous_attachment_names {
                let normalized_filename = Self::normalized_attachment_filename(filename)
                    .unwrap_or_else(|_| filename.clone());
                if !new_attachment_names.contains(&normalized_filename) {
                    result.tarballs_to_delete.insert(filename.clone());
                }
            }
            result.tarballs_to_delete.retain(|filename| {
                let normalized_filename = Self::normalized_attachment_filename(filename)
                    .unwrap_or_else(|_| filename.clone());
                !new_attachment_names.contains(&normalized_filename)
            });
            manifest.insert("_attachments".to_string(), Value::Object(new_attachments));
        } else if !result.tarballs_to_delete.is_empty()
            && let Some(existing_attachments) = manifest
                .get_mut("_attachments")
                .and_then(Value::as_object_mut)
        {
            for filename in &result.tarballs_to_delete {
                existing_attachments.remove(filename);
            }
        }

        if !removed_versions.is_empty()
            && let Some(tags) = manifest.get_mut("dist-tags").and_then(Value::as_object_mut)
        {
            let stale_tags: Vec<String> = tags
                .iter()
                .filter_map(|(tag, version)| {
                    let version = version.as_str().unwrap_or_default();
                    if removed_versions.contains(version) {
                        Some(tag.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for tag in stale_tags {
                tags.remove(&tag);
            }
        }

        Ok(result)
    }

    #[instrument(skip(self, body), fields(package = package_name, username))]
    pub async fn publish_manifest(
        &self,
        package_name: &str,
        body: Value,
        username: &str,
    ) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "publish_manifest", || async {
            self.refresh_package_from_authority_cache(package_name, true)
                .await?;
            self.publish_manifest_inner(package_name, body, username)
                .await
        })
        .await
    }

    async fn publish_manifest_inner(
        &self,
        package_name: &str,
        body: Value,
        username: &str,
    ) -> Result<String, RegistryError> {
        let expected_revision = body.get("_rev").and_then(Value::as_str);
        {
            let state = self.state.read().await;
            if let Some(record) = state.packages.get(package_name)
                && let Some(manifest) = record.manifest.as_object()
                && self.strict_revision_checks
            {
                Self::ensure_revision_matches(manifest, expected_revision)?;
            }
        }

        let is_owner_or_star_update = body.get("versions").is_none()
            && (body.get("users").is_some() || body.get("maintainers").is_some());

        if is_owner_or_star_update {
            return self
                .publish_owner_or_star_update(package_name, &body, username)
                .await;
        }

        let _versions = body
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;

        if !Self::has_attachment_data(&body) {
            return self
                .publish_metadata_only_update(package_name, &body, username)
                .await;
        }

        let attachments = body
            .get("_attachments")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;
        if attachments.is_empty() {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        }

        let versions = body
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;
        self.publish_with_attachments(package_name, &body, versions, attachments, username)
            .await
    }

    async fn publish_owner_or_star_update(
        &self,
        package_name: &str,
        body: &Value,
        username: &str,
    ) -> Result<String, RegistryError> {
        {
            let mut state = self.state.write().await;
            let record = Self::package_record(&mut state, package_name)?;
            let Some(manifest) = record.manifest.as_object_mut() else {
                return Err(RegistryError::Internal);
            };

            if let Some(users) = body.get("users") {
                manifest.insert("users".to_string(), users.clone());
            }
            if let Some(maintainers) = body.get("maintainers") {
                manifest.insert("maintainers".to_string(), maintainers.clone());
            }

            Self::ensure_manifest_defaults(manifest, package_name, username);
            Self::bump_revision(manifest);
            record.updated_at = Self::now_ms();
            record.cached_from_uplink = false;
        }

        self.sync_package_sidecar(package_name).await?;
        debug!("updated package owner/star metadata");
        Ok(API_MESSAGE_PKG_CHANGED.to_string())
    }

    async fn publish_metadata_only_update(
        &self,
        package_name: &str,
        body: &Value,
        username: &str,
    ) -> Result<String, RegistryError> {
        let (merged_manifest, tarballs_to_delete) = {
            let state = self.state.read().await;
            let Some(record) = state.packages.get(package_name) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                ));
            };
            let Some(mut manifest) = record.manifest.as_object().cloned() else {
                return Err(RegistryError::Internal);
            };

            let merge_result = Self::merge_metadata_only_manifest(&mut manifest, body)?;
            Self::ensure_manifest_defaults(&mut manifest, package_name, username);
            Self::bump_revision(&mut manifest);

            if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
                time_obj.insert(
                    "modified".to_string(),
                    Value::String(Self::now_rfc3339_timestamp()),
                );
            }

            (
                manifest,
                merge_result
                    .tarballs_to_delete
                    .into_iter()
                    .collect::<Vec<_>>(),
            )
        };

        for filename in &tarballs_to_delete {
            self.tarball_backend.delete(package_name, filename).await?;
        }

        {
            let mut state = self.state.write().await;
            let Some(record) = state.packages.get_mut(package_name) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                ));
            };
            for filename in &tarballs_to_delete {
                record.upstream_tarballs.remove(filename);
            }
            record.manifest = Value::Object(merged_manifest);
            record.updated_at = Self::now_ms();
            record.cached_from_uplink = false;
        }

        self.sync_package_sidecar(package_name).await?;
        debug!("applied metadata-only publish update");
        Ok(API_MESSAGE_PKG_CHANGED.to_string())
    }

    async fn publish_with_attachments(
        &self,
        package_name: &str,
        body: &Value,
        versions: &Map<String, Value>,
        attachments: &Map<String, Value>,
        username: &str,
    ) -> Result<String, RegistryError> {
        let published_versions: Vec<String> = versions.keys().cloned().collect();
        let attachment_names = Self::normalized_attachment_names(attachments)?;
        for (raw_name, filename) in &attachment_names {
            let Some(attachment) = attachments.get(raw_name) else {
                return Err(RegistryError::Internal);
            };
            let Some(data_b64) = attachment.get("data").and_then(Value::as_str) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                ));
            };
            let data = B64.decode(data_b64).map_err(|_| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;
            self.write_tarball_file(package_name, filename, &data)
                .await?;
        }

        let message = {
            let mut state = self.state.write().await;

            let message;
            if let Some(record) = state.packages.get_mut(package_name) {
                let Some(manifest) = record.manifest.as_object_mut() else {
                    return Err(RegistryError::Internal);
                };

                let dst_versions = manifest
                    .entry("versions".to_string())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or(RegistryError::Internal)?;

                for version in versions.keys() {
                    if dst_versions.contains_key(version) {
                        return Err(RegistryError::http(
                            StatusCode::CONFLICT,
                            API_ERROR_PACKAGE_EXIST,
                        ));
                    }
                }

                for (version, payload) in versions {
                    let mut normalized_payload = payload.clone();
                    Self::normalize_version_dist_tarball(package_name, &mut normalized_payload);
                    dst_versions.insert(version.clone(), normalized_payload);
                }

                if let Some(tags) = body.get("dist-tags").and_then(Value::as_object) {
                    let dst_tags = manifest
                        .entry("dist-tags".to_string())
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                        .ok_or(RegistryError::Internal)?;
                    for (tag, value) in tags {
                        dst_tags.insert(tag.clone(), value.clone());
                    }
                }

                let dst_attachments = manifest
                    .entry("_attachments".to_string())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or(RegistryError::Internal)?;

                for (raw_name, normalized_name) in &attachment_names {
                    let Some(attachment) = attachments.get(raw_name) else {
                        return Err(RegistryError::Internal);
                    };
                    dst_attachments.insert(
                        normalized_name.clone(),
                        Self::attachment_metadata_for_publish(
                            versions,
                            normalized_name,
                            attachment,
                        ),
                    );
                }

                if let Some(users) = body.get("users") {
                    manifest.insert("users".to_string(), users.clone());
                }
                if let Some(maintainers) = body.get("maintainers") {
                    manifest.insert("maintainers".to_string(), maintainers.clone());
                }

                Self::ensure_manifest_defaults(manifest, package_name, username);
                Self::bump_revision(manifest);

                if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
                    let now = Self::now_rfc3339_timestamp();
                    time_obj.insert("modified".to_string(), Value::String(now.clone()));
                    for version in &published_versions {
                        time_obj
                            .entry(version.clone())
                            .or_insert_with(|| Value::String(now.clone()));
                    }
                }

                record.updated_at = Self::now_ms();
                record.cached_from_uplink = false;
                message = API_MESSAGE_PKG_CHANGED.to_string();
            } else {
                let mut manifest = body.as_object().cloned().ok_or_else(|| {
                    RegistryError::http(
                        StatusCode::BAD_REQUEST,
                        API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                    )
                })?;

                if let Some(versions_obj) =
                    manifest.get_mut("versions").and_then(Value::as_object_mut)
                {
                    for payload in versions_obj.values_mut() {
                        Self::normalize_version_dist_tarball(package_name, payload);
                    }
                }
                let mut normalized_attachments = Map::new();
                for (raw_name, normalized_name) in &attachment_names {
                    let Some(attachment) = attachments.get(raw_name) else {
                        return Err(RegistryError::Internal);
                    };
                    normalized_attachments.insert(
                        normalized_name.clone(),
                        Self::attachment_metadata_for_publish(
                            versions,
                            normalized_name,
                            attachment,
                        ),
                    );
                }
                manifest.insert(
                    "_attachments".to_string(),
                    Value::Object(normalized_attachments),
                );

                Self::ensure_manifest_defaults(&mut manifest, package_name, username);
                if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
                    let now = Self::now_rfc3339_timestamp();
                    time_obj.insert("modified".to_string(), Value::String(now.clone()));
                    for version in &published_versions {
                        time_obj
                            .entry(version.clone())
                            .or_insert_with(|| Value::String(now.clone()));
                    }
                }
                manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));

                state.packages.insert(
                    package_name.to_string(),
                    PackageRecord {
                        manifest: Value::Object(manifest),
                        upstream_tarballs: HashMap::new(),
                        updated_at: Self::now_ms(),
                        cached_from_uplink: false,
                    },
                );
                message = API_MESSAGE_PKG_CREATED.to_string();
            }

            message
        };

        self.sync_package_sidecar(package_name).await?;
        self.mark_known_package(package_name).await;
        self.prune_package_cache_if_due(false).await;
        debug!(message = message.as_str(), "published package manifest");
        Ok(message)
    }

    #[instrument(skip(self), fields(package = package_name))]
    pub async fn remove_package(&self, package_name: &str) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "remove_package", || async {
            self.refresh_package_from_authority_cache(package_name, false)
                .await?;
            self.remove_package_inner(package_name, None).await
        })
        .await
    }

    pub async fn remove_package_with_revision(
        &self,
        package_name: &str,
        expected_revision: Option<&str>,
    ) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "remove_package", || async {
            self.refresh_package_from_authority_cache(package_name, false)
                .await?;
            self.remove_package_inner(package_name, expected_revision)
                .await
        })
        .await
    }

    async fn remove_package_inner(
        &self,
        package_name: &str,
        expected_revision: Option<&str>,
    ) -> Result<String, RegistryError> {
        {
            let state = self.state.read().await;
            let Some(record) = state.packages.get(package_name) else {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_PACKAGE,
                ));
            };
            let Some(manifest) = record.manifest.as_object() else {
                return Err(RegistryError::Internal);
            };
            if self.strict_revision_checks {
                Self::ensure_revision_matches(manifest, expected_revision)?;
            }
        }

        self.tarball_backend.delete_package(package_name).await?;

        {
            let mut state = self.state.write().await;
            if state.packages.remove(package_name).is_none() {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_PACKAGE,
                ));
            }
        }
        self.mark_missing_package(package_name).await;

        debug!("removed package");
        Ok(API_MESSAGE_PKG_REMOVED.to_string())
    }

    #[instrument(skip(self), fields(package = package_name, filename))]
    pub async fn remove_tarball(
        &self,
        package_name: &str,
        filename: &str,
    ) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "remove_tarball", || async {
            self.refresh_package_from_authority_cache(package_name, true)
                .await?;
            self.remove_tarball_inner(package_name, filename, None)
                .await
        })
        .await
    }

    pub async fn remove_tarball_with_revision(
        &self,
        package_name: &str,
        filename: &str,
        expected_revision: Option<&str>,
    ) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "remove_tarball", || async {
            self.refresh_package_from_authority_cache(package_name, true)
                .await?;
            self.remove_tarball_inner(package_name, filename, expected_revision)
                .await
        })
        .await
    }

    async fn remove_tarball_inner(
        &self,
        package_name: &str,
        filename: &str,
        expected_revision: Option<&str>,
    ) -> Result<String, RegistryError> {
        {
            let state = self.state.read().await;
            let Some(record) = state.packages.get(package_name) else {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_PACKAGE,
                ));
            };
            let Some(manifest) = record.manifest.as_object() else {
                return Err(RegistryError::Internal);
            };
            if self.strict_revision_checks {
                Self::ensure_revision_matches(manifest, expected_revision)?;
            }
        }

        let removed_file = self.tarball_backend.delete(package_name, filename).await?;
        {
            let mut state = self.state.write().await;
            let record = Self::package_record(&mut state, package_name)?;
            let Some(manifest) = record.manifest.as_object_mut() else {
                return Err(RegistryError::Internal);
            };

            let mut removed_versions = HashSet::new();
            if let Some(versions) = manifest.get_mut("versions").and_then(Value::as_object_mut) {
                let mut to_delete = Vec::new();
                for (version, data) in versions.iter() {
                    let tarball = data
                        .get("dist")
                        .and_then(|dist| dist.get("tarball"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let found = tarball.rsplit('/').next().unwrap_or_default();
                    if found == filename {
                        to_delete.push(version.clone());
                    }
                }
                for version in to_delete {
                    versions.remove(&version);
                    removed_versions.insert(version);
                }
            }

            if let Some(tags) = manifest.get_mut("dist-tags").and_then(Value::as_object_mut) {
                let to_remove: Vec<String> = tags
                    .iter()
                    .filter_map(|(tag, version)| {
                        let version = version.as_str().unwrap_or_default();
                        if removed_versions.contains(version) {
                            Some(tag.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for tag in to_remove {
                    tags.remove(&tag);
                }
            }

            if let Some(attachments) = manifest
                .get_mut("_attachments")
                .and_then(Value::as_object_mut)
            {
                attachments.remove(filename);
            }

            let removed_upstream = record.upstream_tarballs.remove(filename).is_some();

            if !removed_file && !removed_upstream && removed_versions.is_empty() {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_SUCH_FILE,
                ));
            }

            Self::bump_revision(manifest);
            record.updated_at = Self::now_ms();
        }

        self.sync_package_sidecar(package_name).await?;
        debug!("removed tarball");
        Ok(API_MESSAGE_TARBALL_REMOVED.to_string())
    }

    pub async fn merge_dist_tag(
        &self,
        package_name: &str,
        tag: &str,
        version: Option<&str>,
    ) -> Result<String, RegistryError> {
        self.run_package_exclusive(package_name, "merge_dist_tag", || async {
            self.refresh_package_from_authority_cache(package_name, true)
                .await?;
            self.merge_dist_tag_inner(package_name, tag, version).await
        })
        .await
    }

    async fn merge_dist_tag_inner(
        &self,
        package_name: &str,
        tag: &str,
        version: Option<&str>,
    ) -> Result<String, RegistryError> {
        let response = {
            let mut state = self.state.write().await;
            let record = Self::package_record(&mut state, package_name)?;
            let Some(manifest) = record.manifest.as_object_mut() else {
                return Err(RegistryError::Internal);
            };
            let tags = manifest
                .entry("dist-tags".to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or(RegistryError::Internal)?;

            let response = if let Some(version) = version {
                tags.insert(tag.to_string(), Value::String(version.to_string()));
                API_MESSAGE_TAG_ADDED
            } else {
                tags.remove(tag);
                API_MESSAGE_TAG_REMOVED
            };

            Self::bump_revision(manifest);
            record.updated_at = Self::now_ms();
            record.cached_from_uplink = false;

            response.to_string()
        };

        self.sync_package_sidecar(package_name).await?;
        Ok(response)
    }

    pub async fn dist_tags(&self, package_name: &str) -> Result<Value, RegistryError> {
        let Some(record) = self.get_package_record_result(package_name).await? else {
            return Err(RegistryError::http(
                StatusCode::NOT_FOUND,
                API_ERROR_NO_PACKAGE,
            ));
        };
        let tags = record
            .manifest
            .get("dist-tags")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        Ok(tags)
    }

    pub async fn invalidate_package_cache(&self, package_name: &str) -> bool {
        let removed = {
            let mut state = self.state.write().await;
            state.packages.remove(package_name).is_some()
        };
        let mut known = self.known_packages.write().await;
        known.missing.remove(package_name);
        removed
    }

    pub async fn get_package_record_result(
        &self,
        package_name: &str,
    ) -> Result<Option<PackageRecord>, RegistryError> {
        let now_ms = Self::now_ms();
        {
            let state = self.state.read().await;
            if let Some(record) = state.packages.get(package_name)
                && (record.cached_from_uplink
                    || self.authoritative_cache_entry_fresh(record, now_ms))
            {
                return Ok(Some(record.clone()));
            }
        }

        if !self.should_probe_authoritative_backend(package_name).await {
            return Ok(None);
        }

        let authoritative = self.load_authoritative_package_record(package_name).await?;

        match authoritative {
            Some(record) => {
                self.mark_known_package(package_name).await;
                {
                    let mut state = self.state.write().await;
                    state
                        .packages
                        .insert(package_name.to_string(), record.clone());
                }
                self.prune_package_cache_if_due(false).await;
                Ok(Some(record))
            }
            None => {
                if self.package_cache.discovery_mode == PackageDiscoveryMode::SingleNode {
                    let state = self.state.read().await;
                    if let Some(local) = state.packages.get(package_name)
                        && !local.cached_from_uplink
                    {
                        return Ok(Some(local.clone()));
                    }
                }
                self.mark_missing_package(package_name).await;
                Ok(None)
            }
        }
    }

    pub async fn get_package_record(&self, package_name: &str) -> Option<PackageRecord> {
        match self.get_package_record_result(package_name).await {
            Ok(record) => record,
            Err(error) => {
                warn!(
                    error = ?error,
                    package = package_name,
                    "authoritative package lookup failed"
                );
                None
            }
        }
    }

    #[instrument(skip(self, manifest, upstream_tarballs), fields(package = package_name, upstream_tarball_count = upstream_tarballs.len()))]
    pub async fn upsert_upstream_package(
        &self,
        package_name: &str,
        manifest: Value,
        upstream_tarballs: HashMap<String, String>,
    ) -> Result<(), RegistryError> {
        {
            let mut state = self.state.write().await;
            state.packages.insert(
                package_name.to_string(),
                PackageRecord {
                    manifest,
                    upstream_tarballs,
                    updated_at: Self::now_ms(),
                    cached_from_uplink: true,
                },
            );
        }

        debug!("upserted upstream package cache");
        self.prune_package_cache_if_due(false).await;
        Ok(())
    }

    pub async fn upstream_tarball_url(&self, package_name: &str, filename: &str) -> Option<String> {
        let state = self.state.read().await;
        state
            .packages
            .get(package_name)
            .and_then(|record| record.upstream_tarballs.get(filename).cloned())
    }

    pub async fn set_upstream_tarball_url(
        &self,
        package_name: &str,
        filename: &str,
        url: String,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.write().await;
        if let Some(record) = state.packages.get_mut(package_name) {
            record.upstream_tarballs.insert(filename.to_string(), url);
        }
        Ok(())
    }

    #[instrument(skip(self, content), fields(package = package_name, filename, bytes = content.len()))]
    pub async fn cache_tarball(
        &self,
        package_name: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        self.write_tarball_file(package_name, filename, content)
            .await
    }

    pub async fn all_packages(&self) -> Result<Vec<PackageRecord>, RegistryError> {
        let packages = self.tarball_backend.list_packages().await?;
        let mut records = Vec::new();
        for package_name in packages {
            if let Some(record) = self
                .load_authoritative_package_record(&package_name)
                .await?
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub async fn reindex_from_backend(&self) -> Result<Value, RegistryError> {
        let (changed, before_packages, after_packages) = {
            let mut state = self.state.write().await;
            let before_packages = state.packages.len();
            let changed =
                Self::hydrate_from_tarball_backend(&mut state, &self.tarball_backend).await?;
            let after_packages = state.packages.len();
            (changed, before_packages, after_packages)
        };
        if let Err(error) = self.refresh_known_packages_if_due(true).await {
            warn!(error = ?error, "failed to refresh known package index after reindex");
        }
        self.prune_package_cache_now("reindex").await;
        let sidecars_synced = if changed {
            self.sync_all_package_sidecars().await?
        } else {
            0
        };

        Ok(json!({
            "ok": true,
            "changed": changed,
            "packagesBefore": before_packages,
            "packagesAfter": after_packages,
            "sidecarsSynced": sidecars_synced,
        }))
    }

    pub async fn storage_health(&self) -> Result<Value, RegistryError> {
        let references = self.tarball_backend.list().await?;
        let backend_packages = self.tarball_backend.list_packages().await?;
        let legacy_index_package_count = self
            .tarball_backend
            .load_legacy_package_index()
            .await?
            .map(|packages| packages.len())
            .unwrap_or(0);

        let mut backend_tarballs: HashMap<String, HashSet<String>> = HashMap::new();
        for reference in references {
            if Self::infer_version_from_filename(&reference.filename).is_none() {
                continue;
            }
            backend_tarballs
                .entry(reference.package)
                .or_default()
                .insert(reference.filename);
        }

        let backend_package_set = backend_packages.into_iter().collect::<HashSet<_>>();
        let mut sidecar_packages = HashSet::new();
        for package in &backend_package_set {
            if self
                .tarball_backend
                .read_package_metadata(package)
                .await?
                .is_some()
            {
                sidecar_packages.insert(package.clone());
            }
        }

        let local_packages = self.all_packages().await?;
        let mut state_package_set = HashSet::new();
        let mut state_attachments: HashMap<String, HashSet<String>> = HashMap::new();
        for record in local_packages {
            let Some(package_name) = record
                .manifest
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            state_package_set.insert(package_name.clone());
            let filenames = record
                .manifest
                .get("_attachments")
                .and_then(Value::as_object)
                .map(|object| {
                    object
                        .keys()
                        .filter(|filename| Self::infer_version_from_filename(filename).is_some())
                        .cloned()
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default();
            state_attachments.insert(package_name, filenames);
        }

        let mut tarballs_without_sidecar = backend_tarballs
            .keys()
            .filter(|package| !sidecar_packages.contains(*package))
            .cloned()
            .collect::<Vec<_>>();
        tarballs_without_sidecar.sort();

        let mut sidecars_without_tarballs = sidecar_packages
            .iter()
            .filter(|package| backend_tarballs.get(*package).is_none_or(HashSet::is_empty))
            .cloned()
            .collect::<Vec<_>>();
        sidecars_without_tarballs.sort();

        let mut tarballs_missing_from_manifest = Vec::new();
        for (package, files) in &backend_tarballs {
            let Some(manifest_files) = state_attachments.get(package) else {
                for file in files {
                    tarballs_missing_from_manifest.push(format!("{package}/-/{}", file));
                }
                continue;
            };
            for file in files {
                if !manifest_files.contains(file) {
                    tarballs_missing_from_manifest.push(format!("{package}/-/{}", file));
                }
            }
        }
        tarballs_missing_from_manifest.sort();

        let mut manifest_attachments_missing_blob = Vec::new();
        for (package, files) in &state_attachments {
            let Some(backend_files) = backend_tarballs.get(package) else {
                for file in files {
                    manifest_attachments_missing_blob.push(format!("{package}/-/{}", file));
                }
                continue;
            };
            for file in files {
                if !backend_files.contains(file) {
                    manifest_attachments_missing_blob.push(format!("{package}/-/{}", file));
                }
            }
        }
        manifest_attachments_missing_blob.sort();

        let mut stale_state_packages = state_package_set
            .iter()
            .filter(|package| !backend_package_set.contains(*package))
            .cloned()
            .collect::<Vec<_>>();
        stale_state_packages.sort();

        Ok(json!({
            "ok": true,
            "summary": {
                "backendPackages": backend_package_set.len(),
                "backendTarballs": backend_tarballs.values().map(HashSet::len).sum::<usize>(),
                "sidecarPackages": sidecar_packages.len(),
                "statePackages": state_package_set.len(),
                "legacyVerdaccioIndexPackages": legacy_index_package_count,
            },
            "problems": {
                "tarballsWithoutSidecar": tarballs_without_sidecar,
                "sidecarsWithoutTarballs": sidecars_without_tarballs,
                "tarballsMissingFromManifest": tarballs_missing_from_manifest,
                "manifestAttachmentsMissingBlob": manifest_attachments_missing_blob,
                "staleStatePackages": stale_state_packages,
            }
        }))
    }

    pub async fn starred_packages(&self, user_key: &str) -> Result<Vec<String>, RegistryError> {
        let mut rows = Vec::new();
        for record in self.all_packages().await? {
            let Some(name) = record
                .manifest
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            if let Some(users) = record.manifest.get("users").and_then(Value::as_object)
                && users.get(user_key).and_then(Value::as_bool) == Some(true)
            {
                rows.push(name);
            }
        }
        rows.sort();
        Ok(rows)
    }

    pub fn normalize_package_response(
        &self,
        manifest: &Value,
        package_name: &str,
        base_url: &str,
    ) -> (Value, HashMap<String, String>) {
        let mut clone = manifest.clone();
        let mut upstream_tarballs = HashMap::new();

        if let Some(versions) = clone.get_mut("versions").and_then(Value::as_object_mut) {
            for (_version, payload) in versions.iter_mut() {
                if let Some(dist) = payload.get_mut("dist").and_then(Value::as_object_mut)
                    && let Some(raw) = dist.get("tarball").and_then(Value::as_str)
                {
                    let filename = raw.rsplit('/').next().unwrap_or_default().to_string();
                    if !filename.is_empty() {
                        upstream_tarballs.insert(filename.clone(), raw.to_string());
                        dist.insert(
                            "tarball".to_string(),
                            Value::String(format!(
                                "{}/{}/-/{}",
                                base_url.trim_end_matches('/'),
                                urlencoding::encode(package_name),
                                filename
                            )),
                        );
                    }
                }
            }
        }

        (clone, upstream_tarballs)
    }

    pub fn abbreviated_manifest(&self, manifest: &Value) -> Value {
        let mut out = manifest.clone();
        if let Some(obj) = out.as_object_mut() {
            obj.remove("users");
            obj.remove("_attachments");
            obj.remove("_uplinks");
            obj.remove("_distfiles");
            obj.remove("readme");
            if let Some(versions) = obj.get_mut("versions").and_then(Value::as_object_mut) {
                for version in versions.values_mut() {
                    if let Some(version_obj) = version.as_object_mut() {
                        version_obj.retain(|key, _| {
                            matches!(
                                key.as_str(),
                                "name"
                                    | "version"
                                    | "deprecated"
                                    | "bin"
                                    | "dist"
                                    | "engines"
                                    | "funding"
                                    | "directories"
                                    | "dependencies"
                                    | "devDependencies"
                                    | "peerDependencies"
                                    | "optionalDependencies"
                                    | "bundleDependencies"
                                    | "cpu"
                                    | "os"
                                    | "peerDependenciesMeta"
                                    | "acceptDependencies"
                                    | "_hasShrinkwrap"
                                    | "hasInstallScript"
                            )
                        });
                    }
                }
            }
            if !obj.contains_key("time") {
                obj.insert("time".to_string(), Value::Object(Map::new()));
            }
            obj.insert(
                "modified".to_string(),
                Value::String(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            );
        }
        out
    }

    pub fn parse_star_key(raw: &str) -> String {
        raw.trim_matches('"').trim_matches('\'').to_string()
    }

    pub fn package_version_by_query(manifest: &Value, query: &str) -> Option<Value> {
        let versions = manifest.get("versions")?.as_object()?;
        if let Some(version) = versions.get(query) {
            return Some(version.clone());
        }

        let tags = manifest.get("dist-tags").and_then(Value::as_object)?;
        let target = tags.get(query).and_then(Value::as_str)?;
        versions.get(target).cloned()
    }

    pub fn search_response_time() -> String {
        Self::now_http()
    }

    pub fn normalize_support_errors(
        readonly: Option<bool>,
        cidr_whitelist: Option<Vec<String>>,
    ) -> Result<(bool, Vec<String>), RegistryError> {
        let Some(readonly) = readonly else {
            return Err(RegistryError::http(
                StatusCode::UNPROCESSABLE_ENTITY,
                API_ERROR_PARAMETERS_NOT_VALID,
            ));
        };
        let Some(cidr_whitelist) = cidr_whitelist else {
            return Err(RegistryError::http(
                StatusCode::UNPROCESSABLE_ENTITY,
                API_ERROR_PARAMETERS_NOT_VALID,
            ));
        };
        Ok((readonly, cidr_whitelist))
    }

    pub fn login_required_message() -> &'static str {
        API_ERROR_MUST_BE_LOGGED
    }

    pub fn unauthorized_access_message() -> &'static str {
        API_ERROR_UNAUTHORIZED_ACCESS
    }

    pub fn package_removed_message() -> &'static str {
        API_MESSAGE_PKG_REMOVED
    }

    pub fn tag_added_message() -> &'static str {
        API_MESSAGE_TAG_ADDED
    }

    pub fn tag_removed_message() -> &'static str {
        API_MESSAGE_TAG_REMOVED
    }

    pub fn tarball_removed_message() -> &'static str {
        API_MESSAGE_TARBALL_REMOVED
    }

    pub fn no_package_message() -> &'static str {
        API_ERROR_NO_PACKAGE
    }

    pub fn no_such_file_message() -> &'static str {
        API_ERROR_NO_SUCH_FILE
    }

    pub fn unsupported_registry_call_message() -> &'static str {
        API_ERROR_UNSUPPORTED_REGISTRY_CALL
    }
}

pub fn default_profile(name: &str) -> Value {
    json!({
        "tfa": false,
        "name": name,
        "email": "",
        "email_verified": false,
        "created": "",
        "updated": "",
        "cidr_whitelist": null,
        "fullname": "",
    })
}

pub fn make_search_object(package: &Value) -> Option<Value> {
    let name = package.get("name")?.as_str()?.to_string();
    let dist_tags = package.get("dist-tags")?.as_object()?;
    let latest = dist_tags.get("latest")?.as_str()?.to_string();
    let version = package.get("versions")?.get(&latest)?;

    let author = version.get("author").cloned().unwrap_or_else(|| json!({}));
    let description = version
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let keywords = version
        .get("keywords")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let maintainers = package
        .get("maintainers")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let scope = name
        .strip_prefix('@')
        .and_then(|rest| rest.split('/').next())
        .map(|part| format!("@{part}"))
        .unwrap_or_default();

    Some(json!({
        "package": {
            "name": name,
            "version": latest,
            "description": description,
            "keywords": keywords,
            "date": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "links": { "npm": "" },
            "author": author,
            "publisher": {},
            "maintainers": maintainers,
            "scope": scope,
        },
        "score": {
            "final": 1,
            "detail": {
                "quality": 1,
                "popularity": 1,
                "maintenance": 0,
            }
        },
        "searchScore": 1,
        "verdaccioPkgCached": false,
        "verdaccioPrivate": true,
    }))
}

pub fn has_write_auth(user: Option<&str>) -> Result<&str, RegistryError> {
    user.ok_or_else(|| RegistryError::http(StatusCode::UNAUTHORIZED, API_ERROR_MUST_BE_LOGGED))
}

pub fn no_credentials() -> RegistryError {
    RegistryError::auth_unauthorized("no credentials provided")
}

pub fn unauthorized(msg: &str) -> RegistryError {
    RegistryError::auth_unauthorized(msg)
}

pub fn forbidden(msg: &str) -> RegistryError {
    RegistryError::auth_forbidden(msg)
}

pub fn bad_request(msg: &str) -> RegistryError {
    RegistryError::storage_bad_request(msg)
}

pub fn unprocessable(msg: &str) -> RegistryError {
    RegistryError::storage_unprocessable(msg)
}

pub fn is_json_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

pub fn parse_json_body(bytes: &[u8]) -> Result<Value, RegistryError> {
    serde_json::from_slice(bytes).map_err(|_| {
        RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
    })
}

pub fn parse_json_string_body(bytes: &[u8]) -> Result<String, RegistryError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| RegistryError::http(StatusCode::BAD_REQUEST, "version is missing"))?;
    let Some(text) = value.as_str() else {
        return Err(RegistryError::http(
            StatusCode::BAD_REQUEST,
            "version is missing",
        ));
    };
    Ok(text.to_string())
}

pub fn package_filename_from_tarball_url(url: &str) -> Option<String> {
    url.rsplit('/').next().map(|s| s.to_string())
}

pub fn package_name_from_path_or_encoded(path_part: &str) -> String {
    match urlencoding::decode(path_part) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => path_part.to_string(),
    }
}

pub fn package_name_to_encoded(package: &str) -> String {
    urlencoding::encode(package).into_owned()
}

pub fn version_not_found(query: &str) -> RegistryError {
    RegistryError::http(
        StatusCode::NOT_FOUND,
        format!("{API_ERROR_VERSION_NOT_EXIST}: {query}"),
    )
}

pub fn path_exists(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

pub fn parse_write_query(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(k, v)| k == "write" && v == "true")
}

pub fn route_user_param(path: &str) -> Option<&str> {
    path.strip_prefix("/-/user/")
}

pub fn normalize_scope_path(parts: &[&str]) -> String {
    parts.join("/")
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

fn managed_mode_enabled_from_env() -> bool {
    std::env::var("RUSTACCIO_MANAGED_MODE")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn strict_revision_checks_from_env() -> bool {
    let default = managed_mode_enabled_from_env();
    std::env::var("RUSTACCIO_STRICT_REVISION_CHECK")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(default)
}

pub fn parse_authorization(header: Option<&str>) -> Option<String> {
    let value = header?.trim();
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.trim().to_string());
    }
    if let Some(token) = value.strip_prefix("bearer ") {
        return Some(token.trim().to_string());
    }
    None
}

pub fn unauthorized_on_invalid_token(header_present: bool) -> Result<(), RegistryError> {
    if header_present {
        return Err(RegistryError::http(
            StatusCode::UNAUTHORIZED,
            API_ERROR_UNAUTHORIZED_ACCESS,
        ));
    }
    Ok(())
}

pub fn ok_object() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::{PackageCacheSettings, PackageDiscoveryMode, Store};
    use crate::{config::Config, error::RegistryError, models::PackageRecord};
    use axum::http::StatusCode;
    use serde_json::{Map, Value, json};
    use std::{io::Write, path::Path};

    fn config_for_data_dir(data_dir: &Path) -> Config {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "storage: {}", data_dir.display()).expect("write yaml config");
        Config::from_yaml_file(file.path().to_path_buf()).expect("parse config")
    }

    #[tokio::test]
    async fn hydrates_unindexed_local_tarballs_on_startup() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = temp.path().join("registry");
        let package_dir = data_dir.join("tarballs").join("demo");
        tokio::fs::create_dir_all(&package_dir)
            .await
            .expect("create tarball dir");
        tokio::fs::write(package_dir.join("demo-1.0.0.tgz"), b"one")
            .await
            .expect("write tarball");
        tokio::fs::write(package_dir.join("demo-1.2.0.tgz"), b"two")
            .await
            .expect("write tarball");

        let config = config_for_data_dir(&data_dir);
        let store = Store::open(&config).await.expect("open store");
        let package = store
            .get_package_record("demo")
            .await
            .expect("package discovered");
        let versions = package
            .manifest
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .expect("versions object");
        assert!(versions.contains_key("1.0.0"));
        assert!(versions.contains_key("1.2.0"));
        assert_eq!(
            package
                .manifest
                .get("dist-tags")
                .and_then(|tags| tags.get("latest"))
                .and_then(serde_json::Value::as_str),
            Some("1.2.0")
        );

        let state_file = data_dir.join("state.json");
        assert!(
            !tokio::fs::try_exists(&state_file)
                .await
                .expect("state file existence"),
            "package metadata discovery should not write state.json"
        );
    }

    #[tokio::test]
    async fn hydrates_scoped_package_tarballs_on_startup() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = temp.path().join("registry");
        let package_dir = data_dir.join("tarballs").join("@scope__pkg");
        tokio::fs::create_dir_all(&package_dir)
            .await
            .expect("create scoped tarball dir");
        tokio::fs::write(package_dir.join("pkg-2.3.4.tgz"), b"pkg")
            .await
            .expect("write scoped tarball");

        let config = config_for_data_dir(&data_dir);
        let store = Store::open(&config).await.expect("open store");
        let package = store
            .get_package_record("@scope/pkg")
            .await
            .expect("scoped package discovered");
        assert!(
            package
                .manifest
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|versions| versions.contains_key("2.3.4"))
        );
    }

    #[test]
    fn package_cache_prune_enforces_max_entries() {
        let mut state = crate::models::PersistedState::default();
        state.packages.insert(
            "pkg-a".to_string(),
            PackageRecord {
                manifest: json!({}),
                upstream_tarballs: std::collections::HashMap::new(),
                updated_at: 10,
                cached_from_uplink: false,
            },
        );
        state.packages.insert(
            "pkg-b".to_string(),
            PackageRecord {
                manifest: json!({}),
                upstream_tarballs: std::collections::HashMap::new(),
                updated_at: 20,
                cached_from_uplink: false,
            },
        );
        state.packages.insert(
            "pkg-c".to_string(),
            PackageRecord {
                manifest: json!({}),
                upstream_tarballs: std::collections::HashMap::new(),
                updated_at: 30,
                cached_from_uplink: false,
            },
        );

        let settings = PackageCacheSettings {
            discovery_mode: PackageDiscoveryMode::SingleNode,
            max_entries: 2,
            record_ttl_ms: 0,
            prune_interval_ms: 1_000,
            negative_ttl_ms: 1_000,
            discovery_refresh_interval_ms: 0,
        };

        let removed = Store::prune_package_cache_with_settings(&mut state, &settings, 30);
        assert_eq!(removed, 1);
        assert_eq!(state.packages.len(), 2);
        assert!(!state.packages.contains_key("pkg-a"));
        assert!(state.packages.contains_key("pkg-b"));
        assert!(state.packages.contains_key("pkg-c"));
    }

    #[test]
    fn package_cache_prune_drops_expired_entries() {
        let mut state = crate::models::PersistedState::default();
        state.packages.insert(
            "expired".to_string(),
            PackageRecord {
                manifest: json!({}),
                upstream_tarballs: std::collections::HashMap::new(),
                updated_at: 1_000,
                cached_from_uplink: false,
            },
        );
        state.packages.insert(
            "fresh".to_string(),
            PackageRecord {
                manifest: json!({}),
                upstream_tarballs: std::collections::HashMap::new(),
                updated_at: 9_700,
                cached_from_uplink: false,
            },
        );

        let settings = PackageCacheSettings {
            discovery_mode: PackageDiscoveryMode::SingleNode,
            max_entries: 10,
            record_ttl_ms: 2_000,
            prune_interval_ms: 1_000,
            negative_ttl_ms: 1_000,
            discovery_refresh_interval_ms: 0,
        };

        let removed = Store::prune_package_cache_with_settings(&mut state, &settings, 10_000);
        assert_eq!(removed, 1);
        assert!(!state.packages.contains_key("expired"));
        assert!(state.packages.contains_key("fresh"));
    }

    #[test]
    fn package_discovery_mode_parse_supports_aliases() {
        assert_eq!(
            PackageDiscoveryMode::parse("single-node"),
            Some(PackageDiscoveryMode::SingleNode)
        );
        assert_eq!(
            PackageDiscoveryMode::parse("single"),
            Some(PackageDiscoveryMode::SingleNode)
        );
        assert_eq!(
            PackageDiscoveryMode::parse("multi-node"),
            Some(PackageDiscoveryMode::MultiNode)
        );
        assert_eq!(
            PackageDiscoveryMode::parse("cluster"),
            Some(PackageDiscoveryMode::MultiNode)
        );
    }

    #[test]
    fn package_discovery_mode_parse_rejects_unknown_values() {
        assert_eq!(PackageDiscoveryMode::parse(""), None);
        assert_eq!(PackageDiscoveryMode::parse("wat"), None);
    }

    #[test]
    fn revision_match_enforces_expected_revision() {
        let mut manifest = Map::new();
        manifest.insert("_rev".to_string(), Value::String("2-abc".to_string()));
        assert!(Store::ensure_revision_matches(&manifest, Some("2-abc")).is_ok());
        let err = Store::ensure_revision_matches(&manifest, Some("1-stale"))
            .expect_err("stale revision should fail");
        assert!(
            matches!(err, RegistryError::Http { status, .. } if status == StatusCode::CONFLICT)
        );
    }
}
