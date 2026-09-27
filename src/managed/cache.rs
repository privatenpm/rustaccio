//! Bounded decision and payload caches for the managed bridge.
//!
//! Control-plane decisions carry an absolute `expires_at`; cached entries
//! never outlive it (the local TTL is clamped to it) and expired decisions
//! are never re-served. Cache keys include the subject `credential_version`
//! so revoked/rotated credentials cannot be served from stale entries.

use super::client::{AuthorizeDecision, DownloadResolveResponse, ResolveDomainResponse};
use axum::body::Bytes;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicI64, Ordering},
};
use tokio::sync::RwLock;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Parse an RFC3339 timestamp into epoch milliseconds.
pub fn parse_rfc3339_ms(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|parsed| parsed.timestamp_millis())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DecisionKey {
    token: String,
    credential_version: i64,
    operation: String,
    host: String,
    registry_id: String,
    package: String,
    version: String,
}

#[derive(Debug, Clone)]
struct CachedDecision {
    decision: AuthorizeDecision,
    expires_at_ms: i64,
}

/// Inputs identifying one authorization call for caching purposes.
#[derive(Debug, Clone, Default)]
pub struct DecisionScope {
    pub token: String,
    pub operation: String,
    pub host: String,
    pub registry_id: String,
    pub package: String,
    pub version: String,
}

/// Bounded cache of control-plane authorization decisions.
pub struct DecisionCache {
    entries: RwLock<HashMap<DecisionKey, CachedDecision>>,
    credential_versions: RwLock<HashMap<String, i64>>,
    max_entries: usize,
    ttl_ms: i64,
    last_prune_ms: AtomicI64,
    prune_interval_ms: i64,
}

impl DecisionCache {
    pub fn new(max_entries: usize, ttl_ms: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            credential_versions: RwLock::new(HashMap::new()),
            max_entries: max_entries.max(100),
            ttl_ms: ttl_ms as i64,
            last_prune_ms: AtomicI64::new(0),
            prune_interval_ms: 30_000,
        }
    }

    /// Look up a cached decision; expired entries are never served.
    pub async fn get(&self, scope: &DecisionScope) -> Option<AuthorizeDecision> {
        let credential_version = self.known_credential_version(&scope.token).await;
        let key = Self::key(scope, credential_version);
        let entries = self.entries.read().await;
        let entry = entries.get(&key)?;
        if entry.expires_at_ms > now_ms() {
            Some(entry.decision.clone())
        } else {
            None
        }
    }

    /// Store a decision, clamping its lifetime to the decision's `expires_at`.
    /// Decisions already expired are never cached.
    pub async fn put(&self, scope: &DecisionScope, decision: &AuthorizeDecision) {
        let now = now_ms();
        let mut expires_at_ms = now.saturating_add(self.ttl_ms);
        if let Some(deadline) = decision.expires_at.as_deref().and_then(parse_rfc3339_ms) {
            expires_at_ms = expires_at_ms.min(deadline);
        }
        if expires_at_ms <= now {
            return;
        }

        // Token identity includes the credential version: entries are keyed
        // under it so a rotated/revoked credential can never be served from
        // an older entry once the control plane reports the new version.
        let credential_version = decision.credential_version();
        self.credential_versions
            .write()
            .await
            .insert(scope.token.clone(), credential_version);

        let mut entries = self.entries.write().await;
        entries.insert(
            Self::key(scope, credential_version),
            CachedDecision {
                decision: decision.clone(),
                expires_at_ms,
            },
        );
        Self::prune_locked(
            &mut entries,
            self.max_entries,
            &self.last_prune_ms,
            self.prune_interval_ms,
            now,
        );
    }

    pub async fn invalidate(&self) {
        self.entries.write().await.clear();
        self.credential_versions.write().await.clear();
        self.last_prune_ms.store(0, Ordering::Relaxed);
    }

    async fn known_credential_version(&self, token: &str) -> i64 {
        self.credential_versions
            .read()
            .await
            .get(token)
            .copied()
            .unwrap_or(0)
    }

    fn key(scope: &DecisionScope, credential_version: i64) -> DecisionKey {
        DecisionKey {
            token: scope.token.clone(),
            credential_version,
            operation: scope.operation.clone(),
            host: scope.host.clone(),
            registry_id: scope.registry_id.clone(),
            package: scope.package.clone(),
            version: scope.version.clone(),
        }
    }

    fn prune_locked(
        entries: &mut HashMap<DecisionKey, CachedDecision>,
        max_entries: usize,
        last_prune_ms: &AtomicI64,
        prune_interval_ms: i64,
        now: i64,
    ) {
        let last = last_prune_ms.load(Ordering::Relaxed);
        if last > 0 && now.saturating_sub(last) < prune_interval_ms {
            return;
        }
        entries.retain(|_, entry| entry.expires_at_ms > now);
        if entries.len() > max_entries {
            let mut by_expiry = entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.expires_at_ms))
                .collect::<Vec<_>>();
            by_expiry.sort_by_key(|(_, expires)| *expires);
            for (key, _) in by_expiry
                .into_iter()
                .take(entries.len().saturating_sub(max_entries))
            {
                entries.remove(&key);
            }
        }
        last_prune_ms.store(now, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
struct CachedDownload {
    response: DownloadResolveResponse,
    expires_at_ms: i64,
}

/// Bounded cache of `downloads/resolve` responses, clamped to `expires_at`.
pub struct DownloadCache {
    entries: RwLock<HashMap<String, CachedDownload>>,
    max_entries: usize,
    ttl_ms: i64,
}

impl DownloadCache {
    pub fn new(max_entries: usize, ttl_ms: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries: max_entries.max(100),
            ttl_ms: ttl_ms as i64,
        }
    }

    fn key(token: &str, host: &str, package: &str, version: &str) -> String {
        format!("{token}|{host}|{package}|{version}")
    }

    pub async fn get(
        &self,
        token: &str,
        host: &str,
        package: &str,
        version: &str,
    ) -> Option<DownloadResolveResponse> {
        let entries = self.entries.read().await;
        let entry = entries.get(&Self::key(token, host, package, version))?;
        if entry.expires_at_ms > now_ms() {
            Some(entry.response.clone())
        } else {
            None
        }
    }

    pub async fn put(
        &self,
        token: &str,
        host: &str,
        package: &str,
        version: &str,
        response: &DownloadResolveResponse,
    ) {
        let now = now_ms();
        let mut expires_at_ms = now.saturating_add(self.ttl_ms);
        if let Some(deadline) = response.expires_at.as_deref().and_then(parse_rfc3339_ms) {
            expires_at_ms = expires_at_ms.min(deadline);
        }
        if expires_at_ms <= now {
            return;
        }
        let mut entries = self.entries.write().await;
        entries.insert(
            Self::key(token, host, package, version),
            CachedDownload {
                response: response.clone(),
                expires_at_ms,
            },
        );
        if entries.len() > self.max_entries {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
    }

    pub async fn invalidate(&self) {
        self.entries.write().await.clear();
    }
}

/// One cached control-plane packument response.
#[derive(Debug, Clone)]
pub struct CachedPackument {
    pub body: Bytes,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub revision: String,
    pub expires_at_ms: i64,
}

/// Optional, tiny packument cache (disabled by default). Entries are keyed by
/// (origin, path, representation) and only stored when the control plane
/// returned an `X-Package-Revision` header; responses without it are never
/// cached.
pub struct MetadataCache {
    entries: RwLock<HashMap<String, CachedPackument>>,
    max_entries: usize,
    ttl_ms: i64,
    pub max_bytes: usize,
}

impl MetadataCache {
    pub fn new(max_entries: usize, ttl_ms: u64, max_bytes: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries: max_entries.max(16),
            ttl_ms: ttl_ms as i64,
            max_bytes,
        }
    }

    pub fn enabled(&self) -> bool {
        self.ttl_ms > 0
    }

    fn key(origin: &str, path: &str, abbreviated: bool) -> String {
        format!("{origin}|{path}|{abbreviated}")
    }

    pub async fn get(
        &self,
        origin: &str,
        path: &str,
        abbreviated: bool,
    ) -> Option<CachedPackument> {
        let entries = self.entries.read().await;
        let entry = entries.get(&Self::key(origin, path, abbreviated))?;
        if entry.expires_at_ms > now_ms() {
            Some(entry.clone())
        } else {
            None
        }
    }

    pub async fn put(&self, origin: &str, path: &str, abbreviated: bool, entry: CachedPackument) {
        if !self.enabled() {
            return;
        }
        let mut entries = self.entries.write().await;
        entries.insert(Self::key(origin, path, abbreviated), entry);
        if entries.len() > self.max_entries {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
    }

    pub async fn invalidate_package(&self, package: &str) -> usize {
        let plain = format!("/{package}");
        let encoded = format!("/{}", crate::storage::package_name_to_encoded(package));
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|key, _| {
            let path = key.split('|').nth(1).unwrap_or_default();
            !(path == plain
                || path == encoded
                || path.starts_with(&format!("{plain}/"))
                || path.starts_with(&format!("{encoded}/")))
        });
        before - entries.len()
    }

    pub async fn invalidate(&self) {
        self.entries.write().await.clear();
    }

    pub fn expires_at_ms_from_now(&self) -> i64 {
        now_ms().saturating_add(self.ttl_ms)
    }
}

/// Cache of host → registry resolution (`resolve-domain`).
pub struct RegistryHostCache {
    entries: RwLock<HashMap<String, (ResolveDomainResponse, i64)>>,
    ttl_ms: i64,
}

impl RegistryHostCache {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl_ms: ttl_ms as i64,
        }
    }

    pub async fn get(&self, host: &str) -> Option<ResolveDomainResponse> {
        let entries = self.entries.read().await;
        let (resolution, expires_at_ms) = entries.get(host)?;
        if *expires_at_ms > now_ms() {
            Some(resolution.clone())
        } else {
            None
        }
    }

    pub async fn put(&self, host: &str, resolution: &ResolveDomainResponse) {
        let expires_at_ms = now_ms().saturating_add(self.ttl_ms);
        self.entries
            .write()
            .await
            .insert(host.to_string(), (resolution.clone(), expires_at_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::client::{AuthorizeDecision, AuthorizeSubject};

    fn decision(
        allowed: bool,
        expires_at: Option<String>,
        credential_version: i64,
    ) -> AuthorizeDecision {
        AuthorizeDecision {
            allowed,
            reason: None,
            expires_at,
            subject: Some(AuthorizeSubject {
                credential_version,
                ..AuthorizeSubject::default()
            }),
            package: None,
            route: None,
        }
    }

    fn scope() -> DecisionScope {
        DecisionScope {
            token: "npm_test".to_string(),
            operation: "metadata:read".to_string(),
            host: "npm.example.com".to_string(),
            registry_id: String::new(),
            package: "demo".to_string(),
            version: String::new(),
        }
    }

    #[tokio::test]
    async fn decision_cache_serves_fresh_entries() {
        let cache = DecisionCache::new(100, 30_000);
        cache.put(&scope(), &decision(true, None, 7)).await;
        let cached = cache.get(&scope()).await.expect("cached decision");
        assert!(cached.allowed);
    }

    #[tokio::test]
    async fn decision_cache_clamps_ttl_to_expires_at() {
        let cache = DecisionCache::new(100, 3_600_000);
        let already_past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        cache
            .put(&scope(), &decision(true, Some(already_past), 1))
            .await;
        assert!(
            cache.get(&scope()).await.is_none(),
            "expired decisions must never be re-served"
        );
    }

    #[tokio::test]
    async fn decision_cache_expiry_uses_clamped_deadline() {
        let cache = DecisionCache::new(100, 3_600_000);
        let soon = (chrono::Utc::now() + chrono::Duration::milliseconds(500)).to_rfc3339();
        cache.put(&scope(), &decision(true, Some(soon), 1)).await;
        assert!(cache.get(&scope()).await.is_some());
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            cache.get(&scope()).await.is_none(),
            "entry must expire at the control-plane deadline, not the local TTL"
        );
    }

    #[tokio::test]
    async fn decision_cache_keys_include_credential_version() {
        let cache = DecisionCache::new(100, 30_000);
        cache.put(&scope(), &decision(true, None, 3)).await;
        // A later decision for the same token with a newer credential version
        // must not collide with the older entry.
        cache.put(&scope(), &decision(false, None, 4)).await;
        let cached = cache.get(&scope()).await.expect("cached decision");
        assert!(!cached.allowed);
    }

    #[tokio::test]
    async fn decision_cache_invalidate_clears_entries() {
        let cache = DecisionCache::new(100, 30_000);
        cache.put(&scope(), &decision(true, None, 1)).await;
        cache.invalidate().await;
        assert!(cache.get(&scope()).await.is_none());
    }

    #[tokio::test]
    async fn download_cache_clamps_to_expires_at() {
        let cache = DownloadCache::new(100, 3_600_000);
        let response = DownloadResolveResponse {
            allowed: true,
            expires_at: Some((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339()),
            package: None,
            version: None,
            download_url: Some("https://example.com/file.tgz".to_string()),
            credential_id: None,
        };
        cache.put("tok", "host", "pkg", "1.0.0", &response).await;
        assert!(cache.get("tok", "host", "pkg", "1.0.0").await.is_none());
    }

    #[tokio::test]
    async fn metadata_cache_only_serves_within_ttl() {
        let cache = MetadataCache::new(16, 20, 1024);
        let entry = CachedPackument {
            body: Bytes::from_static(b"{}"),
            content_type: Some("application/json".to_string()),
            etag: Some("\"v1\"".to_string()),
            revision: "3".to_string(),
            expires_at_ms: cache.expires_at_ms_from_now(),
        };
        cache.put("https://cp", "/demo", false, entry).await;
        assert!(cache.get("https://cp", "/demo", false).await.is_some());
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(cache.get("https://cp", "/demo", false).await.is_none());
    }

    #[tokio::test]
    async fn metadata_cache_invalidate_package_matches_prefixes() {
        let cache = MetadataCache::new(16, 30_000, 1024);
        let entry = CachedPackument {
            body: Bytes::from_static(b"{}"),
            content_type: None,
            etag: None,
            revision: "1".to_string(),
            expires_at_ms: cache.expires_at_ms_from_now(),
        };
        cache
            .put("https://cp", "/@scope/demo", false, entry.clone())
            .await;
        cache
            .put("https://cp", "/@scope/demo/1.0.0", false, entry)
            .await;
        assert_eq!(cache.invalidate_package("@scope/demo").await, 2);
        assert!(
            cache
                .get("https://cp", "/@scope/demo", false)
                .await
                .is_none()
        );
    }
}
