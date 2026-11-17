use crate::{
    acl::Acl,
    error::RegistryError,
    models::{AuthIdentity, TenantContext},
    storage::Store,
};
use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::{Client, redirect::Policy};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Access,
    Publish,
    Unpublish,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub request_id: Option<String>,
    pub tenant: TenantContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicyConfig {
    pub base_url: String,
    pub decision_endpoint: String,
    pub timeout_ms: u64,
    pub cache_ttl_ms: u64,
    pub cache_max_entries: usize,
    pub cache_prune_interval_ms: u64,
    pub fail_open: bool,
}

impl HttpPolicyConfig {
    pub fn from_env() -> Result<Option<Self>, RegistryError> {
        let backend = std::env::var("RUSTACCIO_POLICY_BACKEND")
            .ok()
            .unwrap_or_else(|| "local".to_string());
        let backend = backend.trim().to_ascii_lowercase();
        match backend.as_str() {
            "local" => return Ok(None),
            "http" => {}
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_POLICY_BACKEND: {other}"),
                ));
            }
        }

        let base_url = std::env::var("RUSTACCIO_POLICY_HTTP_BASE_URL")
            .ok()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        if base_url.is_empty() {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_POLICY_BACKEND=http requires RUSTACCIO_POLICY_HTTP_BASE_URL",
            ));
        }

        let decision_endpoint = std::env::var("RUSTACCIO_POLICY_HTTP_DECISION_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/authorize".to_string());
        let timeout_ms = parse_u64_env("RUSTACCIO_POLICY_HTTP_TIMEOUT_MS", 3_000).max(250);
        let cache_ttl_ms = parse_u64_env("RUSTACCIO_POLICY_HTTP_CACHE_TTL_MS", 5_000);
        let cache_max_entries =
            parse_u64_env("RUSTACCIO_POLICY_HTTP_CACHE_MAX_ENTRIES", 10_000) as usize;
        let cache_prune_interval_ms =
            parse_u64_env("RUSTACCIO_POLICY_HTTP_CACHE_PRUNE_INTERVAL_MS", 30_000).max(1_000);
        let fail_open = parse_bool_env("RUSTACCIO_POLICY_HTTP_FAIL_OPEN", false);

        Ok(Some(Self {
            base_url,
            decision_endpoint: normalize_endpoint(&decision_endpoint),
            timeout_ms,
            cache_ttl_ms,
            cache_max_entries,
            cache_prune_interval_ms,
            fail_open,
        }))
    }
}

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn authorize(
        &self,
        action: PolicyAction,
        package_name: &str,
        identity: Option<&AuthIdentity>,
        request: &RequestContext,
    ) -> Result<bool, RegistryError>;

    async fn invalidate_cache(&self) -> Result<(), RegistryError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct DefaultPolicyEngine {
    store: Arc<Store>,
    acl: Acl,
    http_backend: Option<HttpPolicyBackend>,
}

impl DefaultPolicyEngine {
    pub fn new(store: Arc<Store>, acl: Acl) -> Self {
        Self {
            store,
            acl,
            http_backend: None,
        }
    }

    pub fn new_with_http(
        store: Arc<Store>,
        acl: Acl,
        cfg: HttpPolicyConfig,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            store,
            acl,
            http_backend: Some(HttpPolicyBackend::new(cfg)?),
        })
    }
}

#[async_trait]
impl PolicyEngine for DefaultPolicyEngine {
    async fn authorize(
        &self,
        action: PolicyAction,
        package_name: &str,
        identity: Option<&AuthIdentity>,
        request: &RequestContext,
    ) -> Result<bool, RegistryError> {
        if let Some(http_backend) = &self.http_backend
            && let Some(allowed) = http_backend
                .authorize(action, package_name, identity, request)
                .await?
        {
            return Ok(allowed);
        }

        let plugin_decision = match action {
            PolicyAction::Access => {
                self.store
                    .allow_access(identity, package_name, request.request_id.as_deref())
                    .await?
            }
            PolicyAction::Publish => {
                self.store
                    .allow_publish(identity, package_name, request.request_id.as_deref())
                    .await?
            }
            PolicyAction::Unpublish => {
                self.store
                    .allow_unpublish(identity, package_name, request.request_id.as_deref())
                    .await?
            }
        };
        if let Some(allowed) = plugin_decision {
            return Ok(allowed);
        }

        let acl_allowed = match action {
            PolicyAction::Access => self.acl.can_access(package_name, identity),
            PolicyAction::Publish => self.acl.can_publish(package_name, identity),
            PolicyAction::Unpublish => self.acl.can_unpublish(package_name, identity),
        };
        Ok(acl_allowed)
    }

    async fn invalidate_cache(&self) -> Result<(), RegistryError> {
        if let Some(http_backend) = &self.http_backend {
            http_backend.invalidate_cache().await;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CachedDecision {
    allowed: bool,
    expires_at_ms: i64,
}

#[derive(Clone)]
struct HttpPolicyBackend {
    cfg: HttpPolicyConfig,
    client: Client,
    cache: Arc<RwLock<HashMap<String, CachedDecision>>>,
    last_cache_prune_ms: Arc<AtomicI64>,
}

impl HttpPolicyBackend {
    fn new(cfg: HttpPolicyConfig) -> Result<Self, RegistryError> {
        let timeout = Duration::from_millis(cfg.timeout_ms.max(250));
        let connect_timeout = timeout.min(Duration::from_secs(3));
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(2)
            .tcp_keepalive(Duration::from_secs(30))
            .http1_only()
            .redirect(Policy::limited(3))
            .build()
            .map_err(|_| RegistryError::Internal)?;

        debug!(
            base_url = cfg.base_url,
            decision_endpoint = cfg.decision_endpoint,
            timeout_ms = cfg.timeout_ms,
            cache_ttl_ms = cfg.cache_ttl_ms,
            cache_max_entries = cfg.cache_max_entries,
            cache_prune_interval_ms = cfg.cache_prune_interval_ms,
            fail_open = cfg.fail_open,
            "initialized external policy backend"
        );
        Ok(Self {
            cfg,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            last_cache_prune_ms: Arc::new(AtomicI64::new(0)),
        })
    }

    async fn authorize(
        &self,
        action: PolicyAction,
        package_name: &str,
        identity: Option<&AuthIdentity>,
        request: &RequestContext,
    ) -> Result<Option<bool>, RegistryError> {
        self.prune_cache(false).await;
        let cache_key = self.cache_key(action, package_name, identity, request);
        if self.cfg.cache_ttl_ms > 0
            && let Some(allowed) = self.cached_decision(&cache_key).await
        {
            return Ok(Some(allowed));
        }

        let identity_username = identity.and_then(|id| id.username.clone());
        let identity_groups = identity.map(|id| id.groups.clone()).unwrap_or_default();
        let payload = json!({
            "action": action.as_str(),
            "package": package_name,
            "method": request.method,
            "path": request.path,
            "request_id": request.request_id,
            "username": identity_username,
            "groups": identity_groups,
            "identity": identity,
            "tenant": request.tenant,
            "org_id": request.tenant.org_id,
            "project_id": request.tenant.project_id,
        });

        let endpoint_url = format!("{}{}", self.cfg.base_url, self.cfg.decision_endpoint);
        let mut request_builder = self.client.post(endpoint_url);
        if let Some(request_id) = request.request_id.as_deref() {
            request_builder = request_builder.header("x-request-id", request_id);
        }
        let response = request_builder.json(&payload).send().await;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                if self.cfg.fail_open {
                    warn!(
                        error = ?err,
                        action = action.as_str(),
                        package = package_name,
                        "external policy backend unavailable; falling back to local policy"
                    );
                    return Ok(None);
                }
                error!(
                    error = ?err,
                    action = action.as_str(),
                    package = package_name,
                    "external policy backend unavailable"
                );
                return Err(RegistryError::policy_backend_unavailable(
                    "external policy backend unavailable",
                ));
            }
        };

        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            self.cache_decision(cache_key, false).await;
            return Ok(Some(false));
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            if self.cfg.fail_open {
                warn!(
                    status,
                    action = action.as_str(),
                    package = package_name,
                    "external policy backend returned non-success; falling back to local policy"
                );
                return Ok(None);
            }
            return Err(RegistryError::policy_backend_unavailable(format!(
                "external policy backend returned status {status}"
            )));
        }

        let payload = match response.json::<Value>().await {
            Ok(payload) => payload,
            Err(err) => {
                if self.cfg.fail_open {
                    warn!(
                        error = ?err,
                        action = action.as_str(),
                        package = package_name,
                        "external policy backend returned invalid JSON; falling back to local policy"
                    );
                    return Ok(None);
                }
                return Err(RegistryError::policy_backend_unavailable(
                    "external policy backend returned invalid JSON",
                ));
            }
        };

        let decision = payload
            .get("allowed")
            .and_then(Value::as_bool)
            .or_else(|| payload.as_bool());
        if let Some(allowed) = decision {
            self.cache_decision(cache_key, allowed).await;
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    fn cache_key(
        &self,
        action: PolicyAction,
        package_name: &str,
        identity: Option<&AuthIdentity>,
        request: &RequestContext,
    ) -> String {
        let user = identity
            .and_then(|id| id.username.as_deref())
            .unwrap_or("-");
        let groups = identity.map(|id| id.groups.join(",")).unwrap_or_default();
        let org_id = request.tenant.org_id.as_deref().unwrap_or("-");
        let project_id = request.tenant.project_id.as_deref().unwrap_or("-");
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            action.as_str(),
            package_name,
            user,
            groups,
            request.method,
            request.path,
            org_id,
            project_id
        )
    }

    async fn cached_decision(&self, key: &str) -> Option<bool> {
        let now = jiff::Timestamp::now().as_millisecond();
        let cache = self.cache.read().await;
        let entry = cache.get(key)?;
        if entry.expires_at_ms > now {
            Some(entry.allowed)
        } else {
            None
        }
    }

    async fn cache_decision(&self, key: String, allowed: bool) {
        if self.cfg.cache_ttl_ms == 0 {
            return;
        }
        let expires_at_ms = jiff::Timestamp::now().as_millisecond() + self.cfg.cache_ttl_ms as i64;
        let mut cache = self.cache.write().await;
        cache.insert(
            key,
            CachedDecision {
                allowed,
                expires_at_ms,
            },
        );
        drop(cache);
        self.prune_cache(true).await;
    }

    async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        self.last_cache_prune_ms.store(0, Ordering::Relaxed);
    }

    async fn prune_cache(&self, force: bool) {
        let now_ms = jiff::Timestamp::now().as_millisecond();
        if !force {
            let last_prune_ms = self.last_cache_prune_ms.load(Ordering::Relaxed);
            if last_prune_ms > 0
                && now_ms.saturating_sub(last_prune_ms) < self.cfg.cache_prune_interval_ms as i64
            {
                return;
            }
        }

        let mut cache = self.cache.write().await;
        cache.retain(|_, decision| decision.expires_at_ms > now_ms);
        if self.cfg.cache_max_entries > 0 && cache.len() > self.cfg.cache_max_entries {
            let mut by_expiry = cache
                .iter()
                .map(|(key, decision)| (key.clone(), decision.expires_at_ms))
                .collect::<Vec<_>>();
            by_expiry.sort_by_key(|(_, expires_at_ms)| *expires_at_ms);
            let remove_count = cache.len().saturating_sub(self.cfg.cache_max_entries);
            for (key, _) in by_expiry.into_iter().take(remove_count) {
                cache.remove(&key);
            }
        }
        self.last_cache_prune_ms.store(now_ms, Ordering::Relaxed);
    }
}

impl PolicyAction {
    fn as_str(self) -> &'static str {
        match self {
            PolicyAction::Access => "access",
            PolicyAction::Publish => "publish",
            PolicyAction::Unpublish => "unpublish",
        }
    }
}

fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
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
