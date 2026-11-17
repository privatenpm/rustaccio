use crate::{
    error::RegistryError,
    models::{AuthIdentity, TenantContext},
};
use async_trait::async_trait;
use axum::http::StatusCode;
#[cfg(feature = "postgres")]
use tokio_postgres::NoTls;
use tracing::{debug, error};

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;

#[cfg(feature = "postgres")]
const QUOTA_MIGRATIONS: &[(&str, &str)] = &[(
    "0001_quota_usage_table",
    include_str!("../migrations/0001_quota_usage_table.sql"),
)];
#[cfg(feature = "postgres")]
const QUOTA_MIGRATIONS_LOCK_ID: i64 = 8_426_049_175_951_891_360;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceAction {
    Access,
    Download,
    Publish,
    Unpublish,
    Search,
    Admin,
    Other,
}

impl GovernanceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Download => "download",
            Self::Publish => "publish",
            Self::Unpublish => "unpublish",
            Self::Search => "search",
            Self::Admin => "admin",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceContext {
    pub action: GovernanceAction,
    pub method: String,
    pub path: String,
    pub package_name: Option<String>,
    pub tenant: TenantContext,
    pub username: Option<String>,
    pub groups: Vec<String>,
    pub client_ip: Option<String>,
}

impl Default for GovernanceContext {
    fn default() -> Self {
        Self {
            action: GovernanceAction::Other,
            method: String::new(),
            path: String::new(),
            package_name: None,
            tenant: TenantContext::default(),
            username: None,
            groups: Vec::new(),
            client_ip: None,
        }
    }
}

impl GovernanceContext {
    pub fn from_identity(
        action: GovernanceAction,
        method: &str,
        path: &str,
        package_name: Option<String>,
        identity: Option<&AuthIdentity>,
        tenant: TenantContext,
        client_ip: Option<String>,
    ) -> Self {
        Self {
            action,
            method: method.to_string(),
            path: path.to_string(),
            package_name,
            tenant,
            username: identity.and_then(|id| id.username.clone()),
            groups: identity.map(|id| id.groups.clone()).unwrap_or_default(),
            client_ip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceOutcome {
    Allowed,
    Rejected,
}

#[async_trait]
pub trait GovernanceGuard: Send + Sync {
    async fn check(&self, _ctx: &GovernanceContext) -> Result<(), RegistryError> {
        Ok(())
    }
}

#[async_trait]
pub trait GovernanceMetrics: Send + Sync {
    fn observe(&self, _ctx: &GovernanceContext, _outcome: GovernanceOutcome) {}
    async fn render(&self) -> Option<String> {
        None
    }
}

#[derive(Default)]
pub struct NoopGuard;

#[async_trait]
impl GovernanceGuard for NoopGuard {}

#[derive(Default)]
pub struct NoopMetrics;

#[async_trait]
impl GovernanceMetrics for NoopMetrics {}

pub struct PrometheusTextMetrics {
    counters: Mutex<HashMap<(String, String), u64>>,
}

impl Default for PrometheusTextMetrics {
    fn default() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GovernanceMetrics for PrometheusTextMetrics {
    fn observe(&self, ctx: &GovernanceContext, outcome: GovernanceOutcome) {
        let action = ctx.action.as_str().to_string();
        let outcome = match outcome {
            GovernanceOutcome::Allowed => "allowed",
            GovernanceOutcome::Rejected => "rejected",
        }
        .to_string();

        let mut lock = match self.counters.lock() {
            Ok(lock) => lock,
            Err(poisoned) => {
                error!("governance metrics mutex was poisoned; continuing with recovered state");
                poisoned.into_inner()
            }
        };
        let entry = lock.entry((action, outcome)).or_insert(0);
        *entry += 1;
    }

    async fn render(&self) -> Option<String> {
        let lock = match self.counters.lock() {
            Ok(lock) => lock,
            Err(poisoned) => {
                error!("governance metrics mutex was poisoned; rendering recovered state");
                poisoned.into_inner()
            }
        };
        let mut lines = vec![
            "# HELP rustaccio_governance_requests_total Governance request decisions.".to_string(),
            "# TYPE rustaccio_governance_requests_total counter".to_string(),
        ];
        for ((action, outcome), value) in lock.iter() {
            lines.push(format!(
                "rustaccio_governance_requests_total{{action=\"{action}\",outcome=\"{outcome}\"}} {value}"
            ));
        }
        Some(lines.join("\n"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub backend: String,
    pub requests_per_window: u64,
    pub window_secs: u64,
    pub redis_url: Option<String>,
    pub fail_open: bool,
    pub memory_max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            requests_per_window: 0,
            window_secs: 60,
            redis_url: None,
            fail_open: true,
            memory_max_keys: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaConfig {
    pub backend: String,
    pub requests_per_day: u64,
    pub downloads_per_day: u64,
    pub publishes_per_day: u64,
    pub postgres_url: Option<String>,
    pub fail_open: bool,
    pub memory_max_keys: usize,
    pub memory_retention_days: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            requests_per_day: 0,
            downloads_per_day: 0,
            publishes_per_day: 0,
            postgres_url: None,
            fail_open: true,
            memory_max_keys: 50_000,
            memory_retention_days: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    pub backend: String,
    pub path: String,
    pub require_admin: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            path: "/-/metrics".to_string(),
            require_admin: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GovernanceConfig {
    pub rate_limit: RateLimitConfig,
    pub quota: QuotaConfig,
    pub metrics: MetricsConfig,
}

impl GovernanceConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        cfg.rate_limit.backend =
            env_value("RUSTACCIO_RATE_LIMIT_BACKEND").unwrap_or_else(|| "none".to_string());
        cfg.rate_limit.requests_per_window =
            parse_u64_env("RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW", 0);
        cfg.rate_limit.window_secs = parse_u64_env("RUSTACCIO_RATE_LIMIT_WINDOW_SECS", 60).max(1);
        cfg.rate_limit.redis_url = env_value("RUSTACCIO_RATE_LIMIT_REDIS_URL");
        cfg.rate_limit.fail_open = parse_bool_env("RUSTACCIO_RATE_LIMIT_FAIL_OPEN", true);
        cfg.rate_limit.memory_max_keys =
            parse_u64_env("RUSTACCIO_RATE_LIMIT_MEMORY_MAX_KEYS", 10_000) as usize;

        cfg.quota.backend =
            env_value("RUSTACCIO_QUOTA_BACKEND").unwrap_or_else(|| "none".to_string());
        cfg.quota.requests_per_day = parse_u64_env("RUSTACCIO_QUOTA_REQUESTS_PER_DAY", 0);
        cfg.quota.downloads_per_day = parse_u64_env("RUSTACCIO_QUOTA_DOWNLOADS_PER_DAY", 0);
        cfg.quota.publishes_per_day = parse_u64_env("RUSTACCIO_QUOTA_PUBLISHES_PER_DAY", 0);
        cfg.quota.postgres_url = env_value("RUSTACCIO_QUOTA_POSTGRES_URL");
        cfg.quota.fail_open = parse_bool_env("RUSTACCIO_QUOTA_FAIL_OPEN", true);
        cfg.quota.memory_max_keys =
            parse_u64_env("RUSTACCIO_QUOTA_MEMORY_MAX_KEYS", 50_000) as usize;
        cfg.quota.memory_retention_days =
            parse_u64_env("RUSTACCIO_QUOTA_MEMORY_RETENTION_DAYS", 2).max(1);

        cfg.metrics.backend =
            env_value("RUSTACCIO_METRICS_BACKEND").unwrap_or_else(|| "none".to_string());
        cfg.metrics.path =
            env_value("RUSTACCIO_METRICS_PATH").unwrap_or_else(|| "/-/metrics".to_string());
        cfg.metrics.require_admin = parse_bool_env("RUSTACCIO_METRICS_REQUIRE_ADMIN", true);
        cfg
    }
}

pub struct GovernanceEngine {
    rate_limiter: Arc<dyn GovernanceGuard>,
    quota: Arc<dyn GovernanceGuard>,
    metrics: Arc<dyn GovernanceMetrics>,
    metrics_path: Option<String>,
    metrics_require_admin: bool,
}

impl GovernanceEngine {
    pub async fn from_env() -> Result<Self, RegistryError> {
        let cfg = GovernanceConfig::from_env();

        let rate_limiter: Arc<dyn GovernanceGuard> = match cfg.rate_limit.backend.as_str() {
            "none" | "" => Arc::new(NoopGuard),
            "memory" => Arc::new(InMemoryRateLimiter::new(
                cfg.rate_limit.requests_per_window,
                cfg.rate_limit.window_secs,
                cfg.rate_limit.memory_max_keys.max(100),
            )),
            "redis" => {
                #[cfg(feature = "redis")]
                {
                    let Some(redis_url) = cfg.rate_limit.redis_url.clone() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "RUSTACCIO_RATE_LIMIT_REDIS_URL is required when RUSTACCIO_RATE_LIMIT_BACKEND=redis",
                        ));
                    };
                    Arc::new(RedisRateLimiter::new(
                        redis_url,
                        cfg.rate_limit.requests_per_window,
                        cfg.rate_limit.window_secs,
                        cfg.rate_limit.fail_open,
                    )?)
                }
                #[cfg(not(feature = "redis"))]
                {
                    return Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "RUSTACCIO_RATE_LIMIT_BACKEND=redis requires rustaccio build with `redis` feature",
                    ));
                }
            }
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_RATE_LIMIT_BACKEND: {other}"),
                ));
            }
        };

        let quota: Arc<dyn GovernanceGuard> = match cfg.quota.backend.as_str() {
            "none" | "" => Arc::new(NoopGuard),
            "memory" => Arc::new(InMemoryQuotaGuard::new(&cfg.quota)),
            "postgres" => {
                #[cfg(feature = "postgres")]
                {
                    let Some(postgres_url) = cfg.quota.postgres_url.clone() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "RUSTACCIO_QUOTA_POSTGRES_URL is required when RUSTACCIO_QUOTA_BACKEND=postgres",
                        ));
                    };
                    Arc::new(PostgresQuotaGuard::new(postgres_url, &cfg.quota).await?)
                }
                #[cfg(not(feature = "postgres"))]
                {
                    return Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "RUSTACCIO_QUOTA_BACKEND=postgres requires rustaccio build with `postgres` feature",
                    ));
                }
            }
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_QUOTA_BACKEND: {other}"),
                ));
            }
        };

        let metrics: Arc<dyn GovernanceMetrics> = match cfg.metrics.backend.as_str() {
            "none" | "" => Arc::new(NoopMetrics),
            "prometheus" => Arc::new(PrometheusTextMetrics::default()),
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_METRICS_BACKEND: {other}"),
                ));
            }
        };

        debug!(
            rate_limit_backend = cfg.rate_limit.backend,
            quota_backend = cfg.quota.backend,
            metrics_backend = cfg.metrics.backend,
            metrics_path = cfg.metrics.path,
            metrics_require_admin = cfg.metrics.require_admin,
            "initialized governance engine"
        );

        Ok(Self {
            rate_limiter,
            quota,
            metrics,
            metrics_path: if cfg.metrics.backend.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(normalize_endpoint(&cfg.metrics.path))
            },
            metrics_require_admin: cfg.metrics.require_admin,
        })
    }

    pub async fn enforce(&self, ctx: &GovernanceContext) -> Result<(), RegistryError> {
        if let Err(err) = self.rate_limiter.check(ctx).await {
            self.metrics.observe(ctx, GovernanceOutcome::Rejected);
            return Err(err);
        }
        if let Err(err) = self.quota.check(ctx).await {
            self.metrics.observe(ctx, GovernanceOutcome::Rejected);
            return Err(err);
        }
        self.metrics.observe(ctx, GovernanceOutcome::Allowed);
        Ok(())
    }

    pub fn metrics_path(&self) -> Option<&str> {
        self.metrics_path.as_deref()
    }

    pub fn metrics_require_admin(&self) -> bool {
        self.metrics_require_admin
    }

    pub async fn render_metrics(&self) -> Option<String> {
        self.metrics.render().await
    }
}

impl Default for GovernanceEngine {
    fn default() -> Self {
        Self {
            rate_limiter: Arc::new(NoopGuard),
            quota: Arc::new(NoopGuard),
            metrics: Arc::new(NoopMetrics),
            metrics_path: None,
            metrics_require_admin: true,
        }
    }
}

#[derive(Debug, Clone)]
struct WindowState {
    window_start_ms: i64,
    count: u64,
}

struct InMemoryRateLimiter {
    limit: u64,
    window_secs: u64,
    max_keys: usize,
    windows: AsyncMutex<HashMap<String, WindowState>>,
}

impl InMemoryRateLimiter {
    fn new(limit: u64, window_secs: u64, max_keys: usize) -> Self {
        Self {
            limit,
            window_secs,
            max_keys,
            windows: AsyncMutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GovernanceGuard for InMemoryRateLimiter {
    async fn check(&self, ctx: &GovernanceContext) -> Result<(), RegistryError> {
        if self.limit == 0 {
            return Ok(());
        }

        let key = governance_key(ctx);
        let now_ms = jiff::Timestamp::now().as_millisecond();
        let window_ms = (self.window_secs as i64) * 1000;
        let mut windows = self.windows.lock().await;
        if windows.len() >= self.max_keys && !windows.contains_key(&key) {
            windows.retain(|_, state| now_ms.saturating_sub(state.window_start_ms) < window_ms);
            if windows.len() >= self.max_keys
                && let Some(oldest_key) = windows
                    .iter()
                    .min_by_key(|(_, state)| state.window_start_ms)
                    .map(|(key, _)| key.clone())
            {
                windows.remove(&oldest_key);
            }
        }
        let entry = windows.entry(key).or_insert(WindowState {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms - entry.window_start_ms >= window_ms {
            entry.window_start_ms = now_ms;
            entry.count = 0;
        }
        if entry.count >= self.limit {
            return Err(RegistryError::http(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
        entry.count += 1;
        Ok(())
    }
}

struct InMemoryQuotaGuard {
    requests_per_day: u64,
    downloads_per_day: u64,
    publishes_per_day: u64,
    max_keys: usize,
    retention_days: u64,
    usage: AsyncMutex<HashMap<(String, String, String), u64>>,
}

impl InMemoryQuotaGuard {
    fn new(cfg: &QuotaConfig) -> Self {
        Self {
            requests_per_day: cfg.requests_per_day,
            downloads_per_day: cfg.downloads_per_day,
            publishes_per_day: cfg.publishes_per_day,
            max_keys: cfg.memory_max_keys.max(100),
            retention_days: cfg.memory_retention_days.max(1),
            usage: AsyncMutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GovernanceGuard for InMemoryQuotaGuard {
    async fn check(&self, ctx: &GovernanceContext) -> Result<(), RegistryError> {
        let (metric, limit) = match ctx.action {
            GovernanceAction::Download => ("downloads", self.downloads_per_day),
            GovernanceAction::Publish | GovernanceAction::Unpublish => {
                ("publishes", self.publishes_per_day)
            }
            _ => ("requests", self.requests_per_day),
        };
        if limit == 0 {
            return Ok(());
        }

        let tenant_key = tenant_key(ctx);
        let day = jiff::Timestamp::now().strftime("%Y-%m-%d").to_string();
        let mut usage = self.usage.lock().await;
        let oldest_allowed_day = jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(
                i64::try_from(self.retention_days.saturating_sub(1))
                    .unwrap_or(i64::MAX / 3600)
                    .saturating_mul(24),
            ))
            .unwrap_or(jiff::Timestamp::MIN)
            .strftime("%Y-%m-%d")
            .to_string();
        usage.retain(|(entry_day, _, _), _| entry_day >= &oldest_allowed_day);
        if usage.len() >= self.max_keys {
            let mut keys = usage.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let remove_count = usage.len().saturating_sub(self.max_keys.saturating_sub(1));
            for key in keys.into_iter().take(remove_count) {
                usage.remove(&key);
            }
        }
        let key = (day, tenant_key, metric.to_string());
        let entry = usage.entry(key).or_insert(0);
        if *entry >= limit {
            return Err(RegistryError::http(
                StatusCode::TOO_MANY_REQUESTS,
                "quota exceeded",
            ));
        }
        *entry += 1;
        Ok(())
    }
}

#[cfg(feature = "redis")]
struct RedisRateLimiter {
    client: redis::Client,
    limit: u64,
    window_secs: u64,
    fail_open: bool,
}

#[cfg(feature = "redis")]
impl RedisRateLimiter {
    fn new(
        redis_url: String,
        limit: u64,
        window_secs: u64,
        fail_open: bool,
    ) -> Result<Self, RegistryError> {
        let client = redis::Client::open(redis_url).map_err(|_| {
            RegistryError::http(StatusCode::INTERNAL_SERVER_ERROR, "invalid redis url")
        })?;
        Ok(Self {
            client,
            limit,
            window_secs,
            fail_open,
        })
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl GovernanceGuard for RedisRateLimiter {
    async fn check(&self, ctx: &GovernanceContext) -> Result<(), RegistryError> {
        if self.limit == 0 {
            return Ok(());
        }
        let key = format!("rustaccio:ratelimit:{}", governance_key(ctx));
        let mut conn = match self.client.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(err) => {
                if self.fail_open {
                    tracing::warn!(error = ?err, "redis rate limiter unavailable; fail-open");
                    return Ok(());
                }
                return Err(RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "rate limiter backend unavailable",
                ));
            }
        };

        let script = redis::Script::new(
            r#"
            local c = redis.call('INCR', KEYS[1])
            if c == 1 then
              redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return c
            "#,
        );
        let count: i64 = match script
            .key(&key)
            .arg(self.window_secs as i64)
            .invoke_async(&mut conn)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                if self.fail_open {
                    tracing::warn!(error = ?err, "redis rate limiter failed; fail-open");
                    return Ok(());
                }
                return Err(RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "rate limiter backend unavailable",
                ));
            }
        };
        if count as u64 > self.limit {
            return Err(RegistryError::http(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "postgres")]
struct PostgresQuotaGuard {
    client: tokio_postgres::Client,
    requests_per_day: u64,
    downloads_per_day: u64,
    publishes_per_day: u64,
    fail_open: bool,
}

#[cfg(feature = "postgres")]
impl PostgresQuotaGuard {
    async fn new(url: String, cfg: &QuotaConfig) -> Result<Self, RegistryError> {
        let (client, connection) = tokio_postgres::connect(&url, NoTls).await.map_err(|_| {
            RegistryError::http(StatusCode::INTERNAL_SERVER_ERROR, "invalid postgres url")
        })?;

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::error!(error = ?err, "postgres quota connection terminated");
            }
        });

        apply_quota_migrations(&client).await?;

        Ok(Self {
            client,
            requests_per_day: cfg.requests_per_day,
            downloads_per_day: cfg.downloads_per_day,
            publishes_per_day: cfg.publishes_per_day,
            fail_open: cfg.fail_open,
        })
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl GovernanceGuard for PostgresQuotaGuard {
    async fn check(&self, ctx: &GovernanceContext) -> Result<(), RegistryError> {
        let (metric, limit) = match ctx.action {
            GovernanceAction::Download => ("downloads", self.downloads_per_day),
            GovernanceAction::Publish | GovernanceAction::Unpublish => {
                ("publishes", self.publishes_per_day)
            }
            _ => ("requests", self.requests_per_day),
        };
        if limit == 0 {
            return Ok(());
        }

        let day = jiff::Timestamp::now().strftime("%Y-%m-%d").to_string();
        let tenant_key = tenant_key(ctx);
        let row = self
            .client
            .query_one(
                "INSERT INTO rustaccio_quota_usage (day, tenant_key, metric, used)
                 VALUES ($1, $2, $3, 1)
                 ON CONFLICT (day, tenant_key, metric)
                 DO UPDATE SET used = rustaccio_quota_usage.used + 1
                 RETURNING used",
                &[&day, &tenant_key, &metric],
            )
            .await;
        let used: i64 = match row {
            Ok(row) => row.get(0),
            Err(err) => {
                if self.fail_open {
                    tracing::warn!(error = ?err, "postgres quota guard failed; fail-open");
                    return Ok(());
                }
                return Err(RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "quota backend unavailable",
                ));
            }
        };

        if used as u64 > limit {
            return Err(RegistryError::http(
                StatusCode::TOO_MANY_REQUESTS,
                "quota exceeded",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "postgres")]
async fn apply_quota_migrations(client: &tokio_postgres::Client) -> Result<(), RegistryError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS rustaccio_schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .await
        .map_err(|_| {
            RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to initialize migration state table",
            )
        })?;

    client
        .query("SELECT pg_advisory_lock($1)", &[&QUOTA_MIGRATIONS_LOCK_ID])
        .await
        .map_err(|_| {
            RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to acquire quota migration lock",
            )
        })?;

    for (migration_name, migration_sql) in QUOTA_MIGRATIONS {
        let already_applied = client
            .query_opt(
                "SELECT name FROM rustaccio_schema_migrations WHERE name = $1",
                &[migration_name],
            )
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to check migration state",
                )
            })?
            .is_some();

        if already_applied {
            continue;
        }

        client.batch_execute(migration_sql).await.map_err(|_| {
            RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to apply migration {migration_name}"),
            )
        })?;
        client
            .execute(
                "INSERT INTO rustaccio_schema_migrations (name) VALUES ($1)",
                &[migration_name],
            )
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to persist migration {migration_name}"),
                )
            })?;
    }

    client
        .query(
            "SELECT pg_advisory_unlock($1)",
            &[&QUOTA_MIGRATIONS_LOCK_ID],
        )
        .await
        .map_err(|_| {
            RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to release quota migration lock",
            )
        })?;

    Ok(())
}

fn governance_key(ctx: &GovernanceContext) -> String {
    let tenant = tenant_key(ctx);
    let user = ctx.username.clone().unwrap_or_else(|| "-".to_string());
    let ip = ctx.client_ip.clone().unwrap_or_else(|| "-".to_string());
    format!("{tenant}:{}:{user}:{ip}", ctx.action.as_str(),)
}

fn tenant_key(ctx: &GovernanceContext) -> String {
    if let Some(project_id) = &ctx.tenant.project_id {
        return format!(
            "{}:{project_id}",
            ctx.tenant.org_id.clone().unwrap_or_else(|| "-".to_string())
        );
    }
    if let Some(org_id) = &ctx.tenant.org_id {
        return org_id.clone();
    }
    ctx.username
        .clone()
        .unwrap_or_else(|| "anonymous".to_string())
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    env_value(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    env_value(key)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}
