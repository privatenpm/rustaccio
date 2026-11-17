//! Distributed write coordination for shared sidecar metadata.
//!
//! When several rustaccio instances share authoritative storage, concurrent
//! mutations of the *same* package's sidecar `package.json` (publish,
//! unpublish, remove-tarball, dist-tag merge) must be serialized. This module
//! provides a per-scope distributed advisory lock for that purpose.
//!
//! The lock is abstracted behind the `LockBackend`/`LockGuard` traits so new
//! backends are drop-in. [`StateWriteCoordinator`] owns the backend-agnostic
//! acquire loop (bounded polling, timeout, fail-open); each backend only has to
//! implement a single non-blocking acquire attempt and a release.
//!
//! Backends:
//! - `s3`: conditional `PutObject` (`If-None-Match`/`If-Match`) lease.
//! - `redis`: `SET NX PX` lease with Lua-guarded renew/release.
//! - `postgres`: session-scoped `pg_advisory_lock` on a dedicated connection.

use crate::error::RegistryError;
use async_trait::async_trait;
use axum::http::StatusCode;
use std::sync::Arc;
#[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
use std::time::Duration;
#[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
use tracing::warn;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "redis")]
mod redis;
#[cfg(feature = "s3")]
mod s3;

/// One backend that can grant a mutually-exclusive, per-scope lock.
///
/// Implementations perform a single, non-blocking acquire attempt; the bounded
/// retry/timeout/fail-open policy lives in [`StateWriteCoordinator`].
#[cfg_attr(
    not(any(feature = "redis", feature = "s3", feature = "postgres")),
    allow(dead_code)
)]
#[async_trait]
trait LockBackend: Send + Sync {
    /// Attempt to acquire the lock for `scope` exactly once.
    ///
    /// - `Ok(Some(guard))` — acquired; hold until the guard is released.
    /// - `Ok(None)` — currently held by someone else; the caller should retry.
    /// - `Err(_)` — the backend is unavailable.
    async fn try_acquire(
        &self,
        scope: &str,
        operation: &str,
    ) -> Result<Option<Box<dyn LockGuard>>, RegistryError>;
}

/// A held lock. Dropping the guard without calling [`LockGuard::release`] leaves
/// release to the backend's lease expiry (or connection teardown).
#[cfg_attr(
    not(any(feature = "redis", feature = "s3", feature = "postgres")),
    allow(dead_code)
)]
#[async_trait]
trait LockGuard: Send + Sync {
    /// Best-effort release of the lock. Failures are logged, not propagated.
    async fn release(self: Box<Self>);
}

/// Coordinates exclusive, per-scope writes across instances.
///
/// `None` backend means coordination is disabled (single-instance / local
/// profile) and operations run without locking.
pub struct StateWriteCoordinator {
    backend: Option<Arc<dyn LockBackend>>,
    #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
    acquire_timeout_ms: u64,
    #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
    poll_interval_ms: u64,
    #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
    fail_open: bool,
}

impl StateWriteCoordinator {
    /// Build the coordinator from `RUSTACCIO_STATE_COORDINATION_*` environment.
    pub async fn from_env() -> Result<Self, RegistryError> {
        let cfg = StateCoordinationConfig::from_env();
        let backend: Option<Arc<dyn LockBackend>> = match cfg.backend.as_str() {
            "none" | "" => None,
            "redis" => Some(Self::build_redis(&cfg)?),
            "s3" => Some(Self::build_s3(&cfg).await?),
            "postgres" => Some(Self::build_postgres(&cfg)?),
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_STATE_COORDINATION_BACKEND: {other}"),
                ));
            }
        };

        Ok(Self {
            backend,
            #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
            acquire_timeout_ms: cfg.acquire_timeout_ms,
            #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
            poll_interval_ms: cfg.poll_interval_ms,
            #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
            fail_open: cfg.fail_open,
        })
    }

    #[cfg(feature = "redis")]
    fn build_redis(cfg: &StateCoordinationConfig) -> Result<Arc<dyn LockBackend>, RegistryError> {
        let Some(redis_url) = cfg.redis_url.clone() else {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_STATE_COORDINATION_REDIS_URL is required when RUSTACCIO_STATE_COORDINATION_BACKEND=redis",
            ));
        };
        Ok(Arc::new(redis::RedisLockBackend::new(
            redis_url,
            cfg.lock_key.clone(),
            cfg.lease_ms,
        )?))
    }

    #[cfg(not(feature = "redis"))]
    fn build_redis(_cfg: &StateCoordinationConfig) -> Result<Arc<dyn LockBackend>, RegistryError> {
        Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_STATE_COORDINATION_BACKEND=redis requires rustaccio build with `redis` feature",
        ))
    }

    #[cfg(feature = "s3")]
    async fn build_s3(
        cfg: &StateCoordinationConfig,
    ) -> Result<Arc<dyn LockBackend>, RegistryError> {
        let Some(bucket) = cfg.s3_bucket.clone() else {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_STATE_COORDINATION_S3_BUCKET is required when RUSTACCIO_STATE_COORDINATION_BACKEND=s3",
            ));
        };
        Ok(Arc::new(
            s3::S3LockBackend::new(
                bucket,
                cfg.s3_region.clone(),
                cfg.s3_endpoint.clone(),
                cfg.s3_access_key_id.clone(),
                cfg.s3_secret_access_key.clone(),
                cfg.s3_prefix.clone(),
                cfg.s3_force_path_style,
                cfg.lease_ms,
            )
            .await?,
        ))
    }

    #[cfg(not(feature = "s3"))]
    async fn build_s3(
        _cfg: &StateCoordinationConfig,
    ) -> Result<Arc<dyn LockBackend>, RegistryError> {
        Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_STATE_COORDINATION_BACKEND=s3 requires rustaccio build with `s3` feature",
        ))
    }

    #[cfg(feature = "postgres")]
    fn build_postgres(
        cfg: &StateCoordinationConfig,
    ) -> Result<Arc<dyn LockBackend>, RegistryError> {
        let Some(url) = cfg.postgres_url.clone() else {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_STATE_COORDINATION_POSTGRES_URL is required when RUSTACCIO_STATE_COORDINATION_BACKEND=postgres",
            ));
        };
        Ok(Arc::new(postgres::PostgresLockBackend::new(url)))
    }

    #[cfg(not(feature = "postgres"))]
    fn build_postgres(
        _cfg: &StateCoordinationConfig,
    ) -> Result<Arc<dyn LockBackend>, RegistryError> {
        Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_STATE_COORDINATION_BACKEND=postgres requires rustaccio build with `postgres` feature",
        ))
    }

    /// Run `operation` while holding the global coordination lock.
    pub async fn run_exclusive<T, F, Fut>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, RegistryError>>,
    {
        self.run_exclusive_scoped("global", operation_name, operation)
            .await
    }

    /// Run `operation` while holding the lock for `scope`.
    pub async fn run_exclusive_scoped<T, F, Fut>(
        &self,
        #[cfg_attr(
            not(any(feature = "redis", feature = "s3", feature = "postgres")),
            allow(unused_variables)
        )]
        scope: &str,
        #[cfg_attr(
            not(any(feature = "redis", feature = "s3", feature = "postgres")),
            allow(unused_variables)
        )]
        operation_name: &str,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, RegistryError>>,
    {
        let Some(backend) = self.backend.as_ref() else {
            return operation().await;
        };

        #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
        {
            let guard = self
                .acquire(backend.as_ref(), scope, operation_name)
                .await?;
            let result = operation().await;
            if let Some(guard) = guard {
                guard.release().await;
            }
            result
        }
        // When no backend feature is compiled in, `backend` is uninhabited in
        // practice (from_env never yields Some), but keep the type-checker happy.
        #[cfg(not(any(feature = "redis", feature = "s3", feature = "postgres")))]
        {
            let _ = backend;
            operation().await
        }
    }

    /// Bounded acquire: poll the backend until acquired, the timeout elapses, or
    /// (when `fail_open`) the backend is unavailable.
    #[cfg(any(feature = "redis", feature = "s3", feature = "postgres"))]
    async fn acquire(
        &self,
        backend: &dyn LockBackend,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<Box<dyn LockGuard>>, RegistryError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.acquire_timeout_ms);
        loop {
            match backend.try_acquire(scope, operation_name).await {
                Ok(Some(guard)) => return Ok(Some(guard)),
                Ok(None) => {}
                Err(err) if self.fail_open => {
                    warn!(
                        error = ?err,
                        scope,
                        operation = operation_name,
                        "state coordination backend unavailable; continuing without lock (fail-open)"
                    );
                    return Ok(None);
                }
                Err(err) => return Err(err),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(RegistryError::http(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "state coordination lock timeout",
                ));
            }
            tokio::time::sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateCoordinationConfig {
    backend: String,
    redis_url: Option<String>,
    postgres_url: Option<String>,
    lock_key: String,
    lease_ms: u64,
    acquire_timeout_ms: u64,
    poll_interval_ms: u64,
    fail_open: bool,
    s3_bucket: Option<String>,
    s3_region: String,
    s3_endpoint: Option<String>,
    s3_access_key_id: Option<String>,
    s3_secret_access_key: Option<String>,
    s3_prefix: String,
    s3_force_path_style: bool,
}

impl Default for StateCoordinationConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            redis_url: None,
            postgres_url: None,
            lock_key: "rustaccio:state:lock".to_string(),
            lease_ms: 5_000,
            acquire_timeout_ms: 15_000,
            poll_interval_ms: 100,
            fail_open: false,
            s3_bucket: None,
            s3_region: "us-east-1".to_string(),
            s3_endpoint: None,
            s3_access_key_id: None,
            s3_secret_access_key: None,
            s3_prefix: "rustaccio/state-locks/".to_string(),
            s3_force_path_style: false,
        }
    }
}

impl StateCoordinationConfig {
    fn from_env() -> Self {
        let s3_bucket = env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_BUCKET")
            .or_else(|| env_value_non_empty("RUSTACCIO_S3_BUCKET"));
        let s3_region = env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_REGION")
            .or_else(|| env_value_non_empty("RUSTACCIO_S3_REGION"))
            .unwrap_or_else(|| "us-east-1".to_string());
        let s3_endpoint = env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT")
            .or_else(|| env_value_non_empty("RUSTACCIO_S3_ENDPOINT"));
        let s3_access_key_id = env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID")
            .or_else(|| env_value_non_empty("RUSTACCIO_S3_ACCESS_KEY_ID"));
        let s3_secret_access_key =
            env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY")
                .or_else(|| env_value_non_empty("RUSTACCIO_S3_SECRET_ACCESS_KEY"));
        let s3_prefix_raw = env_value_non_empty("RUSTACCIO_STATE_COORDINATION_S3_PREFIX")
            .or_else(|| env_value_non_empty("RUSTACCIO_S3_PREFIX"))
            .unwrap_or_else(|| "rustaccio/state-locks/".to_string());
        let s3_force_path_style =
            parse_bool_env_optional("RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE")
                .or_else(|| parse_bool_env_optional("RUSTACCIO_S3_FORCE_PATH_STYLE"))
                .unwrap_or(false);

        Self {
            backend: env_value("RUSTACCIO_STATE_COORDINATION_BACKEND")
                .unwrap_or_else(|| "none".to_string()),
            redis_url: env_value("RUSTACCIO_STATE_COORDINATION_REDIS_URL"),
            postgres_url: env_value("RUSTACCIO_STATE_COORDINATION_POSTGRES_URL")
                .or_else(|| env_value("RUSTACCIO_QUOTA_POSTGRES_URL")),
            lock_key: env_value("RUSTACCIO_STATE_COORDINATION_LOCK_KEY")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "rustaccio:state:lock".to_string()),
            lease_ms: parse_u64_env("RUSTACCIO_STATE_COORDINATION_LEASE_MS", 5_000)
                .clamp(1_000, 300_000),
            acquire_timeout_ms: parse_u64_env(
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                15_000,
            )
            .clamp(1_000, 600_000),
            poll_interval_ms: parse_u64_env("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", 100)
                .clamp(10, 5_000),
            fail_open: parse_bool_env("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", false),
            s3_bucket,
            s3_region,
            s3_endpoint,
            s3_access_key_id,
            s3_secret_access_key,
            s3_prefix: normalize_s3_prefix(&s3_prefix_raw),
            s3_force_path_style,
        }
    }
}

/// Restrict a scope to characters safe for use in lock keys / object keys.
#[cfg(any(feature = "redis", feature = "s3"))]
fn sanitize_scope(scope: &str) -> String {
    scope
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn normalize_s3_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

#[cfg(feature = "s3")]
fn now_ms() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn env_value_non_empty(key: &str) -> Option<String> {
    env_value(key).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    env_value(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    parse_bool_env_optional(key).unwrap_or(default)
}

fn parse_bool_env_optional(key: &str) -> Option<bool> {
    env_value_non_empty(key).map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}
