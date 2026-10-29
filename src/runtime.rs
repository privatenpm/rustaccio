use crate::{
    acl::Acl,
    app::{AdminAccessConfig, AppState, build_router},
    auth::AuthHook,
    config::{Config, TarballStorageBackend},
    error::RegistryError,
    events::EventDispatcher,
    governance::GovernanceEngine,
    managed::ManagedState,
    observability,
    policy::{DefaultPolicyEngine, HttpPolicyConfig},
    startup_checks,
    storage::{Store, StoreOptions},
    upstream::Upstream,
};
use axum::{body::Body, extract::Request, http::StatusCode, serve::ListenerExt};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::{Service, ServiceExt as _};
use tracing::instrument;

#[instrument(skip(config, auth_hook))]
pub async fn build_state(
    config: &Config,
    auth_hook: Option<Arc<dyn AuthHook>>,
) -> Result<AppState, RegistryError> {
    let managed_mode = validate_runtime_profile(config)?;
    let admin_access = AdminAccessConfig::from_env();
    validate_managed_mode_guardrails_with_flag(managed_mode, config, &admin_access)?;

    let store = Arc::new(Store::open_with_options(config, StoreOptions { auth_hook }).await?);
    store.start_background_maintenance();
    let acl = Acl::new(config.acl_rules.clone());
    let governance = Arc::new(GovernanceEngine::from_env().await?);
    let events = Arc::new(EventDispatcher::from_env()?);
    let policy = if let Some(policy_cfg) = HttpPolicyConfig::from_env()? {
        Arc::new(DefaultPolicyEngine::new_with_http(
            store.clone(),
            acl.clone(),
            policy_cfg,
        )?)
    } else {
        Arc::new(DefaultPolicyEngine::new(store.clone(), acl.clone()))
    };

    let mut uplinks = HashMap::new();
    for (name, url) in &config.uplinks {
        uplinks.insert(name.clone(), Upstream::new(url.clone()));
    }
    if uplinks.is_empty()
        && let Some(url) = config.upstream_registry.clone()
    {
        uplinks.insert("default".to_string(), Upstream::new(url));
    }

    // Managed data-plane bridge: validates control-plane URL + node token +
    // s3 tarball backend, then heartbeats the fleet registry (with optional
    // placement enforcement) before serving traffic.
    let managed = ManagedState::from_config(config).await?;
    if let Some(managed) = &managed {
        managed.start().await?;
    }

    Ok(AppState {
        store,
        acl,
        policy,
        governance,
        events,
        admin_access,
        uplinks,
        web_enabled: config.web_enabled,
        web_title: config.web_title.clone(),
        publish_check_owners: config.publish_check_owners,
        max_body_size: config.max_body_size,
        audit_enabled: config.audit_enabled,
        url_prefix: config.url_prefix.clone(),
        trust_proxy: config.trust_proxy,
        managed,
    })
}

pub async fn run(
    config: Config,
    auth_hook: Option<Arc<dyn AuthHook>>,
) -> Result<(), RegistryError> {
    let bind = config.bind;
    let data_dir = config.data_dir.display().to_string();
    let uplink_count = config.uplinks.len();
    let state = build_state(&config, auth_hook).await?;
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;

    tracing::info!(
        bind = %bind,
        data_dir,
        uplink_count,
        "rustaccio listening"
    );

    if let Some(keep_alive_timeout_secs) = config.keep_alive_timeout_secs {
        serve_with_keep_alive_timeout(listener, app, keep_alive_timeout_secs).await
    } else {
        let listener = listener.tap_io(|stream| {
            if let Err(error) = stream.set_nodelay(true) {
                tracing::warn!(%error, "failed to disable TCP Nagle buffering");
            }
        });
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|_| RegistryError::Internal)
    }
}

pub async fn run_standalone(config: Config) -> Result<(), RegistryError> {
    let default_level = startup_log_level(&config).to_string();
    let tracing_settings = observability::init_from_env(&default_level);
    tracing::debug!(
        log_filter = tracing_settings.filter,
        log_format = tracing_settings.log_format.as_str(),
        "initialized tracing subscriber"
    );
    startup_checks::run_if_enabled(&config).await;
    run(config, None).await
}

pub async fn run_from_env() -> Result<(), RegistryError> {
    let config = Config::from_env().map_err(|err| {
        RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid runtime configuration: {err}"),
        )
    })?;
    run_standalone(config).await
}

fn startup_log_level(config: &Config) -> &str {
    config.log_level.as_str()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProfile {
    Local,
    S3,
    Managed,
}

fn validate_runtime_profile(config: &Config) -> Result<bool, RegistryError> {
    let managed_mode_from_env = managed_mode_enabled_from_env();
    let inferred_profile = if managed_mode_from_env {
        RuntimeProfile::Managed
    } else if config.tarball_storage.backend == TarballStorageBackend::S3 {
        RuntimeProfile::S3
    } else {
        RuntimeProfile::Local
    };
    let profile = runtime_profile_from_env(inferred_profile)?;
    let managed_mode = managed_mode_from_env || profile == RuntimeProfile::Managed;
    let rate_limit_backend = backend_env("RUSTACCIO_RATE_LIMIT_BACKEND", "none");
    let quota_backend = backend_env("RUSTACCIO_QUOTA_BACKEND", "none");
    let state_coord_backend = backend_env("RUSTACCIO_STATE_COORDINATION_BACKEND", "none");

    validate_runtime_profile_with_inputs(
        profile,
        managed_mode,
        config.tarball_storage.backend.clone(),
        &rate_limit_backend,
        &quota_backend,
        &state_coord_backend,
    )?;
    Ok(managed_mode)
}

fn runtime_profile_from_env(
    default_profile: RuntimeProfile,
) -> Result<RuntimeProfile, RegistryError> {
    let profile = std::env::var("RUSTACCIO_RUNTIME_PROFILE")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase());
    let Some(profile) = profile else {
        return Ok(default_profile);
    };

    match profile.as_str() {
        "local" => Ok(RuntimeProfile::Local),
        "s3" => Ok(RuntimeProfile::S3),
        "managed" => Ok(RuntimeProfile::Managed),
        other => Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unsupported RUSTACCIO_RUNTIME_PROFILE: {other} (expected local|s3|managed)"),
        )),
    }
}

fn backend_env(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn is_none_or_memory(backend: &str) -> bool {
    matches!(backend, "" | "none" | "memory")
}

fn validate_runtime_profile_with_inputs(
    profile: RuntimeProfile,
    managed_mode: bool,
    tarball_backend: TarballStorageBackend,
    rate_limit_backend: &str,
    quota_backend: &str,
    state_coord_backend: &str,
) -> Result<(), RegistryError> {
    match profile {
        RuntimeProfile::Local => {
            if managed_mode {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_MANAGED_MODE=false",
                ));
            }
            if tarball_backend != TarballStorageBackend::Local {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_TARBALL_BACKEND=local",
                ));
            }
            if !is_none_or_memory(rate_limit_backend) {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_RATE_LIMIT_BACKEND=none|memory",
                ));
            }
            if !is_none_or_memory(quota_backend) {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_QUOTA_BACKEND=none|memory",
                ));
            }
            if !matches!(state_coord_backend, "" | "none") {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_STATE_COORDINATION_BACKEND=none",
                ));
            }
        }
        RuntimeProfile::S3 => {
            if managed_mode {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_MANAGED_MODE=false",
                ));
            }
            if tarball_backend != TarballStorageBackend::S3 {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_TARBALL_BACKEND=s3",
                ));
            }
            if !is_none_or_memory(rate_limit_backend) {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_RATE_LIMIT_BACKEND=none|memory",
                ));
            }
            if !is_none_or_memory(quota_backend) {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_QUOTA_BACKEND=none|memory",
                ));
            }
            if !matches!(state_coord_backend, "" | "none" | "s3") {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_STATE_COORDINATION_BACKEND=none|s3",
                ));
            }
        }
        RuntimeProfile::Managed => {
            if !managed_mode {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=managed requires RUSTACCIO_MANAGED_MODE=true",
                ));
            }
            if rate_limit_backend != "redis" {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=managed requires RUSTACCIO_RATE_LIMIT_BACKEND=redis",
                ));
            }
            if quota_backend != "postgres" {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=managed requires RUSTACCIO_QUOTA_BACKEND=postgres",
                ));
            }
            if !matches!(state_coord_backend, "redis" | "s3" | "postgres") {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RUSTACCIO_RUNTIME_PROFILE=managed requires RUSTACCIO_STATE_COORDINATION_BACKEND=redis|s3|postgres",
                ));
            }
        }
    }

    Ok(())
}

fn validate_managed_mode_guardrails_with_flag(
    managed_mode: bool,
    config: &Config,
    admin_access: &AdminAccessConfig,
) -> Result<(), RegistryError> {
    if !managed_mode {
        return Ok(());
    }

    if admin_access.allow_any_authenticated {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_MANAGED_MODE=true requires RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false",
        ));
    }

    if admin_access.users.is_empty() && admin_access.groups.is_empty() {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_MANAGED_MODE=true requires RUSTACCIO_ADMIN_USERS or RUSTACCIO_ADMIN_GROUPS",
        ));
    }

    let Some(auth_plugin) = config.auth_plugin.as_ref() else {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_MANAGED_MODE=true requires RUSTACCIO_AUTH_BACKEND=http",
        ));
    };

    let has_request_auth_endpoint = auth_plugin
        .request_auth_endpoint
        .as_deref()
        .is_some_and(|endpoint| !endpoint.trim().is_empty());
    if !has_request_auth_endpoint {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_MANAGED_MODE=true requires RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT",
        ));
    }

    Ok(())
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

async fn serve_with_keep_alive_timeout(
    listener: TcpListener,
    app: axum::Router,
    keep_alive_timeout_secs: u64,
) -> Result<(), RegistryError> {
    let timeout_secs = keep_alive_timeout_secs.max(1);
    if keep_alive_timeout_secs == 0 {
        tracing::warn!(
            "server.keepAliveTimeout=0 is invalid; clamping to 1 second for HTTP/1 header read timeout"
        );
    }
    let keep_alive_timeout = Duration::from_secs(timeout_secs);
    tracing::info!(
        keep_alive_timeout_secs = timeout_secs,
        "applying server.keepAliveTimeout as HTTP/1 header read timeout"
    );

    let mut make_service = app.into_make_service();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut connection_tasks = tokio::task::JoinSet::new();

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(());
                break;
            }
            incoming = accept_connection(&listener) => {
                match incoming {
                    Some(conn) => conn,
                    None => continue,
                }
            }
        };

        if let Err(error) = tcp_stream.set_nodelay(true) {
            tracing::debug!(%error, "failed to set TCP_NODELAY on incoming connection");
        }

        let io = TokioIo::new(tcp_stream);
        let tower_service = make_service
            .call(())
            .await
            .unwrap_or_else(|err| match err {})
            .map_request(|request: Request<Incoming>| request.map(Body::new));
        let hyper_service = TowerToHyperService::new(tower_service);
        let mut shutdown_rx = shutdown_rx.clone();

        connection_tasks.spawn(async move {
            let mut builder = HyperBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Some(keep_alive_timeout));

            let connection = builder.serve_connection_with_upgrades(io, hyper_service);
            tokio::pin!(connection);

            tokio::select! {
                result = &mut connection => {
                    if let Err(error) = result {
                        tracing::debug!(%error, %remote_addr, "failed to serve connection");
                    }
                }
                _ = shutdown_rx.changed() => {
                    connection.as_mut().graceful_shutdown();
                    if let Err(error) = connection.await {
                        tracing::debug!(%error, %remote_addr, "failed to gracefully shut down connection");
                    }
                }
            }
        });
    }

    while let Some(result) = connection_tasks.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "connection task aborted");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        let terminate = async {
            if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
                let _ = sigterm.recv().await;
            }
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn accept_connection(listener: &TcpListener) -> Option<(TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(conn) => Some(conn),
        Err(error) => {
            if is_connection_error(&error) {
                return None;
            }
            tracing::error!(%error, "accept error");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeProfile, startup_log_level, validate_managed_mode_guardrails_with_flag,
        validate_runtime_profile_with_inputs,
    };
    use crate::{
        app::AdminAccessConfig,
        config::{Config, HttpAuthPluginConfig, TarballStorageBackend, TarballStorageConfig},
    };

    fn config_with_auth(enabled: bool) -> Config {
        let auth_plugin = if enabled {
            Some(HttpAuthPluginConfig {
                base_url: "http://auth.local".to_string(),
                request_auth_endpoint: Some("/request-auth".to_string()),
                allow_access_endpoint: None,
                allow_publish_endpoint: None,
                allow_unpublish_endpoint: None,
                timeout_ms: 5000,
            })
        } else {
            None
        };
        Config {
            bind: "127.0.0.1:4873".parse().expect("bind"),
            data_dir: std::env::temp_dir(),
            listen: vec!["127.0.0.1:4873".to_string()],
            upstream_registry: None,
            uplinks: std::collections::HashMap::new(),
            acl_rules: vec![crate::acl::PackageRule::open("**")],
            web_enabled: true,
            web_title: "Rustaccio".to_string(),
            publish_check_owners: false,
            max_body_size: 50 * 1024 * 1024,
            audit_enabled: true,
            url_prefix: "/".to_string(),
            trust_proxy: false,
            keep_alive_timeout_secs: None,
            log_level: "info".to_string(),
            auth_plugin,
            tarball_storage: TarballStorageConfig {
                backend: TarballStorageBackend::Local,
                s3: None,
            },
        }
    }

    #[test]
    fn startup_log_level_uses_config_value() {
        let mut cfg = Config::defaults_for_examples();
        cfg.log_level = "debug".to_string();
        assert_eq!(startup_log_level(&cfg), "debug");
    }

    #[test]
    fn managed_mode_guardrails_allow_simple_mode_defaults() {
        let config = config_with_auth(false);
        let admin = AdminAccessConfig::default();
        assert!(validate_managed_mode_guardrails_with_flag(false, &config, &admin).is_ok());
    }

    #[test]
    fn managed_mode_guardrails_reject_any_authenticated_admin_access() {
        let config = config_with_auth(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: true,
            users: vec!["ops".to_string()],
            groups: Vec::new(),
        };
        let err = validate_managed_mode_guardrails_with_flag(true, &config, &admin)
            .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("ADMIN_ALLOW_ANY_AUTHENTICATED=false")
        );
    }

    #[test]
    fn managed_mode_guardrails_reject_missing_admin_principals() {
        let config = config_with_auth(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: Vec::new(),
            groups: Vec::new(),
        };
        let err = validate_managed_mode_guardrails_with_flag(true, &config, &admin)
            .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("ADMIN_USERS or RUSTACCIO_ADMIN_GROUPS")
        );
    }

    #[test]
    fn managed_mode_guardrails_require_auth_plugin() {
        let config = config_with_auth(false);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: vec!["ops".to_string()],
            groups: Vec::new(),
        };
        let err = validate_managed_mode_guardrails_with_flag(true, &config, &admin)
            .expect_err("must fail");
        assert!(err.to_string().contains("AUTH_BACKEND=http"));
    }

    #[test]
    fn managed_mode_guardrails_accept_external_mode_with_explicit_admins() {
        let config = config_with_auth(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: vec!["ops".to_string()],
            groups: vec!["platform-admins".to_string()],
        };
        assert!(validate_managed_mode_guardrails_with_flag(true, &config, &admin).is_ok());
    }

    #[test]
    fn managed_mode_guardrails_require_request_auth_endpoint() {
        let mut config = config_with_auth(true);
        if let Some(plugin) = config.auth_plugin.as_mut() {
            plugin.request_auth_endpoint = None;
        }
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: vec!["ops".to_string()],
            groups: Vec::new(),
        };
        let err = validate_managed_mode_guardrails_with_flag(true, &config, &admin)
            .expect_err("must fail");
        assert!(err.to_string().contains("AUTH_HTTP_REQUEST_AUTH_ENDPOINT"));
    }

    #[test]
    fn runtime_profile_local_accepts_local_simple_settings() {
        let result = validate_runtime_profile_with_inputs(
            RuntimeProfile::Local,
            false,
            TarballStorageBackend::Local,
            "none",
            "memory",
            "none",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn runtime_profile_local_rejects_s3_tarballs() {
        let err = validate_runtime_profile_with_inputs(
            RuntimeProfile::Local,
            false,
            TarballStorageBackend::S3,
            "none",
            "none",
            "none",
        )
        .expect_err("must fail");
        assert!(
            err.to_string().contains(
                "RUSTACCIO_RUNTIME_PROFILE=local requires RUSTACCIO_TARBALL_BACKEND=local"
            )
        );
    }

    #[test]
    fn runtime_profile_s3_rejects_managed_mode() {
        let err = validate_runtime_profile_with_inputs(
            RuntimeProfile::S3,
            true,
            TarballStorageBackend::S3,
            "none",
            "none",
            "none",
        )
        .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("RUSTACCIO_RUNTIME_PROFILE=s3 requires RUSTACCIO_MANAGED_MODE=false")
        );
    }

    #[test]
    fn runtime_profile_managed_requires_redis_and_postgres() {
        let err = validate_runtime_profile_with_inputs(
            RuntimeProfile::Managed,
            true,
            TarballStorageBackend::S3,
            "memory",
            "postgres",
            "redis",
        )
        .expect_err("must fail");
        assert!(err.to_string().contains(
            "RUSTACCIO_RUNTIME_PROFILE=managed requires RUSTACCIO_RATE_LIMIT_BACKEND=redis"
        ));
    }

    #[test]
    fn runtime_profile_managed_accepts_strict_backends() {
        let result = validate_runtime_profile_with_inputs(
            RuntimeProfile::Managed,
            true,
            TarballStorageBackend::S3,
            "redis",
            "postgres",
            "redis",
        );
        assert!(result.is_ok());
    }
}
