#![cfg(feature = "s3")]

use aws_sdk_s3::{
    Client as S3Client,
    config::{Builder as S3ConfigBuilder, Credentials, Region},
    error::ProvideErrorMetadata,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use rustaccio::{
    config::{Config, S3TarballStorageConfig, TarballStorageBackend, TarballStorageConfig},
    runtime,
};
use serde_json::json;
use std::{collections::HashMap, future::Future, sync::OnceLock, time::Duration};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn base_config(data_dir: std::path::PathBuf) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![rustaccio::acl::PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        publish_check_owners: false,
        max_body_size: 50 * 1024 * 1024,
        audit_enabled: true,
        url_prefix: "/".to_string(),
        trust_proxy: false,
        keep_alive_timeout_secs: None,
        log_level: "info".to_string(),
        auth_plugin: None,
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::S3,
            s3: Some(S3TarballStorageConfig {
                bucket: "rustaccio-it".to_string(),
                region: "us-east-1".to_string(),
                endpoint: Some("http://127.0.0.1:9002".to_string()),
                access_key_id: Some("minioadmin".to_string()),
                secret_access_key: Some("minioadmin".to_string()),
                prefix: "registry/".to_string(),
                force_path_style: true,
            }),
        },
    }
}

fn env_lock() -> &'static tokio::sync::Mutex<()> {
    ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn with_env<T, F>(vars: &[(&str, Option<&str>)], run: F) -> T
where
    F: Future<Output = T>,
{
    let _guard = env_lock().lock().await;
    let previous = vars
        .iter()
        .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
        .collect::<Vec<_>>();

    for (key, value) in vars {
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    let result = run.await;

    for (key, value) in previous {
        unsafe {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
    result
}

fn it_endpoint() -> String {
    std::env::var("RUSTACCIO_S3_IT_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9002".to_string())
}

fn it_region() -> String {
    std::env::var("RUSTACCIO_S3_IT_REGION").unwrap_or_else(|_| "us-east-1".to_string())
}

fn it_bucket() -> String {
    std::env::var("RUSTACCIO_S3_IT_BUCKET").unwrap_or_else(|_| "rustaccio-it".to_string())
}

fn it_access_key() -> String {
    std::env::var("RUSTACCIO_S3_IT_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string())
}

fn it_secret_key() -> String {
    std::env::var("RUSTACCIO_S3_IT_SECRET_KEY").unwrap_or_else(|_| "minioadmin".to_string())
}

async fn s3_client(endpoint: &str, region: &str, access_key: &str, secret_key: &str) -> S3Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(Credentials::new(
            access_key.to_string(),
            secret_key.to_string(),
            None,
            None,
            "rustaccio-it",
        ));

    // aws-config is built without `default-https-client`; provide an explicit
    // connector for both HTTP and HTTPS endpoints.
    loader = loader.http_client(
        if endpoint
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("http://")
        {
            aws_smithy_http_client::Builder::new().build_http()
        } else {
            aws_smithy_http_client::Builder::new()
                .tls_provider(aws_smithy_http_client::tls::Provider::rustls(
                    aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
                ))
                .build_https()
        },
    );

    let shared = loader.load().await;

    let conf = S3ConfigBuilder::from(&shared)
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    S3Client::from_conf(conf)
}

async fn wait_for_s3(client: &S3Client) {
    for _ in 0..80 {
        if client.list_buckets().send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("S3 endpoint was not reachable in time");
}

async fn ensure_bucket(client: &S3Client, bucket: &str) {
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => {}
        Err(err) => {
            let code = err
                .as_service_error()
                .and_then(|service_err| service_err.code())
                .unwrap_or_default();
            if code != "BucketAlreadyOwnedByYou" && code != "BucketAlreadyExists" {
                panic!("failed to create bucket `{bucket}`: {err}");
            }
        }
    }
}

async fn app_with_env(cfg: &Config) -> axum::Router {
    let state = runtime::build_state(cfg, None).await.expect("state");
    rustaccio::app::build_router(state)
}

fn publish_manifest(name: &str) -> serde_json::Value {
    json!({
        "_id": name,
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": { "tarball": format!("http://localhost:4873/{name}/-/{name}-1.0.0.tgz") }
            }
        },
        "_attachments": {
            format!("{name}-1.0.0.tgz"): {
                "content_type": "application/octet-stream",
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"abc"),
                "length": 3
            }
        }
    })
}

/// Perform an authenticated package publish, which exercises a coordinated
/// state-write. The bearer token is treated as the username by the mock auth
/// service.
async fn publish_package(app: &axum::Router, token: &str, package: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/{package}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&publish_manifest(package)).expect("payload"),
        ))
        .expect("request");
    app.clone().oneshot(req).await.expect("response").status()
}

#[tokio::test]
#[ignore = "requires managed profile integration harness; local profile forbids s3 state coordination"]
async fn state_coordination_s3_fail_open_allows_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            ("RUSTACCIO_STATE_COORDINATION_S3_BUCKET", Some("unused")),
            ("RUSTACCIO_STATE_COORDINATION_S3_REGION", Some("us-east-1")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some("http://127.0.0.1:1"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("true")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-open-{}", Uuid::new_v4().as_simple());
            let pkg = format!("state-open-pkg-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::CREATED
            );
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires managed profile integration harness; local profile forbids s3 state coordination"]
async fn state_coordination_s3_fail_closed_rejects_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            ("RUSTACCIO_STATE_COORDINATION_S3_BUCKET", Some("unused")),
            ("RUSTACCIO_STATE_COORDINATION_S3_REGION", Some("us-east-1")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some("http://127.0.0.1:1"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-closed-{}", Uuid::new_v4().as_simple());
            let pkg = format!("state-closed-pkg-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::BAD_GATEWAY
            );
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires local S3 emulator (`just minio-up`)"]
async fn state_coordination_s3_lock_timeout_when_key_is_held() {
    let endpoint = it_endpoint();
    let region = it_region();
    let bucket = it_bucket();
    let access_key = it_access_key();
    let secret_key = it_secret_key();
    let client = s3_client(&endpoint, &region, &access_key, &secret_key).await;
    wait_for_s3(&client).await;
    ensure_bucket(&client, &bucket).await;

    let prefix = format!("rustaccio-it-locks/{}/", Uuid::new_v4().as_simple());
    let pkg = format!("state-lock-pkg-{}", Uuid::new_v4().as_simple());
    // Package writes coordinate on the per-package scope `package:<name>`; seed a
    // still-held lock at exactly that scope so the publish below cannot acquire it.
    let held_key = format!("{prefix}package:{pkg}.lock");
    let lease_until_ms = jiff::Timestamp::now().as_millisecond() + 10_000;
    let payload = json!({
        "token": "held-token",
        "lease_until_ms": lease_until_ms,
        "operation": "held",
    });
    client
        .put_object()
        .bucket(&bucket)
        .key(&held_key)
        .body(aws_sdk_s3::primitives::ByteStream::from(
            serde_json::to_vec(&payload).expect("payload"),
        ))
        .send()
        .await
        .expect("set held lock");

    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_BUCKET",
                Some(bucket.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_REGION",
                Some(region.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some(endpoint.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID",
                Some(access_key.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY",
                Some(secret_key.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_PREFIX",
                Some(prefix.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE",
                Some("true"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("400"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", Some("50")),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-lock-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
        },
    )
    .await;
}
