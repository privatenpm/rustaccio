// Large async test bodies push rustc's layout query depth past the default
// recursion limit on recent toolchains; raise it for this test crate.
#![recursion_limit = "256"]

//! End-to-end tests of the managed data-plane bridge against a mock
//! control plane (wiremock): authorization, the publish
//! reserve → upload → finalize bridge, metadata proxying and downloads.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use rustaccio::{
    acl::{Acl, PackageRule},
    app::{AdminAccessConfig, AppState, build_router},
    config::{Config, TarballStorageBackend, TarballStorageConfig},
    managed::{DownloadMode, ManagedConfig, ManagedState},
    policy::DefaultPolicyEngine,
    storage::Store,
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const TOKEN: &str = "npm_test_token";
const NODE_TOKEN: &str = "node-secret";

fn base_config(data_dir: PathBuf) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_enabled: false,
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
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    }
}

fn managed_config(control_plane: &MockServer, data_dir: PathBuf) -> ManagedConfig {
    ManagedConfig {
        control_plane_url: control_plane.uri(),
        token: NODE_TOKEN.to_string(),
        metadata_origin: control_plane.uri(),
        download_mode: DownloadMode::Redirect,
        identity: "test-node".to_string(),
        require_placement: false,
        capabilities: vec!["publish-bridge".to_string()],
        decision_cache_max_entries: 100,
        decision_cache_ttl_ms: 30_000,
        metadata_cache_ttl_ms: 0,
        metadata_cache_max_entries: 16,
        metadata_cache_max_bytes: 1024 * 1024,
        max_metadata_bytes: 8 * 1024 * 1024,
        upload_timeout_ms: 30_000,
        event_spool_dir: data_dir.join("managed-events"),
        event_spool_max_bytes: 8 * 1024 * 1024,
        spool_dir: data_dir.join("managed-spool"),
    }
}

fn authorize_response(allowed: bool, reason: &str) -> Value {
    json!({
        "allowed": allowed,
        "reason": reason,
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        "subject": {
            "kind": "publisher",
            "tenant_id": "org_1",
            "user_id": "user_1",
            "token_id": "ntok_1",
            "credential_version": 1
        },
        "package": {
            "id": "npkg_1",
            "name": "demo",
            "registry_id": "reg_1",
            "owner_tenant_id": "org_1",
            "visibility": "private",
            "revision": 3
        }
    })
}

async fn managed_app(control_plane: &MockServer) -> (axum::Router, TempDir) {
    let temp = TempDir::new().expect("tempdir");
    let cfg = base_config(temp.path().to_path_buf());
    let store = Arc::new(Store::open(&cfg).await.expect("store"));
    let acl = Acl::new(cfg.acl_rules.clone());
    let managed = Arc::new(
        ManagedState::new(managed_config(control_plane, temp.path().to_path_buf()))
            .await
            .expect("managed state"),
    );
    let app = build_router(AppState {
        store: store.clone(),
        acl: acl.clone(),
        policy: Arc::new(DefaultPolicyEngine::new(store, acl)),
        governance: Arc::new(rustaccio::governance::GovernanceEngine::default()),
        events: Arc::new(rustaccio::events::EventDispatcher::disabled()),
        admin_access: AdminAccessConfig::default(),
        uplinks: HashMap::new(),
        web_enabled: cfg.web_enabled,
        web_title: cfg.web_title,
        publish_check_owners: cfg.publish_check_owners,
        max_body_size: cfg.max_body_size,
        audit_enabled: cfg.audit_enabled,
        url_prefix: cfg.url_prefix,
        trust_proxy: cfg.trust_proxy,
        managed: Some(managed),
    });
    (app, temp)
}

async fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    app.clone().oneshot(req).await.expect("response")
}

fn authed(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "npm.example.test")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(body)
        .expect("request")
}

async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

fn publish_body(package: &str) -> Body {
    let tarball = format!("{package}-1.0.0.tgz");
    let doc = json!({
        "_id": package,
        "name": package,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": { "tarball": format!("http://localhost/{package}/-/{tarball}") }
            }
        },
        "_attachments": {
            tarball: {
                "content_type": "application/octet-stream",
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"fake-tarball-bytes"),
                "length": 18
            }
        }
    });
    Body::from(serde_json::to_vec(&doc).expect("doc"))
}

#[tokio::test]
async fn whoami_uses_control_plane_identity() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_response(true, "")))
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::GET, "/-/whoami", Body::empty())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["username"], "user_1");
}

#[tokio::test]
async fn publish_flows_through_reserve_upload_finalize() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_response(true, "")))
        .mount(&control_plane)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/publishes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session_id": "nps_1",
            "generation": 1,
            "package_id": "npkg_1",
            "replayed": false,
            "upload": {
                "document_id": "doc_1",
                "url": format!("{}/upload/doc_1", control_plane.uri()),
                "headers": {},
                "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339()
            }
        })))
        .mount(&control_plane)
        .await;
    Mock::given(method("PUT"))
        .and(path("/upload/doc_1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&control_plane)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/publishes/nps_1/finalize"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "success": true, "ok": "published" })),
        )
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::PUT, "/demo", publish_body("demo"))).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["ok"], "published");

    let requests = control_plane.received_requests().await.expect("requests");
    let finalize = requests
        .iter()
        .find(|req| req.url.path() == "/api/registry/v1/publishes/nps_1/finalize")
        .expect("finalize call");
    let finalize: Value = serde_json::from_slice(&finalize.body).expect("finalize json");
    assert!(
        finalize["integrity"]
            .as_str()
            .unwrap()
            .starts_with("sha512-")
    );
    assert_eq!(finalize["tarball_bytes"], 18);
    assert_eq!(finalize["shasum"].as_str().unwrap().len(), 40);
    // The verified manifest travels to finalize: the control plane stores it
    // on the committed version and hash-binds it to the reservation.
    assert_eq!(finalize["manifest"]["name"], "demo");
    assert_eq!(finalize["manifest"]["version"], "1.0.0");
}

#[tokio::test]
async fn publish_maps_version_exists_to_npm_style_403() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_response(true, "")))
        .mount(&control_plane)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/publishes"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": { "code": "version_exists" }
        })))
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::PUT, "/demo", publish_body("demo"))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("cannot publish over the previously published versions")
    );
}

#[tokio::test]
async fn publish_denied_by_control_plane_never_reserves() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(authorize_response(false, "permission_denied")),
        )
        .mount(&control_plane)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/publishes"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::PUT, "/demo", publish_body("demo"))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    control_plane.verify().await;
}

#[tokio::test]
async fn packument_get_is_proxied_to_the_control_plane() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_response(true, "")))
        .mount(&control_plane)
        .await;
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("x-package-revision", "3")
                .set_body_json(json!({ "name": "demo", "versions": { "1.0.0": {} } })),
        )
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::GET, "/demo", Body::empty())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["name"], "demo");
}

#[tokio::test]
async fn tarball_get_redirects_to_the_resolved_url() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_response(true, "")))
        .mount(&control_plane)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/downloads/resolve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            "package": {
                "id": "npkg_1", "name": "demo", "registry_id": "reg_1",
                "owner_tenant_id": "org_1", "visibility": "private", "revision": 3
            },
            "version": { "semver": "1.0.0", "integrity": "sha512-x", "shasum": "y", "tarball_bytes": 18 },
            "download_url": "https://storage.example.test/demo-1.0.0.tgz"
        })))
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(
        &app,
        authed(Method::GET, "/demo/-/demo-1.0.0.tgz", Body::empty()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "https://storage.example.test/demo-1.0.0.tgz"
    );
}

#[tokio::test]
async fn control_plane_outage_fails_closed() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::GET, "/demo", Body::empty())).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = body_json(response).await;
    assert_eq!(body["code"], "CONTROL_PLANE_UNAVAILABLE");
}

#[tokio::test]
async fn node_credential_flushes_managed_caches() {
    let control_plane = MockServer::start().await;
    let (app, _temp) = managed_app(&control_plane).await;

    let denied = send(
        &app,
        authed(
            Method::POST,
            "/-/admin/policy-cache/invalidate",
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let allowed = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/-/admin/policy-cache/invalidate")
            .header(header::AUTHORIZATION, format!("Bearer {NODE_TOKEN}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
}

fn authorize_with_route(route: Option<&str>) -> Value {
    let mut body = authorize_response(false, "package_not_found");
    if let Some(route) = route {
        body["route"] = json!(route);
    }
    body
}

#[tokio::test]
async fn upstream_route_forwards_original_host_and_authorization() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(authorize_with_route(Some("upstream"))),
        )
        .mount(&control_plane)
        .await;
    Mock::given(method("GET"))
        .and(path("/lodash"))
        .and(header("host", "npm.example.test"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({ "name": "lodash" })),
        )
        .expect(1)
        .mount(&control_plane)
        .await;
    Mock::given(method("GET"))
        .and(path("/lodash/-/lodash-4.17.21.tgz"))
        .and(header("host", "npm.example.test"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(b"tarball".to_vec()),
        )
        .expect(1)
        .mount(&control_plane)
        .await;
    // Hosted resolve must not run: the node forwards instead of serving storage.
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/downloads/resolve"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let packument = send(&app, authed(Method::GET, "/lodash", Body::empty())).await;
    assert_eq!(packument.status(), StatusCode::OK);
    assert_eq!(body_json(packument).await["name"], "lodash");

    let tarball = send(
        &app,
        authed(Method::GET, "/lodash/-/lodash-4.17.21.tgz", Body::empty()),
    )
    .await;
    assert_eq!(tarball.status(), StatusCode::OK);
    control_plane.verify().await;
}

#[tokio::test]
async fn absent_route_stays_not_found() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorize_with_route(None)))
        .mount(&control_plane)
        .await;
    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "name": "lodash" })))
        .expect(0)
        .mount(&control_plane)
        .await;

    let (app, _temp) = managed_app(&control_plane).await;
    let response = send(&app, authed(Method::GET, "/lodash", Body::empty())).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    control_plane.verify().await;
}
