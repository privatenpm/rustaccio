//! Managed-mode request handling.
//!
//! Every private npm operation is authorized by the control plane before any
//! byte moves; failures fail closed with a stable 502 body. Packuments and
//! metadata writes are reverse-proxied to the control-plane registry surface;
//! publishes go through the reserve → upload → finalize bridge; downloads are
//! resolved to presigned URLs and served as redirects (default) or streamed
//! through (`RUSTACCIO_MANAGED_DOWNLOAD_MODE=proxy`). An authorize answer of
//! `route: "upstream"` reverse-proxies the original request to the
//! control-plane npm surface instead; uplinks stay disabled.

use super::cache::DecisionScope;
use super::client::{
    AbortPublishRequest, AuthorizeDecision, AuthorizeRequest, ControlPlaneError,
    DownloadResolveRequest, FinalizePublishRequest, OP_DIST_TAG_WRITE, OP_IDENTITY_READ,
    OP_METADATA_READ, OP_PACKAGE_PUBLISH, OP_PACKAGE_UNPUBLISH, OP_TARBALL_READ,
    ReservePublishRequest,
};
use super::extract::{
    ExtractError, Extracted, PublishExtractor, PublishMetadata, ensure_no_attachment_data,
    publish_fingerprint,
};
use super::{DownloadMode, ManagedState};
use crate::api::{parse_canonical_dist_tags_path, parse_package_path};
use crate::app::AppState;
use crate::constants::{HEADER_JSON, HEADER_OCTET};
use crate::error::{RegistryError, code};
use crate::policy::RequestContext;
use crate::storage::parse_authorization;
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header},
};
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;
use tracing::warn;

/// Spool flush granularity while streaming a publish body to disk.
const SPOOL_FLUSH_BYTES: usize = 1024 * 1024;

pub struct ManagedRequest {
    pub state: AppState,
    pub managed: Arc<ManagedState>,
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub request_context: RequestContext,
    pub req: axum::extract::Request,
}

/// Route one request in managed mode. Local storage, ACL uplinks and the
/// policy engine are never consulted for private operations.
pub async fn dispatch(input: ManagedRequest) -> Result<Response<Body>, RegistryError> {
    let ManagedRequest {
        state,
        managed,
        method,
        path,
        query,
        headers,
        request_context,
        req,
    } = input;
    let token = bearer_token(&headers);
    let host = host_of(&headers, state.trust_proxy);
    let request_id = request_context
        .request_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if method == Method::POST && path == "/-/admin/policy-cache/invalidate" {
        require_node_credential(&managed, &token)?;
        managed.invalidate_caches().await;
        return Ok(json_response(
            StatusCode::OK,
            json!({ "ok": "policy cache invalidated" }),
        ));
    }

    if method == Method::POST && path == "/-/admin/package-cache/invalidate" {
        require_node_credential(&managed, &token)?;
        let bytes = to_bytes(req.into_body(), state.max_body_size)
            .await
            .map_err(|_| {
                RegistryError::http(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large")
            })?;
        let payload: Value = serde_json::from_slice(&bytes)
            .map_err(|_| RegistryError::storage_bad_request("invalid JSON request body"))?;
        let package = payload
            .get("package")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                RegistryError::storage_bad_request("missing `package` in request body")
            })?;
        let removed = managed.metadata.invalidate_package(package).await;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "ok": "package cache invalidated",
                "package": package,
                "removed": removed,
            }),
        ));
    }

    if method == Method::GET && path == "/-/whoami" {
        let decision = authorize(
            &managed,
            &request_id,
            &token,
            &host,
            OP_IDENTITY_READ,
            "",
            "",
        )
        .await?;
        if !decision.allowed {
            return Err(deny(decision.reason.as_deref()));
        }
        let username = decision
            .principal_name()
            .ok_or_else(|| unauthorized("control plane did not return an identity"))?;
        return Ok(json_response(
            StatusCode::OK,
            json!({ "username": username }),
        ));
    }

    if let Some((package_name, tag)) = parse_canonical_dist_tags_path(&path) {
        if method == Method::GET && tag.is_none() {
            let decision = authorize(
                &managed,
                &request_id,
                &token,
                &host,
                OP_METADATA_READ,
                &package_name,
                "",
            )
            .await?;
            if decision.is_upstream() {
                return forward_npm_surface(&managed, &method, &path, query.as_deref(), &headers)
                    .await;
            }
            if !decision.allowed {
                return Err(deny(decision.reason.as_deref()));
            }
            return proxy_metadata(
                &managed,
                &method,
                &path,
                query.as_deref(),
                &headers,
                &package_name,
                &decision,
            )
            .await;
        }
        if method == Method::PUT || (method == Method::DELETE && tag.is_some()) {
            let decision = authorize(
                &managed,
                &request_id,
                &token,
                &host,
                OP_DIST_TAG_WRITE,
                &package_name,
                "",
            )
            .await?;
            if !decision.allowed {
                return Err(deny(decision.reason.as_deref()));
            }
            return proxy_write(
                &managed,
                &method,
                &path,
                query.as_deref(),
                &headers,
                req.into_body(),
            )
            .await;
        }
    }

    if let Some((package_name, tail)) = parse_package_path(&path) {
        return handle_package_routes(PackageInput {
            state,
            managed,
            method,
            path,
            query,
            headers,
            request_id,
            token,
            host,
            package_name,
            tail,
            req,
        })
        .await;
    }

    // Unmatched routes stay 404. Managed mode does not consult uplinks.
    // Package names the control plane classifies as upstream are forwarded
    // from the authorize answer; an absent `route` keeps this 404.
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

struct PackageInput {
    state: AppState,
    managed: Arc<ManagedState>,
    method: Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
    request_id: String,
    token: String,
    host: String,
    package_name: String,
    tail: Vec<String>,
    req: axum::extract::Request,
}

async fn handle_package_routes(input: PackageInput) -> Result<Response<Body>, RegistryError> {
    let PackageInput {
        state,
        managed,
        method,
        path,
        query,
        headers,
        request_id,
        token,
        host,
        package_name,
        tail,
        req,
    } = input;

    if method == Method::GET || method == Method::HEAD {
        let operation = match tail.as_slice() {
            [] | [_] => Some(OP_METADATA_READ),
            [dash, _] if dash == "-" => Some(OP_TARBALL_READ),
            _ => None,
        };
        match (operation, tail.as_slice()) {
            (Some(OP_METADATA_READ), _) => {
                let decision = authorize(
                    &managed,
                    &request_id,
                    &token,
                    &host,
                    OP_METADATA_READ,
                    &package_name,
                    "",
                )
                .await?;
                if decision.is_upstream() {
                    return forward_npm_surface(
                        &managed,
                        &method,
                        &path,
                        query.as_deref(),
                        &headers,
                    )
                    .await;
                }
                if !decision.allowed {
                    return Err(deny(decision.reason.as_deref()));
                }
                return proxy_metadata(
                    &managed,
                    &method,
                    &path,
                    query.as_deref(),
                    &headers,
                    &package_name,
                    &decision,
                )
                .await;
            }
            (Some(OP_TARBALL_READ), [_, filename]) => {
                return handle_download(DownloadInput {
                    managed,
                    method,
                    headers,
                    request_id,
                    token,
                    host,
                    path,
                    query,
                    package_name,
                    filename: filename.clone(),
                })
                .await;
            }
            _ => {}
        }
    }

    if method == Method::PUT {
        if tail.is_empty() {
            return handle_publish(PublishInput {
                state,
                managed,
                headers,
                request_id,
                token,
                host,
                path,
                package_name,
                req,
            })
            .await;
        }
        let operation = match tail.as_slice() {
            [dash, _] if dash == "-rev" => Some(OP_PACKAGE_PUBLISH),
            [_tag] => Some(OP_DIST_TAG_WRITE),
            _ => None,
        };
        if let Some(operation) = operation {
            let decision = authorize(
                &managed,
                &request_id,
                &token,
                &host,
                operation,
                &package_name,
                "",
            )
            .await?;
            if !decision.allowed {
                return Err(deny(decision.reason.as_deref()));
            }
            return proxy_write(
                &managed,
                &method,
                &path,
                query.as_deref(),
                &headers,
                req.into_body(),
            )
            .await;
        }
    }

    if method == Method::DELETE {
        let is_unpublish = matches!(
            tail.as_slice(),
            [dash, _] if dash == "-rev"
        ) || matches!(
            tail.as_slice(),
            [dash, _, rev, _] if dash == "-" && rev == "-rev"
        );
        if is_unpublish {
            let decision = authorize(
                &managed,
                &request_id,
                &token,
                &host,
                OP_PACKAGE_UNPUBLISH,
                &package_name,
                "",
            )
            .await?;
            if !decision.allowed {
                return Err(deny(decision.reason.as_deref()));
            }
            return proxy_write(
                &managed,
                &method,
                &path,
                query.as_deref(),
                &headers,
                req.into_body(),
            )
            .await;
        }
    }

    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

/// Authorize one operation against the control plane, using the bounded
/// decision cache. Control-plane failures fail closed (502).
async fn authorize(
    managed: &ManagedState,
    request_id: &str,
    token: &str,
    host: &str,
    operation: &str,
    package: &str,
    version: &str,
) -> Result<AuthorizeDecision, RegistryError> {
    let scope = DecisionScope {
        token: token.to_string(),
        operation: operation.to_string(),
        host: host.to_string(),
        registry_id: String::new(),
        package: package.to_string(),
        version: version.to_string(),
    };
    if let Some(decision) = managed.decisions.get(&scope).await {
        return Ok(decision);
    }
    let decision = managed
        .client
        .authorize(&AuthorizeRequest {
            request_id,
            token,
            operation,
            host,
            registry_id: "",
            package,
            version,
        })
        .await
        .map_err(|err| err.into_unavailable("authorize"))?;
    managed.decisions.put(&scope, &decision).await;
    Ok(decision)
}

/// Map a control-plane denial reason to the npm-facing error.
fn deny(reason: Option<&str>) -> RegistryError {
    match reason {
        Some("package_not_found") => {
            RegistryError::http(StatusCode::NOT_FOUND, "no such package available")
        }
        Some(message) if !message.is_empty() && message != "token_denied" => {
            RegistryError::auth_forbidden(message)
        }
        _ => unauthorized("unauthorized access"),
    }
}

fn unauthorized(message: &str) -> RegistryError {
    RegistryError::http(StatusCode::UNAUTHORIZED, message)
}

fn control_plane_unavailable(operation: &str) -> RegistryError {
    RegistryError::http_code(
        StatusCode::BAD_GATEWAY,
        code::CONTROL_PLANE_UNAVAILABLE,
        format!("control plane {operation} unavailable"),
    )
}

fn require_node_credential(managed: &ManagedState, token: &str) -> Result<(), RegistryError> {
    if managed.is_node_credential(token) {
        return Ok(());
    }
    Err(RegistryError::http(
        StatusCode::FORBIDDEN,
        "node credential required",
    ))
}

fn bearer_token(headers: &HeaderMap) -> String {
    parse_authorization(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
    )
    .unwrap_or_default()
}

fn host_of(headers: &HeaderMap, trust_proxy: bool) -> String {
    if trust_proxy
        && let Some(host) = headers
            .get("x-forwarded-host")
            .and_then(|value| value.to_str().ok())
    {
        return host.to_string();
    }
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, HEADER_JSON)
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("{}")))
}

// ---------------------------------------------------------------------------
// Metadata reads (packument proxy)
// ---------------------------------------------------------------------------

async fn proxy_metadata(
    managed: &ManagedState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    package: &str,
    decision: &AuthorizeDecision,
) -> Result<Response<Body>, RegistryError> {
    let abbreviated = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("application/vnd.npm.install-v1+json"));
    let origin = &managed.config.metadata_origin;

    if method == Method::GET
        && managed.metadata.enabled()
        && let Some(entry) = managed.metadata.get(origin, path, abbreviated).await
    {
        if let (Some(etag), Some(if_none_match)) = (
            entry.etag.as_deref(),
            headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok()),
        ) && if_none_match
            .split(',')
            .any(|candidate| candidate.trim() == "*" || candidate.trim() == etag)
        {
            observe_packument_hit(managed, decision, package, 0, true);
            return Ok(Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty())));
        }
        let hit_bytes = entry.body.len() as u64;
        observe_packument_hit(managed, decision, package, hit_bytes, false);
        let mut builder = Response::builder().status(StatusCode::OK);
        if let Some(content_type) = entry.content_type.as_deref() {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        if let Some(etag) = entry.etag.as_deref() {
            builder = builder.header(header::ETAG, etag);
        }
        return Ok(builder
            .body(Body::from(entry.body))
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }

    let url = with_query(origin, path, query);
    let mut request = managed.client.http().request(method.clone(), url);
    request = forward_headers(request, headers);
    let response = request.send().await.map_err(|err| {
        warn!(error = ?err, "metadata proxy request failed");
        control_plane_unavailable("metadata proxy")
    })?;

    let status = response.status();
    let content_type = header_value(&response, header::CONTENT_TYPE);
    let etag = header_value(&response, header::ETAG);
    let cache_control = header_value(&response, header::CACHE_CONTROL);
    let revision = header_value(&response, "x-package-revision");

    let cacheable = method == Method::GET
        && status == StatusCode::OK
        && managed.metadata.enabled()
        && revision.is_some();
    if cacheable {
        let mut buffered = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| control_plane_unavailable("metadata proxy"))?;
            if buffered.len() + chunk.len() > managed.metadata.max_bytes {
                return Err(control_plane_unavailable("metadata proxy"));
            }
            buffered.extend_from_slice(&chunk);
        }
        let entry = super::cache::CachedPackument {
            body: Bytes::from(buffered),
            content_type: content_type.clone(),
            etag: etag.clone(),
            revision: revision.clone().unwrap_or_default(),
            expires_at_ms: managed.metadata.expires_at_ms_from_now(),
        };
        let body = entry.body.clone();
        managed.metadata.put(origin, path, abbreviated, entry).await;
        let mut builder = Response::builder().status(status);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        if let Some(etag) = etag {
            builder = builder.header(header::ETAG, etag);
        }
        return Ok(builder
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }

    Ok(stream_response(
        response,
        status,
        content_type,
        etag,
        cache_control,
    ))
}

fn stream_response(
    response: reqwest::Response,
    status: StatusCode,
    content_type: Option<String>,
    etag: Option<String>,
    cache_control: Option<String>,
) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    if let Some(cache_control) = cache_control {
        builder = builder.header(header::CACHE_CONTROL, cache_control);
    }
    builder
        .body(Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Proxy a metadata write (dist-tag changes, `-rev` updates, unpublish,
/// metadata-only publishes) to the control-plane registry surface. Bodies are
/// bounded by the router's body limit, so they are buffered here.
async fn proxy_write(
    managed: &ManagedState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response<Body>, RegistryError> {
    let url = with_query(&managed.config.metadata_origin, path, query);
    let mut request = managed.client.http().request(method.clone(), url);
    request = forward_headers(request, headers);
    if let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if *method != Method::GET && *method != Method::HEAD {
        let bytes = to_bytes(body, managed.config.max_metadata_bytes)
            .await
            .map_err(|_| {
                RegistryError::http(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large")
            })?;
        request = request.body(bytes);
    }
    let response = request.send().await.map_err(|err| {
        warn!(error = ?err, "metadata write proxy request failed");
        control_plane_unavailable("metadata write proxy")
    })?;
    let status = response.status();
    let content_type = header_value(&response, header::CONTENT_TYPE);
    let etag = header_value(&response, header::ETAG);
    let cache_control = header_value(&response, header::CACHE_CONTROL);
    Ok(stream_response(
        response,
        status,
        content_type,
        etag,
        cache_control,
    ))
}

fn observe_packument_hit(
    managed: &ManagedState,
    decision: &AuthorizeDecision,
    package: &str,
    bytes: u64,
    not_modified: bool,
) {
    managed
        .events
        .observe_metadata(super::events::MetadataObservation {
            tenant_id: decision.tenant_id().unwrap_or_default().to_string(),
            registry_id: decision.registry_id().unwrap_or_default().to_string(),
            credential_id: decision.credential_id().unwrap_or_default().to_string(),
            package: package.to_string(),
            bytes,
            not_modified,
            at: chrono::Utc::now(),
        });
}

/// Reverse-proxy the original request to the control-plane npm surface.
///
/// Authorize answers `route: "upstream"` here instead of 404. The node never
/// talks to public registries; uplinks stay disabled. Host and Authorization
/// are the caller's, so the surface stays host-dispatched and authenticates
/// the original credential. An absent `route` does not reach this function.
async fn forward_npm_surface(
    managed: &ManagedState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response<Body>, RegistryError> {
    let url = with_query(&managed.config.metadata_origin, path, query);
    let request = forward_headers(managed.client.http().request(method.clone(), &url), headers);
    let response = request.send().await.map_err(|err| {
        warn!(error = ?err, "upstream forward request failed");
        control_plane_unavailable("upstream forward")
    })?;
    Ok(proxied_response(response))
}

fn proxied_response(response: reqwest::Response) -> Response<Body> {
    let status = response.status();
    let mut builder = Response::builder().status(status);
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::CONTENT_ENCODING,
        header::ETAG,
        header::CACHE_CONTROL,
        header::LOCATION,
        header::LAST_MODIFIED,
        header::ACCEPT_RANGES,
    ] {
        if let Some(value) = response.headers().get(&name) {
            builder = builder.header(name, value.clone());
        }
    }
    if let Some(value) = response.headers().get("x-package-revision") {
        builder = builder.header("x-package-revision", value.clone());
    }
    builder
        .body(Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn with_query(origin: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{origin}{path}?{query}"),
        _ => format!("{origin}{path}"),
    }
}

/// Forward end-user routing headers (never the node credential): the
/// control-plane registry surface is host-dispatched and authenticates the
/// npm token itself.
fn forward_headers(
    request: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    let mut request = request;
    for name in [
        header::AUTHORIZATION,
        header::ACCEPT,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::HOST,
        header::RANGE,
        header::USER_AGENT,
    ] {
        if let Some(value) = headers.get(&name) {
            request = request.header(name, value.clone());
        }
    }
    for name in ["x-request-id", "npm-command", "npm-session"] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value.clone());
        }
    }
    request
}

fn header_value(response: &reqwest::Response, name: impl header::AsHeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

struct DownloadInput {
    managed: Arc<ManagedState>,
    method: Method,
    headers: HeaderMap,
    request_id: String,
    token: String,
    host: String,
    path: String,
    query: Option<String>,
    package_name: String,
    filename: String,
}

async fn handle_download(input: DownloadInput) -> Result<Response<Body>, RegistryError> {
    let DownloadInput {
        managed,
        method,
        headers,
        request_id,
        token,
        host,
        path,
        query,
        package_name,
        filename,
    } = input;

    let Some(version) = infer_version_from_filename(&filename, &package_name) else {
        return Err(RegistryError::http(
            StatusCode::NOT_FOUND,
            "no such file available",
        ));
    };

    let decision = authorize(
        &managed,
        &request_id,
        &token,
        &host,
        OP_TARBALL_READ,
        &package_name,
        &version,
    )
    .await?;
    if decision.is_upstream() {
        return forward_npm_surface(&managed, &method, &path, query.as_deref(), &headers).await;
    }
    if !decision.allowed {
        return Err(deny(decision.reason.as_deref()));
    }

    let resolve = match managed
        .downloads
        .get(&token, &host, &package_name, &version)
        .await
    {
        Some(resolve) => resolve,
        None => {
            let resolve = managed
                .client
                .resolve_download(&DownloadResolveRequest {
                    request_id: &request_id,
                    token: &token,
                    host: &host,
                    registry_id: decision
                        .package
                        .as_ref()
                        .map(|package| package.registry_id.as_str())
                        .unwrap_or_default(),
                    package: &package_name,
                    version: &version,
                })
                .await
                .map_err(|err| err.into_unavailable("downloads/resolve"))?;
            managed
                .downloads
                .put(&token, &host, &package_name, &version, &resolve)
                .await;
            resolve
        }
    };

    if !resolve.allowed {
        return Err(RegistryError::auth_forbidden("download not allowed"));
    }
    let Some(download_url) = resolve
        .download_url
        .as_deref()
        .filter(|url| !url.is_empty())
    else {
        return Err(control_plane_unavailable(
            "downloads/resolve (no download URL issued)",
        ));
    };
    let tarball_bytes = resolve
        .version
        .as_ref()
        .map(|version| version.tarball_bytes)
        .unwrap_or(0);
    let tenant_id = resolve
        .package
        .as_ref()
        .map(|package| package.owner_tenant_id.clone())
        .or_else(|| decision.tenant_id().map(ToOwned::to_owned));

    let registry_id = resolve
        .package
        .as_ref()
        .map(|package| package.registry_id.clone())
        .filter(|id| !id.is_empty())
        .or_else(|| decision.registry_id().map(ToOwned::to_owned))
        .unwrap_or_default();
    let report = TransferReport {
        events: managed.events.clone(),
        kind: super::events::EVENT_DOWNLOAD,
        tenant_id: tenant_id.clone(),
        package: package_name.clone(),
        version: resolve
            .version
            .as_ref()
            .map(|version| version.semver.clone()),
        credential_id: resolve.credential_id.clone(),
        registry_id,
        file: filename.clone(),
        declared_bytes: tarball_bytes,
        host: host.clone(),
        request_id: request_id.clone(),
        headers: headers.clone(),
    };

    if managed.config.download_mode == DownloadMode::Redirect {
        report
            .emit(tarball_bytes, super::events::STATUS_REDIRECTED, None)
            .await;
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, download_url)
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }

    // Proxy mode: stream the presigned URL through this node. Range requests
    // are forwarded so 206/416 pass through; everything else is a full GET.
    let mut request = managed.client.http().get(download_url);
    if method == Method::GET
        && let Some(range) = headers.get(header::RANGE)
    {
        request = request.header(header::RANGE, range.clone());
    }
    let response = request.send().await.map_err(|err| {
        warn!(error = ?err, "proxied download request failed");
        control_plane_unavailable("proxied download")
    })?;
    let status = response.status();

    if method == Method::HEAD {
        // Presigned URLs are issued for GET; fetch headers and drop the body.
        let content_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| tarball_bytes.to_string());
        drop(response);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, HEADER_OCTET)
            .header(header::CONTENT_LENGTH, content_length)
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }

    let content_type = header_value(&response, header::CONTENT_TYPE);
    let content_range = header_value(&response, header::CONTENT_RANGE);
    let content_length = header_value(&response, header::CONTENT_LENGTH);

    let transfer_status = if status == StatusCode::PARTIAL_CONTENT {
        super::events::STATUS_PARTIAL
    } else if status.is_success() {
        super::events::STATUS_COMPLETE
    } else {
        super::events::STATUS_ABORTED
    };
    let range = content_range
        .as_deref()
        .and_then(super::events::parse_content_range);

    let transferred = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&transferred);
    let counted = response.bytes_stream().map(move |chunk| {
        if let Ok(bytes) = &chunk {
            counter.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        chunk
    });
    let events_done = futures::stream::once(async move {
        let bytes = transferred.load(Ordering::Relaxed);
        report.emit(bytes, transfer_status, range).await;
        Ok::<Bytes, reqwest::Error>(Bytes::new())
    });
    let body = Body::from_stream(counted.chain(events_done));

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(content_range) = content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    if let Some(content_length) = content_length {
        builder = builder.header(header::CONTENT_LENGTH, content_length);
    }
    Ok(builder
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

struct TransferReport {
    events: super::events::EventReporter,
    kind: &'static str,
    tenant_id: Option<String>,
    package: String,
    version: Option<String>,
    credential_id: Option<String>,
    registry_id: String,
    file: String,
    declared_bytes: u64,
    host: String,
    request_id: String,
    headers: HeaderMap,
}

impl TransferReport {
    async fn emit(
        self,
        bytes: u64,
        status: &'static str,
        range: Option<super::client::EventRange>,
    ) {
        let mut event = super::events::EventReporter::event(
            self.kind,
            self.tenant_id.as_deref(),
            &self.package,
            self.version.as_deref(),
            bytes,
            self.credential_id.as_deref(),
        );
        super::events::apply_transfer(
            &mut event,
            super::events::TransferFacts {
                registry_id: &self.registry_id,
                file: &self.file,
                declared_bytes: self.declared_bytes,
                status,
                range,
                host: &self.host,
                request_id: &self.request_id,
                headers: &self.headers,
            },
        );
        self.events.report(event).await;
    }
}

/// Infer the exact version from a tarball filename (`name-1.2.3.tgz`).
/// Splits at the first `-` followed by a digit so prerelease suffixes
/// (`pkg-1.0.0-beta.1.tgz`) stay intact; package names themselves never start
/// with a digit, so the first digit-led segment begins the version.
/// Infer the exact version from a tarball filename by stripping the package
/// base name: `<base>-<semver>.tgz`. The base comes from the request path, so
/// names containing dashes or digit-starting segments parse correctly.
fn infer_version_from_filename(filename: &str, package_name: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".tgz")
        .or_else(|| filename.strip_suffix(".tar.gz"))?;
    let base = package_name.rsplit('/').next().unwrap_or(package_name);
    let version = stem.strip_prefix(base)?.strip_prefix('-')?;
    // The version is npm-semver-shaped: digit-starting with a patch segment.
    // (The control plane validates strictly; this keeps foreign files 404.)
    let mut parts = version.split('.');
    let (major, minor, patch) = (parts.next()?, parts.next()?, parts.next()?);
    let digit = |s: &str| s.chars().next().is_some_and(|c| c.is_ascii_digit());
    if !(digit(major) && digit(minor) && digit(patch)) {
        return None;
    }
    Some(version.to_string())
}

// ---------------------------------------------------------------------------
// Publish bridge
// ---------------------------------------------------------------------------

struct PublishInput {
    state: AppState,
    managed: Arc<ManagedState>,
    headers: HeaderMap,
    request_id: String,
    token: String,
    host: String,
    path: String,
    package_name: String,
    req: axum::extract::Request,
}

async fn handle_publish(input: PublishInput) -> Result<Response<Body>, RegistryError> {
    let PublishInput {
        state,
        managed,
        headers,
        request_id,
        token,
        host,
        path,
        package_name,
        req,
    } = input;

    let decision = authorize(
        &managed,
        &request_id,
        &token,
        &host,
        OP_PACKAGE_PUBLISH,
        &package_name,
        "",
    )
    .await?;
    if !decision.allowed {
        return Err(deny(decision.reason.as_deref()));
    }

    let spool_path = managed
        .config
        .spool_dir
        .join(format!("{}.tgz", uuid::Uuid::new_v4()));
    let result = publish_inner(
        &state,
        &managed,
        &headers,
        &request_id,
        &token,
        &host,
        &path,
        &package_name,
        &decision,
        req,
        &spool_path,
    )
    .await;
    if let Err(error) = tokio::fs::remove_file(&spool_path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(error = ?error, "failed to remove publish spool file");
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn publish_inner(
    state: &AppState,
    managed: &ManagedState,
    headers: &HeaderMap,
    request_id: &str,
    token: &str,
    host: &str,
    path: &str,
    package_name: &str,
    decision: &AuthorizeDecision,
    req: axum::extract::Request,
    spool_path: &std::path::Path,
) -> Result<Response<Body>, RegistryError> {
    let extracted = extract_publish_body(
        state.max_body_size,
        managed.config.max_metadata_bytes,
        req.into_body(),
        spool_path,
    )
    .await?;

    let (metadata, integrity, shasum, tarball_bytes) = match extracted {
        Extracted::Publish {
            metadata,
            integrity,
            shasum,
            tarball_bytes,
        } => (metadata, integrity, shasum, tarball_bytes),
        // Metadata-only publish (no attachment data): forward verbatim.
        Extracted::MetadataOnly(bytes) => {
            ensure_no_attachment_data(&bytes).map_err(extract_error)?;
            return proxy_write(
                managed,
                &Method::PUT,
                path,
                None,
                headers,
                Body::from(bytes),
            )
            .await;
        }
    };

    let publish = PublishMetadata::parse(&metadata, package_name).map_err(extract_error)?;
    let declared_bytes = publish.declared_bytes.unwrap_or(tarball_bytes);
    let fingerprint = publish_fingerprint(
        &publish.name,
        &publish.version,
        &publish.manifest,
        declared_bytes,
    );
    let registry_id = registry_id_for(managed, request_id, host, decision).await?;

    // One operation key per publish attempt; it stays stable across the
    // reserve → upload → finalize retries of this attempt.
    let operation_key = uuid::Uuid::new_v4().to_string();
    let reserve = managed
        .client
        .reserve_publish(&ReservePublishRequest {
            request_id,
            token,
            host,
            registry_id: &registry_id,
            package: &publish.name,
            version: &publish.version,
            manifest: &publish.manifest,
            tarball_bytes: declared_bytes,
            dist_tags: &publish.dist_tags,
            operation_key: &operation_key,
            fingerprint: &fingerprint,
        })
        .await
        .map_err(|err| publish_error(&publish.version, err))?;

    let upload = match reserve.upload {
        Some(upload) => upload,
        None => {
            // Replayed operation with no upload capability: resolve the
            // recorded session instead of re-uploading.
            return recover_publish_session(
                managed,
                &reserve.session_id,
                request_id,
                &publish.version,
            )
            .await;
        }
    };

    if let Err(err) = upload_tarball(managed, &upload, spool_path, tarball_bytes).await {
        abort_publish(managed, &reserve.session_id, token, reserve.generation).await;
        return Err(err);
    }

    let finalize = managed
        .client
        .finalize_publish(
            &reserve.session_id,
            &FinalizePublishRequest {
                request_id,
                token,
                generation: reserve.generation,
                fingerprint: &fingerprint,
                manifest: &publish.manifest,
                integrity: &integrity,
                shasum: &shasum,
                tarball_bytes,
            },
        )
        .await;

    let body = match finalize {
        Ok(body) => body,
        Err(err @ ControlPlaneError::Rejected { .. }) => {
            return Err(publish_error(&publish.version, err));
        }
        Err(ControlPlaneError::Unavailable) => {
            // Uncertain outcome: ask for the recorded result before failing.
            return recover_publish_session(
                managed,
                &reserve.session_id,
                request_id,
                &publish.version,
            )
            .await;
        }
    };

    let file = format!("{}-{}.tgz", publish.name, publish.version);
    TransferReport {
        events: managed.events.clone(),
        kind: super::events::EVENT_PUBLISH,
        tenant_id: decision.tenant_id().map(ToOwned::to_owned),
        package: publish.name.clone(),
        version: Some(publish.version.clone()),
        credential_id: decision.credential_id().map(ToOwned::to_owned),
        registry_id,
        file,
        declared_bytes: tarball_bytes,
        host: host.to_string(),
        request_id: request_id.to_string(),
        headers: headers.clone(),
    }
    .emit(tarball_bytes, super::events::STATUS_COMPLETE, None)
    .await;
    Ok(json_response(StatusCode::CREATED, body))
}

/// After a finalize timeout/5xx, resolve the session: when the control plane
/// recorded a commit, return its npm response; otherwise fail closed. The
/// session is not aborted here: its state is unknown, and the control plane
/// expires uncommitted sessions itself.
async fn recover_publish_session(
    managed: &ManagedState,
    session_id: &str,
    request_id: &str,
    version: &str,
) -> Result<Response<Body>, RegistryError> {
    let session = managed.client.publish_session(session_id, request_id).await;
    if let Ok(response) = session
        && matches!(response.session.status.as_str(), "committed" | "finalized")
        && let Some(result) = response.session.result
    {
        return Ok(json_response(StatusCode::CREATED, result));
    }
    Err(RegistryError::http_code(
        StatusCode::BAD_GATEWAY,
        code::CONTROL_PLANE_UNAVAILABLE,
        format!("publish of {version} could not be confirmed; retry the publish"),
    ))
}

async fn abort_publish(managed: &ManagedState, session_id: &str, token: &str, generation: i64) {
    if let Err(error) = managed
        .client
        .abort_publish(
            session_id,
            &AbortPublishRequest { token, generation },
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
    {
        warn!(session_id, error = ?error, "failed to abort publish session");
    }
}

/// Map reserve/finalize rejections to npm-facing errors.
fn publish_error(version: &str, err: ControlPlaneError) -> RegistryError {
    match err {
        ControlPlaneError::Rejected {
            status: StatusCode::CONFLICT,
            code,
            ..
        } if code == "version_exists" => RegistryError::auth_forbidden(format!(
            "You cannot publish over the previously published versions: {version}."
        )),
        ControlPlaneError::Rejected {
            status: StatusCode::CONFLICT,
            code,
            message,
        } => RegistryError::storage_conflict(if message.is_empty() {
            format!("publish conflict: {code}")
        } else {
            message
        }),
        ControlPlaneError::Rejected {
            status: StatusCode::GONE,
            ..
        } => RegistryError::http(StatusCode::GONE, "publish session expired"),
        ControlPlaneError::Rejected {
            status: StatusCode::FORBIDDEN,
            code,
            message,
        } => RegistryError::auth_forbidden(if message.is_empty() { code } else { message }),
        other => other.into_unavailable("publish"),
    }
}

async fn registry_id_for(
    managed: &ManagedState,
    request_id: &str,
    host: &str,
    decision: &AuthorizeDecision,
) -> Result<String, RegistryError> {
    if let Some(package) = &decision.package
        && !package.registry_id.is_empty()
    {
        return Ok(package.registry_id.clone());
    }
    if let Some(resolution) = managed.registry_hosts.get(host).await {
        return Ok(resolution.registry_id);
    }
    let resolution = managed
        .client
        .resolve_domain(host, request_id)
        .await
        .map_err(|err| err.into_unavailable("resolve-domain"))?
        .ok_or_else(|| control_plane_unavailable("resolve-domain (host did not resolve)"))?;
    managed.registry_hosts.put(host, &resolution).await;
    Ok(resolution.registry_id)
}

/// Stream the publish body through the extractor: metadata is buffered
/// (bounded), the decoded tarball is spooled to `spool_path`, and digests are
/// computed over the decoded bytes while streaming.
async fn extract_publish_body(
    max_body_size: usize,
    max_metadata_bytes: usize,
    body: Body,
    spool_path: &std::path::Path,
) -> Result<Extracted, RegistryError> {
    let mut file = tokio::fs::File::create(spool_path).await?;
    let mut extractor = PublishExtractor::new(max_metadata_bytes);
    let mut stream = body.into_data_stream();
    let mut total = 0usize;
    let mut decoded = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            RegistryError::http(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large")
        })?;
        total = total.saturating_add(chunk.len());
        if total > max_body_size {
            return Err(RegistryError::http(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request entity too large",
            ));
        }
        extractor
            .feed(&chunk, &mut decoded)
            .map_err(extract_error)?;
        if decoded.len() >= SPOOL_FLUSH_BYTES {
            file.write_all(&decoded).await?;
            decoded.clear();
        }
    }
    if !decoded.is_empty() {
        file.write_all(&decoded).await?;
    }
    file.flush().await?;
    drop(file);
    extractor.finish().map_err(extract_error)
}

fn extract_error(err: ExtractError) -> RegistryError {
    match err {
        ExtractError::MetadataTooLarge => RegistryError::http(
            StatusCode::PAYLOAD_TOO_LARGE,
            "publish metadata exceeds the configured limit",
        ),
        ExtractError::Malformed(reason) => RegistryError::http(StatusCode::BAD_REQUEST, reason),
    }
}

/// PUT the spooled tarball to the control-plane issued create-only URL.
async fn upload_tarball(
    managed: &ManagedState,
    upload: &super::client::ReserveUpload,
    spool_path: &std::path::Path,
    tarball_bytes: u64,
) -> Result<(), RegistryError> {
    let file = tokio::fs::File::open(spool_path).await?;
    let stream = futures::stream::try_unfold(
        (file, vec![0u8; 64 * 1024]),
        |(mut file, mut buffer)| async move {
            use tokio::io::AsyncReadExt;
            let read = file.read(&mut buffer).await?;
            Ok::<_, std::io::Error>(if read == 0 {
                None
            } else {
                Some((Bytes::copy_from_slice(&buffer[..read]), (file, buffer)))
            })
        },
    );

    let has_content_length = upload
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("content-length"));
    let mut request =
        managed
            .client
            .http()
            .put(&upload.url)
            .timeout(std::time::Duration::from_millis(
                managed.config.upload_timeout_ms,
            ));
    for (name, value) in &upload.headers {
        if let Ok(value) = HeaderValue::from_str(value) {
            request = request.header(name, value);
        }
    }
    if !has_content_length {
        request = request.header(header::CONTENT_LENGTH, tarball_bytes.to_string());
    }
    let response = request
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .map_err(|err| {
            warn!(error = ?err, "presigned tarball upload failed");
            control_plane_unavailable("presigned upload")
        })?;
    if !response.status().is_success() {
        let status = response.status();
        warn!(
            status = status.as_u16(),
            "presigned tarball upload rejected"
        );
        return Err(control_plane_unavailable("presigned upload"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::infer_version_from_filename;

    #[test]
    fn infers_versions_from_tarball_filenames() {
        assert_eq!(
            infer_version_from_filename("demo-1.2.3.tgz", "demo"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            infer_version_from_filename("core-0.1.0-beta.1.tgz", "core"),
            Some("0.1.0-beta.1".to_string())
        );
        assert_eq!(infer_version_from_filename("demo.tgz", "demo"), None);
        assert_eq!(infer_version_from_filename("demo-beta.tgz", "demo"), None);
        assert_eq!(
            infer_version_from_filename("demo-1.2.3.tar.gz", "demo"),
            Some("1.2.3".to_string())
        );
        // Scoped names and digit-starting dash segments parse through the
        // base name, never by segment heuristics.
        assert_eq!(
            infer_version_from_filename(
                "hello-1790123229837107000-1.0.0.tgz",
                "@it/hello-1790123229837107000"
            ),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            infer_version_from_filename("foo-2-3.1.4.tgz", "@scope/foo-2"),
            Some("3.1.4".to_string())
        );
        // A foreign tarball never resolves.
        assert_eq!(infer_version_from_filename("other-1.0.0.tgz", "demo"), None);
    }
}
