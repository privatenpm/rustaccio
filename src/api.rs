use crate::{
    app::AppState,
    constants::{
        ANONYMOUS_USER, API_ERROR_ONLY_OWNER, API_ERROR_SERVER_TIME_OUT, HEADER_JSON,
        HEADER_JSON_INSTALL, HEADER_OCTET,
    },
    error::RegistryError,
    events::RegistryEvent,
    governance::{GovernanceAction, GovernanceContext},
    models::{AuthIdentity, TenantContext},
    policy::{PolicyAction, RequestContext},
    storage::{
        Store, bad_request, forbidden, make_search_object, parse_authorization, parse_json_body,
        parse_json_string_body, unauthorized,
    },
};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, Method, Response, StatusCode,
        header::{self},
    },
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use tracing::{debug, instrument, warn};

#[derive(Clone, Copy)]
struct SelectedUplink<'a> {
    name: &'a str,
    upstream: &'a crate::upstream::Upstream,
}

pub async fn dispatch(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, RegistryError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let raw_path = uri.path().to_string();
    let Some(path) = normalize_incoming_path(&raw_path, &state.url_prefix) else {
        warn!(
            raw_path,
            url_prefix = state.url_prefix.as_str(),
            "request path did not match configured url_prefix"
        );
        return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
    };
    let query = uri.query().map(ToOwned::to_owned);
    let headers = req.headers().clone();
    let request_id = request_id_from_headers(&headers);
    let request_context = RequestContext {
        method: method.to_string(),
        path: path.clone(),
        request_id: request_id.clone(),
        tenant: tenant_context_from_headers(&headers),
    };
    let span = tracing::Span::current();
    span.record("method", tracing::field::display(&method));
    span.record("path", tracing::field::display(&raw_path));
    debug!(has_query = query.is_some(), "dispatching request");

    if let Some(response) = crate::web_ui::maybe_handle_request(&state, &method, &path) {
        return Ok(response);
    }

    let managed = state.managed.clone();
    let auth_identity = if managed.is_some() {
        // Managed mode: the control plane authenticates and authorizes every
        // private operation; local auth backends are never consulted.
        None
    } else {
        resolve_auth_identity(
            &state.store,
            &headers,
            &method,
            &path,
            request_id.as_deref(),
        )
        .await?
    };
    let auth_user = auth_identity_primary_name(auth_identity.as_ref()).map(ToOwned::to_owned);

    if method == Method::GET
        && let Some(metrics_path) = state.governance.metrics_path()
        && path == metrics_path
    {
        if state.governance.metrics_require_admin() {
            ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        }
        let mut metrics = state.governance.render_metrics().await.unwrap_or_default();
        if let Some(managed) = &managed {
            if !metrics.is_empty() && !metrics.ends_with('\n') {
                metrics.push('\n');
            }
            metrics.push_str(&managed.events.render_metrics());
        }
        if metrics.is_empty() {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        return Ok(text_response(
            StatusCode::OK,
            "text/plain; version=0.0.4",
            metrics,
        ));
    }

    let governance_context = governance_context_for_request(
        &method,
        &path,
        &headers,
        auth_identity.as_ref(),
        &request_context.tenant,
    );
    if managed.is_none() {
        state.governance.enforce(&governance_context).await?;
    }

    if method == Method::GET && path == "/-/ping" {
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if let Some(managed) = managed {
        // Boxed: the managed dispatch future is large; boxing keeps the
        // surrounding dispatch future's layout depth small for dependents.
        return Box::pin(crate::managed::dispatch::dispatch(
            crate::managed::dispatch::ManagedRequest {
                state,
                managed,
                method,
                path,
                query,
                headers,
                request_context,
                req,
            },
        ))
        .await;
    }

    if method == Method::GET && path == "/-/whoami" {
        let Some(username) = auth_user else {
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
            ));
        };
        return Ok(json_response(
            StatusCode::OK,
            json!({ "username": username }),
            HEADER_JSON,
        ));
    }

    if method == Method::GET && path == "/-/npm/v1/bootstrap" {
        let body = npm_bootstrap_payload(
            &headers,
            state.trust_proxy,
            &state.url_prefix,
            query.as_deref(),
            auth_user.as_deref(),
        );
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if method == Method::POST && path == "/-/admin/reindex" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        let body = state.store.reindex_from_backend().await?;
        emit_registry_event(
            &state,
            "admin.reindex",
            &request_context,
            auth_user.as_deref(),
            None,
            json!({
                "changed": body.get("changed").cloned().unwrap_or(Value::Null),
                "packagesBefore": body.get("packagesBefore").cloned().unwrap_or(Value::Null),
                "packagesAfter": body.get("packagesAfter").cloned().unwrap_or(Value::Null),
            }),
        )
        .await;
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if method == Method::GET && path == "/-/admin/storage-health" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        let body = state.store.storage_health().await?;
        emit_registry_event(
            &state,
            "admin.storage_health.read",
            &request_context,
            auth_user.as_deref(),
            None,
            json!({}),
        )
        .await;
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if method == Method::POST && path == "/-/admin/policy-cache/invalidate" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        state.policy.invalidate_cache().await?;
        emit_registry_event(
            &state,
            "admin.policy_cache.invalidate",
            &request_context,
            auth_user.as_deref(),
            None,
            json!({}),
        )
        .await;
        return Ok(json_response(
            StatusCode::OK,
            json!({ "ok": "policy cache invalidated" }),
            HEADER_JSON,
        ));
    }

    if method == Method::POST && path == "/-/admin/package-cache/invalidate" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        let payload = parse_json_body(&read_body(req, state.max_body_size).await?)?;
        let package_name = payload
            .get("package")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| bad_request("missing `package` in request body"))?;
        let removed = state.store.invalidate_package_cache(package_name).await;
        emit_registry_event(
            &state,
            "admin.package_cache.invalidate",
            &request_context,
            auth_user.as_deref(),
            Some(package_name),
            json!({
                "removed": removed,
            }),
        )
        .await;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "ok": "package cache invalidated",
                "package": package_name,
                "removed": removed
            }),
            HEADER_JSON,
        ));
    }

    if method == Method::GET && (path == "/-/all" || path == "/-/all/since") {
        return local_database_response(
            &state,
            query.as_deref(),
            auth_identity.as_ref(),
            &request_context,
        )
        .await;
    }

    if path == "/-/v1/search" && method == Method::GET {
        return handle_search(
            &state,
            query.as_deref(),
            auth_identity.as_ref(),
            &request_context,
        )
        .await;
    }

    if method == Method::POST
        && let Some(kind) = security_audit_kind(&path)
    {
        ensure_audit_enabled(&state)?;
        let payload = parse_json_body(&read_body(req, state.max_body_size).await?)?;
        let body = proxy_security_audit_request(&state, &payload, kind).await?;
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if path == "/-/_view/starredByUser" && method == Method::GET {
        let params = query_params(query.as_deref());
        let Some(raw_key) = params.get("key") else {
            return Err(bad_request("missing query key username"));
        };
        let key = Store::parse_star_key(raw_key);
        let rows = state.store.starred_packages(&key).await?;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "rows": rows.into_iter().map(|name| json!({"value": name})).collect::<Vec<_>>()
            }),
            HEADER_JSON,
        ));
    }

    if let Some((package_name, tag)) = parse_canonical_dist_tags_path(&path) {
        if method == Method::GET && tag.is_none() {
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            let tags = state.store.dist_tags(&package_name).await?;
            return Ok(json_response(StatusCode::OK, tags, HEADER_JSON));
        }

        if method == Method::PUT {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let bytes = read_body(req, state.max_body_size).await?;
            let version = parse_json_string_body(&bytes)?;
            let message = state
                .store
                .merge_dist_tag(
                    &package_name,
                    tag.as_deref().unwrap_or_default(),
                    Some(&version),
                )
                .await?;
            emit_registry_event(
                &state,
                "package.dist_tag.updated",
                &request_context,
                auth_user.as_deref(),
                Some(&package_name),
                json!({
                    "tag": tag.as_deref().unwrap_or_default(),
                    "version": version,
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }

        if method == Method::DELETE {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state
                .store
                .merge_dist_tag(&package_name, tag.as_deref().unwrap_or_default(), None)
                .await?;
            emit_registry_event(
                &state,
                "package.dist_tag.removed",
                &request_context,
                auth_user.as_deref(),
                Some(&package_name),
                json!({
                    "tag": tag.as_deref().unwrap_or_default(),
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    if let Some((package_name, tail)) = parse_package_path(&path) {
        return handle_package_routes(PackageRouteContext {
            state,
            method,
            headers,
            request_context,
            query,
            auth_user,
            auth_identity,
            package_name,
            tail,
            req,
        })
        .await;
    }

    let mut upstream_error = false;
    for upstream in select_default_uplinks(&state) {
        match upstream
            .passthrough_request(&method, &path, query.as_deref())
            .await
        {
            Ok(Some(proxy)) if is_transient_uplink_status(proxy.status) => {
                upstream_error = true;
                continue;
            }
            Ok(Some(proxy)) => return Ok(proxy_response(proxy)),
            Ok(None) => continue,
            Err(err) if is_uplink_transient_error(&err) => {
                upstream_error = true;
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    if upstream_error {
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }

    warn!("route not found");
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

struct PackageRouteContext {
    state: AppState,
    method: Method,
    headers: HeaderMap,
    request_context: RequestContext,
    query: Option<String>,
    auth_user: Option<String>,
    auth_identity: Option<AuthIdentity>,
    package_name: String,
    tail: Vec<String>,
    req: Request<Body>,
}

#[instrument(
    skip(ctx),
    fields(method, path, package, route, tail, has_query, authenticated)
)]
async fn handle_package_routes(ctx: PackageRouteContext) -> Result<Response<Body>, RegistryError> {
    let route = package_route_pattern(&ctx.method, &ctx.tail);
    let tail_path = if ctx.tail.is_empty() {
        "<root>".to_string()
    } else {
        ctx.tail.join("/")
    };
    let span = tracing::Span::current();
    span.record("method", tracing::field::display(&ctx.method));
    span.record("path", tracing::field::display(&ctx.request_context.path));
    span.record("package", tracing::field::display(&ctx.package_name));
    span.record("route", tracing::field::display(route));
    span.record("tail", tracing::field::display(&tail_path));
    span.record("has_query", tracing::field::display(ctx.query.is_some()));
    span.record(
        "authenticated",
        tracing::field::display(ctx.auth_identity.is_some()),
    );

    let PackageRouteContext {
        state,
        method,
        headers,
        request_context,
        query,
        auth_user,
        auth_identity,
        package_name,
        tail,
        req,
    } = ctx;
    debug!(
        package = package_name,
        method = %method,
        route,
        tail = tail_path,
        authenticated = auth_identity.is_some(),
        "handling package route"
    );

    if method == Method::GET || method == Method::HEAD {
        let response = match tail.as_slice() {
            [] => {
                ensure_access_permission(
                    &state,
                    &package_name,
                    auth_identity.as_ref(),
                    &request_context,
                )
                .await?;
                Some(
                    handle_get_package(
                        &state,
                        &headers,
                        query.as_deref(),
                        &package_name,
                        auth_user.as_deref(),
                    )
                    .await?,
                )
            }
            [version] => {
                ensure_access_permission(
                    &state,
                    &package_name,
                    auth_identity.as_ref(),
                    &request_context,
                )
                .await?;
                Some(handle_get_package_version(&state, &headers, &package_name, version).await?)
            }
            [dash, filename] if dash == "-" => {
                ensure_access_permission(
                    &state,
                    &package_name,
                    auth_identity.as_ref(),
                    &request_context,
                )
                .await?;
                Some(handle_get_tarball(&state, &package_name, filename).await?)
            }
            _ => None,
        };

        if let Some(response) = response {
            return Ok(if method == Method::HEAD {
                head_response(response)
            } else {
                response
            });
        }
    }

    if method == Method::PUT {
        if tail.is_empty() {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
            let message = state
                .store
                .publish_manifest(&package_name, body, user)
                .await?;
            emit_registry_event(
                &state,
                "package.published",
                &request_context,
                Some(user),
                Some(&package_name),
                json!({
                    "route": "PUT /:package",
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({"success": true, "ok": message}),
                HEADER_JSON,
            ));
        }

        if tail.len() == 2 && tail[0] == "-rev" {
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
            let message = state
                .store
                .publish_manifest(&package_name, body, user)
                .await?;
            emit_registry_event(
                &state,
                "package.metadata_updated",
                &request_context,
                Some(user),
                Some(&package_name),
                json!({
                    "route": "PUT /:package/-rev/:revision",
                    "revision": tail[1].clone(),
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({"success": true, "ok": message}),
                HEADER_JSON,
            ));
        }

        if tail.len() == 1 {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let version = parse_json_string_body(&read_body(req, state.max_body_size).await?)?;
            let message = state
                .store
                .merge_dist_tag(&package_name, &tail[0], Some(&version))
                .await?;
            emit_registry_event(
                &state,
                "package.dist_tag.updated",
                &request_context,
                auth_user.as_deref(),
                Some(&package_name),
                json!({
                    "tag": tail[0].clone(),
                    "version": version,
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    if method == Method::DELETE {
        if tail.len() == 2 && tail[0] == "-rev" {
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state
                .store
                .remove_package_with_revision(&package_name, Some(&tail[1]))
                .await?;
            emit_registry_event(
                &state,
                "package.removed",
                &request_context,
                auth_user.as_deref(),
                Some(&package_name),
                json!({
                    "revision": tail[1].clone(),
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }

        if tail.len() == 4 && tail[0] == "-" && tail[2] == "-rev" {
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state
                .store
                .remove_tarball_with_revision(&package_name, &tail[1], Some(&tail[3]))
                .await?;
            emit_registry_event(
                &state,
                "package.tarball.removed",
                &request_context,
                auth_user.as_deref(),
                Some(&package_name),
                json!({
                    "filename": tail[1].clone(),
                    "revision": tail[3].clone(),
                }),
            )
            .await;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    warn!(package = package_name, method = %method, "package route not found");
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

async fn handle_get_package(
    state: &AppState,
    headers: &HeaderMap,
    query: Option<&str>,
    package_name: &str,
    auth_user: Option<&str>,
) -> Result<Response<Body>, RegistryError> {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let abbreviated = accept.contains("application/vnd.npm.install-v1+json");
    let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);

    ensure_package_cached(state, headers, package_name).await?;
    let Some(record) = state.store.get_package_record_result(package_name).await? else {
        return Err(RegistryError::http(
            StatusCode::NOT_FOUND,
            Store::no_package_message(),
        ));
    };

    let (normalized, _) =
        state
            .store
            .normalize_package_response(&record.manifest, package_name, &base);

    let write = crate::storage::parse_write_query(query);
    if write && auth_user.is_none() {
        return Err(bad_request(Store::login_required_message()));
    }
    if write {
        ensure_package_owner_permission(state, package_name, auth_user).await?;
    }

    if abbreviated {
        let body = state.store.abbreviated_manifest(&normalized);
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON_INSTALL));
    }

    Ok(json_response(StatusCode::OK, normalized, HEADER_JSON))
}

async fn handle_get_package_version(
    state: &AppState,
    headers: &HeaderMap,
    package_name: &str,
    query_version: &str,
) -> Result<Response<Body>, RegistryError> {
    ensure_package_cached(state, headers, package_name).await?;
    let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);
    let Some(record) = state.store.get_package_record_result(package_name).await? else {
        return Err(RegistryError::http(
            StatusCode::NOT_FOUND,
            Store::no_package_message(),
        ));
    };
    let (normalized, _) =
        state
            .store
            .normalize_package_response(&record.manifest, package_name, &base);

    let Some(version) = Store::package_version_by_query(&normalized, query_version) else {
        return Err(crate::storage::version_not_found(query_version));
    };

    Ok(json_response(StatusCode::OK, version, HEADER_JSON))
}

async fn handle_get_tarball(
    state: &AppState,
    package_name: &str,
    filename: &str,
) -> Result<Response<Body>, RegistryError> {
    if let Some(bytes) = state
        .store
        .read_local_tarball(package_name, filename)
        .await?
    {
        return Ok(bytes_response(StatusCode::OK, bytes));
    }

    if !state.store.is_known_package(package_name).await {
        let headers = HeaderMap::new();
        ensure_package_cached(state, &headers, package_name).await?;
        if let Some(bytes) = state
            .store
            .read_local_tarball(package_name, filename)
            .await?
        {
            return Ok(bytes_response(StatusCode::OK, bytes));
        }
        if !state.store.is_known_package(package_name).await {
            return Ok(bytes_response(StatusCode::NOT_FOUND, Vec::new()));
        }
    }

    let mut upstream_error = false;
    for selected in select_uplinks_for_package(state, package_name) {
        let url = state
            .store
            .upstream_tarball_url(package_name, filename)
            .await
            .unwrap_or_else(|| {
                selected
                    .upstream
                    .default_tarball_url(package_name, filename)
            });

        match selected.upstream.fetch_tarball(&url).await {
            Ok(Some(bytes)) => {
                state
                    .store
                    .set_upstream_tarball_url(package_name, filename, url)
                    .await?;
                state
                    .store
                    .cache_tarball(package_name, filename, &bytes)
                    .await?;
                return Ok(bytes_response(StatusCode::OK, bytes));
            }
            Ok(None) => continue,
            Err(err) if is_uplink_transient_error(&err) => {
                upstream_error = true;
            }
            Err(err) => return Err(err),
        }
    }
    if upstream_error {
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }

    Ok(bytes_response(StatusCode::NOT_FOUND, Vec::new()))
}

#[instrument(skip(state, headers), fields(package = package_name))]
async fn ensure_package_cached(
    state: &AppState,
    headers: &HeaderMap,
    package_name: &str,
) -> Result<(), RegistryError> {
    let matched_rule = state.acl.rule_for(package_name);
    let uplinks = select_uplinks_for_package(state, package_name);
    let selected_uplink_names: Vec<&str> = uplinks.iter().map(|selected| selected.name).collect();

    let authoritative_lookup_error = match state.store.get_package_record_result(package_name).await
    {
        Ok(Some(_)) => {
            debug!("package already cached");
            return Ok(());
        }
        Ok(None) => None,
        Err(err) => {
            if uplinks.is_empty() {
                return Err(err);
            }
            let (status, code, message) = registry_error_details(&err);
            warn!(
                error_status = status,
                error_code = code,
                error = message,
                "authoritative package lookup failed before uplink lookup; trying configured proxy"
            );
            Some(err)
        }
    };

    debug!(
        acl_pattern = matched_rule.map(|rule| rule.pattern.as_str()).unwrap_or("none"),
        acl_proxy = matched_rule
            .and_then(|rule| rule.proxy.as_deref())
            .unwrap_or("none"),
        selected_uplinks = ?selected_uplink_names,
        "selected uplinks for package manifest lookup"
    );
    if uplinks.is_empty() {
        if let Some(proxy_name) = matched_rule.and_then(|rule| rule.proxy.as_deref()) {
            warn!(
                acl_proxy = proxy_name,
                "package rule references an uplink that is not configured"
            );
        } else {
            debug!("package rule has no proxy; skipping uplink lookup");
        }
        return Ok(());
    }

    let mut had_upstream_error = false;
    for selected in uplinks {
        let Some(manifest) = (match selected.upstream.fetch_package(package_name).await {
            Ok(manifest) => {
                if manifest.is_none() {
                    debug!(
                        uplink_name = selected.name,
                        uplink = selected.upstream.base_url(),
                        outcome = "miss",
                        "uplink did not have package manifest"
                    );
                }
                manifest
            }
            Err(err) if is_uplink_transient_error(&err) => {
                let (status, code, message) = registry_error_details(&err);
                warn!(
                    uplink_name = selected.name,
                    uplink = selected.upstream.base_url(),
                    outcome = "transient_error",
                    error_status = status,
                    error_code = code,
                    error = message,
                    "uplink package fetch failed, trying next candidate"
                );
                had_upstream_error = true;
                continue;
            }
            Err(err) => {
                let (status, code, message) = registry_error_details(&err);
                warn!(
                    uplink_name = selected.name,
                    uplink = selected.upstream.base_url(),
                    outcome = "non_transient_error",
                    error_status = status,
                    error_code = code,
                    error = message,
                    "uplink package fetch failed"
                );
                return Err(err);
            }
        }) else {
            continue;
        };

        let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);
        let (normalized, upstream_map) =
            state
                .store
                .normalize_package_response(&manifest, package_name, &base);
        state
            .store
            .upsert_upstream_package(package_name, normalized, upstream_map)
            .await?;
        debug!(
            uplink_name = selected.name,
            uplink = selected.upstream.base_url(),
            outcome = "hit",
            "cached package manifest from upstream"
        );
        return Ok(());
    }

    if had_upstream_error {
        warn!(
            selected_uplinks = ?selected_uplink_names,
            "all selected uplinks failed transiently for package manifest lookup"
        );
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }
    if let Some(err) = authoritative_lookup_error {
        return Err(err);
    }
    debug!("package missing on upstream");
    Ok(())
}

#[instrument(
    skip(state, query, auth_identity, request_context),
    fields(
        method = %request_context.method,
        path = %request_context.path,
        has_query = query.is_some(),
        query_text,
        query_size,
        query_from,
        authenticated = auth_identity.is_some()
    )
)]
async fn handle_search(
    state: &AppState,
    query: Option<&str>,
    auth_identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<Response<Body>, RegistryError> {
    let params = query_params(query);
    let text = params
        .get("text")
        .cloned()
        .unwrap_or_default()
        .to_lowercase();
    let size = params
        .get("size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20)
        .min(250);
    let from = params
        .get("from")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let query_text = params.get("text").map(String::as_str).unwrap_or_default();
    let span = tracing::Span::current();
    span.record("query_text", tracing::field::display(query_text));
    span.record("query_size", tracing::field::display(size));
    span.record("query_from", tracing::field::display(from));

    let mut objects = Vec::new();

    for package in state.store.all_packages().await? {
        if let Some(item) = make_search_object(&package.manifest) {
            let name = item
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let name_lc = name.to_lowercase();

            let allowed = state
                .policy
                .authorize(PolicyAction::Access, &name, auth_identity, request_context)
                .await?;
            if allowed && (text.is_empty() || name_lc.contains(&text)) {
                objects.push(item);
            }
        }
    }

    for upstream in select_default_uplinks(state) {
        let remote = match upstream.fetch_search(query.unwrap_or_default()).await {
            Ok(remote) => remote,
            Err(err) if is_uplink_transient_error(&err) => continue,
            Err(err) => return Err(err),
        };
        for item in remote {
            let package_name = item
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if package_name.is_empty() {
                continue;
            }
            let allowed = state
                .policy
                .authorize(
                    PolicyAction::Access,
                    &package_name,
                    auth_identity,
                    request_context,
                )
                .await?;
            if allowed {
                objects.push(item);
            }
        }
    }

    let mut seen = HashSet::new();
    objects.retain(|item| {
        let key = item
            .get("package")
            .and_then(|pkg| pkg.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if key.is_empty() {
            return false;
        }
        if seen.contains(&key) {
            return false;
        }
        seen.insert(key)
    });

    let start = from.min(objects.len());
    let end = (start + size).min(objects.len());
    let sliced = objects[start..end].to_vec();
    debug!(
        results = sliced.len(),
        total_before_paging = objects.len(),
        "search completed"
    );

    Ok(json_response(
        StatusCode::OK,
        json!({
            "objects": sliced,
            "total": sliced.len(),
            "time": Store::search_response_time(),
        }),
        HEADER_JSON,
    ))
}

#[instrument(
    level = "debug",
    skip(store, headers),
    fields(method = %method, path = %path)
)]
async fn resolve_auth_identity(
    store: &Store,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    request_id: Option<&str>,
) -> Result<Option<AuthIdentity>, RegistryError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let header_present = raw.is_some();
    let auth_scheme = raw.and_then(|value| value.split_whitespace().next());
    let token = parse_authorization(raw);
    debug!(
        authorization_header = header_present,
        authorization_scheme = auth_scheme.unwrap_or("<none>"),
        "resolving auth identity"
    );

    match token {
        Some(token) => {
            let Some(identity) = store
                .authenticate_request(&token, method.as_str(), path, request_id)
                .await?
            else {
                warn!(
                    method = method.as_str(),
                    path, "authorization token rejected by auth backends"
                );
                return Err(unauthorized_message_for_path(path));
            };
            if identity.username.is_none() && identity.groups.is_empty() {
                warn!("auth identity did not contain a user");
                return Err(unauthorized_message_for_path(path));
            }
            debug!("token accepted");
            Ok(Some(identity))
        }
        None if header_present => {
            warn!(
                authorization_scheme = auth_scheme.unwrap_or("<unknown>"),
                "malformed authorization header (expected 'Bearer <token>')"
            );
            Err(unauthorized_message_for_path(path))
        }
        None => Ok(None),
    }
}

fn unauthorized_message_for_path(path: &str) -> RegistryError {
    if let Some((package_name, _)) = parse_package_path(path) {
        return unauthorized(&format!(
            "authorization required to access package {package_name}"
        ));
    }
    unauthorized(Store::unauthorized_access_message())
}

async fn ensure_access_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Access,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "access denied by policy engine"
    );
    Err(unauthorized(&format!(
        "authorization required to access package {package_name}"
    )))
}

async fn ensure_publish_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Publish,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "publish denied by policy engine"
    );
    Err(RegistryError::policy_denied(format!(
        "authorization required to publish package {package_name}"
    )))
}

async fn ensure_unpublish_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Unpublish,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "unpublish denied by policy engine"
    );
    Err(RegistryError::policy_denied(format!(
        "authorization required to unpublish package {package_name}"
    )))
}

async fn ensure_package_owner_permission(
    state: &AppState,
    package_name: &str,
    user: Option<&str>,
) -> Result<(), RegistryError> {
    if !state.publish_check_owners {
        return Ok(());
    }

    let Some(record) = state.store.get_package_record_result(package_name).await? else {
        return Ok(());
    };

    let username = user.unwrap_or(ANONYMOUS_USER);
    if is_package_owner(&record.manifest, username) {
        return Ok(());
    }

    Err(forbidden(API_ERROR_ONLY_OWNER))
}

fn is_package_owner(manifest: &Value, username: &str) -> bool {
    let Some(maintainers) = manifest.get("maintainers").and_then(Value::as_array) else {
        return true;
    };
    if maintainers.is_empty() {
        return true;
    }

    maintainers.iter().any(|maintainer| {
        maintainer.as_str() == Some(username)
            || maintainer.get("name").and_then(Value::as_str) == Some(username)
    })
}

fn auth_identity_primary_name(identity: Option<&AuthIdentity>) -> Option<&str> {
    let identity = identity?;
    identity
        .username
        .as_deref()
        .or_else(|| identity.groups.first().map(String::as_str))
}

fn request_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn emit_registry_event(
    state: &AppState,
    event_type: &str,
    request_context: &RequestContext,
    actor: Option<&str>,
    package: Option<&str>,
    attributes: Value,
) {
    state
        .events
        .emit_best_effort(RegistryEvent::new(
            event_type,
            actor.map(ToOwned::to_owned),
            package.map(ToOwned::to_owned),
            request_context.request_id.clone(),
            request_context.tenant.clone(),
            attributes,
        ))
        .await;
}

fn select_uplinks_for_package<'a>(
    state: &'a AppState,
    package_name: &str,
) -> Vec<SelectedUplink<'a>> {
    let Some(proxy_name) = state.acl.proxy_for(package_name) else {
        return Vec::new();
    };

    state
        .uplinks
        .get_key_value(proxy_name)
        .map(|(resolved_name, upstream)| {
            vec![SelectedUplink {
                name: resolved_name.as_str(),
                upstream,
            }]
        })
        .unwrap_or_default()
}

fn select_default_uplinks(state: &AppState) -> Vec<&crate::upstream::Upstream> {
    let mut selected_names = vec!["default".to_string()];
    let mut remaining: Vec<String> = state.uplinks.keys().cloned().collect();
    remaining.sort();
    for name in remaining {
        if !selected_names.iter().any(|selected| selected == &name) {
            selected_names.push(name);
        }
    }

    selected_names
        .into_iter()
        .filter_map(|name| state.uplinks.get(&name))
        .collect()
}

fn is_uplink_transient_error(err: &RegistryError) -> bool {
    match err {
        RegistryError::Http { status, .. } => is_transient_uplink_status(*status),
        RegistryError::Internal => false,
    }
}

fn registry_error_details(err: &RegistryError) -> (u16, &str, &str) {
    match err {
        RegistryError::Http {
            status,
            code,
            message,
        } => (status.as_u16(), code.as_str(), message.as_str()),
        RegistryError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            crate::error::code::INTERNAL_ERROR,
            "internal server error",
        ),
    }
}

fn is_transient_uplink_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::REQUEST_TIMEOUT
    )
}

#[derive(Clone, Copy)]
enum SecurityAuditKind {
    AdvisoriesBulk,
    AuditsQuick,
    Audits,
}

fn security_audit_kind(path: &str) -> Option<SecurityAuditKind> {
    match path {
        "/-/npm/v1/security/advisories/bulk" => Some(SecurityAuditKind::AdvisoriesBulk),
        "/-/npm/v1/security/audits/quick" => Some(SecurityAuditKind::AuditsQuick),
        "/-/npm/v1/security/audits" => Some(SecurityAuditKind::Audits),
        _ => None,
    }
}

async fn proxy_security_audit_request(
    state: &AppState,
    payload: &Value,
    kind: SecurityAuditKind,
) -> Result<Value, RegistryError> {
    for upstream in select_default_uplinks(state) {
        let response = match kind {
            SecurityAuditKind::AdvisoriesBulk => {
                upstream.post_security_advisories_bulk(payload).await
            }
            SecurityAuditKind::AuditsQuick => upstream.post_security_audits_quick(payload).await,
            SecurityAuditKind::Audits => upstream.post_security_audits(payload).await,
        };
        match response {
            Ok(Some(body)) => return Ok(body),
            Ok(None) => continue,
            Err(err) if is_uplink_transient_error(&err) => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(match kind {
        SecurityAuditKind::AdvisoriesBulk => json!({}),
        SecurityAuditKind::AuditsQuick => empty_quick_audit_response(),
        SecurityAuditKind::Audits => empty_audit_response(),
    })
}

async fn local_database_response(
    state: &AppState,
    query: Option<&str>,
    auth_identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<Response<Body>, RegistryError> {
    let params = query_params(query);
    let start_key = params
        .get("since")
        .or_else(|| params.get("startkey"))
        .cloned();

    let mut rows: Vec<(String, Value)> = Vec::new();
    for record in state.store.all_packages().await? {
        let Some(name) = record
            .manifest
            .get("name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        let allowed = state
            .policy
            .authorize(PolicyAction::Access, &name, auth_identity, request_context)
            .await?;
        if !allowed {
            continue;
        }

        let latest = record
            .manifest
            .get("dist-tags")
            .and_then(|tags| tags.get("latest"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        rows.push((
            name.clone(),
            json!({
                "name": name,
                "version": latest,
            }),
        ));
    }
    rows.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut out = serde_json::Map::new();
    for (name, row) in rows {
        if let Some(start) = &start_key
            && name <= *start
        {
            continue;
        }
        out.insert(name, row);
    }

    Ok(json_response(
        StatusCode::OK,
        Value::Object(out),
        HEADER_JSON,
    ))
}

fn empty_quick_audit_response() -> Value {
    json!({
        "auditReportVersion": 2,
        "actions": [],
        "advisories": {},
        "vulnerabilities": {},
        "muted": [],
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
            },
            "dependencies": 0,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 0,
        }
    })
}

fn empty_audit_response() -> Value {
    let mut body = empty_quick_audit_response();
    if let Some(obj) = body.as_object_mut() {
        obj.insert("runId".to_string(), Value::String("0".to_string()));
    }
    body
}

fn query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(query) = query else {
        return out;
    };

    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key = urlencoding::decode(key)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| key.to_string());
        let value = urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string());
        out.insert(key, value);
    }

    out
}

fn governance_context_for_request(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    identity: Option<&AuthIdentity>,
    tenant: &TenantContext,
) -> GovernanceContext {
    let (package_name, action) = if let Some((package_name, tail)) = parse_package_path(path) {
        let action = match method {
            &Method::GET | &Method::HEAD if tail.len() == 2 && tail[0] == "-" => {
                GovernanceAction::Download
            }
            &Method::GET | &Method::HEAD => GovernanceAction::Access,
            &Method::PUT if tail.is_empty() => GovernanceAction::Publish,
            &Method::PUT if tail.len() == 2 && tail[0] == "-rev" => GovernanceAction::Unpublish,
            &Method::DELETE if tail.len() == 2 && tail[0] == "-rev" => GovernanceAction::Unpublish,
            &Method::DELETE if tail.len() == 4 && tail[0] == "-" && tail[2] == "-rev" => {
                GovernanceAction::Unpublish
            }
            &Method::PUT if tail.len() == 1 => GovernanceAction::Publish,
            &Method::DELETE if tail.len() == 1 => GovernanceAction::Publish,
            _ => GovernanceAction::Other,
        };
        (Some(package_name), action)
    } else if let Some((package_name, tag)) = parse_canonical_dist_tags_path(path) {
        let action = match *method {
            Method::GET => GovernanceAction::Access,
            Method::PUT => GovernanceAction::Publish,
            Method::DELETE if tag.is_some() => GovernanceAction::Publish,
            _ => GovernanceAction::Other,
        };
        (Some(package_name), action)
    } else if method == Method::GET
        && (path == "/-/v1/search" || path == "/-/all" || path == "/-/all/since")
    {
        (None, GovernanceAction::Search)
    } else if path.starts_with("/-/admin/") {
        (None, GovernanceAction::Admin)
    } else {
        (None, GovernanceAction::Other)
    };

    GovernanceContext::from_identity(
        action,
        method.as_str(),
        path,
        package_name,
        identity,
        tenant.clone(),
        first_header_value(headers, &["x-forwarded-for"]).and_then(first_csv_token),
    )
}

fn first_csv_token(value: String) -> Option<String> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn tenant_context_from_headers(headers: &HeaderMap) -> TenantContext {
    TenantContext {
        org_id: first_header_value(headers, &["x-rustaccio-org-id", "x-org-id"]),
        project_id: first_header_value(headers, &["x-rustaccio-project-id", "x-project-id"]),
    }
}

fn first_header_value(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        headers
            .get(*name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn text_response(status: StatusCode, content_type: &str, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from(String::new())))
}

pub(crate) fn parse_canonical_dist_tags_path(path: &str) -> Option<(String, Option<String>)> {
    let rest = path.strip_prefix("/-/package/")?;
    let idx = rest.find("/dist-tags")?;
    let pkg = decode_path_component(&rest[..idx]);
    let suffix = &rest[idx + "/dist-tags".len()..];
    if suffix.is_empty() {
        return Some((pkg, None));
    }
    let tag = suffix.strip_prefix('/').map(decode_path_component);
    Some((pkg, tag))
}

pub(crate) fn parse_package_path(path: &str) -> Option<(String, Vec<String>)> {
    if path.starts_with("/-/") {
        return None;
    }

    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        return None;
    }

    let segments: Vec<String> = clean.split('/').map(decode_path_component).collect();

    if segments.is_empty() {
        return None;
    }

    if segments[0].starts_with('@') && !segments[0].contains('/') {
        if segments.len() < 2 {
            return None;
        }
        let package = format!("{}/{}", segments[0], segments[1]);
        let tail = segments[2..].to_vec();
        return Some((package, tail));
    }

    let package = segments[0].clone();
    let tail = segments[1..].to_vec();
    Some((package, tail))
}

fn package_route_pattern(method: &Method, tail: &[String]) -> &'static str {
    match method {
        &Method::GET | &Method::HEAD => match tail {
            [] => "GET|HEAD /:package",
            [_] => "GET|HEAD /:package/:version",
            [dash, _filename] if dash == "-" => "GET|HEAD /:package/-/:filename",
            _ => "GET|HEAD /:package/<unmatched>",
        },
        &Method::PUT => match tail {
            [] => "PUT /:package",
            [dash, _revision] if dash == "-rev" => "PUT /:package/-rev/:revision",
            [_tag] => "PUT /:package/:tag",
            _ => "PUT /:package/<unmatched>",
        },
        &Method::DELETE => match tail {
            [dash, _revision] if dash == "-rev" => "DELETE /:package/-rev/:revision",
            [dash, _filename, rev, _revision] if dash == "-" && rev == "-rev" => {
                "DELETE /:package/-/:filename/-rev/:revision"
            }
            _ => "DELETE /:package/<unmatched>",
        },
        _ => "/:package/<unsupported-method>",
    }
}

fn decode_path_component(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn request_base_url(headers: &HeaderMap, trust_proxy: bool) -> String {
    let protocol = if trust_proxy {
        headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("http")
    } else {
        "http"
    };

    let host = if trust_proxy {
        headers
            .get("x-forwarded-host")
            .or_else(|| headers.get(header::HOST))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("localhost:4873")
    } else {
        headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("localhost:4873")
    };

    format!("{protocol}://{host}")
}

fn request_registry_base_url(headers: &HeaderMap, trust_proxy: bool, url_prefix: &str) -> String {
    let origin = request_base_url(headers, trust_proxy);
    if url_prefix == "/" {
        origin
    } else {
        format!("{origin}{url_prefix}")
    }
}

fn npm_bootstrap_payload(
    headers: &HeaderMap,
    trust_proxy: bool,
    url_prefix: &str,
    query: Option<&str>,
    auth_user: Option<&str>,
) -> Value {
    let params = query_params(query);
    let scope = params.get("scope").map(|value| {
        if value.starts_with('@') {
            value.clone()
        } else {
            format!("@{value}")
        }
    });

    let registry_base = request_registry_base_url(headers, trust_proxy, url_prefix);
    let registry = format!("{registry_base}/");
    let auth_host = registry
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let auth_key = format!("//{auth_host}/:_authToken");
    let scope_registry_line = scope
        .as_ref()
        .map(|scope| format!("{scope}:registry={registry}"))
        .unwrap_or_else(|| "# optional: @your-scope:registry=<registry-url>".to_string());
    let npmrc = format!(
        "registry={registry}\n{scope_registry_line}\nalways-auth=true\n{auth_key}=${{RUSTACCIO_NPM_TOKEN}}"
    );
    let user_hint = auth_user
        .map(|user| format!("Authenticated as `{user}`."))
        .unwrap_or_else(|| "Not authenticated yet.".to_string());

    json!({
        "registry": registry,
        "scope": scope,
        "authTokenKey": auth_key,
        "userHint": user_hint,
        "snippets": {
            "npmrc": npmrc,
            "npm": format!("npm config set registry {registry}"),
            "pnpm": format!("pnpm config set registry {registry}"),
            "yarn": format!("yarn config set npmRegistryServer {registry}"),
            "bun": format!("bun pm config set registry {registry}"),
        },
        "notes": [
            "Export token before install/publish: export RUSTACCIO_NPM_TOKEN=<token>",
            "For CI, prefer project-scoped tokens and rotate periodically."
        ],
    })
}

fn normalize_incoming_path(path: &str, url_prefix: &str) -> Option<String> {
    if url_prefix == "/" {
        return Some(path.to_string());
    }

    if path == url_prefix {
        return Some("/".to_string());
    }

    let prefix_with_slash = format!("{url_prefix}/");
    if let Some(stripped) = path.strip_prefix(&prefix_with_slash) {
        return Some(format!("/{stripped}"));
    }

    None
}

fn proxy_response(proxy: crate::upstream::UpstreamPassthroughResponse) -> Response<Body> {
    let mut builder = Response::builder().status(proxy.status);
    if let Some(content_type) = proxy.content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder
        .body(Body::from(proxy.body))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::<u8>::new())))
}

fn json_response(status: StatusCode, body: Value, content_type: &str) -> Response<Body> {
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("{}")))
}

fn bytes_response(status: StatusCode, bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, HEADER_OCTET)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::<u8>::new())))
}

fn head_response(mut response: Response<Body>) -> Response<Body> {
    *response.body_mut() = Body::empty();
    response
}

fn ensure_audit_enabled(state: &AppState) -> Result<(), RegistryError> {
    if state.audit_enabled {
        return Ok(());
    }
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

fn ensure_admin_authenticated(
    state: &AppState,
    identity: Option<&AuthIdentity>,
) -> Result<(), RegistryError> {
    let Some(identity) = identity else {
        return Err(RegistryError::http(
            StatusCode::UNAUTHORIZED,
            "authorization required",
        ));
    };

    if state.admin_access.allow_any_authenticated {
        return Ok(());
    }

    let is_user_admin = identity
        .username
        .as_deref()
        .map(|username| {
            state
                .admin_access
                .users
                .iter()
                .any(|allowed| allowed == username)
        })
        .unwrap_or(false);
    let is_group_admin = identity.groups.iter().any(|group| {
        state
            .admin_access
            .groups
            .iter()
            .any(|allowed| allowed == group)
    });

    if is_user_admin || is_group_admin {
        return Ok(());
    }

    Err(RegistryError::http(
        StatusCode::FORBIDDEN,
        "admin authorization required",
    ))
}

async fn read_body(req: Request<Body>, max_body_size: usize) -> Result<Vec<u8>, RegistryError> {
    to_bytes(req.into_body(), max_body_size)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|_| RegistryError::http(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large"))
}

#[cfg(test)]
mod tests {
    use super::{package_route_pattern, registry_error_details};
    use crate::error::{RegistryError, code};
    use axum::http::Method;
    use axum::http::StatusCode;

    fn tail(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn package_route_pattern_get_variants() {
        assert_eq!(
            package_route_pattern(&Method::GET, &tail(&[])),
            "GET|HEAD /:package"
        );
        assert_eq!(
            package_route_pattern(&Method::HEAD, &tail(&["1.2.3"])),
            "GET|HEAD /:package/:version"
        );
        assert_eq!(
            package_route_pattern(&Method::GET, &tail(&["-", "pkg-1.2.3.tgz"])),
            "GET|HEAD /:package/-/:filename"
        );
        assert_eq!(
            package_route_pattern(&Method::GET, &tail(&["too", "many", "parts"])),
            "GET|HEAD /:package/<unmatched>"
        );
    }

    #[test]
    fn package_route_pattern_write_variants() {
        assert_eq!(
            package_route_pattern(&Method::PUT, &tail(&[])),
            "PUT /:package"
        );
        assert_eq!(
            package_route_pattern(&Method::PUT, &tail(&["latest"])),
            "PUT /:package/:tag"
        );
        assert_eq!(
            package_route_pattern(&Method::PUT, &tail(&["-rev", "17-abc"])),
            "PUT /:package/-rev/:revision"
        );
        assert_eq!(
            package_route_pattern(&Method::DELETE, &tail(&["-rev", "17-abc"])),
            "DELETE /:package/-rev/:revision"
        );
        assert_eq!(
            package_route_pattern(&Method::DELETE, &tail(&["-", "a.tgz", "-rev", "18-def"])),
            "DELETE /:package/-/:filename/-rev/:revision"
        );
        assert_eq!(
            package_route_pattern(&Method::DELETE, &tail(&["latest"])),
            "DELETE /:package/<unmatched>"
        );
    }

    #[test]
    fn registry_error_details_return_structured_fields() {
        let err = RegistryError::http_code(
            StatusCode::BAD_GATEWAY,
            code::UPSTREAM_BAD_GATEWAY,
            "uplink is offline",
        );
        assert_eq!(
            registry_error_details(&err),
            (502, code::UPSTREAM_BAD_GATEWAY, "uplink is offline")
        );
    }
}
