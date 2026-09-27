//! Typed HTTP client for the Go control-plane registry contract.
//!
//! All calls go to `{base}/api/registry`, carry the node credential as
//! `Authorization: Bearer …` and propagate the inbound `x-request-id`.
//! Fail-closed semantics: transport errors, timeouts and unreadable payloads
//! surface as [`ControlPlaneError::Unavailable`]; non-success statuses surface
//! as [`ControlPlaneError::Rejected`] with the parsed error code. The client
//! never retries 4xx responses; the only retry is one extra attempt on
//! connect-timeout for `GET /v1/publishes/{id}` (publish uncertainty
//! resolution).

use crate::error::{RegistryError, code};
use axum::http::StatusCode;
use reqwest::{Client, RequestBuilder, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, warn};

/// Operations understood by `POST /v1/authorize`.
pub const OP_METADATA_READ: &str = "metadata:read";
pub const OP_TARBALL_READ: &str = "tarball:read";
pub const OP_IDENTITY_READ: &str = "identity:read";
pub const OP_PACKAGE_PUBLISH: &str = "package:publish";
pub const OP_DIST_TAG_WRITE: &str = "dist-tag:write";
pub const OP_PACKAGE_UNPUBLISH: &str = "package:unpublish";

const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(5);
const EVENTS_TIMEOUT: Duration = Duration::from_secs(5);
const RESERVE_TIMEOUT: Duration = Duration::from_secs(15);
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const ABORT_TIMEOUT: Duration = Duration::from_secs(5);
const DOWNLOAD_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLVE_DOMAIN_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);
const FLEET_CONFIG_TIMEOUT: Duration = Duration::from_secs(10);

/// A control-plane call failed.
#[derive(Debug)]
pub enum ControlPlaneError {
    /// The control plane answered a non-success status; `code`/`message` are
    /// parsed from the `{ "error": { "code", "message" } }` body when present.
    Rejected {
        status: StatusCode,
        code: String,
        message: String,
    },
    /// Transport error, timeout, or unreadable response payload.
    Unavailable,
}

impl ControlPlaneError {
    /// Fail-closed mapping for private operations: a stable 502 body, never a
    /// local permissive fallback.
    pub fn into_unavailable(self, operation: &str) -> RegistryError {
        let message = match &self {
            ControlPlaneError::Rejected { status, code, .. } => {
                format!("control plane {operation} rejected with status {status} ({code})")
            }
            ControlPlaneError::Unavailable => {
                format!("control plane {operation} unavailable")
            }
        };
        RegistryError::http_code(
            StatusCode::BAD_GATEWAY,
            code::CONTROL_PLANE_UNAVAILABLE,
            message,
        )
    }
}

#[derive(Debug, Serialize)]
pub struct AuthorizeRequest<'a> {
    pub request_id: &'a str,
    pub token: &'a str,
    pub operation: &'a str,
    pub host: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub registry_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub package: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub version: &'a str,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizeSubject {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub credential_version: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageSummary {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub registry_id: String,
    #[serde(default)]
    pub owner_tenant_id: String,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub revision: i64,
}

/// Authorize answers may classify a name the control plane will serve itself.
/// Absent (and `"hosted"`) keep today's behavior; only `"upstream"` forwards.
pub const ROUTE_UPSTREAM: &str = "upstream";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizeDecision {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub subject: Option<AuthorizeSubject>,
    #[serde(default)]
    pub package: Option<PackageSummary>,
    /// `"hosted"` or `"upstream"`. Absent on older control planes.
    #[serde(default)]
    pub route: Option<String>,
}

impl AuthorizeDecision {
    pub fn credential_version(&self) -> i64 {
        self.subject
            .as_ref()
            .map(|subject| subject.credential_version)
            .unwrap_or(0)
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.subject
            .as_ref()
            .map(|subject| subject.tenant_id.as_str())
            .filter(|tenant| !tenant.is_empty())
    }

    pub fn principal_name(&self) -> Option<&str> {
        let subject = self.subject.as_ref()?;
        subject
            .user_id
            .as_deref()
            .or(subject.customer_id.as_deref())
            .or(subject.token_id.as_deref())
    }

    /// The control plane asked this node to reverse-proxy the original request
    /// to the npm surface instead of answering from hosted storage.
    pub fn is_upstream(&self) -> bool {
        self.route.as_deref() == Some(ROUTE_UPSTREAM)
    }

    /// Credential the decision was made for: a publisher token, else a
    /// download-key customer. Empty values are omitted.
    pub fn credential_id(&self) -> Option<&str> {
        let subject = self.subject.as_ref()?;
        nonempty(subject.token_id.as_deref()).or_else(|| nonempty(subject.customer_id.as_deref()))
    }

    pub fn registry_id(&self) -> Option<&str> {
        self.package
            .as_ref()
            .and_then(|package| nonempty(Some(package.registry_id.as_str())))
    }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[derive(Debug, Serialize)]
pub struct ReservePublishRequest<'a> {
    pub request_id: &'a str,
    pub token: &'a str,
    pub host: &'a str,
    pub registry_id: &'a str,
    pub package: &'a str,
    pub version: &'a str,
    pub manifest: &'a Value,
    pub tarball_bytes: u64,
    pub dist_tags: &'a [String],
    pub operation_key: &'a str,
    pub fingerprint: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReserveUpload {
    #[serde(default)]
    pub document_id: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReservePublishResponse {
    pub session_id: String,
    #[serde(default)]
    pub generation: i64,
    #[serde(default)]
    pub package_id: String,
    #[serde(default)]
    pub replayed: bool,
    #[serde(default)]
    pub upload: Option<ReserveUpload>,
}

#[derive(Debug, Serialize)]
pub struct FinalizePublishRequest<'a> {
    pub request_id: &'a str,
    pub token: &'a str,
    pub generation: i64,
    pub fingerprint: &'a str,
    /// The verified version manifest travels again: the control plane stores
    /// it on the committed version and checks it against the reservation's
    /// manifest hash.
    pub manifest: &'a Value,
    pub integrity: &'a str,
    pub shasum: &'a str,
    pub tarball_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct AbortPublishRequest<'a> {
    pub token: &'a str,
    pub generation: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishSession {
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub generation: i64,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishSessionResponse {
    pub session: PublishSession,
}

#[derive(Debug, Serialize)]
pub struct DownloadResolveRequest<'a> {
    pub request_id: &'a str,
    pub token: &'a str,
    pub host: &'a str,
    pub registry_id: &'a str,
    pub package: &'a str,
    pub version: &'a str,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResolvedVersion {
    #[serde(default)]
    pub semver: String,
    #[serde(default)]
    pub integrity: String,
    #[serde(default)]
    pub shasum: String,
    #[serde(default)]
    pub tarball_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DownloadResolveResponse {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub package: Option<PackageSummary>,
    #[serde(default)]
    pub version: Option<ResolvedVersion>,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// Inclusive byte range of a partial (206) transfer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRange {
    pub start: u64,
    pub end: u64,
}

/// One usage observation. Optional fields are omitted when unknown so older
/// control planes still accept the payload. `client_ip` is a trusted edge
/// address only; client-supplied forwarding headers are never copied here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedEvent {
    pub event_id: String,
    pub kind: String,
    pub tenant_id: String,
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    pub bytes: u64,
    pub occurred_at: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<EventRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm_session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<String>,
    /// Aggregate observation count for `kind = "metadata"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// Aggregate 304 count for `kind = "metadata"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_modified: Option<u64>,
}

#[derive(Debug, Serialize)]
struct EventsRequest<'a> {
    events: &'a [ManagedEvent],
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveDomainResponse {
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub registry_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub owner_tenant_id: String,
    #[serde(default)]
    pub revision: i64,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest<'a> {
    pub identity: &'a str,
    pub version: &'a str,
    pub capabilities: &'a [String],
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub config_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FleetConfigResponse {
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub content: Option<Value>,
}

/// HTTP client for the control plane. One client serves every endpoint;
/// timeouts are applied per request.
#[derive(Clone)]
pub struct ControlPlaneClient {
    base_url: String,
    token: String,
    http: Client,
}

impl ControlPlaneClient {
    pub fn new(control_plane_url: &str, token: &str) -> Result<Self, RegistryError> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .pool_idle_timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .tcp_keepalive(Duration::from_secs(30))
            .redirect(Policy::none())
            .build()
            .map_err(|_| RegistryError::Internal)?;
        Ok(Self {
            base_url: format!("{}/api/registry", control_plane_url.trim_end_matches('/')),
            token: token.to_string(),
            http,
        })
    }

    /// Raw client for metadata-proxy and presigned-upload calls (no node
    /// credential is attached by default).
    pub fn http(&self) -> &Client {
        &self.http
    }

    fn post(&self, path: &str, request_id: &str) -> RequestBuilder {
        self.http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("x-request-id", request_id)
    }

    fn get(&self, path: &str, request_id: &str) -> RequestBuilder {
        self.http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("x-request-id", request_id)
    }

    async fn send_json<T: DeserializeOwned>(
        builder: RequestBuilder,
        timeout: Duration,
    ) -> Result<T, ControlPlaneError> {
        let response = builder.timeout(timeout).send().await.map_err(|err| {
            warn!(error = ?err, "control plane call failed");
            ControlPlaneError::Unavailable
        })?;
        Self::parse_response(response).await
    }

    async fn parse_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ControlPlaneError> {
        let status = response.status();
        if !status.is_success() {
            let body = response.json::<Value>().await.ok();
            let (code, message) = body
                .as_ref()
                .and_then(|body| body.get("error"))
                .map(|error| {
                    let code = error
                        .get("code")
                        .and_then(Value::as_str)
                        .or_else(|| error.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    (code, message)
                })
                .unwrap_or_default();
            return Err(ControlPlaneError::Rejected {
                status,
                code,
                message,
            });
        }
        response.json::<T>().await.map_err(|err| {
            warn!(error = ?err, "control plane returned an unreadable payload");
            ControlPlaneError::Unavailable
        })
    }

    pub async fn authorize(
        &self,
        request: &AuthorizeRequest<'_>,
    ) -> Result<AuthorizeDecision, ControlPlaneError> {
        Self::send_json(
            self.post("/v1/authorize", request.request_id).json(request),
            AUTHORIZE_TIMEOUT,
        )
        .await
    }

    pub async fn resolve_domain(
        &self,
        host: &str,
        request_id: &str,
    ) -> Result<Option<ResolveDomainResponse>, ControlPlaneError> {
        let response = self
            .get(
                &format!("/resolve-domain?host={}", urlencoding::encode(host)),
                request_id,
            )
            .timeout(RESOLVE_DOMAIN_TIMEOUT)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "control plane resolve-domain call failed");
                ControlPlaneError::Unavailable
            })?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let parsed: ResolveDomainResponse = Self::parse_response(response).await?;
        Ok(parsed.resolved.then_some(parsed))
    }

    pub async fn reserve_publish(
        &self,
        request: &ReservePublishRequest<'_>,
    ) -> Result<ReservePublishResponse, ControlPlaneError> {
        Self::send_json(
            self.post("/v1/publishes", request.request_id).json(request),
            RESERVE_TIMEOUT,
        )
        .await
    }

    pub async fn finalize_publish(
        &self,
        session_id: &str,
        request: &FinalizePublishRequest<'_>,
    ) -> Result<Value, ControlPlaneError> {
        Self::send_json(
            self.post(
                &format!("/v1/publishes/{session_id}/finalize"),
                request.request_id,
            )
            .json(request),
            FINALIZE_TIMEOUT,
        )
        .await
    }

    /// Resolve an uncertain publish outcome. Retries once when the connection
    /// itself times out (the only retried call in the client).
    pub async fn publish_session(
        &self,
        session_id: &str,
        request_id: &str,
    ) -> Result<PublishSessionResponse, ControlPlaneError> {
        let mut attempt = 0;
        loop {
            let response = self
                .get(&format!("/v1/publishes/{session_id}"), request_id)
                .timeout(SESSION_TIMEOUT)
                .send()
                .await;
            match response {
                Ok(response) => return Self::parse_response(response).await,
                Err(err) if attempt == 0 && err.is_connect() && err.is_timeout() => {
                    attempt += 1;
                    debug!("retrying publish session lookup after connect timeout");
                }
                Err(err) => {
                    warn!(error = ?err, "control plane publish session lookup failed");
                    return Err(ControlPlaneError::Unavailable);
                }
            }
        }
    }

    pub async fn abort_publish(
        &self,
        session_id: &str,
        request: &AbortPublishRequest<'_>,
        request_id: &str,
    ) -> Result<(), ControlPlaneError> {
        let response = self
            .post(&format!("/v1/publishes/{session_id}/abort"), request_id)
            .json(request)
            .timeout(ABORT_TIMEOUT)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "control plane abort call failed");
                ControlPlaneError::Unavailable
            })?;
        if response.status().is_success() {
            return Ok(());
        }
        Self::parse_response::<Value>(response).await.map(|_| ())
    }

    pub async fn resolve_download(
        &self,
        request: &DownloadResolveRequest<'_>,
    ) -> Result<DownloadResolveResponse, ControlPlaneError> {
        Self::send_json(
            self.post("/v1/downloads/resolve", request.request_id)
                .json(request),
            DOWNLOAD_RESOLVE_TIMEOUT,
        )
        .await
    }

    pub async fn send_events(&self, events: &[ManagedEvent]) -> Result<(), ControlPlaneError> {
        if events.is_empty() {
            return Ok(());
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let response = self
            .post("/v1/events", &request_id)
            .json(&EventsRequest { events })
            .timeout(EVENTS_TIMEOUT)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "control plane events call failed");
                ControlPlaneError::Unavailable
            })?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        warn!(
            status = status.as_u16(),
            "control plane events call rejected"
        );
        Err(ControlPlaneError::Rejected {
            status,
            code: String::new(),
            message: String::new(),
        })
    }

    pub async fn heartbeat(
        &self,
        request: &HeartbeatRequest<'_>,
        request_id: &str,
    ) -> Result<HeartbeatResponse, ControlPlaneError> {
        Self::send_json(
            self.post("/v1/fleet/heartbeat", request_id).json(request),
            HEARTBEAT_TIMEOUT,
        )
        .await
    }

    pub async fn fleet_config(
        &self,
        after: i64,
        request_id: &str,
    ) -> Result<FleetConfigResponse, ControlPlaneError> {
        Self::send_json(
            self.get(&format!("/v1/fleet/config?after={after}"), request_id),
            FLEET_CONFIG_TIMEOUT,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authorize_request_serializes_contract_shape() {
        let request = AuthorizeRequest {
            request_id: "req-1",
            token: "npm_abc",
            operation: OP_PACKAGE_PUBLISH,
            host: "npm.example.com",
            registry_id: "",
            package: "@appx/core",
            version: "",
        };
        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            value,
            json!({
                "request_id": "req-1",
                "token": "npm_abc",
                "operation": "package:publish",
                "host": "npm.example.com",
                "package": "@appx/core"
            })
        );
    }

    #[test]
    fn reserve_request_serializes_contract_shape() {
        let manifest = json!({ "name": "@x/y", "version": "1.2.3" });
        let request = ReservePublishRequest {
            request_id: "req-2",
            token: "npm_abc",
            host: "npm.example.com",
            registry_id: "reg_1",
            package: "@x/y",
            version: "1.2.3",
            manifest: &manifest,
            tarball_bytes: 12345,
            dist_tags: &["latest".to_string()],
            operation_key: "op-key",
            fingerprint: "ZmluZ2VycHJpbnQ=",
        };
        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            value,
            json!({
                "request_id": "req-2",
                "token": "npm_abc",
                "host": "npm.example.com",
                "registry_id": "reg_1",
                "package": "@x/y",
                "version": "1.2.3",
                "manifest": { "name": "@x/y", "version": "1.2.3" },
                "tarball_bytes": 12345,
                "dist_tags": ["latest"],
                "operation_key": "op-key",
                "fingerprint": "ZmluZ2VycHJpbnQ="
            })
        );
    }

    #[test]
    fn authorize_decision_parses_contract_shape() {
        let payload = json!({
            "allowed": true,
            "reason": "",
            "expires_at": "2026-09-22T12:00:00Z",
            "subject": {
                "kind": "publisher",
                "tenant_id": "org_1",
                "user_id": "user_1",
                "token_id": "ntok_1",
                "credential_version": 3
            },
            "package": {
                "id": "npkg_1",
                "name": "@appx/core",
                "registry_id": "reg_1",
                "owner_tenant_id": "org_1",
                "visibility": "private",
                "revision": 3
            }
        });
        let decision: AuthorizeDecision = serde_json::from_value(payload).expect("parse decision");
        assert!(decision.allowed);
        assert_eq!(decision.credential_version(), 3);
        assert_eq!(
            decision
                .subject
                .as_ref()
                .and_then(|s| s.token_id.as_deref()),
            Some("ntok_1")
        );
        assert_eq!(decision.tenant_id(), Some("org_1"));
        assert_eq!(decision.principal_name(), Some("user_1"));
        assert!(
            !decision.is_upstream(),
            "absent route is not an upstream forward"
        );
        assert_eq!(decision.credential_id(), Some("ntok_1"));
        let package = decision.package.expect("package summary");
        assert_eq!(package.registry_id, "reg_1");
    }

    #[test]
    fn authorize_decision_parses_upstream_route() {
        let payload = json!({
            "allowed": false,
            "reason": "package_not_found",
            "route": "upstream"
        });
        let decision: AuthorizeDecision = serde_json::from_value(payload).expect("parse");
        assert!(decision.is_upstream());

        let hosted: AuthorizeDecision =
            serde_json::from_value(json!({"allowed": true, "route": "hosted"})).expect("parse");
        assert!(!hosted.is_upstream(), "hosted keeps the local path");
    }

    #[test]
    fn reserve_response_parses_contract_shape() {
        let payload = json!({
            "session_id": "nps_1",
            "generation": 1,
            "package_id": "npkg_1",
            "replayed": false,
            "upload": {
                "document_id": "doc_1",
                "url": "https://storage.example.com/put",
                "headers": { "x-amz-meta": "1" },
                "expires_at": "2026-09-22T12:05:00Z"
            }
        });
        let response: ReservePublishResponse =
            serde_json::from_value(payload).expect("parse reserve");
        assert_eq!(response.session_id, "nps_1");
        assert!(!response.replayed);
        let upload = response.upload.expect("upload capability");
        assert_eq!(upload.url, "https://storage.example.com/put");
        assert_eq!(upload.headers.get("x-amz-meta"), Some(&"1".to_string()));
    }

    #[test]
    fn session_response_parses_contract_shape() {
        let payload = json!({
            "session": {
                "id": "nps_1",
                "status": "committed",
                "generation": 2,
                "expires_at": "2026-09-22T12:05:00Z",
                "result": { "success": true, "ok": "package published" }
            }
        });
        let response: PublishSessionResponse =
            serde_json::from_value(payload).expect("parse session");
        assert_eq!(response.session.status, "committed");
        assert_eq!(
            response.session.result,
            Some(json!({ "success": true, "ok": "package published" }))
        );
    }

    #[test]
    fn download_resolve_parses_contract_shape() {
        let payload = json!({
            "allowed": true,
            "expires_at": "2026-09-22T12:00:00Z",
            "package": {
                "id": "npkg_1",
                "name": "@x/y",
                "registry_id": "reg_1",
                "owner_tenant_id": "org_7",
                "visibility": "private",
                "revision": 4
            },
            "version": {
                "semver": "1.2.3",
                "integrity": "sha512-abc",
                "shasum": "def",
                "tarball_bytes": 42
            },
            "download_url": "https://storage.example.com/get"
        });
        let response: DownloadResolveResponse =
            serde_json::from_value(payload).expect("parse resolve");
        assert!(response.allowed);
        assert_eq!(response.version.expect("version").tarball_bytes, 42);
        assert_eq!(response.package.expect("package").owner_tenant_id, "org_7");
    }

    #[test]
    fn event_serializes_contract_shape() {
        let event = ManagedEvent {
            event_id: "evt-1".to_string(),
            kind: "download".to_string(),
            tenant_id: "org_1".to_string(),
            package: "@x/y".to_string(),
            version: Some("1.2.3".to_string()),
            credential_id: Some("rdk_123".to_string()),
            bytes: 7,
            occurred_at: "2026-09-22T12:00:00Z".to_string(),
            ..ManagedEvent::default()
        };
        let value = serde_json::to_value(&event).expect("serialize");
        assert_eq!(
            value,
            json!({
                "event_id": "evt-1",
                "kind": "download",
                "tenant_id": "org_1",
                "package": "@x/y",
                "version": "1.2.3",
                "credential_id": "rdk_123",
                "bytes": 7,
                "occurred_at": "2026-09-22T12:00:00Z"
            })
        );
    }

    #[test]
    fn heartbeat_serializes_contract_shape() {
        let request = HeartbeatRequest {
            identity: "node-1",
            version: "0.10.0",
            capabilities: &["publish-bridge".to_string()],
        };
        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            value,
            json!({
                "identity": "node-1",
                "version": "0.10.0",
                "capabilities": ["publish-bridge"]
            })
        );
    }
}
