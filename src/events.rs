use crate::{error::RegistryError, models::TenantContext};
use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryEvent {
    pub event_type: String,
    pub occurred_at: String,
    pub actor: Option<String>,
    pub package: Option<String>,
    pub request_id: Option<String>,
    pub tenant: TenantContext,
    pub attributes: Value,
}

impl RegistryEvent {
    pub fn new(
        event_type: impl Into<String>,
        actor: Option<String>,
        package: Option<String>,
        request_id: Option<String>,
        tenant: TenantContext,
        attributes: Value,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            occurred_at: jiff::Timestamp::now().to_string(),
            actor,
            package,
            request_id,
            tenant,
            attributes,
        }
    }
}

#[async_trait]
trait EventSink: Send + Sync {
    async fn emit(&self, event: &RegistryEvent) -> Result<(), RegistryError>;
}

#[derive(Default)]
struct NoopEventSink;

#[async_trait]
impl EventSink for NoopEventSink {
    async fn emit(&self, _event: &RegistryEvent) -> Result<(), RegistryError> {
        Ok(())
    }
}

struct HttpEventSink {
    endpoint_url: String,
    client: Client,
}

impl HttpEventSink {
    fn new(endpoint_url: String, timeout_ms: u64) -> Result<Self, RegistryError> {
        let timeout = Duration::from_millis(timeout_ms.max(250));
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

        debug!(endpoint_url, timeout_ms, "initialized registry event sink");
        Ok(Self {
            endpoint_url,
            client,
        })
    }

    fn from_env() -> Result<Self, RegistryError> {
        let base_url = std::env::var("RUSTACCIO_EVENT_HTTP_BASE_URL")
            .ok()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        if base_url.is_empty() {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RUSTACCIO_EVENT_SINK=http requires RUSTACCIO_EVENT_HTTP_BASE_URL",
            ));
        }
        let endpoint = std::env::var("RUSTACCIO_EVENT_HTTP_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/events/registry".to_string());
        let endpoint = normalize_endpoint(&endpoint);
        let timeout_ms = parse_u64_env("RUSTACCIO_EVENT_HTTP_TIMEOUT_MS", 2_000).max(250);
        let endpoint_url = format!("{base_url}{endpoint}");
        Self::new(endpoint_url, timeout_ms)
    }
}

#[async_trait]
impl EventSink for HttpEventSink {
    async fn emit(&self, event: &RegistryEvent) -> Result<(), RegistryError> {
        let mut request_builder = self.client.post(&self.endpoint_url);
        if let Some(request_id) = event.request_id.as_deref() {
            request_builder = request_builder.header("x-request-id", request_id);
        }
        let response =
            request_builder.json(event).send().await.map_err(|_| {
                RegistryError::upstream_bad_gateway("registry event sink unavailable")
            })?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status().as_u16();
        Err(RegistryError::upstream_bad_gateway(format!(
            "registry event sink returned status {status}"
        )))
    }
}

#[derive(Clone)]
pub struct EventDispatcher {
    sink: Arc<dyn EventSink>,
}

impl EventDispatcher {
    pub fn disabled() -> Self {
        Self {
            sink: Arc::new(NoopEventSink),
        }
    }

    pub fn from_env() -> Result<Self, RegistryError> {
        let sink = std::env::var("RUSTACCIO_EVENT_SINK")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "none".to_string());
        let sink_impl: Arc<dyn EventSink> = match sink.as_str() {
            "none" => Arc::new(NoopEventSink),
            "http" => Arc::new(HttpEventSink::from_env()?),
            other => {
                return Err(RegistryError::http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unsupported RUSTACCIO_EVENT_SINK: {other} (expected none|http)"),
                ));
            }
        };
        Ok(Self { sink: sink_impl })
    }

    pub async fn emit_best_effort(&self, event: RegistryEvent) {
        if let Err(error) = self.sink.emit(&event).await {
            warn!(
                event_type = event.event_type.as_str(),
                request_id = event.request_id.as_deref().unwrap_or("-"),
                error = ?error,
                "failed to emit registry event"
            );
        }
    }
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
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

#[cfg(test)]
mod tests {
    use super::{EventDispatcher, RegistryEvent, normalize_endpoint};
    use crate::models::TenantContext;
    use serde_json::json;

    #[test]
    fn normalize_endpoint_handles_missing_slash() {
        assert_eq!(normalize_endpoint("/events"), "/events");
        assert_eq!(normalize_endpoint("events"), "/events");
    }

    #[tokio::test]
    async fn disabled_dispatcher_accepts_events() {
        let dispatcher = EventDispatcher::disabled();
        let event = RegistryEvent::new(
            "package.published",
            Some("alice".to_string()),
            Some("demo".to_string()),
            Some("req-event-1".to_string()),
            TenantContext::default(),
            json!({"ok": true}),
        );
        dispatcher.emit_best_effort(event).await;
    }
}
