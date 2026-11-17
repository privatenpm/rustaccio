use crate::{constants::API_ERROR_SERVER_TIME_OUT, error::RegistryError};
use axum::http::{Method, StatusCode};
use reqwest::{Client, redirect::Policy};
use serde_json::Value;
use std::{sync::OnceLock, time::Duration};
use tracing::{debug, instrument, warn};

#[derive(Debug, Clone)]
pub struct UpstreamPassthroughResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    base_url: String,
    client: Client,
}

impl Upstream {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: shared_client(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[instrument(skip(self), fields(package = package_name, upstream = %self.base_url))]
    pub async fn fetch_package(&self, package_name: &str) -> Result<Option<Value>, RegistryError> {
        let encoded = urlencoding::encode(package_name);
        let url = format!("{}/{}", self.base_url, encoded);
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(map_uplink_request_err)?;
        if resp.status() == StatusCode::NOT_FOUND {
            debug!(
                status = resp.status().as_u16(),
                outcome = "miss",
                "package not found upstream"
            );
            return Ok(None);
        }
        if resp.status() == StatusCode::NOT_MODIFIED {
            debug!(
                status = resp.status().as_u16(),
                outcome = "not_modified",
                "package not modified upstream"
            );
            return Ok(None);
        }
        if matches!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
        ) {
            warn!(
                status = resp.status().as_u16(),
                outcome = "transient_error",
                reason = "upstream_status",
                "upstream package request returned transient status"
            );
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                API_ERROR_SERVER_TIME_OUT,
            ));
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                outcome = "non_transient_error",
                reason = "unexpected_status",
                "unexpected uplink package status"
            );
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let value = resp.json::<Value>().await.map_err(|_| {
            warn!(
                outcome = "non_transient_error",
                reason = "bad_payload",
                "upstream package response was not valid JSON"
            );
            RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload")
        })?;
        debug!("fetched package from upstream");
        Ok(Some(value))
    }

    #[instrument(skip(self), fields(has_query = !query.is_empty(), upstream = %self.base_url))]
    pub async fn fetch_search(&self, query: &str) -> Result<Vec<Value>, RegistryError> {
        let url = if query.is_empty() {
            format!("{}/-/v1/search", self.base_url)
        } else {
            format!("{}/-/v1/search?{}", self.base_url, query)
        };
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(map_uplink_request_err)?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if matches!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
        ) {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                API_ERROR_SERVER_TIME_OUT,
            ));
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected uplink search status"
            );
            return Ok(Vec::new());
        }

        let body = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        let objects = body
            .get("objects")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        debug!(result_count = objects.len(), "fetched upstream search");
        Ok(objects)
    }

    #[instrument(skip(self), fields(upstream = %self.base_url))]
    pub async fn fetch_tarball(&self, tarball_url: &str) -> Result<Option<Vec<u8>>, RegistryError> {
        let resp = self
            .client
            .get(tarball_url)
            .send()
            .await
            .map_err(map_uplink_request_err)?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if matches!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
        ) {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                API_ERROR_SERVER_TIME_OUT,
            ));
        }

        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected uplink tarball status"
            );
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        debug!(bytes = bytes.len(), "fetched upstream tarball");
        Ok(Some(bytes.to_vec()))
    }

    pub async fn post_security_advisories_bulk(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/advisories/bulk", payload)
            .await
    }

    pub async fn post_security_audits_quick(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/audits/quick", payload)
            .await
    }

    pub async fn post_security_audits(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/audits", payload)
            .await
    }

    pub async fn passthrough_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> Result<Option<UpstreamPassthroughResponse>, RegistryError> {
        let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|_| RegistryError::Internal)?;
        let mut url = format!("{}{}", self.base_url, path);
        if let Some(query) = query
            && !query.is_empty()
        {
            url.push('?');
            url.push_str(query);
        }

        let resp = self
            .client
            .request(req_method, url)
            .send()
            .await
            .map_err(map_uplink_request_err)?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let body = resp
            .bytes()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;

        Ok(Some(UpstreamPassthroughResponse {
            status,
            body: body.to_vec(),
            content_type,
        }))
    }

    #[instrument(
        level = "debug",
        skip(self, payload),
        fields(path = %path, upstream = %self.base_url)
    )]
    async fn post_json_path(
        &self,
        path: &str,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = match self.client.post(url).json(payload).send().await {
            Ok(resp) => resp,
            Err(_) => {
                warn!("upstream post request failed");
                return Ok(None);
            }
        };

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected upstream post status"
            );
            return Ok(None);
        }

        let value = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        debug!("received upstream post response");
        Ok(Some(value))
    }

    pub fn default_tarball_url(&self, package_name: &str, filename: &str) -> String {
        format!(
            "{}/{}/-/{}",
            self.base_url,
            urlencoding::encode(package_name),
            filename
        )
    }
}

fn shared_client() -> Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .connect_timeout(Duration::from_secs(env_u64(
                    "RUSTACCIO_UPSTREAM_CONNECT_TIMEOUT_SECS",
                    3,
                )))
                .timeout(Duration::from_secs(env_u64(
                    "RUSTACCIO_UPSTREAM_TIMEOUT_SECS",
                    20,
                )))
                .pool_idle_timeout(Duration::from_secs(env_u64(
                    "RUSTACCIO_UPSTREAM_POOL_IDLE_TIMEOUT_SECS",
                    30,
                )))
                .pool_max_idle_per_host(env_usize(
                    "RUSTACCIO_UPSTREAM_POOL_MAX_IDLE_PER_HOST",
                    4,
                    1,
                    1024,
                ))
                .tcp_keepalive(Duration::from_secs(env_u64(
                    "RUSTACCIO_UPSTREAM_TCP_KEEPALIVE_SECS",
                    30,
                )))
                .http1_only()
                .redirect(Policy::limited(5))
                .build()
                .unwrap_or_else(|_| Client::new())
        })
        .clone()
}

fn env_u64(key: &str, default: u64) -> u64 {
    load_env_value(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    load_env_value(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn load_env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn map_uplink_request_err(err: reqwest::Error) -> RegistryError {
    let reason = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect_error"
    } else if err.is_decode() {
        "decode_error"
    } else if err.is_body() {
        "body_error"
    } else if err.is_redirect() {
        "redirect_error"
    } else if err.is_request() {
        "request_error"
    } else if err.is_builder() {
        "builder_error"
    } else {
        "unknown_request_error"
    };
    warn!(reason, error = %err, "uplink request failed");
    if err.is_timeout() {
        return RegistryError::http(StatusCode::SERVICE_UNAVAILABLE, API_ERROR_SERVER_TIME_OUT);
    }
    RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline")
}
