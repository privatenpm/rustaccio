#[cfg(feature = "s3")]
use crate::config::S3TarballStorageConfig;
use crate::{
    config::{Config, TarballStorageBackend},
    error::RegistryError,
};
#[cfg(feature = "s3")]
use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata};
use axum::http::StatusCode;
use serde_json::Value;
#[cfg(feature = "s3")]
use std::collections::HashSet;
#[cfg(feature = "s3")]
use std::error::Error as StdError;
use std::path::PathBuf;
#[cfg(feature = "s3")]
use tracing::warn;
use tracing::{debug, instrument};

#[cfg(feature = "s3")]
const DEFAULT_CA_BUNDLE_PATHS: [&str; 2] =
    ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarballRef {
    pub package: String,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub enum TarballBackend {
    Local(LocalTarballBackend),
    #[cfg(feature = "s3")]
    S3(S3TarballBackend),
}

impl TarballBackend {
    #[instrument(skip(config), fields(backend = ?config.tarball_storage.backend, data_dir = %config.data_dir.display()))]
    pub async fn from_config(config: &Config) -> Result<Self, RegistryError> {
        match config.tarball_storage.backend {
            TarballStorageBackend::Local => {
                let root = config.data_dir.join("tarballs");
                crate::storage::create_startup_dir(&root).await?;
                debug!(root = %root.display(), "initialized local tarball backend");
                Ok(Self::Local(LocalTarballBackend::new(root)))
            }
            TarballStorageBackend::S3 => {
                #[cfg(feature = "s3")]
                {
                    let Some(s3) = config.tarball_storage.s3.as_ref() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "s3 tarball backend configured without s3 section",
                        ));
                    };
                    Ok(Self::S3(S3TarballBackend::new(s3).await?))
                }
                #[cfg(not(feature = "s3"))]
                {
                    Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "s3 tarball backend is not compiled in (enable `s3` feature)",
                    ))
                }
            }
        }
    }

    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        match self {
            Self::Local(backend) => backend.put(package, filename, content).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => {
                // Keep S3 SDK publish writes on a fresh task stack; this avoids stack
                // overflows in all-features parity runs with mocked S3 backends.
                let backend = backend.clone();
                let package = package.to_string();
                let filename = filename.to_string();
                let content = content.to_vec();
                tokio::spawn(async move { backend.put(&package, &filename, &content).await })
                    .await
                    .map_err(|_| RegistryError::Internal)?
            }
        }
    }

    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        match self {
            Self::Local(backend) => backend.get(package, filename).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.get(package, filename).await,
        }
    }

    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        match self {
            Self::Local(backend) => backend.delete(package, filename).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => {
                let backend = backend.clone();
                let package = package.to_string();
                let filename = filename.to_string();
                tokio::spawn(async move { backend.delete(&package, &filename).await })
                    .await
                    .map_err(|_| RegistryError::Internal)?
            }
        }
    }

    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        match self {
            Self::Local(backend) => backend.delete_package(package).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.delete_package(package).await,
        }
    }

    pub async fn list(&self) -> Result<Vec<TarballRef>, RegistryError> {
        match self {
            Self::Local(backend) => backend.list().await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.list().await,
        }
    }

    pub async fn list_package_tarballs(&self, package: &str) -> Result<Vec<String>, RegistryError> {
        match self {
            Self::Local(backend) => backend.list_package_tarballs(package).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.list_package_tarballs(package).await,
        }
    }

    pub async fn list_packages(&self) -> Result<Vec<String>, RegistryError> {
        match self {
            Self::Local(backend) => backend.list_packages().await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.list_packages().await,
        }
    }

    pub async fn read_package_metadata(
        &self,
        package: &str,
    ) -> Result<Option<Value>, RegistryError> {
        match self {
            Self::Local(backend) => backend.read_package_metadata(package).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.read_package_metadata(package).await,
        }
    }

    pub async fn write_package_metadata(
        &self,
        package: &str,
        metadata: &Value,
    ) -> Result<(), RegistryError> {
        match self {
            Self::Local(backend) => backend.write_package_metadata(package, metadata).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => {
                let backend = backend.clone();
                let package = package.to_string();
                let metadata = metadata.clone();
                tokio::spawn(
                    async move { backend.write_package_metadata(&package, &metadata).await },
                )
                .await
                .map_err(|_| RegistryError::Internal)?
            }
        }
    }

    pub async fn load_legacy_package_index(&self) -> Result<Option<Vec<String>>, RegistryError> {
        match self {
            Self::Local(_) => Ok(None),
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.load_legacy_package_index().await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalTarballBackend {
    root: PathBuf,
}

impl LocalTarballBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn package_dir(name: &str) -> String {
        name.replace('/', "__")
    }

    fn package_name(dir: &str) -> String {
        dir.replace("__", "/")
    }

    fn tarball_path(&self, package: &str, filename: &str) -> PathBuf {
        self.root.join(Self::package_dir(package)).join(filename)
    }

    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        let path = self.tarball_path(package, filename);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, content).await?;
        debug!(path = %path.display(), "wrote tarball to local storage");
        Ok(())
    }

    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        let path = self.tarball_path(package, filename);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            debug!(path = %path.display(), "local tarball missing");
            return Ok(None);
        }
        debug!(path = %path.display(), "reading local tarball");
        Ok(Some(tokio::fs::read(path).await?))
    }

    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        let path = self.tarball_path(package, filename);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(false);
        }
        tokio::fs::remove_file(path).await?;
        debug!("deleted local tarball");
        Ok(true)
    }

    #[instrument(skip(self), fields(package))]
    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        let path = self.root.join(Self::package_dir(package));
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            tokio::fs::remove_dir_all(path).await?;
            debug!("deleted local package tarball directory");
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<TarballRef>, RegistryError> {
        let mut out = Vec::new();
        let mut package_dirs = tokio::fs::read_dir(&self.root).await?;

        while let Some(package_dir) = package_dirs.next_entry().await? {
            if !package_dir.file_type().await?.is_dir() {
                continue;
            }

            let encoded = package_dir.file_name().to_string_lossy().to_string();
            let package = Self::package_name(&encoded);
            let mut files = tokio::fs::read_dir(package_dir.path()).await?;

            while let Some(file) = files.next_entry().await? {
                if !file.file_type().await?.is_file() {
                    continue;
                }

                out.push(TarballRef {
                    package: package.clone(),
                    filename: file.file_name().to_string_lossy().to_string(),
                });
            }
        }

        Ok(out)
    }

    pub async fn list_packages(&self) -> Result<Vec<String>, RegistryError> {
        let mut out = Vec::new();
        let mut package_dirs = tokio::fs::read_dir(&self.root).await?;

        while let Some(package_dir) = package_dirs.next_entry().await? {
            if !package_dir.file_type().await?.is_dir() {
                continue;
            }
            let encoded = package_dir.file_name().to_string_lossy().to_string();
            out.push(Self::package_name(&encoded));
        }

        Ok(out)
    }

    pub async fn list_package_tarballs(&self, package: &str) -> Result<Vec<String>, RegistryError> {
        let path = self.root.join(Self::package_dir(package));
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(_) => return Ok(Vec::new()),
        };
        if !metadata.is_dir() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        let mut files = tokio::fs::read_dir(path).await?;
        while let Some(file) = files.next_entry().await? {
            if !file.file_type().await?.is_file() {
                continue;
            }
            out.push(file.file_name().to_string_lossy().to_string());
        }
        Ok(out)
    }

    pub async fn read_package_metadata(
        &self,
        package: &str,
    ) -> Result<Option<Value>, RegistryError> {
        let path = self
            .root
            .join(Self::package_dir(package))
            .join("package.json");
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(None);
        }
        let bytes = tokio::fs::read(path).await?;
        let parsed = serde_json::from_slice::<Value>(&bytes).ok();
        Ok(parsed.filter(Value::is_object))
    }

    pub async fn write_package_metadata(
        &self,
        package: &str,
        metadata: &Value,
    ) -> Result<(), RegistryError> {
        let path = self
            .root
            .join(Self::package_dir(package))
            .join("package.json");
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes = serde_json::to_vec_pretty(metadata)?;
        tokio::fs::write(path, bytes).await?;
        Ok(())
    }
}

#[cfg(feature = "s3")]
#[derive(Debug, Clone)]
pub struct S3TarballBackend {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
    endpoint: String,
}

#[cfg(feature = "s3")]
impl S3TarballBackend {
    const LEGACY_VERDACCIO_DB_FILENAME: &'static str = "verdaccio-s3-db.json";

    #[instrument(skip(cfg), fields(bucket = cfg.bucket, region = cfg.region, endpoint = cfg.endpoint.as_deref().unwrap_or("<aws-default>")))]
    pub async fn new(cfg: &S3TarballStorageConfig) -> Result<Self, RegistryError> {
        if cfg.bucket.trim().is_empty() {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "s3.bucket is required for s3 tarball backend",
            ));
        }

        let endpoint_is_https = cfg
            .endpoint
            .as_deref()
            .map(|endpoint| {
                endpoint
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("https://")
            })
            .unwrap_or(true);

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(cfg.region.clone()));

        // Always set an explicit connector: aws-config is built without its
        // `default-https-client` feature so TLS stays on `ring` (avoids
        // compiling aws-lc-sys alongside the ring already used by reqwest).
        let http_client = if endpoint_is_https {
            let client_builder = aws_smithy_http_client::Builder::new().tls_provider(
                aws_smithy_http_client::tls::Provider::rustls(
                    aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
                ),
            );
            if let Some(ca_bundle) = load_s3_ca_bundle_pem()? {
                let tls_context = aws_smithy_http_client::tls::TlsContext::builder()
                    .with_trust_store(
                        aws_smithy_http_client::tls::TrustStore::empty()
                            .with_native_roots(false)
                            .with_pem_certificate(ca_bundle),
                    )
                    .build()
                    .map_err(|_| RegistryError::Internal)?;
                debug!("configured s3 http client with PEM CA bundle");
                client_builder.tls_context(tls_context).build_https()
            } else {
                client_builder.build_https()
            }
        } else {
            aws_smithy_http_client::Builder::new().build_http()
        };
        loader = loader.http_client(http_client);

        if let (Some(access_key), Some(secret_key)) =
            (cfg.access_key_id.clone(), cfg.secret_access_key.clone())
        {
            loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "rustaccio-static",
            ));
        }

        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(endpoint) = cfg.endpoint.clone() {
            builder = builder.endpoint_url(endpoint);
        }
        if cfg.force_path_style {
            builder = builder.force_path_style(true);
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket: cfg.bucket.clone(),
            prefix: normalize_prefix(&cfg.prefix),
            endpoint: cfg
                .endpoint
                .clone()
                .unwrap_or_else(|| "<aws-default>".to_string()),
        })
    }

    fn key(&self, package: &str, filename: &str) -> String {
        format!("{}{}/{}", self.prefix, package.replace('/', "__"), filename)
    }

    fn package_prefix(&self, package: &str) -> String {
        format!("{}{}/", self.prefix, package.replace('/', "__"))
    }

    fn parse_ref_from_key(&self, key: &str) -> Option<TarballRef> {
        parse_tarball_ref_from_object_key(&self.prefix, key)
    }

    fn verdaccio_dash_key(&self, package: &str, filename: &str) -> String {
        format!("{}{package}/-/{filename}", self.prefix)
    }

    fn verdaccio_plain_key(&self, package: &str, filename: &str) -> String {
        format!("{}{package}/{filename}", self.prefix)
    }

    fn encoded_verdaccio_dash_key(&self, package: &str, filename: &str) -> String {
        format!(
            "{}{}/-/{}",
            self.prefix,
            urlencoding::encode(package),
            filename
        )
    }

    fn encoded_verdaccio_plain_key(&self, package: &str, filename: &str) -> String {
        format!(
            "{}{}/{}",
            self.prefix,
            urlencoding::encode(package),
            filename
        )
    }

    fn candidate_keys_for_tarball(&self, package: &str, filename: &str) -> Vec<String> {
        let mut keys = Vec::new();
        for key in [
            self.key(package, filename),
            self.verdaccio_dash_key(package, filename),
            self.verdaccio_plain_key(package, filename),
            self.encoded_verdaccio_dash_key(package, filename),
            self.encoded_verdaccio_plain_key(package, filename),
        ] {
            if !keys.iter().any(|existing| existing == &key) {
                keys.push(key);
            }
        }
        keys
    }

    fn candidate_prefixes_for_package(&self, package: &str) -> Vec<String> {
        let mut prefixes = Vec::new();
        for prefix in [
            self.package_prefix(package),
            format!("{}{package}/", self.prefix),
            format!("{}{}/", self.prefix, urlencoding::encode(package)),
        ] {
            if !prefixes.iter().any(|existing| existing == &prefix) {
                prefixes.push(prefix);
            }
        }
        prefixes
    }

    fn candidate_keys_for_package_metadata(&self, package: &str) -> Vec<String> {
        let filename = "package.json";
        let mut keys = Vec::new();
        for key in [
            self.key(package, filename),
            self.verdaccio_plain_key(package, filename),
            self.encoded_verdaccio_plain_key(package, filename),
        ] {
            if !keys.iter().any(|existing| existing == &key) {
                keys.push(key);
            }
        }
        keys
    }

    fn candidate_keys_for_legacy_index(&self) -> Vec<String> {
        let mut keys = vec![format!(
            "{}{}",
            self.prefix,
            Self::LEGACY_VERDACCIO_DB_FILENAME
        )];
        if !self.prefix.is_empty() {
            keys.push(Self::LEGACY_VERDACCIO_DB_FILENAME.to_string());
        }
        keys
    }

    async fn get_by_key(&self, key: &str) -> Result<Option<Vec<u8>>, RegistryError> {
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) if is_not_found(&err) => return Ok(None),
            Err(err) => {
                return Err(map_s3_sdk_error(
                    "get_object",
                    &self.endpoint,
                    &self.bucket,
                    Some(key),
                    None,
                    &err,
                ));
            }
        };

        let bytes = response.body.collect().await.map_err(|err| {
            RegistryError::http(
                StatusCode::BAD_GATEWAY,
                format!("s3 get_object stream failed: {err}"),
            )
        })?;
        Ok(Some(bytes.into_bytes().to_vec()))
    }

    async fn exists(&self, key: &str) -> Result<bool, RegistryError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) if is_not_found(&err) => Ok(false),
            Err(err) => Err(map_s3_sdk_error(
                "head_object",
                &self.endpoint,
                &self.bucket,
                Some(key),
                None,
                &err,
            )),
        }
    }

    #[instrument(skip(self, content), fields(package, filename, bytes = content.len()))]
    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        let key = self.verdaccio_plain_key(package, filename);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(aws_sdk_s3::primitives::ByteStream::from(content.to_vec()))
            .send()
            .await
            .map_err(|err| {
                map_s3_sdk_error(
                    "put_object",
                    &self.endpoint,
                    &self.bucket,
                    Some(&key),
                    None,
                    &err,
                )
            })?;
        debug!("uploaded tarball to s3");
        Ok(())
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        for key in self.candidate_keys_for_tarball(package, filename) {
            if let Some(bytes) = self.get_by_key(&key).await? {
                debug!(bytes = bytes.len(), key, "downloaded tarball from s3");
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        for key in self.candidate_keys_for_tarball(package, filename) {
            if !self.exists(&key).await? {
                continue;
            }
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
                .map_err(|err| {
                    map_s3_sdk_error(
                        "delete_object",
                        &self.endpoint,
                        &self.bucket,
                        Some(&key),
                        None,
                        &err,
                    )
                })?;
            debug!("deleted tarball from s3");
            return Ok(true);
        }
        Ok(false)
    }

    #[instrument(skip(self), fields(package))]
    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        for prefix in self.candidate_prefixes_for_package(package) {
            let mut continuation: Option<String> = None;
            loop {
                let mut request = self
                    .client
                    .list_objects_v2()
                    .bucket(&self.bucket)
                    .prefix(prefix.clone());
                if let Some(token) = continuation.clone() {
                    request = request.continuation_token(token);
                }

                let response = request.send().await.map_err(|err| {
                    map_s3_sdk_error(
                        "list_objects_v2",
                        &self.endpoint,
                        &self.bucket,
                        None,
                        Some(&prefix),
                        &err,
                    )
                })?;
                let objects = response.contents();
                for object in objects {
                    if let Some(key) = object.key() {
                        self.client
                            .delete_object()
                            .bucket(&self.bucket)
                            .key(key)
                            .send()
                            .await
                            .map_err(|err| {
                                map_s3_sdk_error(
                                    "delete_object",
                                    &self.endpoint,
                                    &self.bucket,
                                    Some(key),
                                    Some(&prefix),
                                    &err,
                                )
                            })?;
                    }
                }

                if response.is_truncated.unwrap_or(false) {
                    continuation = response.next_continuation_token;
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<TarballRef>, RegistryError> {
        let mut continuation: Option<String> = None;
        let mut out = Vec::new();

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(self.prefix.clone());
            if let Some(token) = continuation.clone() {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|err| {
                map_s3_sdk_error(
                    "list_objects_v2",
                    &self.endpoint,
                    &self.bucket,
                    None,
                    Some(&self.prefix),
                    &err,
                )
            })?;
            for object in response.contents() {
                if let Some(key) = object.key()
                    && let Some(reference) = self.parse_ref_from_key(key)
                {
                    out.push(reference);
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(out)
    }

    pub async fn list_packages(&self) -> Result<Vec<String>, RegistryError> {
        let mut continuation: Option<String> = None;
        let mut packages = HashSet::new();

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(self.prefix.clone());
            if let Some(token) = continuation.clone() {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|err| {
                map_s3_sdk_error(
                    "list_objects_v2",
                    &self.endpoint,
                    &self.bucket,
                    None,
                    Some(&self.prefix),
                    &err,
                )
            })?;
            for object in response.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                if let Some(reference) = self.parse_ref_from_key(key) {
                    packages.insert(reference.package);
                    continue;
                }
                if let Some(package) = parse_package_from_metadata_object_key(&self.prefix, key) {
                    packages.insert(package);
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation = response.next_continuation_token;
            } else {
                break;
            }
        }

        let mut out = packages.into_iter().collect::<Vec<_>>();
        out.sort();
        Ok(out)
    }

    pub async fn list_package_tarballs(&self, package: &str) -> Result<Vec<String>, RegistryError> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        for prefix in self.candidate_prefixes_for_package(package) {
            let mut continuation: Option<String> = None;
            loop {
                let mut request = self
                    .client
                    .list_objects_v2()
                    .bucket(&self.bucket)
                    .prefix(prefix.clone());
                if let Some(token) = continuation.clone() {
                    request = request.continuation_token(token);
                }

                let response = request.send().await.map_err(|err| {
                    map_s3_sdk_error(
                        "list_objects_v2",
                        &self.endpoint,
                        &self.bucket,
                        None,
                        Some(&prefix),
                        &err,
                    )
                })?;
                for object in response.contents() {
                    let Some(key) = object.key() else {
                        continue;
                    };
                    let Some(reference) = self.parse_ref_from_key(key) else {
                        continue;
                    };
                    if reference.package == package && seen.insert(reference.filename.clone()) {
                        out.push(reference.filename);
                    }
                }

                if response.is_truncated.unwrap_or(false) {
                    continuation = response.next_continuation_token;
                } else {
                    break;
                }
            }
        }

        out.sort();
        Ok(out)
    }

    pub async fn read_package_metadata(
        &self,
        package: &str,
    ) -> Result<Option<Value>, RegistryError> {
        for key in self.candidate_keys_for_package_metadata(package) {
            let Some(bytes) = self.get_by_key(&key).await? else {
                continue;
            };
            let parsed = serde_json::from_slice::<Value>(&bytes).ok();
            if let Some(value) = parsed.filter(Value::is_object) {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub async fn write_package_metadata(
        &self,
        package: &str,
        metadata: &Value,
    ) -> Result<(), RegistryError> {
        let key = self.verdaccio_plain_key(package, "package.json");
        let body = serde_json::to_vec_pretty(metadata)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body))
            .send()
            .await
            .map_err(|err| {
                map_s3_sdk_error(
                    "put_object",
                    &self.endpoint,
                    &self.bucket,
                    Some(&key),
                    None,
                    &err,
                )
            })?;
        Ok(())
    }

    pub async fn load_legacy_package_index(&self) -> Result<Option<Vec<String>>, RegistryError> {
        for key in self.candidate_keys_for_legacy_index() {
            let Some(bytes) = self.get_by_key(&key).await? else {
                continue;
            };
            let parsed = serde_json::from_slice::<Value>(&bytes).ok();
            let list = parsed
                .as_ref()
                .and_then(|value| value.get("list"))
                .and_then(Value::as_array)
                .map(|array| {
                    array
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                });
            if let Some(packages) = list {
                return Ok(Some(packages));
            }
        }
        Ok(None)
    }
}

#[cfg(feature = "s3")]
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

#[cfg(feature = "s3")]
fn parse_tarball_ref_from_object_key(prefix: &str, key: &str) -> Option<TarballRef> {
    let rest = key.strip_prefix(prefix)?.trim_matches('/');
    if rest.is_empty() || !(rest.ends_with(".tgz") || rest.ends_with(".tar.gz")) {
        return None;
    }

    let (package_raw, filename, from_dash_layout) =
        if let Some((package, filename)) = rest.split_once("/-/") {
            if filename.is_empty() || filename.contains('/') {
                return None;
            }
            (package, filename, true)
        } else {
            let (package, filename) = rest.rsplit_once('/')?;
            if package.is_empty() || filename.is_empty() || filename.contains('/') {
                return None;
            }
            (package, filename, false)
        };

    let decoded = urlencoding::decode(package_raw)
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| package_raw.to_string());
    let package = if from_dash_layout || decoded.contains('/') {
        decoded
    } else {
        decoded.replace("__", "/")
    };
    if package.is_empty() {
        return None;
    }

    Some(TarballRef {
        package,
        filename: filename.to_string(),
    })
}

#[cfg(feature = "s3")]
fn parse_package_from_metadata_object_key(prefix: &str, key: &str) -> Option<String> {
    let rest = key.strip_prefix(prefix)?.trim_matches('/');
    if rest.is_empty() || !rest.ends_with("/package.json") {
        return None;
    }
    let package_raw = rest.strip_suffix("/package.json")?;
    if package_raw.is_empty() {
        return None;
    }

    let decoded = urlencoding::decode(package_raw)
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| package_raw.to_string());
    if decoded.contains('/') {
        return Some(decoded);
    }
    if decoded.contains("__") {
        return Some(decoded.replace("__", "/"));
    }
    Some(decoded)
}

#[cfg(feature = "s3")]
fn load_s3_ca_bundle_pem() -> Result<Option<Vec<u8>>, RegistryError> {
    if let Some(path) = load_env_value("RUSTACCIO_S3_CA_BUNDLE")
        && !path.trim().is_empty()
    {
        let bytes = std::fs::read(&path).map_err(|err| {
            RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read RUSTACCIO_S3_CA_BUNDLE at {path}: {err}"),
            )
        })?;
        return Ok(Some(strip_non_certificate_lines(bytes)));
    }

    for path in DEFAULT_CA_BUNDLE_PATHS {
        if let Ok(bytes) = std::fs::read(path) {
            debug!(path, "loaded system CA bundle for s3 tls");
            return Ok(Some(strip_non_certificate_lines(bytes)));
        }
    }

    Ok(None)
}

#[cfg(feature = "s3")]
fn load_env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

#[cfg(feature = "s3")]
fn strip_non_certificate_lines(input: Vec<u8>) -> Vec<u8> {
    let text = String::from_utf8_lossy(&input);
    let mut out = String::new();
    let mut in_cert = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
        }
        if in_cert {
            out.push_str(line);
            out.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
        }
    }
    if out.is_empty() {
        input
    } else {
        out.into_bytes()
    }
}

#[cfg(feature = "s3")]
fn map_s3_sdk_error<E>(
    operation: &str,
    endpoint: &str,
    bucket: &str,
    key: Option<&str>,
    prefix: Option<&str>,
    err: &aws_sdk_s3::error::SdkError<E>,
) -> RegistryError
where
    E: ProvideErrorMetadata + StdError + std::fmt::Debug + 'static,
{
    let http_status = s3_http_status(err);
    let aws_code = err.code().unwrap_or("unknown");
    let aws_message = err.message().unwrap_or("");
    let aws_request_id = s3_error_header(err, "x-amz-request-id").unwrap_or("<none>");
    let aws_extended_request_id = s3_error_header(err, "x-amz-id-2").unwrap_or("<none>");
    let response_server = s3_error_header(err, "server").unwrap_or("<none>");
    let response_via = s3_error_header(err, "via").unwrap_or("<none>");
    let response_content_type = s3_error_header(err, "content-type").unwrap_or("<none>");
    let key = key.filter(|value| !value.is_empty()).unwrap_or("<none>");
    let prefix = prefix
        .map(|value| if value.is_empty() { "<root>" } else { value })
        .unwrap_or("<none>");

    warn!(
        operation,
        bucket,
        endpoint,
        key,
        prefix,
        http_status = http_status.as_u16(),
        sdk_error_kind = s3_sdk_error_kind(err),
        aws_code = ?err.code(),
        aws_message = ?err.message(),
        aws_request_id,
        aws_extended_request_id,
        response_server,
        response_via,
        response_content_type,
        sdk_error = %DisplayErrorContext(err),
        "s3 operation failed"
    );

    let detail = if aws_message.is_empty() {
        aws_code.to_string()
    } else {
        format!("{aws_code} - {aws_message}")
    };
    RegistryError::http(
        http_status,
        format!(
            "s3 {operation} failed (status {}): {detail}",
            http_status.as_u16()
        ),
    )
}

#[cfg(feature = "s3")]
fn s3_http_status<E>(err: &aws_sdk_s3::error::SdkError<E>) -> StatusCode
where
    E: ProvideErrorMetadata,
{
    if let Some(status) = err
        .raw_response()
        .and_then(|response| StatusCode::from_u16(response.status().as_u16()).ok())
    {
        return status;
    }

    match err {
        aws_sdk_s3::error::SdkError::TimeoutError(_)
        | aws_sdk_s3::error::SdkError::DispatchFailure(_) => StatusCode::SERVICE_UNAVAILABLE,
        aws_sdk_s3::error::SdkError::ConstructionFailure(_)
        | aws_sdk_s3::error::SdkError::ResponseError(_)
        | aws_sdk_s3::error::SdkError::ServiceError(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::BAD_GATEWAY,
    }
}

#[cfg(feature = "s3")]
fn s3_error_header<'a, E>(
    err: &'a aws_sdk_s3::error::SdkError<E>,
    header: &str,
) -> Option<&'a str> {
    err.raw_response()
        .and_then(|response| response.headers().get(header))
}

#[cfg(feature = "s3")]
fn s3_sdk_error_kind<E, R>(err: &aws_sdk_s3::error::SdkError<E, R>) -> &'static str {
    match err {
        aws_sdk_s3::error::SdkError::ConstructionFailure(_) => "construction_failure",
        aws_sdk_s3::error::SdkError::TimeoutError(_) => "timeout",
        aws_sdk_s3::error::SdkError::DispatchFailure(_) => "dispatch_failure",
        aws_sdk_s3::error::SdkError::ResponseError(_) => "response_error",
        aws_sdk_s3::error::SdkError::ServiceError(_) => "service_error",
        _ => "unknown",
    }
}

#[cfg(feature = "s3")]
fn is_not_found<E>(err: &aws_sdk_s3::error::SdkError<E>) -> bool {
    err.raw_response()
        .map(|response| response.status().as_u16() == 404)
        .unwrap_or(false)
}

#[cfg(all(test, feature = "s3"))]
mod tests {
    use super::{
        TarballRef, parse_package_from_metadata_object_key, parse_tarball_ref_from_object_key,
        s3_http_status, s3_sdk_error_kind,
    };
    use axum::http::StatusCode;
    use std::io;

    #[test]
    fn parses_rustaccio_legacy_key_layout() {
        let key = "registry/@scope__pkg/pkg-1.2.3.tgz";
        let parsed = parse_tarball_ref_from_object_key("registry/", key);
        assert_eq!(
            parsed,
            Some(TarballRef {
                package: "@scope/pkg".to_string(),
                filename: "pkg-1.2.3.tgz".to_string(),
            })
        );
    }

    #[test]
    fn parses_verdaccio_dash_key_layout() {
        let key = "registry/@scope/pkg/-/pkg-1.2.3.tgz";
        let parsed = parse_tarball_ref_from_object_key("registry/", key);
        assert_eq!(
            parsed,
            Some(TarballRef {
                package: "@scope/pkg".to_string(),
                filename: "pkg-1.2.3.tgz".to_string(),
            })
        );
    }

    #[test]
    fn parses_verdaccio_encoded_dash_key_layout() {
        let key = "registry/%40scope%2fpkg/-/pkg-1.2.3.tgz";
        let parsed = parse_tarball_ref_from_object_key("registry/", key);
        assert_eq!(
            parsed,
            Some(TarballRef {
                package: "@scope/pkg".to_string(),
                filename: "pkg-1.2.3.tgz".to_string(),
            })
        );
    }

    #[test]
    fn parses_verdaccio_package_metadata_layout() {
        let key = "registry/@scope/pkg/package.json";
        let parsed = parse_package_from_metadata_object_key("registry/", key);
        assert_eq!(parsed.as_deref(), Some("@scope/pkg"));
    }

    #[test]
    fn parses_verdaccio_encoded_package_metadata_layout() {
        let key = "registry/%40scope%2fpkg/package.json";
        let parsed = parse_package_from_metadata_object_key("registry/", key);
        assert_eq!(parsed.as_deref(), Some("@scope/pkg"));
    }

    #[test]
    fn classifies_sdk_error_variants_for_logging() {
        type TestSdkError = aws_sdk_s3::error::SdkError<aws_sdk_s3::error::ErrorMetadata, ()>;

        let construction = TestSdkError::construction_failure(io::Error::other("build"));
        assert_eq!(s3_sdk_error_kind(&construction), "construction_failure");

        let timeout = TestSdkError::timeout_error(io::Error::other("timeout"));
        assert_eq!(s3_sdk_error_kind(&timeout), "timeout");

        let dispatch = TestSdkError::dispatch_failure(aws_sdk_s3::error::ConnectorError::other(
            io::Error::other("dispatch").into(),
            None,
        ));
        assert_eq!(s3_sdk_error_kind(&dispatch), "dispatch_failure");

        let response = TestSdkError::response_error(io::Error::other("response"), ());
        assert_eq!(s3_sdk_error_kind(&response), "response_error");

        let service = TestSdkError::service_error(
            aws_sdk_s3::error::ErrorMetadata::builder()
                .message("service")
                .build(),
            (),
        );
        assert_eq!(s3_sdk_error_kind(&service), "service_error");
    }

    #[test]
    fn maps_transport_s3_errors_to_service_unavailable() {
        type TestSdkError = aws_sdk_s3::error::SdkError<
            aws_sdk_s3::operation::get_object::GetObjectError,
            aws_sdk_s3::config::http::HttpResponse,
        >;

        let timeout = TestSdkError::timeout_error(io::Error::other("timeout"));
        assert_eq!(s3_http_status(&timeout), StatusCode::SERVICE_UNAVAILABLE);

        let dispatch = TestSdkError::dispatch_failure(aws_sdk_s3::error::ConnectorError::other(
            io::Error::other("dispatch").into(),
            None,
        ));
        assert_eq!(s3_http_status(&dispatch), StatusCode::SERVICE_UNAVAILABLE);
    }
}
