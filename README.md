# rustaccio

![Rustaccio logo](docs/logo.png)

A Rust/Tokio/Axum npm registry proxy inspired by Verdaccio core behavior.

## Compatibility Policy

Rustaccio prioritizes npm client compatibility for common Verdaccio workflows (install, publish, dist-tags, auth, and uplink proxying). It does not guarantee byte-for-byte parity with Verdaccio internals or edge-case behavior; known differences and current limits are documented in [Verdaccio Differences and Limits](#verdaccio-differences-and-limits).

## Quick Start

1. Copy the example config:

```bash
cp config.example.yml config.yml
```

2. Start the server with that config:

```bash
cargo run -- --config ./config.yml
```

3. Point npm to Rustaccio:

```bash
npm config set registry http://127.0.0.1:4873/
```

## Authentication

Rustaccio supports exactly two authentication modes:

1. **No auth (anonymous)** — `RUSTACCIO_AUTH_BACKEND=none` (or unset). All requests are anonymous and are subject to ACL/policy rules.
2. **External HTTP token auth** — `RUSTACCIO_AUTH_BACKEND=http` with a request-auth endpoint. Incoming bearer tokens are verified by POSTing to an external auth service, which returns the caller's identity (`username`/`groups`).

There is no local user database. Rustaccio does not create users, issue tokens, or manage passwords. Tokens are issued **out of band** by the external system; clients place a pre-issued bearer token in their `.npmrc`:

```
//<registry-host>/:_authToken=<token>
```

External HTTP token auth env example:

```
RUSTACCIO_AUTH_BACKEND=http
RUSTACCIO_AUTH_HTTP_BASE_URL=http://your-auth-service:8080
RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT=/request-auth
```

`GET /-/whoami` returns the username resolved from the external identity when a valid bearer token is sent. The token-to-identity contract is documented in [`docs/contracts/auth-request-v1.md`](docs/contracts/auth-request-v1.md). Optional ACL/policy hooks (`allowAccessEndpoint`/`allowPublishEndpoint`/`allowUnpublishEndpoint`) and `RUSTACCIO_AUTH_HTTP_TIMEOUT_MS` are described in [HTTP Auth Plugin Contract](#http-auth-plugin-contract).

## Deployment

Standalone with defaults (no config file):

```bash
cargo run
```

Standalone with explicit config file:

```bash
cargo run -- --config ./config.yml
```

Standalone help:

```bash
cargo run -- --help
```

Release binary:

```bash
cargo build --release
./target/release/rustaccio --config ./config.yml
```

Maximum-optimization distribution build:

```bash
cargo build --profile dist
./target/dist/rustaccio --config ./config.yml
```

Container (local build + run):

```bash
docker build -t rustaccio:local .
# Lower memory pressure on constrained builders (slower compile):
docker build --build-arg CARGO_BUILD_JOBS=1 -t rustaccio:local .
# Build image with managed-profile backends enabled at compile-time:
docker build \
  --build-arg CARGO_FEATURES="s3,redis,postgres,otel" \
  -t rustaccio:managed .

docker run --rm -p 4873:4873 \
  -v "$(pwd)/.rustaccio-data:/var/lib/rustaccio/data" \
  -v "$(pwd)/config.yml:/etc/rustaccio/config.yml:ro" \
  -e RUSTACCIO_CONFIG=/etc/rustaccio/config.yml \
  rustaccio:local
```

The Docker image compiles `rustaccio` with `--features s3` by default.
Override compile-time features with `--build-arg CARGO_FEATURES=...` when you need optional backends:

- `redis` for distributed rate limiting (`RUSTACCIO_RATE_LIMIT_BACKEND=redis`)
- `postgres` for persistent quota backend (`RUSTACCIO_QUOTA_BACKEND=postgres`)
- `otel` for OTLP tracing export (`RUSTACCIO_OTEL_ENABLED=true`)

If a backend is configured at runtime without its compile-time feature, startup fails fast.
The image does not include `config.example.yml`; mount your own config and set `RUSTACCIO_CONFIG`.

`--config` loads the given YAML file and fails fast if the file cannot be read or parsed.
`RUSTACCIO_CONFIG` and `RUSTACCIO_CONFIG_BASE64` remain available as environment-variable alternatives.
Unified merge precedence is:

`defaults < RUSTACCIO_CONFIG or RUSTACCIO_CONFIG_BASE64 < --config file < environment variables`.

`main` delegates to library runtime (`rustaccio::runtime::run_from_env()`), so standalone and embedded usage share the same config/runtime path.
The full `RUSTACCIO_*` environment variable list is generated into `.env.example` via `cargo run --bin sync_examples`.

Environment variables:

- `RUSTACCIO_BIND` (default `127.0.0.1:4873`)
- `PORT` (optional platform-assigned port; when set, rustaccio binds to `0.0.0.0:$PORT` and this takes precedence over `RUSTACCIO_BIND`)
- `RUSTACCIO_DATA_DIR` (default `.rustaccio-data`)
- `RUSTACCIO_CONFIG` (optional Verdaccio-style YAML; loads `packages` ACL rules + `uplinks`)
- `RUSTACCIO_CONFIG_BASE64` (optional base64-encoded Verdaccio-style YAML; mutually exclusive with `RUSTACCIO_CONFIG`)
- `RUSTACCIO_UPSTREAM` (optional, eg `https://registry.npmjs.org`)
- `RUSTACCIO_WEB_ENABLE` (default `true`)
- `RUSTACCIO_WEB_TITLE` (default `Rustaccio`; used by built-in web UI title)
- `RUSTACCIO_PUBLISH_CHECK_OWNERS` (default `false`; enforces owner-only package mutations)
- `RUSTACCIO_MAX_BODY_SIZE` (default `50mb`, accepts `kb|mb|gb` suffixes)
- `RUSTACCIO_AUDIT_ENABLED` (default `true`)
- `RUSTACCIO_URL_PREFIX` (default `/`)
- `RUSTACCIO_TRUST_PROXY` (default `false`)
- `RUSTACCIO_KEEP_ALIVE_TIMEOUT` (seconds, optional; applied as HTTP/1 keep-alive/header-read timeout)
- `RUSTACCIO_REQUEST_TIMEOUT_SECS` (default `30`, clamps `1..=300`)
- `RUSTACCIO_LOG_LEVEL` (default `info`)
- `RUSTACCIO_LOG_FORMAT` (`auto`, `pretty`, `compact`, or `json`, default `auto`: `pretty` on an interactive terminal, `json` otherwise; colours only on a terminal and never with `NO_COLOR`)
- `RUSTACCIO_VERBOSE_DEP_LOGS` (default `false`; set `true`/`1` to keep noisy dependency targets at your chosen `RUST_LOG` level)
- `RUST_LOG` (optional full tracing filter; overrides default `rustaccio=<level>,tower_http=info`)
- `RUSTACCIO_TOKIO_WORKER_THREADS` (default `min(max(available_parallelism, 2), 8)`)
- `RUSTACCIO_TOKIO_MAX_BLOCKING_THREADS` (default `64`)
- `RUSTACCIO_TOKIO_THREAD_STACK_SIZE` (bytes, default `1048576`)
- `RUSTACCIO_STARTUP_CONNECTIVITY_CHECK` (default `false`; when enabled, runs non-fatal startup TCP reachability checks for `https://registry.npmjs.org` and the configured tarball S3 endpoint, logging IPv4 and IPv6 results separately)
- `RUSTACCIO_UPSTREAM_CONNECT_TIMEOUT_SECS` (default `3`)
- `RUSTACCIO_UPSTREAM_TIMEOUT_SECS` (default `20`)
- `RUSTACCIO_UPSTREAM_POOL_IDLE_TIMEOUT_SECS` (default `30`)
- `RUSTACCIO_UPSTREAM_POOL_MAX_IDLE_PER_HOST` (default `4`)
- `RUSTACCIO_UPSTREAM_TCP_KEEPALIVE_SECS` (default `30`)
- `RUSTACCIO_AUTH_BACKEND` (`none` or `http`, default `none`; `none`/unset means all requests are anonymous, subject to ACL/policy)
- `RUSTACCIO_AUTH_HTTP_BASE_URL` (required for `http` auth backend)
- `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT` (required for `http` auth backend; verifies incoming bearer tokens, eg `/request-auth`)
- `RUSTACCIO_AUTH_HTTP_ALLOW_ACCESS_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_HTTP_ALLOW_PUBLISH_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_HTTP_ALLOW_UNPUBLISH_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_HTTP_TIMEOUT_MS` (default `5000`)
- `RUSTACCIO_RUNTIME_PROFILE` (`local`, `s3`, or `managed`; primary mode selector when set, otherwise inferred from `RUSTACCIO_MANAGED_MODE` and tarball backend)
- `RUSTACCIO_STRICT_REVISION_CHECK` (optional `true|false`; default `true` in managed mode, otherwise `false`)
- `RUSTACCIO_PACKAGE_DISCOVERY_MODE` (`single-node` or `multi-node`; default is mode-aware: `multi-node` for managed/S3 runtime, `single-node` otherwise)
- `RUSTACCIO_PACKAGE_CACHE_MAX_ENTRIES` (default `5000`; bounded in-memory package cache cap)
- `RUSTACCIO_PACKAGE_CACHE_TTL_SECS` (default `0` in `single-node`, `120` in `multi-node`; `0` keeps strict sidecar revalidation)
- `RUSTACCIO_PACKAGE_CACHE_PRUNE_INTERVAL_SECS` (default `30`; periodic package-cache pruning)
- `RUSTACCIO_PACKAGE_NEGATIVE_CACHE_TTL_SECS` (default `30` in `single-node`, `5` in `multi-node`)
- `RUSTACCIO_PACKAGE_DISCOVERY_REFRESH_SECS` (default `0` in `single-node`, `15` in `multi-node`; periodic shared-backend package-name refresh)
- `RUSTACCIO_TARBALL_BACKEND` (`local` or `s3`, default `local`)
- `RUSTACCIO_S3_BUCKET` (required for `s3` backend)
- `RUSTACCIO_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_S3_ENDPOINT` (optional, eg MinIO/LocalStack endpoint)
- `RUSTACCIO_S3_ACCESS_KEY_ID` / `RUSTACCIO_S3_SECRET_ACCESS_KEY` (optional static credentials)
- `RUSTACCIO_S3_PREFIX` (optional key prefix)
- `RUSTACCIO_S3_FORCE_PATH_STYLE` (default `true`)
- `RUSTACCIO_S3_CA_BUNDLE` (optional PEM bundle path for S3 TLS trust; falls back to common system bundle paths when present)
- `RUSTACCIO_METADATA_BACKEND` (`sidecar` or `managed`; default `sidecar`. `managed` selects the [managed data-plane bridge](#managed-data-plane-bridge-control-plane-managed); `transactional` is reserved and rejected at startup with a pointer to `managed`)
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY` (`sidecar`, default `sidecar`)
  - Any non-empty value other than `sidecar` is rejected at startup.
- `RUSTACCIO_STATE_COORDINATION_BACKEND` (`none`, `redis`, `s3`, or `postgres`, default `none`)
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL` (required for `redis` state coordination backend)
- `RUSTACCIO_STATE_COORDINATION_POSTGRES_URL` (required for `postgres` state coordination backend; falls back to `RUSTACCIO_QUOTA_POSTGRES_URL`)
- `RUSTACCIO_STATE_COORDINATION_LOCK_KEY` (default `rustaccio:state:lock`)
- `RUSTACCIO_STATE_COORDINATION_LEASE_MS` (default `5000`)
- `RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS` (default `15000`)
- `RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS` (default `100`)
- `RUSTACCIO_STATE_COORDINATION_FAIL_OPEN` (default `false`)
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET` (required for `s3` state coordination backend)
- `RUSTACCIO_STATE_COORDINATION_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT` (optional, eg MinIO/LocalStack endpoint)
- `RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID` / `RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY` (optional static credentials)
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX` (default `rustaccio/state-locks/`)
- `RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE` (default `false`)
- When `RUSTACCIO_STATE_COORDINATION_S3_*` fields are unset, Rustaccio falls back to matching `RUSTACCIO_S3_*` tarball backend settings.
- `RUSTACCIO_RATE_LIMIT_MEMORY_MAX_KEYS` (default `10000`; in-memory rate-limit key bound)
- `RUSTACCIO_QUOTA_MEMORY_MAX_KEYS` (default `50000`; in-memory quota key bound)
- `RUSTACCIO_QUOTA_MEMORY_RETENTION_DAYS` (default `2`; in-memory quota day retention window)
- `RUSTACCIO_POLICY_HTTP_CACHE_MAX_ENTRIES` (default `10000`; bounded policy decision cache)
- `RUSTACCIO_POLICY_HTTP_CACHE_PRUNE_INTERVAL_MS` (default `30000`; periodic policy-cache pruning)
- `RUSTACCIO_EVENT_SINK` (`none` or `http`, default `none`)
- `RUSTACCIO_EVENT_HTTP_BASE_URL` (required when `RUSTACCIO_EVENT_SINK=http`)
- `RUSTACCIO_EVENT_HTTP_ENDPOINT` (default `/events/registry`)
- `RUSTACCIO_EVENT_HTTP_TIMEOUT_MS` (default `2000`)

Build features:

- `s3` feature enables native S3 tarball backend support (disabled by default for a leaner production binary).
- Enable with `--features s3` when you need S3 tarball storage.

## CI and Releases

- Rust CI is in `.github/workflows/ci.yml` and runs `fmt`, `check`, `clippy -D warnings`, tests (`all-features` and `no-default-features`), and docs with `-D warnings`.
- Container publish is in `.github/workflows/docker-publish.yml` and pushes multi-arch images to `ghcr.io/<owner>/<repo>` on version tags (`vX.Y.Z`).
- Keep a Changelog format changelog lives in `CHANGELOG.md`.

## Test

```bash
cargo test
cargo test --features s3
```

Run real S3-backend integration tests against a local, pinned S3 emulator:

```bash
just minio-up
just test-s3-it
just minio-down
```

Run Redis/Postgres governance integration tests:

```bash
just governance-up
just test-governance-it
just governance-down
```

Defaults:

- S3 API: `http://127.0.0.1:9002`
- Test access key / secret: `minioadmin` / `minioadmin`
- Test bucket: `rustaccio-it`

Override integration test connection settings with:

- `RUSTACCIO_S3_IT_ENDPOINT`
- `RUSTACCIO_S3_IT_REGION`
- `RUSTACCIO_S3_IT_BUCKET`
- `RUSTACCIO_S3_IT_ACCESS_KEY`
- `RUSTACCIO_S3_IT_SECRET_KEY`

Governance integration test connection settings:

- `RUSTACCIO_REDIS_IT_URL` (default `redis://127.0.0.1:56379/`)
- `RUSTACCIO_POSTGRES_IT_URL` (default `postgres://postgres:postgres@127.0.0.1:55432/rustaccio`)

## Just Commands

```bash
just          # default: check + test
just check
just test
just build    # fast local release profile
just dist     # fully optimized distribution profile
just serve
just serve ./config.yml
just minio-up
just minio-down
just test-s3-it
just governance-up
just governance-down
just test-governance-it
```

## Git Hooks (lefthook)

Install and enable local pre-commit hooks:

```bash
brew install lefthook
lefthook install
```

Run hooks manually:

```bash
lefthook run pre-commit
```

Configured pre-commit checks:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --locked --quiet`

Quality gate:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Library Embedding

### User-Owned `main` with `--config`

If you want your own binary entrypoint but keep rustaccio runtime/config behavior:

```rust
use rustaccio::{config::Config, runtime};
use std::{error::Error, path::PathBuf};

fn parse_config_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cfg = if let Some(path) = parse_config_arg() {
        Config::from_env_with_config_file(path)
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?
    } else {
        Config::from_env()
    };

    runtime::run_standalone(cfg).await?;
    Ok(())
}
```

### Custom `AuthHook` Implementation

```rust
use async_trait::async_trait;
use rustaccio::{auth::AuthHook, error::RegistryError, models::AuthIdentity};

#[derive(Default)]
struct CompanyAuthHook;

#[async_trait]
impl AuthHook for CompanyAuthHook {
    async fn authenticate_request(
        &self,
        token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        if token == "internal-token" {
            return Ok(Some(AuthIdentity {
                username: Some("ci-bot".to_string()),
                groups: vec!["publishers".to_string()],
            }));
        }
        Ok(None)
    }

    async fn allow_publish(
        &self,
        identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        let can_publish = identity
            .as_ref()
            .map(|id| id.groups.iter().any(|g| g == "publishers"))
            .unwrap_or(false);
        Ok(Some(can_publish))
    }
}
```

### Integrate into an Existing Axum Server

```rust
use axum::{Router, routing::get};
use rustaccio::{app::build_router, runtime};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = rustaccio::config::Config::from_env();

    // Router::nest("/registry", ...) strips the prefix before dispatch.
    // Keep url_prefix as "/" in this mode.
    cfg.url_prefix = "/".to_string();

    let state = runtime::build_state(&cfg, Some(Arc::new(CompanyAuthHook::default()))).await?;
    let registry_router = build_router(state);

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/registry", registry_router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

If you instead run rustaccio at the root path (not nested) behind a reverse proxy prefix, set `RUSTACCIO_URL_PREFIX` (for example `/registry`) so generated URLs include that prefix.

Key APIs:
- `rustaccio::auth::AuthHook`
- `rustaccio::storage::Store::open_with_options`
- `rustaccio::runtime::{build_state, run, run_from_env}`

## Implemented Core API Surface

- `/-/ping`
- `/-/whoami` (returns the username from the external identity when a valid bearer token is sent)
- `/-/v1/search`
- `/-/all` and `/-/all/since` (deprecated response)
- `/-/admin/reindex`, `/-/admin/storage-health`, `/-/admin/policy-cache/invalidate`, and `/-/admin/package-cache/invalidate` (admin/ops endpoints)
- `/-/_view/starredByUser`
- `/-/package/:package/dist-tags` (+ `:tag`)
- `/-/npm/v1/bootstrap` (npm/pnpm/yarn/bun onboarding snippets)
- `/-/npm/v1/security/advisories/bulk`
- `/-/npm/v1/security/audits/quick`
- `/-/npm/v1/security/audits`
- `/-/metrics` (optional, when `RUSTACCIO_METRICS_BACKEND=prometheus`)
- Built-in web UI routes: `/`, `/-/web`, `/-/web/settings`, `/-/web/detail/:package`, and static assets under `/-/web/static/*`
- Package/tarball/publish routes (including scoped packages):
  - `GET|HEAD /:package/:version?`
  - `GET|HEAD /:package/-/:filename`
  - `PUT /:package`
  - `PUT /:package/-rev/:revision`
  - `DELETE /:package/-rev/:revision`
  - `DELETE /:package/-/:filename/-rev/:revision`
  - legacy dist-tag `PUT /:package/:tag`

## Parity Coverage

The integration suite in `tests/parity.rs` currently validates:

- whoami identity resolution from external bearer tokens
- package publish/get/tarball (including scoped and encoded scoped names)
- package version and dist-tag lookups (`/:package/:versionOrTag`)
- `?write=true` package reads for unpublish-style flows
- dist-tags add/remove/read + invalid body handling
- owner/star update flows
- deprecate + undeprecate package versions via metadata updates
- unpublish-version flow via `PUT /:package/-rev/:revision` metadata mutation
- `publish.check_owners` parity for write routes (`GET ?write=true`, publish/unpublish, dist-tags)
- external HTTP auth backend token verification
- HTTP request-auth hook contract (`token + method + path -> identity/groups`)
- pluggable tarball backend (`local` filesystem or `s3`)
- `tarball backend startup reindexing` to discover versions from existing backend tarballs before serving requests
- security audit endpoints (uplink proxy + local fallback response shape)
- search v1 with pagination semantics
- deprecated search endpoint (`/-/all`)
- uplink behavior for package metadata, dist-tags, search, and tarballs
- package ACL parity subset (`access`/`publish`/`unpublish`) with pattern matching and proxy uplink selection
- `url_prefix` path handling + `max_body_size` request enforcement
- built-in web UI serving, SPA fallback behavior, and `web.enable` route gating

## Verdaccio Differences and Limits

Rustaccio targets Verdaccio-compatible npm client behavior for core flows, but it is not a byte-for-byte Verdaccio clone. Current known differences/limits:

- ACL matching is a parity subset: rule matching supports common wildcard patterns, but not full Verdaccio/micromatch pattern semantics.
- Package routes only consult an explicitly configured package-rule `proxy` uplink; they do not implicitly fall back to `default` or every configured uplink.
- Authorization parsing currently accepts `Bearer <token>` only.
- `:revision` route segments are accepted for Verdaccio-compatible route shapes, but revision values are not currently used for optimistic-concurrency checks.
- There is no local user store: `npm login`/`npm adduser`, npm token management, password changes, and web-login session flows are not supported. Identity comes only from an external HTTP auth backend verifying pre-issued bearer tokens.
- Search (`/-/v1/search`) currently uses `text`, `size`, and `from`; score tuning params are ignored, and `total` reflects returned page size.
- YAML `listen` can be configured as a list for config compatibility, but the server currently binds a single effective socket address.
- `server.keepAliveTimeout` is currently mapped to an HTTP/1 header-read timeout for keep-alive connections (not a byte-for-byte Node.js socket timeout implementation).
- Built-in web UI is a lightweight Verdaccio-style SPA shell and static assets, not the full upstream Verdaccio frontend/runtime surface.
- Rustaccio-specific admin endpoints are exposed at `/-/admin/reindex`, `/-/admin/storage-health`, `/-/admin/policy-cache/invalidate`, and `/-/admin/package-cache/invalidate`.

## Architecture

- `src/api.rs`: HTTP routing + Verdaccio-compatible endpoint behavior
- `src/acl.rs`: package rule matching + access/publish/unpublish permission checks
- `src/config.rs`: env + Verdaccio-style YAML parsing (`packages`, `uplinks`)
- `src/storage.rs`: in-memory package runtime state + tarball/sidecar backend integration
- `src/policy.rs`: policy engine abstraction (`external policy backend -> auth hook/plugin decisions -> ACL fallback`)
- `src/governance.rs`: opt-in governance controls (`rate limiting`, `quota`, `metrics`) via trait-based guards/backends
- `src/auth_plugin.rs`: HTTP auth backend client (external bearer-token verification)
- `src/tarball_backend.rs`: tarball backend abstraction (`local`, `s3`)
- `src/upstream.rs`: npm uplink proxy client for package/search/tarball
- `src/app.rs`: app state + router construction
- `src/web_ui.rs`: built-in Verdaccio-style web UI shell/assets and SPA route handling

## Plugin Config (YAML)

```yaml
auth:
  backend: http
  http:
    baseUrl: http://auth.local:9000
    requestAuthEndpoint: /request-auth
    allowAccessEndpoint: /allow-access
    allowPublishEndpoint: /allow-publish
    allowUnpublishEndpoint: /allow-unpublish
    timeoutMs: 5000

store:
  backend: s3
  s3:
    bucket: npm-cache
    region: us-east-1
    endpoint: http://127.0.0.1:9002
    accessKeyId: minio
    secretAccessKey: miniopass
    prefix: tarballs/
    forcePathStyle: true
```

## HTTP Auth Plugin Contract

When `RUSTACCIO_AUTH_BACKEND=http`, Rustaccio verifies every incoming bearer token by calling the external auth service's request-auth endpoint, which returns the caller's identity (`username`/`groups`). Tokens are issued out of band by the external system; Rustaccio never creates users or tokens.

Versioned contract reference: `docs/contracts/auth-request-v1.md`

## npm Bootstrap Endpoint

`GET /-/npm/v1/bootstrap` returns registry and `.npmrc` snippets for npm/pnpm/yarn/bun.
Use `?scope=<name>` (for example `?scope=acme`) to include scope-specific registry lines.

Versioned contract reference: `docs/contracts/npm-bootstrap-v1.md`

- `POST {baseUrl}{requestAuthEndpoint}` with `{ "token", "method", "path", "request_id" }` and response including:
  - `authenticated` (`true|false`, optional)
  - user identity: `username` or `user` or `name` (optional)
  - groups: `groups`/`roles` array or `group` scalar (optional)
- Optional ACL override callbacks:
  - `POST {baseUrl}{allowAccessEndpoint}`
  - `POST {baseUrl}{allowPublishEndpoint}`
  - `POST {baseUrl}{allowUnpublishEndpoint}`
  - request body includes `{ "package", "username", "groups", "identity", "request_id" }`, response supports `{ "allowed": true|false }` or raw boolean

Request ID propagation:

- Rustaccio sends `x-request-id` to request-auth and allow-* plugin callbacks when available.

Behavior:

- `2xx` means success.
- Non-`2xx` propagates status and `error`/`message` from plugin JSON body when present.

## External Policy Backend (HTTP, via Env)

Policy decisions can be sourced from a dedicated HTTP backend and will run before auth-hook/plugin/ACL fallback.

Versioned contract reference: `docs/contracts/policy-decision-v1.md`

Environment variables:

- `RUSTACCIO_POLICY_BACKEND=local|http` (default `local`)
- `RUSTACCIO_POLICY_HTTP_BASE_URL` (required when backend=`http`)
- `RUSTACCIO_POLICY_HTTP_DECISION_ENDPOINT` (default `/authorize`)
- `RUSTACCIO_POLICY_HTTP_TIMEOUT_MS` (default `3000`)
- `RUSTACCIO_POLICY_HTTP_CACHE_TTL_MS` (default `5000`, set `0` to disable cache)
- `RUSTACCIO_POLICY_HTTP_FAIL_OPEN` (default `false`)

Decision request payload includes:

- `action` (`access|publish|unpublish`)
- `package`
- `method`
- `path`
- `request_id`
- identity context: `username`, `groups`, `identity`
- tenant context: `tenant`, `org_id`, `project_id` (from request headers when present)

Request ID propagation:

- Rustaccio sends `x-request-id` to external policy requests when available.

Decision response:

- `{ "allowed": true|false }` or raw JSON boolean
- `401/403` is treated as an explicit deny
- Other non-`2xx`:
  - with `RUSTACCIO_POLICY_HTTP_FAIL_OPEN=true`: fall back to local policy chain
  - with `RUSTACCIO_POLICY_HTTP_FAIL_OPEN=false`: request fails with `502`

Cache control:

- `POST /-/admin/policy-cache/invalidate` clears in-memory external policy decision cache for the running instance.
- `RUSTACCIO_POLICY_HTTP_CACHE_MAX_ENTRIES` bounds in-memory policy decisions (default `10000`).
- `RUSTACCIO_POLICY_HTTP_CACHE_PRUNE_INTERVAL_MS` controls periodic expired-entry pruning (default `30000`).

## Error Codes

Error responses include machine-readable `code` in addition to `error`.
Versioned taxonomy: `docs/contracts/error-taxonomy-v1.md`.

## Registry Events (Best-Effort)

Rustaccio can emit structured registry/admin mutation events to a configured sink.

Versioned schema: `docs/contracts/registry-events-v1.md`.

Environment variables:

- `RUSTACCIO_EVENT_SINK=none|http` (default `none`)
- `RUSTACCIO_EVENT_HTTP_BASE_URL` (required for `http` sink)
- `RUSTACCIO_EVENT_HTTP_ENDPOINT` (default `/events/registry`)
- `RUSTACCIO_EVENT_HTTP_TIMEOUT_MS` (default `2000`)

Notes:

- Event emission is best-effort; npm request success does not depend on sink availability.
- `x-request-id` is forwarded to the HTTP sink when present.

## Governance Controls (Opt-In)

Rustaccio defaults to simple mode. Governance controls are disabled unless explicitly enabled via env.

Rate limiting:

- `RUSTACCIO_RATE_LIMIT_BACKEND=none|memory|redis` (default `none`)
- `RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW` (default `0`, disabled)
- `RUSTACCIO_RATE_LIMIT_WINDOW_SECS` (default `60`)
- `RUSTACCIO_RATE_LIMIT_REDIS_URL` (required when backend=`redis`)
- `RUSTACCIO_RATE_LIMIT_FAIL_OPEN` (default `true`)
- `RUSTACCIO_RATE_LIMIT_MEMORY_MAX_KEYS` (default `10000`; bounds in-memory limiter key cardinality)

Quota enforcement:

- `RUSTACCIO_QUOTA_BACKEND=none|memory|postgres` (default `none`)
- `RUSTACCIO_QUOTA_REQUESTS_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_DOWNLOADS_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_PUBLISHES_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_POSTGRES_URL` (required when backend=`postgres`)
- `RUSTACCIO_QUOTA_FAIL_OPEN` (default `true`)
- `RUSTACCIO_QUOTA_MEMORY_MAX_KEYS` (default `50000`; bounds in-memory quota cardinality)
- `RUSTACCIO_QUOTA_MEMORY_RETENTION_DAYS` (default `2`; prunes old in-memory quota day buckets)

Postgres quota migrations:

- Rustaccio applies quota schema migrations automatically on startup when `RUSTACCIO_QUOTA_BACKEND=postgres`.
- Migration files live under `migrations/` (current: `migrations/0001_quota_usage_table.sql`).

State write coordination (opt-in):

- `RUSTACCIO_STATE_COORDINATION_BACKEND=none|redis|s3|postgres` (default `none`)
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL` (required when backend=`redis`)
- `RUSTACCIO_STATE_COORDINATION_LOCK_KEY` (default `rustaccio:state:lock`)
- `RUSTACCIO_STATE_COORDINATION_LEASE_MS` (default `5000`)
- `RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS` (default `15000`)
- `RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS` (default `100`)
- `RUSTACCIO_STATE_COORDINATION_FAIL_OPEN` (default `false`)
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET` (required when backend=`s3`)
- `RUSTACCIO_STATE_COORDINATION_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT` (optional)
- `RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID`, `RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY` (optional)
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX` (default `rustaccio/state-locks/`)
- `RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE` (default `false`)
- If unset, `RUSTACCIO_STATE_COORDINATION_S3_*` values fall back to matching `RUSTACCIO_S3_*` values.

Semantics:

- Coordinates write sections with scoped lease locks (`package:<name>` scope for package mutations).
- Prevents overlapping multi-instance write sections when all instances use the same coordination backend.
- This is a write-coordination primitive, not full multi-writer state conflict resolution.

Metrics endpoint:

- `RUSTACCIO_METRICS_BACKEND=none|prometheus` (default `none`)
- `RUSTACCIO_METRICS_PATH` (default `/-/metrics`)
- `RUSTACCIO_METRICS_REQUIRE_ADMIN` (default `true`)

Build features for external backends:

- `cargo build --features redis` for Redis rate limiter
- `cargo build --features postgres` for Postgres quota backend
- `cargo build --features otel` for OTLP span export

OpenTelemetry (opt-in):

- `RUSTACCIO_OTEL_ENABLED=false|true` (default `false`)
- `RUSTACCIO_OTEL_EXPORTER_OTLP_ENDPOINT` (for example `http://otel-collector:4318/v1/traces`)
- `RUSTACCIO_OTEL_SERVICE_NAME` (default `rustaccio`)

## Admin Endpoint Authorization

Admin endpoints are controlled by environment variables:

- `RUSTACCIO_MANAGED_MODE=false|true` (default `false`)
- `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED` (default `true`)
- `RUSTACCIO_ADMIN_USERS` (comma/space-separated usernames)
- `RUSTACCIO_ADMIN_GROUPS` (comma/space-separated groups/roles)

Behavior:

- If `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=true`, any authenticated identity can call `/-/admin/*`.
- If `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`, only identities whose username is in `RUSTACCIO_ADMIN_USERS` or whose group/role is in `RUSTACCIO_ADMIN_GROUPS` are allowed.
- Unauthenticated requests receive `401`; authenticated non-admin requests receive `403`.
- If `RUSTACCIO_MANAGED_MODE=true`, startup enforces stricter guardrails:
  - `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
  - at least one explicit admin principal in `RUSTACCIO_ADMIN_USERS` or `RUSTACCIO_ADMIN_GROUPS`
  - `RUSTACCIO_AUTH_BACKEND=http` (external identity provider mode)
  - `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT=<path>`

Recommended managed-mode posture:

- Set `RUSTACCIO_MANAGED_MODE=true`.
- Set `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`.
- Define a dedicated admin group from your identity provider, and set it in `RUSTACCIO_ADMIN_GROUPS`.

## Run Modes

Rustaccio now runs sidecar-authoritative package metadata in all modes.
Mode-specific env presets are included at repo root: `.env.local.example`, `.env.s3.example`, `.env.managed.example`.

| Mode | Tarball Backend | Metadata Authority | Governance Backends | Typical Use |
|---|---|---|---|---|
| Simple local | `local` | package sidecars (`package.json`) | none/memory | single-node, low ops |
| Shared object store | `s3` | package sidecars (`package.json`) | none/memory | multi-node with shared blob storage |
| Managed governance | `local` or `s3` | package sidecars (`package.json`) | Redis/Postgres/Prometheus/OTel | managed platform with limits/observability |

Simple local mode defaults:

- `RUSTACCIO_RUNTIME_PROFILE=local`
- `RUSTACCIO_TARBALL_BACKEND=local`
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar`
- `RUSTACCIO_RATE_LIMIT_BACKEND=none`
- `RUSTACCIO_QUOTA_BACKEND=none`
- `RUSTACCIO_POLICY_BACKEND=local`
- `RUSTACCIO_MANAGED_MODE=false`
- `RUSTACCIO_STATE_COORDINATION_BACKEND=none`
- `RUSTACCIO_PACKAGE_DISCOVERY_MODE=single-node`
- `RUSTACCIO_PACKAGE_DISCOVERY_REFRESH_SECS=0`

Shared object store mode defaults:

- `RUSTACCIO_RUNTIME_PROFILE=s3`
- `RUSTACCIO_TARBALL_BACKEND=s3`
- `RUSTACCIO_S3_BUCKET=<tarball-bucket>`
- `RUSTACCIO_MANAGED_MODE=false`
- `RUSTACCIO_RATE_LIMIT_BACKEND=none|memory`
- `RUSTACCIO_QUOTA_BACKEND=none|memory`
- `RUSTACCIO_STATE_COORDINATION_BACKEND=none|s3`
- `RUSTACCIO_PACKAGE_DISCOVERY_MODE=multi-node`
- `RUSTACCIO_PACKAGE_DISCOVERY_REFRESH_SECS=15`

Managed hardening mode:

- `RUSTACCIO_RUNTIME_PROFILE=managed`
- `RUSTACCIO_RUNTIME_PROFILE=managed` implies managed guardrails even when `RUSTACCIO_MANAGED_MODE` is unset (`RUSTACCIO_MANAGED_MODE=true` remains a compatibility alias)
- Managed guardrails enforce:
  - `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
  - explicit admin principals (`RUSTACCIO_ADMIN_USERS` or `RUSTACCIO_ADMIN_GROUPS`)
  - `RUSTACCIO_AUTH_BACKEND=http` (external identity provider mode)
  - `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT=<path>`
- Managed profile additionally requires:
  - `RUSTACCIO_RATE_LIMIT_BACKEND=redis`
  - `RUSTACCIO_QUOTA_BACKEND=postgres`
  - `RUSTACCIO_STATE_COORDINATION_BACKEND=redis|s3|postgres`

Package discovery and cache behavior:

- Rustaccio keeps an in-memory package record cache and a package-name index to avoid storage-backend round-trips on every request.
- `RUSTACCIO_PACKAGE_DISCOVERY_MODE=single-node` favors local cache hits and on-demand backend probes (no periodic list refresh by default).
- `RUSTACCIO_PACKAGE_DISCOVERY_MODE=multi-node` enables periodic backend list refresh (`RUSTACCIO_PACKAGE_DISCOVERY_REFRESH_SECS`) to detect package adds/removals from other nodes.
- Invalid `RUSTACCIO_PACKAGE_DISCOVERY_MODE` values fail startup (accepted: `single-node`, `multi-node` and their aliases).
- Package cache growth is bounded by `RUSTACCIO_PACKAGE_CACHE_MAX_ENTRIES`, TTL-controlled by `RUSTACCIO_PACKAGE_CACHE_TTL_SECS`, and pruned periodically by `RUSTACCIO_PACKAGE_CACHE_PRUNE_INTERVAL_SECS`.
- Missing-package probes are negative-cached with `RUSTACCIO_PACKAGE_NEGATIVE_CACHE_TTL_SECS` to suppress repeated misses.
- For strict multi-node write safety, still configure `RUSTACCIO_STATE_COORDINATION_BACKEND=redis|s3|postgres`; package discovery refresh is not a write lock.
- External event-driven cache hook: `POST /-/admin/package-cache/invalidate` with `{ "package": "<name>" }` evicts a package from in-memory cache so subsequent reads reload from authoritative storage.

### Managed data-plane bridge (control-plane managed)

`RUSTACCIO_METADATA_BACKEND=managed` turns Rustaccio into a pure data plane
for the Go control plane (contract: `docs/contracts/managed-v1.md`). The
control plane owns metadata, entitlement and publish sessions; the node
authorizes every private operation over HTTP, decodes/hashes publish bodies
with bounded memory (spooling tarballs to disk), uploads them to
control-plane issued create-only presigned URLs, reverse-proxies packument
reads and metadata writes, redirects (or proxies) tarball downloads, and
reports download/publish events from a durable spool. An authorize answer
of `route: "upstream"` is reverse-proxied to the control-plane npm surface
(original `Host` and `Authorization`); an absent route stays 404, and
uplinks stay disabled.

Required env:

- `RUSTACCIO_CONTROL_PLANE_URL` (for example `https://control-plane.example.com`)
- `RUSTACCIO_CONTROL_PLANE_TOKEN` (node credential, sent as Bearer on every control-plane call)
- `RUSTACCIO_TARBALL_BACKEND=s3` plus the usual S3 settings (startup fails otherwise)

Optional env:

- `RUSTACCIO_MANAGED_DOWNLOAD_MODE=redirect|proxy` (default `redirect`: 302 to the resolved presigned URL)
- `RUSTACCIO_MANAGED_METADATA_ORIGIN` (default: the control-plane URL)
- `RUSTACCIO_DATA_PLANE_ID` (fleet identity; default: hostname), `RUSTACCIO_REQUIRE_PLACEMENT=true` to refuse startup until the control plane placed the node
- `RUSTACCIO_MANAGED_DECISION_CACHE_TTL_MS` (default `30000`; decisions never outlive their control-plane `expires_at`), `RUSTACCIO_MANAGED_DECISION_CACHE_MAX_ENTRIES` (default `10000`)
- `RUSTACCIO_MANAGED_METADATA_CACHE_TTL_MS` (default `0` = off), `RUSTACCIO_MANAGED_METADATA_CACHE_MAX_ENTRIES` (default `128`), `RUSTACCIO_MANAGED_METADATA_CACHE_MAX_BYTES` (default 4 MiB)
- `RUSTACCIO_MANAGED_MAX_METADATA_BYTES` (default 8 MiB publish metadata bound), `RUSTACCIO_MANAGED_UPLOAD_TIMEOUT_MS` (default `300000`)
- `RUSTACCIO_MANAGED_EVENT_SPOOL_DIR` (default `<data_dir>/managed-events`; must not be the publish spool directory) and `RUSTACCIO_MANAGED_EVENT_SPOOL_MAX_BYTES` (default 64 MiB). Usage events are fsynced to this spool and retried with the same `event_id` until the control plane acknowledges them. When the bound is hit the newest event is dropped and `rustaccio_events_dropped_total` is incremented (served on the metrics endpoint).

In managed mode control-plane failures fail closed (`502` with
`CONTROL_PLANE_UNAVAILABLE`); local ACLs, uplinks and the external
auth/policy plugins are not consulted for private operations, and
non-registry routes fail closed with 404. Admin cache flush endpoints require
the node credential as the bearer token.

## Deploying with Redis/Postgres Backends

### 1) Build image with required compile-time features

```bash
docker build \
  --build-arg CARGO_FEATURES="s3,redis,postgres,otel" \
  -t rustaccio:managed .
```

### 2) Runtime env for managed governance

Required profile and mode:

- `RUSTACCIO_RUNTIME_PROFILE=managed`
- `RUSTACCIO_MANAGED_MODE=true`

Required for Redis rate limiter:

- `RUSTACCIO_RATE_LIMIT_BACKEND=redis`
- `RUSTACCIO_RATE_LIMIT_REDIS_URL=redis://redis:6379/`

Required for Postgres quotas:

- `RUSTACCIO_QUOTA_BACKEND=postgres`
- `RUSTACCIO_QUOTA_POSTGRES_URL=postgres://postgres:postgres@postgres:5432/rustaccio`

Recommended managed security baseline:

- `RUSTACCIO_AUTH_BACKEND=http`
- `RUSTACCIO_AUTH_HTTP_BASE_URL=http://your-auth-service:8080`
- `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT=/request-auth`
- `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
- `RUSTACCIO_ADMIN_GROUPS=<admin-group>`
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar`
- `RUSTACCIO_STATE_COORDINATION_BACKEND=redis`
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL=redis://redis:6379/`

Alternative coordination backend (if you prefer object-storage-native locking):

- `RUSTACCIO_STATE_COORDINATION_BACKEND=s3`
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET=<lock-bucket>`
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX=rustaccio/state-locks/`

Example container run:

```bash
docker run --rm -p 4873:4873 \
  -v "$(pwd)/.rustaccio-data:/var/lib/rustaccio/data" \
  -v "$(pwd)/config.yml:/etc/rustaccio/config.yml:ro" \
  -e RUSTACCIO_CONFIG=/etc/rustaccio/config.yml \
  -e RUSTACCIO_RUNTIME_PROFILE=managed \
  -e RUSTACCIO_MANAGED_MODE=true \
  -e RUSTACCIO_AUTH_BACKEND=http \
  -e RUSTACCIO_AUTH_HTTP_BASE_URL=http://your-auth-service:8080 \
  -e RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT=/request-auth \
  -e RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false \
  -e RUSTACCIO_ADMIN_GROUPS=platform-admins \
  -e RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar \
  -e RUSTACCIO_RATE_LIMIT_BACKEND=redis \
  -e RUSTACCIO_RATE_LIMIT_REDIS_URL=redis://redis:6379/ \
  -e RUSTACCIO_STATE_COORDINATION_BACKEND=redis \
  -e RUSTACCIO_STATE_COORDINATION_REDIS_URL=redis://redis:6379/ \
  -e RUSTACCIO_QUOTA_BACKEND=postgres \
  -e RUSTACCIO_QUOTA_POSTGRES_URL=postgres://postgres:postgres@postgres:5432/rustaccio \
  -e RUSTACCIO_METRICS_BACKEND=prometheus \
  rustaccio:managed
```

Notes:

- `RUSTACCIO_RATE_LIMIT_FAIL_OPEN=true|false` controls availability vs strictness on Redis failures.
- `RUSTACCIO_QUOTA_FAIL_OPEN=true|false` controls availability vs strictness on Postgres failures.
- Postgres migrations for quotas run automatically at startup.

## Storage and Data Model

### Core model

Rustaccio does not persist any local state file. There is no `state.json` and no on-disk users, auth tokens, npm tokens, or login sessions — those concepts no longer exist. Identity is resolved per request from the external HTTP auth backend, and package metadata authority is sidecar-only (backend-stored `package.json` sidecars).

Package runtime state is held in memory as a bounded cache. Each `PackageRecord` contains:

- `manifest` (full package manifest JSON)
- `upstream_tarballs` (filename -> original upstream URL cache)
- `updated_at`
- `cached_from_uplink`

### Metadata sidecars

Package metadata is stored in backend sidecars:

- Local: `<data_dir>/tarballs/<package-with-slashes-replaced>/package.json`
- S3: `<prefix><package>/package.json` (Verdaccio-compatible layout)

Rustaccio writes sidecars after manifest mutations (`publish`, metadata-only update, dist-tag/owner/star changes, tarball removals).

At startup and reindex:

- Rustaccio loads tarball references from backend listing.
- It loads sidecars when available.
- It merges legacy Verdaccio package index hints (`verdaccio-s3-db.json`) when present.
- It rebuilds missing manifest structures from tarball filenames and sidecar metadata.

## Data Inconsistency and Failure Modes

Known failure windows:

1. Tarball written, sidecar write fails:
- blob may exist without updated manifest reference.

2. Sidecar updated, tarball delete fails:
- manifest may stop referencing a blob that still exists (or vice versa, depending on operation ordering).

3. Sidecar authority multi-writer races:
- if coordination backend is `none`, concurrent writers can still race.
- with `redis`/`s3` coordination enabled, rustaccio serializes package mutations by `package:<name>` scope, which removes overlapping write sections but is still not a full transactional metadata system.

4. Backend outages (Redis/Postgres/S3 lock backend):
- behavior depends on `*_FAIL_OPEN` settings (`allow` vs reject with backend-unavailable errors).

Operational diagnostics:

- `GET /-/admin/storage-health` reports drift signals:
  - `tarballsWithoutSidecar`
  - `sidecarsWithoutTarballs`
  - `tarballsMissingFromManifest`
  - `manifestAttachmentsMissingBlob`
  - `staleStatePackages`

## Rebuild and Recovery

### Online reindex from storage backend

Use admin endpoint:

```bash
curl -X POST \
  -H "Authorization: Bearer <admin-token>" \
  http://<host>:4873/-/admin/reindex
```

Response includes:

- `changed`
- `packagesBefore`
- `packagesAfter`
- `sidecarsSynced`

This rebuilds package metadata from backend tarballs/sidecars and can repair many drift cases.

### Recommended backup strategy

- Back up all tarball objects and package sidecars (this is the full authoritative dataset; there is no local auth/session state to back up).
- For governance:
  - back up Postgres quota tables
  - persist Redis if you require durable counters across restarts (optional by policy)
- Identity is managed entirely by the external auth service; back that up according to its own policy.

### Outbound client lifecycle

- HTTP integrations (`upstream`, auth plugin, external policy backend, event sink) use process-scoped `reqwest` clients with bounded idle pools; they do not accumulate per-request entries in Rustaccio maps.
- The Postgres quota backend keeps one background connection task for the lifetime of the process when enabled.
- Redis/S3 state coordination create renewal tasks only while a write lease is held and release them when the lease ends.
- OTLP tracing may keep exporter workers while the process is running when `RUSTACCIO_OTEL_ENABLED=true`.
- These outbound clients are expected to stop with the server/runtime shutdown path; they are not an independent container keepalive mechanism.

## Scalability Characteristics

What scales today:

- Object-store tarballs (`s3`) and sidecars.
- Horizontal read/write nodes with shared object storage.
- Distributed rate limiting (Redis) and quota accounting (Postgres).

Current bottlenecks/limits:

- Metadata writes are still not transactional across tarball + sidecar artifacts.
- Sidecar conflict resolution remains optimistic at application level.

Deployments that need transactional metadata, centralized entitlement and
publish-session state can run the [managed data-plane
bridge](#managed-data-plane-bridge-control-plane-managed), where a control
plane owns metadata and Rustaccio only bridges bytes.

## License

Licensed under either of:

- MIT (`LICENSE-MIT`)
- Apache-2.0 (`LICENSE-APACHE`)

## Embedded Auth Hook Contract

When embedding, implement `AuthHook`:
- `authenticate_request(token, method, path)` for token-to-identity mapping (tokens are issued out of band by your system)
- `allow_access(identity, package)` optional override for read permission
- `allow_publish(identity, package)` optional override for publish permission
- `allow_unpublish(identity, package)` optional override for unpublish permission

Returned identity (`AuthIdentity`) is used directly by package ACL rules (`access`, `publish`, `unpublish`) via `username` and `groups`.
If `allow_*` returns `Some(true|false)`, that decision overrides ACL; `None` falls back to ACL rules.
