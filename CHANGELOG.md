# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Managed usage events are fsynced to a durable spool (`RUSTACCIO_MANAGED_EVENT_SPOOL_DIR`, `RUSTACCIO_MANAGED_EVENT_SPOOL_MAX_BYTES`) and retried with the same `event_id` until the control plane acknowledges them. A full spool drops the newest event and increments `rustaccio_events_dropped_total` instead of failing the npm operation.
- Managed download and publish events now carry the optional transfer context (`registry_id`, `format`, `file`, `declared_bytes`, `status`, `range`, trusted edge `client_ip`, `user_agent`, `npm_command`, `npm_session`, `ci`, `host`, `request_id`). `client_ip` is taken from `Fly-Client-IP` or `CF-Connecting-IP`; client-supplied `X-Forwarded-For` is ignored.
- Packument cache hits are aggregated per registry, credential, package and minute and reported as `kind: "metadata"` events (`count`, `bytes`, `not_modified`).
- An authorize answer of `route: "upstream"` reverse-proxies the original request to the control-plane npm surface, preserving `Host` and `Authorization`. An absent or `hosted` route keeps the previous 404. Uplinks stay disabled in managed mode.
- Fleet heartbeats advertise `events_v2` and `upstream_forward`.
- Managed download events now carry the optional control-plane `credential_id` and resolved version, allowing customer-level delivery attribution by package version in redirect and proxy modes.

### Removed

- Removed the `docs/oss-plus-saas-control-plane-spec.md` and `docs/oss-saas-implementation-backlog.md` planning documents; the versioned data-plane contracts in `docs/contracts/` (including `managed-v1.md`) remain the integration reference.
- Removed the unused `argon2` and `password-hash` dependencies (leftovers from the local auth backend removed in 0.10.0).

### Fixed

- S3 integration tests use a pinned LocalStack community image after the old MinIO image stopped permitting public pulls.
- The mode preset files `.env.local.example`, `.env.s3.example` and `.env.managed.example` no longer reference the removed `RUSTACCIO_AUTH_BACKEND=local`, `RUSTACCIO_AUTH_EXTERNAL_MODE` and `RUSTACCIO_AUTH_TOKEN_TTL_SECS` settings, and a mangled line in `.env.s3.example` was repaired.
- The startup error for an invalid `RUSTACCIO_METADATA_BACKEND` now names the valid values (`sidecar|managed`).
- Documentation no longer points at a specific hosted control-plane deployment; examples use neutral hostnames.

## [0.13.0] - 2026-09-24

### Changed

- `RUSTACCIO_LOG_FORMAT` defaults to `auto`: `pretty` on an interactive terminal, `json` otherwise (containers, log shippers). Set `pretty` or `compact` explicitly to keep human-readable output outside a terminal.
- ANSI colours are emitted only when stdout is a terminal, and never when `NO_COLOR` is set.
- HTTP requests log one `request completed` line (`status`, `latency_ms`, inside the `http_request` span with `method`, `path`, `request_id`) instead of a tower-http response line plus a span-close line.
- `/-/ping` health probes are logged at debug level, so they no longer appear at the default `info` level.

### Fixed

- The `http_request` span now carries the generated or caller-supplied `x-request-id`; it was always `-` because the trace layer ran before the request ID was set.

## [0.12.0] - 2026-09-23

### Changed

- Switched the S3 client's TLS provider from `aws-lc-rs` to `ring` (`ring` was already in the dependency tree via `reqwest`): `aws-smithy-http-client` now uses its `rustls-ring` feature, `aws-config`/`aws-sdk-s3` no longer enable their `default-https-client` feature, and all S3 code paths set an explicit HTTP connector. This removes the large `aws-lc-sys` C build, cutting cold `--features s3` / `--all-features` compile times. No behavioral change is expected for S3 operations; note the S3 client no longer negotiates post-quantum hybrid TLS key exchange.

### Build

- Pre-commit hooks now auto-use the `sccache` compiler cache when it is installed (`brew install sccache`), matching the existing `just` recipes and CI behavior.
- Dev profile now uses `debug = 1` (line tables only) for faster codegen/linking and smaller artifacts; breakpoints and backtraces still work, debugger variable inspection is limited.
- Release profile no longer uses incremental compilation.
- Pre-commit hook drops the standalone `cargo check` step; `cargo clippy --all-targets --all-features` is a strict superset and running both forced full rebuilds.

## [0.11.0] - 2026-09-23

### Added

- Added a managed data-plane bridge (`RUSTACCIO_METADATA_BACKEND=managed`): Rustaccio runs as a byte-heavy data plane for the Go control plane (`RUSTACCIO_CONTROL_PLANE_URL` + `RUSTACCIO_CONTROL_PLANE_TOKEN`), with control-plane authorization of every private operation, a streaming reserve → upload → finalize publish bridge (bounded memory, SHA-512/SHA-1 hashing, create-only presigned uploads), packument reverse-proxying, redirect/proxy tarball downloads, best-effort usage events, and fleet heartbeat/placement. See `docs/contracts/managed-v1.md`.

## [0.10.0] - 2026-06-19

### Added

- Added versioned integration contracts in `docs/contracts/` for auth request mapping, external policy decisions, npm bootstrap payloads, registry event schema, and error taxonomy.
- Added machine-readable error `code` (and contextual `hint` for key auth/policy failures) to JSON error responses.
- Added request ID propagation (`x-request-id`) into external auth and policy HTTP backends.
- Added best-effort registry event emission with pluggable sink (`RUSTACCIO_EVENT_SINK=none|http`) and event emission for admin/package mutation operations.
- Added `GET /-/npm/v1/bootstrap` endpoint for npm/pnpm/yarn/bun onboarding snippets and `.npmrc` bootstrap guidance.
- Added admin cache invalidation hook endpoint `POST /-/admin/package-cache/invalidate` for external/event-driven cache eviction.
- Added opt-in startup connectivity probing via `RUSTACCIO_STARTUP_CONNECTIVITY_CHECK`, logging IPv4/IPv6 TCP reachability to `registry.npmjs.org` and the configured tarball S3 endpoint.
- Added a `postgres` state-coordination backend (`RUSTACCIO_STATE_COORDINATION_BACKEND=postgres`, `RUSTACCIO_STATE_COORDINATION_POSTGRES_URL`) using session-scoped `pg_advisory_lock`; the multi-instance write lock is now abstracted behind a `LockBackend`/`LockGuard` trait with per-backend modules (`s3`, `redis`, `postgres`). The managed profile accepts `redis|s3|postgres` for state coordination.

### Changed

- Breaking: authentication is now limited to two modes selected by `RUSTACCIO_AUTH_BACKEND`: `none` (anonymous, subject to ACL/policy) and `http` (external HTTP token verification). The `http` backend verifies incoming bearer tokens against `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT` and resolves identity (`username`/`groups`) from the response. Tokens are issued out of band by the external system and supplied by clients via `.npmrc` (`//<registry>/:_authToken=<token>`).
- Breaking: managed mode now requires `RUSTACCIO_AUTH_BACKEND=http` plus `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT` instead of the removed `RUSTACCIO_AUTH_EXTERNAL_MODE` flag.
- Breaking: removed snapshot-based package metadata persistence and shared S3 `__rustaccio_meta/state.json` package snapshots. Package metadata is now always sidecar-authoritative (`package.json`), and Rustaccio no longer writes any local `state.json` (no on-disk auth/session/token records).
- Breaking: runtime startup now enforces deployment profiles (`local|s3|managed`) with `RUSTACCIO_RUNTIME_PROFILE` override or automatic profile inference from config, including strict backend requirements for the managed profile (`redis` rate limiting + `postgres` quotas + `redis|s3|postgres` state coordination).
- Breaking: backend selector parsing is now strict for auth, tarball, and policy backends (invalid backend values fail fast at startup instead of silently falling back).
- Added bounded in-memory caches with periodic pruning for package metadata and external policy decisions; added package discovery modes (`single-node|multi-node`) with optional periodic shared-backend package-name refresh.
- Added memory-cardinality bounds for in-memory governance backends (rate limiter/quota) to prevent unbounded key growth.
- Hardened mode config semantics: `RUSTACCIO_RUNTIME_PROFILE=managed` now implies managed guardrails, managed guardrails additionally require `RUSTACCIO_AUTH_BACKEND=http` and `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT`, and package discovery mode parsing now fails fast on invalid values.
- State-coordination S3 config now falls back to `RUSTACCIO_S3_*` values when `RUSTACCIO_STATE_COORDINATION_S3_*` are unset to reduce duplicated configuration.
- Added metadata backend abstraction scaffold via `RUSTACCIO_METADATA_BACKEND` (currently `sidecar` only; transactional backend reserved/not yet available).
- Added optional strict revision-concurrency guard (`RUSTACCIO_STRICT_REVISION_CHECK`, defaults enabled in managed mode) for package mutation paths.
- Package routes now require an explicit package-rule `proxy` to consult an uplink; they no longer implicitly fall back to `default` or all configured uplinks.
- Local bearer auth tokens now expire by TTL (`RUSTACCIO_AUTH_TOKEN_TTL_SECS`, default 30 days), and expired auth/login-session state is pruned on startup, lookup, and background maintenance to prevent unbounded auth/session growth.

### Removed

- Breaking: removed the local authentication backend (`RUSTACCIO_AUTH_BACKEND=local` / `auth.backend: local`) and all local user/credential management. There is no local user database.
- Breaking: removed `npm login`/`npm adduser` (PUT `/-/user`), npm token create/list/revoke (`/-/npm/v1/tokens`), profile/password change (`/-/npm/v1/user` POST), and the web login session flow (`/-/v1/login`, `/-/v1/done`, `/-/v1/login_cli`) along with the web UI login/register forms.
- Breaking: removed on-disk auth/session persistence — `state.json` and its `users`, `auth_tokens`, `npm_tokens`, and `login_sessions` no longer exist.
- Breaking: removed auth config keys and env vars: `flags.webLogin`/`RUSTACCIO_WEB_LOGIN`, `RUSTACCIO_PASSWORD_MIN`, `RUSTACCIO_LOGIN_SESSION_TTL_SECONDS`, `RUSTACCIO_AUTH_TOKEN_TTL_SECS`, `RUSTACCIO_AUTH_EXTERNAL_MODE`, and the auth HTTP endpoints `addUserEndpoint`/`loginEndpoint`/`changePasswordEndpoint` (env `RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT`, `..._LOGIN_ENDPOINT`, `..._CHANGE_PASSWORD_ENDPOINT`). The external HTTP request-auth and optional `allow*` policy hooks (plus `RUSTACCIO_AUTH_HTTP_TIMEOUT_MS`) are retained.
- Legacy Verdaccio `store.aws-s3-storage` YAML compatibility path for tarball backend configuration.

### Fixed

- Scoped package publishes now normalize `_attachments` keys and `dist.tarball` entries to canonical tarball filenames, preventing nested tarball paths like `@scope/pkg.tgz` from causing `npm install` 404s.
- Request tracing now records route/query context on API spans and demotes high-frequency external auth helper spans to `debug`, reducing noisy `INFO` close-event logs.
- S3 tarball backend warnings now include endpoint, bucket, key/prefix scope, AWS request IDs, gateway headers, and SDK error kind to speed up production diagnosis of broken S3 backends and proxies.
- Authoritative S3 metadata lookup failures now surface as upstream `502/503` responses instead of being collapsed into `404 no such package available`; transport-level S3 timeouts are classified as `503`.

## [0.9.0] - 2026-02-14

### Added

- CI: MinIO integration test job that spins up MinIO and runs S3 backend tests on every push and PR.

## [0.8.0] - 2026-02-14

### Fixed

- Package manifest `versions` object now preserves insertion (publish) order instead of sorting lexicographically, matching Verdaccio behavior.

## [0.7.0] - 2026-02-14

### Changed

- CI: increased Docker publish workflow timeout from 45 to 120 minutes.

## [0.6.0] - 2026-02-14

### Fixed

- Docker build: pass `CARGO_BUILD_JOBS` as env var to `cargo-chef cook` instead of unsupported `-j` flag.

## [0.5.0] - 2026-02-14

### Fixed

- Web UI: content area no longer overflows viewport width (added `min-width: 0` to cards/grids and `overflow: hidden` to content container).

### Changed

- Docker build: `cargo chef cook` now respects `CARGO_PROFILE` build arg, using the `dist` profile when specified instead of always using `release`.
- Switched Docker runtime base image to distroless (`gcr.io/distroless/cc-debian12:nonroot`).
- Improved config loading and runtime setup.
- CI: made sccache optional when GHA cache is unavailable.

## [0.4.0] - 2026-02-14

### Added

- `RUSTACCIO_CONFIG_BASE64` support for loading base64-encoded Verdaccio-style YAML configuration from environment variables.
- Validation and test coverage for `RUSTACCIO_CONFIG_BASE64` success/failure paths and conflicts with `RUSTACCIO_CONFIG`.
- New `justfile` with common local development and build commands.
- Project logo asset and updated README branding.
- Tagged-release binary artifact publishing in CI (`rustaccio-linux-amd64` attached to GitHub releases).

### Changed

- Config loading flow refactor to unify YAML/env parsing paths while preserving precedence (`defaults < env config source < --config file < env overrides`).
- Built-in web UI redesign across package listing, package details, login, and settings views, including improved responsive layout and accessibility polish.
- CI and container build pipeline updates for faster, more reliable release builds (cache/sccache and dist-profile build path improvements).
- Docker and release documentation updated to reflect the revised build/release workflow.

## [0.3.0] - 2026-02-14

### Added

- Graceful shutdown handling for standalone runtime on `SIGTERM`/`Ctrl+C`.
- Additional runtime/config test coverage for timeout parsing, `audit.enabled` route gating, `web.enable` route gating, and invalid `RUSTACCIO_CONFIG` handling.
- Explicit compatibility policy and documented Verdaccio behavior differences/limits in `README.md`.

### Changed

- CI Rust job timeout increased from 30 to 60 minutes.
- `Config::from_env()` now returns `Result` and fails fast when `RUSTACCIO_CONFIG` is set but invalid/unreadable.
- Security audit endpoints now return `404` when audit middleware is disabled.
- Search endpoint now caps `size` to `250`.
- Store persistence and sidecar syncing were refactored to reduce unnecessary state cloning and filter uplink-cached package snapshots during serialization.
- Docker publish workflow now builds with `CARGO_BUILD_JOBS=1` for lower-memory builds.
- Docker runtime image hardening updated user creation with `useradd --no-log-init`.
- Dependency surface cleanup:
  - removed unused direct deps `bytes`, `futures-util`, and `http`
  - removed unused `reqwest` `stream` feature
  - moved `flate2` and `tar` to `dev-dependencies`
  - removed unused `chrono` `serde` feature
- Repo hygiene updates for local artifacts (`.gitignore`, `.dockerignore`).

### Removed

- Deprecated file-length gate test (`tests/file_length.rs`).

## [0.2.0] - 2026-02-14

### Added

- GitHub Actions CI for formatting, check, clippy, feature-matrix tests, and docs with warnings denied.
- Multi-stage Docker build with non-root runtime defaults.
- GitHub Actions workflow to build and publish multi-arch container images to GHCR on version tags.
- GitHub Actions release job for version tags that publishes a GitHub Release using the matching version section from `CHANGELOG.md`.
- README deployment and embedding examples for standalone, library-owned `main`, and Axum sidecar integration with a custom `AuthHook`.
- S3 TLS CA bundle controls and richer S3 error reporting.

## [0.1.0] - 2026-02-13

### Added

- Verdaccio-compatible npm registry proxy core API surface.
- Config loading from defaults, YAML config, CLI `--config`, and environment variables.
- Local and S3 tarball storage backends.
- Pluggable auth backends (local, HTTP plugin, embedded `AuthHook`).
- Built-in web UI routes and parity test suite.
