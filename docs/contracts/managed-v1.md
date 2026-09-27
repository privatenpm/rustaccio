# Managed Data-Plane Bridge Contract v1

Status: Active  
Version: `v1`

This document describes how Rustaccio behaves when it runs as a managed data
plane of the Go control plane (`RUSTACCIO_METADATA_BACKEND=managed`). The
control plane is authoritative for package metadata, entitlement and publish
session state; Rustaccio stays the byte-heavy data plane: publish decoding,
hashing, tarball upload streaming, download redirects/proxying and usage
events. The wire contract itself (endpoints, payloads, failure semantics) is
specified in `docs/plan/registry-contract.md` of the control-plane repository;
this file documents the data-plane view.

## Activation and startup validation

Managed mode is enabled with:

```
RUSTACCIO_METADATA_BACKEND=managed
RUSTACCIO_CONTROL_PLANE_URL=https://control-plane.example.com
RUSTACCIO_CONTROL_PLANE_TOKEN=<node credential>
```

Startup fails fast unless all of the following hold:

1. `RUSTACCIO_CONTROL_PLANE_URL` and `RUSTACCIO_CONTROL_PLANE_TOKEN` are set.
2. `RUSTACCIO_TARBALL_BACKEND=s3` with a configured bucket (the control
   plane's create-only storage contract assumes the S3 deployment shape).
3. With `RUSTACCIO_REQUIRE_PLACEMENT=true`, the first fleet heartbeat must
   succeed and the control plane must have placed this node (a fleet config
   content is known for it), otherwise startup is refused.

The existing `sidecar` metadata backend remains the default; OSS/self-hosted
mode is untouched. `RUSTACCIO_METADATA_BACKEND=transactional` stays a preview
error and now points at `managed`.

## Node credential and request identity

Every control-plane call is a JSON call under
`{RUSTACCIO_CONTROL_PLANE_URL}/api/registry` with
`Authorization: Bearer $RUSTACCIO_CONTROL_PLANE_TOKEN` (the node credential)
and an `x-request-id` header propagated from the inbound request (or a fresh
UUID). The end-user npm token travels inside the request payload, never as
the node credential.

Timeouts: authorize/events/downloads 5s, publish reserve 15s, publish
finalize 30s, session lookup 10s, fleet calls 5–10s, presigned uploads 300s
(`RUSTACCIO_MANAGED_UPLOAD_TIMEOUT_MS`). No call is retried on 4xx; the only
retry is one extra attempt on connect-timeout for `GET /v1/publishes/{id}`
(publish uncertainty resolution).

Failure semantics:

- 401 from the control plane means the node credential failed: the request
  fails, never falls back.
- Control-plane outages fail **closed** for private operations: a stable
  `502` body `{"error": "…", "code": "CONTROL_PLANE_UNAVAILABLE"}`. There is
  no upstream (npmjs) fallback and no local permissive path in managed mode.

## Authorization enforcement

Before any storage or proxy byte moves, managed handlers call
`POST /v1/authorize`:

| npm operation | `operation` |
| --- | --- |
| packument/version/dist-tag reads | `metadata:read` |
| tarball GET/HEAD | `tarball:read` |
| `GET /-/whoami` | `identity:read` |
| `PUT /:package`, `PUT /:package/-rev/:rev` | `package:publish` |
| dist-tag PUT/DELETE | `dist-tag:write` |
| unpublish DELETE routes | `package:unpublish` |

Denials map `reason` codes: `token_denied`/missing → 401,
`package_not_found` → 404, everything else → 403 carrying the reason.

Decisions are cached in a bounded TTL map
(`RUSTACCIO_MANAGED_DECISION_CACHE_MAX_ENTRIES`, default 10000) keyed by
(token, credential_version, operation, host, package, version). The cache
entry expires at `min(local TTL, expires_at)` — a cached decision never
outlives its control-plane deadline, and an already-expired decision is never
cached. The local TTL ceiling defaults to 30s
(`RUSTACCIO_MANAGED_DECISION_CACHE_TTL_MS`).

`POST /-/admin/policy-cache/invalidate` flushes the decision, download and
packument caches; `POST /-/admin/package-cache/invalidate` flushes one
package's packument entries. In managed mode both require the node
credential as the bearer token.

## Publish bridge (`PUT /:package`)

1. `POST /v1/authorize` with `package:publish` (the package may not exist
   yet).
2. The body is consumed as a stream with bounded memory: metadata before the
   first `_attachments.*.data` payload is buffered up to
   `RUSTACCIO_MANAGED_MAX_METADATA_BYTES` (default 8 MiB), the base64 payload
   is decoded incrementally and spooled to `<data_dir>/managed-spool/`, and
   the JSON tail is buffered under the same bound. Total body size is still
   capped by `max_body_size` (413 above it). Decoded bytes are hashed while
   streaming: exact byte count, SHA-512 SRI (`sha512-<base64>`) and SHA-1 hex.
   Exactly one attachment and one `versions` entry are supported; anything
   else is a 400. A document without attachment data is a metadata-only write
   and is proxied to the control-plane registry surface verbatim.
3. `POST /v1/publishes` reserves the version. `operation_key` is a fresh
   UUID per publish attempt (stable across the attempt's reserve → upload →
   finalize); `fingerprint` is base64 SHA-256 over
   `name\nversion\n<manifest json>\n<declared bytes>`. `registry_id` comes
   from the authorize response or `GET /resolve-domain` (cached).
4. The spooled tarball is streamed with `PUT` to `upload.url` using
   `upload.headers` (a `Content-Length` is added when absent). Upload
   failures abort the session (`POST /v1/publishes/{id}/abort`, best-effort)
   and fail with 502.
5. `POST /v1/publishes/{id}/finalize` commits with the computed
   integrity/shasum/byte count. On a finalize transport failure or 5xx the
   outcome is uncertain: the node resolves `GET /v1/publishes/{id}` (one
   retry on connect timeout) and, when the session is recorded committed,
   returns the recorded npm response instead of failing.

Error mapping: `409 version_exists` → 403 "You cannot publish over the
previously published versions: `<version>`."; other 409 codes
(`storage_conflict`, `fingerprint_mismatch`) → 409; `410` → 410 Gone; 403 →
403 with the control-plane reason. Success answers 201 with the
control-plane recorded npm response body.

## Metadata reads

`GET/HEAD /:package` and `GET/HEAD /:package/:version` are reverse-proxied to
the control-plane registry surface (`RUSTACCIO_MANAGED_METADATA_ORIGIN`,
default = `RUSTACCIO_CONTROL_PLANE_URL`), preserving the method, `Accept`,
`Authorization`, `Host` (the surface is host-dispatched) and the
`If-None-Match`/`ETag` pair; responses stream through with bounded buffers.
An optional tiny packument cache (default off,
`RUSTACCIO_MANAGED_METADATA_CACHE_TTL_MS`) keys entries by (origin, path,
representation) and only stores responses carrying an `X-Package-Revision`
header; responses without it are never cached.

## Downloads (`GET/HEAD /:package/-/:filename`)

1. Authorize `tarball:read` for the exact version inferred from the filename.
2. `POST /v1/downloads/resolve`; the response (including `download_url`) is
   cached up to `expires_at`. An optional `credential_id` identifies the
   control-plane download key that authorized the transfer.
3. With a `download_url`: default `redirect` mode answers `302 Location:
   <url>`; `RUSTACCIO_MANAGED_DOWNLOAD_MODE=proxy` streams the URL through,
   forwarding `Range` so 206/416 pass through. HEAD in proxy mode answers
   with the resolved content headers without streaming the body.
4. Without a `download_url` the node answers 502
   (`CONTROL_PLANE_UNAVAILABLE`); direct-storage is the supported shape.

## Upstream forward

Authorize answers may include an optional `route` of `"hosted"` or
`"upstream"`. An absent field, and `"hosted"`, keep today's behavior
(a denied name answers 404). `"upstream"` reverse-proxies the original
request — method, path, query, `Host`, `Authorization`, and the npm client
headers — to the control-plane npm surface
(`RUSTACCIO_MANAGED_METADATA_ORIGIN`, default the control-plane URL). The
node does not talk to public registries itself: uplinks stay disabled in
managed mode, and a forward failure is a 502, not a local fallback.

## Events

Completed transfers are reported through `POST /v1/events` with UUID v4 event
IDs: `publish` after a committed finalize, `download` when a redirect is
issued (`status: redirected`, bytes = the recorded tarball size) or a proxied
stream completes (bytes actually streamed; `complete`, `partial` with `range`,
or `aborted`). Each event is fsynced to an append-only spool
(`RUSTACCIO_MANAGED_EVENT_SPOOL_DIR`, default `<data_dir>/managed-events`,
bounded by `RUSTACCIO_MANAGED_EVENT_SPOOL_MAX_BYTES`, default 64 MiB) before
the enqueue returns. A background worker batches the spool (50 or 5s) and
retries a failed batch — same `event_id`s — until the control plane answers
2xx. Acknowledged batches are removed; a restart replays whatever is left.
When the byte bound is hit the newest event is dropped and
`rustaccio_events_dropped_total` is incremented (always present on the
metrics endpoint, including zero). A spool failure does not fail the npm
operation.

Download and publish events carry the optional transfer context when known:
`registry_id`, `format` (`npm`), `file`, `declared_bytes`, `status`, `range`,
`client_ip`, `user_agent`, `npm_command`, `npm_session`, `ci`, `host` and
`request_id`. `client_ip` is the trusted edge address (`Fly-Client-IP`, else
`CF-Connecting-IP`); a client-supplied `X-Forwarded-For` is never copied.
`ci` is set from an npm `ci/<name>` user-agent token or a pip/twine
`"ci":true` marker. `cache` is left unset on hosted transfers (it denotes an
upstream cache outcome the node does not observe). Older control planes that
ignore unknown fields remain compatible. Download events still echo
`credential_id` and the resolved version when present.

Packument cache hits, which never reach the control plane, are aggregated per
(registry, credential, package, minute) and emitted as one `kind: "metadata"`
event with `count`, `bytes` and `not_modified` when the minute closes.

## Fleet

At startup and every 30s the node POSTs `/v1/fleet/heartbeat` with its
identity (`RUSTACCIO_DATA_PLANE_ID`, default hostname), the binary version
and capabilities (`publish-bridge`, `metadata-proxy`, `download-redirect` or
`download-proxy`, plus `events_v2` and `upstream_forward`). When the
response's `config_revision` is newer than the stored one, the node fetches
`GET /v1/fleet/config?after=<current>` and stores the content.
`RUSTACCIO_REQUIRE_PLACEMENT=true` makes placement a startup requirement
(see above).

## Not served in managed mode

Search (`/-/v1/search`), `/-/all`, the npm bootstrap payload, the web UI
package views, and local storage answers are disabled: unmatched routes fail
closed with 404. Local ACLs, uplinks and the external auth/policy HTTP
plugins are never consulted for private operations, including when an
authorize answer asks for an upstream forward. Metrics keep working when
`RUSTACCIO_METRICS_REQUIRE_ADMIN=false`.
