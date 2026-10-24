# Configuration reference

Generated from the typed configuration (`attome_config::AppConfig`) by
`crates/foundation/attome-config/tests/config_schema.rs`; do not edit it by hand.
To regenerate it and `config.schema.json`, run
`ATTOME_WRITE_CONFIG_SCHEMA=1 cargo test -p attome-config --test config_schema`.

A **secret** field is never shown back (it is write-only) and should come from an
environment variable (`${VAR}`). Unknown keys are reported at boot and refused by
`preflight`, except keys starting with `_`, so the file carries no `$schema` key;
point an editor at `config.schema.json` through its own settings instead.

## `app`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `app.contract_reference` | string, optional | `null` |  | U11-T1: the operator's contract or purchase-order reference, shown on the usage page. Free text; nothing is enforced by it. |
| `app.debug_pipeline_trace` | boolean | `false` |  | Z5-T1: in a debug build, every response carries `x-attome-layers`, the layers the request passed, outermost first, so a test can pin the middleware order. Ignored in a release build. |
| `app.deployment_profile` | string | `"development"` |  | P-production-safety-profile — one of `"development"`/`"production"` (see `VALID_DEPLOYMENT_PROFILES` in `validate()`). Default `"development"` — today's behavior, unchanged: every other field in this file keeps whatever value an operator gave it, validated only by the per-field checks that already existed. Setting `"production"` is an explicit, additional opt-in (never derived from `APP_ENV`, which already means "tolerate unresolved `${VAR}` placeholders for local dev" — a different concern) that runs `validate_production_profile`: a fixed set of individually-valid-but-unsafe-in-combination defaults (`database.ssl_mode = "prefer"`, `cache.tls_enabled = false`, `storage.s3_verify_ssl = false`, no `auth.apikey_default_expiry_days`, `audit.signing_enabled = false`, `database.migrate_on_boot = true`, `jobs.run_worker_inline = true`) become hard boot errors instead of silent template carry-overs. No per-check escape hatch by design — a hatch on any one of these would reopen exactly the gap this profile closes. |
| `app.failover_retry_max_secs` | integer | `10` |  | AB2-T3: seconds a GET, HEAD or `Idempotency-Key` request that lost its database connection is run again inside the server, across a failover. 0 turns it off; at most 30. |
| `app.frontend_host` | string |  |  |  |
| `app.frontend_port` | integer |  |  |  |
| `app.max_body_size_bytes` | integer | `10485760` |  |  |
| `app.max_concurrent_per_ip` | integer | `64` |  | Z5-T5: requests one address runs at once before answering 429 with `Retry-After: 1`. 1 to `max_concurrent_requests`. |
| `app.max_concurrent_requests` | integer | `1024` |  | Z5-T5: requests this node runs at once before answering 503 with `Retry-After: 1`, ahead of authentication. 1 to 1,000,000. |
| `app.packs` | array of string | `[]` |  | Packs applied at every boot, in order (`attome init --pack crm`): each pack's changesets from `<packs_root>/<name>/changesets/`, through the changeset ledger, so a second boot changes nothing. |
| `app.packs_root` | string, optional | `null` |  | Where packs live. Unset: `packs` next to the executable. |
| `app.port` | integer |  |  |  |
| `app.public_frontend_url` | string, optional | `null` |  | P-account-lifecycle — canonical public URL used to build links in emails (password reset, verification), e.g. "https://app.customer.com". `None` (the default) falls back to the same dev-only derived origin `allowed_origins()` uses (`http://{frontend_host}:{frontend_port}`) — any deployment behind TLS must set this explicitly, mirroring the `cors.allowed_origins` rule. |
| `app.request_timeout_secs` | integer | `30` |  |  |
| `app.server_host` | string | `"0.0.0.0"` |  |  |
| `app.shutdown_drain_delay_secs` | integer | `10` |  | S1 (BSV-F13 / BSV-D11) — how many seconds a draining node keeps answering `/health/ready` with 503 **before** it signals its HTTP listeners to stop accepting connections. |
| `app.time_zone` | string, optional | `null` |  | A4-T1: the deployment's time zone, an IANA name such as `Asia/Riyadh`. Dates in autonumber formats and their yearly, monthly and daily resets follow it. Unset (or unknown): UTC. |
| `app.tls.cert_path` | string | `""` |  | The PEM certificate chain, leaf first. |
| `app.tls.enabled` | boolean | `false` |  | Serve HTTPS on `app.port` from the certificate and key below. |
| `app.tls.key_path` | string | `""` |  | The PEM private key (PKCS#8, PKCS#1 or SEC1). |
| `app.tls.min_version` | string, optional | `null` |  | The oldest TLS version accepted: `"1.2"` (the default) or `"1.3"`. |
| `app.web_root` | string, optional | `null` |  | The built web app's directory, served by `attome serve` for every GET outside the API (`attome_server::web`). Unset: a `web` directory next to the executable when one exists; otherwise the server serves the API only and the web app is hosted separately. |

## `approval`

D-195 / P-four-eyes-approval — which `attome_approval` action_type strings require dual-control approval instead of executing inline. Empty by default (opt-in, same "ships dark behind a flag" posture as `idempotency`/`audit.chainer_enabled`) — a deployment names an action here only once a customer's security policy or compliance framework actually requires it (the backlog's own trigger condition).

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `approval.required_actions` | array of string | `[]` |  | `action_type` strings (e.g. `"security.rewrap"`, `"security.role_grant"`; `xrm_server::KNOWN_ACTION_TYPES` is the list of record) that must go through `attome_approval::submit` instead of executing inline. Empty by default — a deployment opts in explicitly, same shape as `idempotency.mandatory_operations`. |
| `approval.ttl_hours` | integer | `72` |  | How long a submitted request stays decidable before `attome_approval::sweep_expired` reaps it as `expired`. |

## `audit`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `audit.anchor_store.object_lock_mode` | string | `""` |  | What the operator provisioned on the bucket, out-of-band: `"compliance"`, `"governance"`, or `"none"`. Mirrors `deploy/backup/README.md`'s fallback ladder, and means the same things: compliance mode cannot be bypassed even by the bucket owner's root credentials; governance mode can, by a distinct identity holding `s3:BypassGovernanceRetention`. `"none"` is honest about having no bucket-side backstop at all and is refused in production. |
| `audit.anchor_store.object_lock_retention_days` | integer | `0` |  | The default retention period, in days, configured on the bucket. Must be at least as long as the deployment's audit-retention obligation — an anchor that expires before the events it attests to is worse than useless, because the chain then looks anchored right up until the moment someone needs it. Zero is refused in production. |
| `audit.anchor_store.s3_access_key` | string | `""` |  | The **producer** identity: `PutObject`/`GetObject`/`ListBucket` only. No `DeleteObject`, no `DeleteObjectVersion`, no `PutBucketVersioning`/`PutBucketPolicy`/`PutLifecycleConfiguration`, no `s3:BypassGovernanceRetention`, no `PutObjectRetention` (which would let a compromised app shorten its own retention). |
| `audit.anchor_store.s3_bucket` | string | `""` |  | Must differ from `storage.s3_bucket` — `validate()` rejects the same bucket for both, since the whole point is that this one is WORM and that one cannot be. |
| `audit.anchor_store.s3_endpoint` | string | `""` |  | S3-compatible endpoint holding the anchor bucket. May be the same endpoint as `storage.s3_endpoint` (one RustFS/MinIO deployment, two buckets) or a wholly separate one — a different account, region, or provider is strictly better, since it widens the blast-radius gap this whole mechanism exists to create. Empty selects AWS S3 proper (the same convention `storage.s3_endpoint` uses). |
| `audit.anchor_store.s3_region` | string | `""` |  |  |
| `audit.anchor_store.s3_secret_key` | string |  | yes |  |
| `audit.anchor_store.s3_verify_ssl` | boolean | `true` |  |  |
| `audit.chainer_enabled` | boolean | `true` |  | P1.13 stage 4 — the cutover, and since D-316 the **default**. When true, `write()` only durably captures the event into `xrm_audit_ingest` (no lock, no chain read) and the `audit_chainer` process becomes solely responsible for producing header rows — requires `audit_chainer` to actually be running, or events accumulate in `xrm_audit_ingest` unchained (the lag gauge, the `AuditChainerLagHigh` alert, and finally `ingest_backlog_threshold`'s mutation gate are what make that visible rather than silent). |
| `audit.erasure_enabled` | boolean, optional | `null` |  | D-107 (P-data-lifecycle item (d)'s erasure ruling) — crypto-shredding. When active, every audit write for a record with an `id` fetches-or-creates that record's data-encryption key (`xrm_audit_erasure_key`, migration 0039) and encrypts its field values in place before any storage — see `xrm_audit::erasure`. |
| `audit.erasure_key_encryption_key` | string \| object |  | yes | D-107 — AES-256-GCM master key(s) (64 hex chars each) wrapping every record's data-encryption key in `xrm_audit_erasure_key.wrapped_dek`. A *dedicated* key, same reasoning as `auth.mfa_encryption_key` not reusing `s2s.key_encryption_key`: audit-erasure keys are their own trust domain. Only required (`check_secret`-validated) when `erasure_enabled = true`. Generate with: openssl rand -hex 32. P-key-rotation-and-jwt (a): a `KeyRing` — see that type's doc. |
| `audit.external_anchoring_enabled` | boolean | `false` |  | P-audit-chain-hardening item (b) — anchors each sealed batch's Merkle root to the deployment's own configured object store (`attome_storage`, e.g. RustFS), outside this database's own blast radius, so a compromise of the DB+app config together can no longer silently rewrite history undetected. Default false: ships dark, same posture as every other flag in this section. Best-effort — an anchoring failure is logged/alertable but never blocks the chainer's own batch commit (`xrm_audit::chainer`'s degrade-not-fail design, D-027). See `xrm_audit::anchor`. |
| `audit.ingest_backlog_threshold` | integer | `100000` |  | P-audit-chain-hardening item (e) — ingest circuit breaker. How many undrained `xrm_audit_ingest` rows (summed across organizations, `xrm_audit::chainer::aggregate_lag`'s `total_pending_ingest`) trip the mutating-request gate (`AppState::audit_ingest_backlog_exceeded`). 100_000 matches the originating review's own number — a starting point, not a measured one; tune per deployment. Reads are never affected, only `POST`/`PUT`/`PATCH`/`DELETE`. |
| `audit.ingest_capture_enabled` | boolean | `false` |  | P1.13 stage 1: additionally durably capture every audit event into `xrm_audit_ingest` (same transaction as the existing header/detail/ snapshot writes) so a future async chainer has something to drain. Purely additive today — the synchronous chain append in `AuditService::write` still runs unconditionally either way; this flag does not yet turn it off. Default false until the chainer (a later P1.13 stage) exists to consume the table. |
| `audit.ingest_retention_days` | integer | `0` |  | P1.13 step 6 — how many days a `xrm_audit_ingest` row is kept after its batch has already been drained into `xrm_audit_header` (i.e. it is provably redundant, kept only for a debugging/replay window). `0` disables pruning entirely — an explicit opt-in, never a default-on delete of audit data. |
| `audit.partition_create_ahead_months` | integer | `2` |  | P-db-maintenance item (c) — how many months of partitions the create-ahead job keeps provisioned beyond the current one, for the audit family + `xrm_s2s_access_log` (migrations/0026). `2` matches the plan's stated default; raise it for a deployment whose maintenance window runs less often than this job's own poll interval. |
| `audit.signing_enabled` | boolean | `false` |  | Sign every audit chain event's (prev_hash\|\|event_hash) with a dedicated Ed25519 keypair (D-016 — unrelated to the license verifier's verify-only key in xrm-license, D-142). When false, `signature`/`signing_key_id` are left NULL; hash-chaining alone still applies. |
| `audit.signing_key_id` | string | `""` |  | Identifies which keypair produced a signature — stays alongside every signature it makes so old signatures remain attributable after a key rotation. Any operator-chosen label, e.g. "audit-key-1". |
| `audit.signing_private_key` | string |  | yes | 64-hex-char Ed25519 signing seed. Required when signing_enabled = true. Generate with: openssl rand -hex 32 |

## `auth`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `auth.access_token_expiry_mins` | integer | `15` |  | Access-token (session_token cookie) lifetime, in minutes. Deliberately short (Plan 1.6a) — the refresh flow is what makes that tolerable. |
| `auth.apikey_default_expiry_days` | integer, optional | `null` |  | P-account-lifecycle — default `api_key.expires_at` for newly created keys, in days. `None` (the default) means new keys still get no expiry unless the caller passes one explicitly — existing deployments are unaffected until an operator opts in. |
| `auth.apikey_hash_pepper` | string |  | yes | P-api-key-hashing (D-112, revised by D-118) — HMAC-SHA256 pepper ring for `api_key.secret_hash`, superseding per-request Argon2 for api-key secrets only (user passwords stay Argon2, `password.rs`, untouched). The *current* pepper — every newly issued key and every rehash-on-use conversion writes with this one. Unconditionally `check_secret`-validated in `validate()` below — unlike `mfa_encryption_key`/`s2s.key_encryption_key`, there is no feature flag gating this: every deployment authenticates api-key requests, so an unset/short pepper is always a boot error (D-038), never a silent unkeyed-hash fallback. `#[serde(default)]` (empty string) only so a config file that omits it still deserializes — `validate()` is what actually enforces the requirement. |
| `auth.apikey_hash_pepper_id` | integer | `0` |  | Id of `apikey_hash_pepper` above, stored inline in `api_key.secret_hash` as `hmac256:v{id}$<hex>`. **The very first pepper a deployment ever sets must use id 0** — id 0 doubles as the fallback for the original, pre-rotation D-112 rollout's unversioned `hmac256$<hex>` rows (see `attome_auth::apikey_hash`'s module doc), so a deployment that skips straight to id 1+ on its very first boot with no `hmac256$`-format rows in the database is fine, but one migrating forward from the original rollout MUST keep id 0 resolvable (either `apikey_hash_pepper_id = 0` or an `apikey_hash_previous_peppers` entry with `id = 0`) or its existing keys stop verifying. `validate()` below only enforces the id-collision/duplicate checks it can prove statically — it cannot know whether unversioned rows exist in a given database, so this precondition is operator-enforced, documented here and in D-112's revision entry, not boot-checked. |
| `auth.apikey_hash_previous_peppers` | array of object |  |  | Retired pepper(s), keyed by id, kept only long enough to verify already-issued keys that haven't rehashed to the current id yet — same "current + previous" dual-key-slot shape `s2s.key_encryption_key` already uses for the same reason. Empty (the default) means no rotation has ever happened. A row referencing an id present in neither this list nor `apikey_hash_pepper_id` fails closed (same "wrong secret" outcome as any other verify failure) rather than erroring — do not remove an id from this list while any `api_key` row might still reference it. |
| `auth.breach_check_online` | boolean | `false` |  | Z4-T9: also ask an online k-anonymity range service when a password is set at registration or reset (off by default; only the first five hex characters of the password's SHA-1 are sent). |
| `auth.breach_list_file` | string, optional | `null` |  | Q7-T1: an offline set of breached passwords (the Have I Been Pwned SHA-1 download, `HASH` or `HASH:COUNT` per line), checked locally when a password is set. Unset, only the small built-in list applies. Replace the file and restart to update it. |
| `auth.breach_range_url` | string, optional | `null` |  | Z4-T9: the range service, the five-character prefix appended (Have I Been Pwned's when unset). |
| `auth.jwt_audience` | string | `""` |  | P-key-rotation-and-jwt (c) — the `aud` claim every session/pending token carries and is validated against. Empty (the default) means "use `jwt_issuer`" (`AppConfig::jwt_audience`) — a deployment only needs to set this explicitly if it wants a distinct audience string. |
| `auth.jwt_issuer` | string |  |  |  |
| `auth.jwt_secret` | string \| object |  | yes | P-key-rotation-and-jwt (a)/(c): a `KeyRing` rather than a bare secret — see that type's doc. A plain config-file string still deserializes (wrapped into a single active/legacy entry), so an existing deployment that never touches this field sees zero behavior change. `kid` in every minted JWT's header names which ring entry signed it; a second (retired) entry left in the ring is accepted for verification during a rotation's overlap window and rejected once removed. |
| `auth.jwt_signing_keys` | string \| object |  | yes | Z4-T3: Ed25519 signing keys for session and pending tokens, each a 32-byte seed as 64 hex characters, by key id. When the ring has an active key, new tokens are signed EdDSA under it; `jwt_secret` keeps verifying the HS256 tokens already issued until they expire, so the cut-over logs nobody out. Empty (the default) keeps HS256. |
| `auth.kdf.acquire_timeout_ms` | integer | `2000` |  | How long a request waits for a KDF permit before a 503 (100..=30000). |
| `auth.kdf.argon2_m_cost` | integer | `19456` |  | Argon2id memory cost in KiB for new hashes. OWASP floor 19456. |
| `auth.kdf.argon2_t_cost` | integer | `2` |  | Argon2id passes for new hashes. OWASP floor 2. |
| `auth.kdf.hard_cap` | integer | `6` |  | Upper bound on concurrent KDF operations whatever the host (1..=64). |
| `auth.kdf.memory_budget_bytes` | integer | `268435456` |  | Memory all concurrent KDF operations may use together; must fit at least one operation. |
| `auth.kdf.password_min_length` | integer | `12` |  | Minimum password length in characters (floor 12, security contract I2). |
| `auth.mfa_challenge_max_attempts` | integer | `5` |  | P-mfa-challenge-hardening: per-challenge attempt ceiling enforced atomically against the `mfa:pending:{jti}` Redis marker (see `attome_auth::mfa`) — reaching it kills the challenge outright (the client must re-authenticate with the password for a fresh `pending_token`), independent of the general per-IP/user `rate_limit.categories.mfa` budget. Default `5`, same "additive, default-safe" posture as every other new config field in this section — a deployment that never touches this sees a sane default, not a behavior change requiring opt-in. |
| `auth.mfa_encryption_key` | string \| object |  | yes | P2.8 step 7 — AES-256-GCM master key(s) (64 hex chars each) encrypting `base_user_mfa.secret_encrypted` at rest, same pattern as `s2s.key_encryption_key` (`xrm_s2s::crypto`) but a dedicated key: TOTP secrets and S2S client secrets are separate trust domains and must not share a key. Only required (`check_secret`-validated) when `mfa_policy != "off"`. P-key-rotation-and-jwt (a): a `KeyRing` — see that type's doc for the bare-string back-compat shape and how rotation works. |
| `auth.mfa_policy` | string | `"off"` |  | P2.8 step 7 — one of `"off"`/`"optional"`/`"required"` (see `VALID_MFA_POLICIES` in `validate()`). `"off"` (the default) is today's behavior unchanged. `"optional"` challenges only accounts that have self-enrolled TOTP; `"required"` blocks a password login for an unenrolled account until it completes enrollment (`attome_auth::mfa`/D-068). Same string-enum convention as `database.ssl_mode` — deliberately a plain `String`, not a Rust enum. |
| `auth.oauth_google_client_id` | string | `""` |  |  |
| `auth.oauth_google_client_secret` | string |  | yes |  |
| `auth.refresh_absolute_lifetime_days` | integer | `30` |  | D-504 — absolute lifetime of a refresh family, in days. A family ends this long after the credential verification that started it, however often it rotates. Default 30. `AppConfig::validate` requires 1 to 365; migration 0462's fallback anchor for an inconsistent lineage relies on that ceiling to be expired. |
| `auth.refresh_token_expiry_days` | integer | `30` |  | Idle lifetime of one `base_refresh_token` row, in days: how long a refresh token stays valid without being rotated. |
| `auth.registration_mode` | string | `"disabled"` |  | P-registration-gating — one of `"public"`/`"invite"`/`"disabled"` (see `VALID_REGISTRATION_MODES` in `validate()`). Default `"disabled"` — deliberately secure-by-default (D-128): a deployment upgrading without touching config loses public self-registration, not the other way around. `"public"` is today's pre-P-registration-gating behavior (anyone can `POST /api/v1/auth/register`); `"disabled"` rejects every registration attempt with `AppError::Forbidden` before any DB work; `"invite"` additionally requires a valid, unconsumed `base_invitation_token` bearer matching the submitted email (Phase 2). Same plain-`String` string-enum convention as `mfa_policy`/ `database.ssl_mode` — not a Rust enum. |
| `auth.require_verified_email` | boolean | `false` |  | P-account-lifecycle — when true, `attome_auth::accounts::login` rejects (403) a local password account whose `email_verified` is still false. Default false so air-gapped/no-SMTP deployments are unaffected; only turn this on once `email.enabled` is also true, or every local account locks itself out with no way to receive a verification link. |
| `auth.secure_cookies` | boolean | `true` |  | Gates the `Secure` flag on both auth cookies (Plan 1.6a). Default true — only `config.debug.json` sets this false, so plain-http local dev keeps working. `SameSite=Strict`/`HttpOnly` apply unconditionally either way. |

## `backup`

U6-T1 — the daily local database backup. On by default.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `backup.dir` | string, optional | `null` |  | Where archives go. Unset: a `backups` folder next to the configuration file. |
| `backup.enabled` | boolean | `true` |  | Run the daily backup. On by default. |
| `backup.files` | boolean | `true` |  | Copy the object store's files (attachments, brand assets) beside each database backup. On by default. |
| `backup.hour` | integer | `2` |  | The hour of the day (UTC, 0–23) the backup runs. |
| `backup.keep` | integer | `7` |  | How many archives to keep, newest first. At least 1. |
| `backup.pg_dump` | string, optional | `null` |  | The `pg_dump` program. Unset: `pg_dump` on the PATH. |

## `cache`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `cache.backend` | `redis` \| `memory` |  |  | `redis` (the default) or `memory`. With `memory`, `host`, `port`, `password` and `db` are not used and may be left at any value. |
| `cache.connection_pool_size` | integer | `32` |  | Pool size — plausibly scales with hardware/load. Has a default so a deployment that hasn't tuned it can omit the key entirely. |
| `cache.db` | integer | `0` |  |  |
| `cache.encryption_key` | string \| object, optional |  | yes | Z3-T3: the key ring a cache declared `EncryptedInRedis` seals its values with before they reach Redis (AES-256-GCM, tagged with the key id so a rotation keeps old entries readable). Required when such a cache runs over Redis; such a cache refuses to start without it. |
| `cache.host` | string | `""` |  |  |
| `cache.metadata_poll_interval_secs` | integer | `5` |  | Y8-T2: how often a node checks the metadata change log for a change whose doorbell it missed (a crash between commit and publish, a Redis blip). The check is one indexed `MAX(id)`; 5 seconds bounds how stale a node can be after a lost doorbell. At least 1. |
| `cache.metadata_registry_enabled` | boolean | `true` |  | Rollback switch for Plan 1.2 (kept for one release, not deleted): when `false`, `resolve_entity` falls back to the pre-1.2 direct Postgres query path instead of the arc-swap metadata registry. |
| `cache.password` | string |  | yes |  |
| `cache.port` | integer | `0` |  |  |
| `cache.roles.coordination.connection_pool_size` | integer | `16` |  |  |
| `cache.roles.coordination.db` | integer | `0` |  |  |
| `cache.roles.coordination.host` | string |  |  |  |
| `cache.roles.coordination.password` | string |  | yes |  |
| `cache.roles.coordination.port` | integer |  |  |  |
| `cache.roles.coordination.sentinel.nodes` | array of object |  |  |  |
| `cache.roles.coordination.sentinel.sentinel_password` | string, optional |  | yes |  |
| `cache.roles.coordination.sentinel.sentinel_username` | string, optional | `null` |  |  |
| `cache.roles.coordination.sentinel.service_name` | string |  |  | Fred's `sentinelServiceName` — the name Sentinel knows the monitored master by (often `mymaster`). Required whenever `sentinel` is set. |
| `cache.roles.coordination.timeout` | integer | `2000` |  |  |
| `cache.roles.coordination.tls_ca_path` | string, optional | `null` |  |  |
| `cache.roles.coordination.tls_enabled` | boolean | `false` |  | P-datastore-tls — see `CacheSection::tls_enabled`. A role override can point at a differently-secured endpoint than the base block. |
| `cache.sentinel.nodes` | array of object |  |  |  |
| `cache.sentinel.sentinel_password` | string, optional |  | yes |  |
| `cache.sentinel.sentinel_username` | string, optional | `null` |  |  |
| `cache.sentinel.service_name` | string |  |  | Fred's `sentinelServiceName` — the name Sentinel knows the monitored master by (often `mymaster`). Required whenever `sentinel` is set. |
| `cache.timeout` | integer | `2000` |  | Connect/command timeout in milliseconds — plausibly varies with network latency. |
| `cache.tls_ca_path` | string, optional | `null` |  | P-datastore-tls — path to a CA certificate file (PEM) to pin, instead of trusting the system/default root store. Only meaningful when `tls_enabled` is true. |
| `cache.tls_enabled` | boolean | `false` |  | P-datastore-tls — connect via `rediss://` (fred's TLS-enabled scheme) instead of `redis://`. Default false — byte-for-byte identical to pre-TLS behavior when unset. |

## `capability`

D-344 (amends D-167) — the durability-capability gate. Governs a *route-level* 503 for operations that cannot durably complete (upload, bulk import, mail resend), never node readiness. See `CapabilitySection`'s doc comment for why `enforcement_enabled` defaults on where most flags in this tree ship dark.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `capability.enforcement_enabled` | boolean | `true` |  | Whether a confirmed-unavailable capability actually rejects requests on the routes that declare it, or is only reported. |
| `capability.failure_threshold` | integer | `2` |  | Consecutive failed probes before a capability flips to `unavailable`. 2 (i.e. up to ~60s at the default interval) rather than 1: a single dropped connection to S3 or a relay is normal background noise and must not start rejecting uploads. A single success clears the counter immediately — slow to trip, fast to recover. |
| `capability.probe_enabled` | boolean | `true` |  | Whether `xrm_server::spawn_capability_refresh` should run at all. `false` leaves every capability at `unknown` forever, which the gate treats as "pass" — byte-identical to the behavior before D-344, same "nothing happens unless the poll task is spawned" posture as `audit.ingest_backlog_threshold`'s breaker. |
| `capability.probe_interval_secs` | integer | `30` |  | Seconds between probe rounds. 30s, not the 15s a readiness probe would use: this drives a route gate, not traffic routing, and the SMTP probe opens a real TCP+TLS connection to the relay each round — a tighter loop is a connection-rate cost paid against every deployment's mail provider for no decision-making benefit. |
| `capability.worker_stale_after_secs` | integer | `90` |  | How stale (`apalis.workers.last_seen`, via `attome_jobs::worker_last_seen_age_seconds`) a queue's worker heartbeat may be before that queue counts as a failed probe. 90s matches the `ApalisWorkerStale` alert rule's own expression (`observability/alerts.yml`) — 3 missed 30s `keep_alive` beats — so the gate and the alert can never disagree about what "the worker is down" means. |

## `change_feed`

M01 §7 C-04 — how long a change-feed row that every registered consumer has passed is kept before `PlatformJob::PruneChangeFeed` deletes it. See `ChangeFeedSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `change_feed.retention_days` | integer | `30` |  | Floor for `PlatformJob::PruneChangeFeed`: how long a fully-processed `xrm_core_entity_change_event` row is kept before it becomes eligible for deletion. This is a floor, not a target — `xrm_foundation:: change_feed::prune` additionally never deletes a row the slowest registered consumer cursor has not passed, however old it is, so raising this only ever makes pruning MORE conservative, never less. |

## `cors`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `cors.allowed_origins` | array of string | `[]` |  | Explicit allow-list of origins (scheme + host + port), e.g. "https://app.example.com". Never a wildcard alongside credentials. When empty, `AppConfig::allowed_origins` derives a dev-only default from `app.frontend_host`/`app.frontend_port` (always `http://` — set this explicitly for any deployment behind TLS). |

## `database`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `database.connection_number` | integer | `10` |  | Pool size — plausibly scales with hardware/load. Has a default so a deployment that hasn't tuned it can omit the key entirely. |
| `database.dbname` | string |  |  |  |
| `database.direct_url` | string, optional | `null` |  | P1.12 — a raw `postgres://` URL used ONLY for schema bootstrap + migrations (`attome_db::create_direct_pool`), bypassing whatever `host`/`port` above point at. Set this when `host`/`port` point at a transaction-mode pgbouncer, since `sqlx::migrate!`'s internal session-level advisory lock is unsafe under transaction pooling. `None` (the default — no pgbouncer in front of this deployment) falls back to `database_url()`, i.e. identical to today's behavior. Stays on `user`/`password` even when `migrator` above is configured — see `AppConfig::direct_database_url`'s doc comment (P-db-privilege- separation) for why. |
| `database.disable_statement_cache` | boolean | `false` |  | P1.12 — disables sqlx's client-side prepared-statement cache. Found necessary while actually load-testing the pgbouncer recipe (P1.8d step 5, 2026-07-21, D-106): a transaction-mode pgbouncer without protocol-level prepared-statement support (added in pgbouncer 1.21) can hand a client's logical connection a different real backend between transactions, so a statement sqlx cached as prepared on one backend does not exist on the next — surfacing as `prepared statement "sqlx_s_N" already exists` or "does not exist" under real concurrent load. D-171: `pgbouncer/Dockerfile` (this platform's reference recipe) moved off the Debian bookworm apt package (1.18) onto a maintained >=1.21 image, so this flag is no longer needed for that recipe by default — it remains a general escape hatch for any deployment fronted by a pre-1.21 pooler. Set this `true` whenever `database.host`/`port` point at such a pooler; `false` (the default — no behavior change for a direct-to-Postgres deployment) keeps the cache on. |
| `database.host` | string |  |  |  |
| `database.max_server_connections` | integer, optional | `null` |  | Z2-T2: PostgreSQL's (or pgbouncer's) `max_connections`, when known. `None` assumes 100 once sizing applies. |
| `database.migrate_on_boot` | boolean | `true` |  | P-db-privilege-separation follow-up (§1's "move migrations to a one-shot deployment job"). `true` (the default — today's behavior, unchanged) keeps `main.rs`'s inline `ensure_schema`, `run_migrations`, and role-password-seed sequence on every server boot, same as before this flag existed. Set `false` once a deployment's release process runs the dedicated `migrate` binary (`crates/server/src/bin/migrate.rs`, same `direct_database_url()` bootstrap identity, same migration set) as its own one-shot step ahead of starting/rolling any `server` process — the point being that the long-lived web process no longer needs to hold `CREATE ROLE`/DDL-capable bootstrap credentials at all once its deploy pipeline guarantees migrations already ran. `server` does not verify the schema is current when this is `false`; an operator who flips it without wiring the `migrate` step first will see ordinary runtime queries fail against a stale schema, not a boot error. |
| `database.migrator.password` | string |  | yes |  |
| `database.migrator.user` | string |  |  |  |
| `database.node_count` | integer | `1` |  | Z2-T2: how many processes share this database. With more than one, or with `max_server_connections` set, a pool with no `database.pools` entry is sized from PostgreSQL's connection budget split across the nodes instead of from `connection_number`. |
| `database.password` | string, optional |  | yes | P-bootstrap-credential-scoping (D-204) — the schema-bootstrap/ `CREATE ROLE`-capable identity (`database_url()`/`direct_database_url()`), needed ONLY by the one-shot `migrate` binary and, when `migrate_on_boot = true`, by the inline bootstrap sequence in `boot::init`. `server`/`worker` never legitimately reach either code path once `migrate_on_boot = false` and `migrator`/`runtime` below are configured (D-148) — so a deployment that renders those two processes' `config.json` without this field (and without `DB_PASSWORD` in their `.env`) keeps the bootstrap credential out of their container environment and out of the `AppState` they hold in memory for the life of the process, instead of it merely going unused. `None` is valid whenever nothing in this process can reach `database_url()`; `validate()` enforces `Some` when `migrate_on_boot = true`, and `bin/migrate.rs` independently requires `Some` unconditionally (that binary is not gated by `migrate_on_boot` — see its own module doc). |
| `database.pools.long.max_connections` | integer |  |  |  |
| `database.pools.migrator.max_connections` | integer |  |  |  |
| `database.pools.readonly.max_connections` | integer |  |  |  |
| `database.pools.readonly_primary.max_connections` | integer |  |  |  |
| `database.pools.runtime.max_connections` | integer |  |  |  |
| `database.port` | integer |  |  |  |
| `database.readonly.host` | string, optional | `null` |  | P-ha-failover-hardening follow-up / D-155 — closes the gap D-125 flagged ("`ReadonlyDbCredentials` only overrides user/password, there is no host/port override for the readonly role"): lets the readonly pool point at a genuinely different endpoint than `database.host`/`.port` — e.g. a Patroni HAProxy replica-routing listener (`deploy/ha/haproxy.cfg`'s `postgres_replicas`, port 5433) or a pgbouncer `attome_ro` alias on its own port. `None` (the default) falls back to `database.host` — today's behavior, unchanged. Unlike `readonly` itself (required outside debug, D-038), leaving this unset is never a boot error: a deployment sharing one endpoint for both roles (today's default topology) is still fully supported. |
| `database.readonly.password` | string |  | yes |  |
| `database.readonly.port` | integer, optional | `null` |  | See `host` above — same override, for the port. `None` falls back to `database.port`. |
| `database.readonly.user` | string |  |  |  |
| `database.replica_max_lag_secs` | integer, optional | `null` |  | P-ha-failover-hardening item (e), D-125 — consumed by `AppState::route_if_lag_ok` (P-read-your-writes-lsn) as an unconditional circuit breaker: whenever `replica_watermark::ReplicaWatermark.lag_seconds` (the always-on poller's cached value, `AppState.replica_watermark`) exceeds this threshold, every routed read falls back to the primary regardless of any specific user's pin. Also widens `pin_write_with_lsn`'s effective TTL to `max(sticky_primary_ttl_secs, replica_max_lag_secs)` so the pin never expires before this policy's own declared lag tolerance (`P-read-your-writes-lsn.md` §4(6)). `None` (the default) means "no max-lag policy configured" — today's behavior, unchanged: no circuit breaker, and the TTL formula reduces to `sticky_primary_ttl_secs` alone. |
| `database.runtime.password` | string |  | yes |  |
| `database.runtime.user` | string |  |  |  |
| `database.schema` | string |  |  |  |
| `database.ssl_mode` | string | `"prefer"` |  | P-datastore-tls — one of Postgres's six `sslmode` values: "disable", "allow", "prefer" (the default — matches sqlx's own default, so unset is byte-for-byte identical to pre-TLS behavior), "require", "verify-ca", "verify-full". Validated against this fixed set at boot (`AppConfig::validate`, D-038) — `attome-db` parses the validated string into `sqlx::postgres::PgSslMode`, kept out of this crate to avoid a `sqlx` dependency here (attome-config stays DB-agnostic). |
| `database.ssl_root_cert` | string, optional | `null` |  | P-datastore-tls — path to a CA certificate file (PEM) used by "verify-ca"/"verify-full" modes. Deployment-provided (D-002: one customer, one set of certs) — no CA machinery lives in this platform. |
| `database.statement_classes.admin.idle_in_transaction_timeout_ms` | integer |  |  |  |
| `database.statement_classes.admin.lock_timeout_ms` | integer |  |  |  |
| `database.statement_classes.admin.statement_timeout_ms` | integer |  |  |  |
| `database.statement_classes.fast.idle_in_transaction_timeout_ms` | integer |  |  |  |
| `database.statement_classes.fast.lock_timeout_ms` | integer |  |  |  |
| `database.statement_classes.fast.statement_timeout_ms` | integer |  |  |  |
| `database.statement_classes.report.idle_in_transaction_timeout_ms` | integer |  |  |  |
| `database.statement_classes.report.lock_timeout_ms` | integer |  |  |  |
| `database.statement_classes.report.statement_timeout_ms` | integer |  |  |  |
| `database.statement_classes.standard.idle_in_transaction_timeout_ms` | integer |  |  |  |
| `database.statement_classes.standard.lock_timeout_ms` | integer |  |  |  |
| `database.statement_classes.standard.statement_timeout_ms` | integer |  |  |  |
| `database.sticky_primary_ttl_secs` | integer | `5` |  | P1.12 — TTL (seconds) of the Redis "just wrote" pin (`attome-db:rw-pin:{user_id}`) that `AppState::read_pool` checks before routing a read to `readonly` instead of the primary. Widen this if a deployment's replica routinely lags past the default window. |
| `database.timeout` | number | `5.0` |  | Pool **acquire** timeout in seconds, fractional allowed (`0.5` is 500ms): how long a caller waits for a pooled connection, which includes opening a new one. Also bounds the connect of attome-db's unpooled direct/migrator connections. `AppConfig::validate` requires a finite value in `(0, 120]`. |
| `database.user` | string |  |  |  |

## `deployment`

P-data-protection-governance §4 — data-residency declaration; see `DeploymentSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `deployment.bundle_ref` | string, optional | `null` |  |  |
| `deployment.bundle_signing_public_key` | string, optional | `null` |  |  |
| `deployment.data_region` | string, optional | `null` |  |  |
| `deployment.outbound_proxy` | string, optional |  | yes | Q21-T1: an HTTP(S) proxy for calls to public addresses (vendor APIs, webhooks), for a network that reaches the internet only through one, such as `http://proxy.corp:3128` (credentials may be in the URL). Hosts the operator lists as private for a call (a model server, an identity provider) are reached directly. `HTTP_PROXY` and the other environment variables are never used. Absent means no proxy. |
| `deployment.portal_hosts` | array of string | `[]` |  | D-585: the hosts web portals (`/{keyword}/...`) answer on, disjoint from `staff_hosts`. Empty means portals answer on any host outside the production profile, and on **no** host in it. |
| `deployment.read_only_at_database_bytes` | integer, optional | `null` |  | AB5-T6: when the database reaches this many bytes the deployment turns read-only, before the disk fills. Absent means no ceiling. |
| `deployment.sovereign` | boolean | `false` |  | U1-T5, the sovereign preset: when true, boot refuses any configured destination outside this deployment (object store, SMTP relay, model servers, identity providers, trace collector, render service) and any outside AI provider, so the deployment makes no outbound connection its operator did not name. See `AppConfig::sovereign_violations`. |
| `deployment.sovereign_allowed_hosts` | array of string | `[]` |  | Host names a sovereign deployment may still reach although they are not on its own network: the organisation's own mail relay or identity provider, for example. Exact, lowercase host names. |
| `deployment.staff_hosts` | array of string | `[]` |  | D-585: the hosts the staff app and `/api/v1` answer on. Empty means "any host" (today's behaviour), and is refused once `portal_hosts` is set: a portal host must never also serve the staff API. |

## `docgen`

M57 Phase 1 — Document Generation. The isolated render sidecar's address plus its explicit timeout/size caps. See `DocgenSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `docgen.max_html_bytes` | integer | `5000000` |  | Cap on the merged HTML document sent to the sidecar — bounds both the request body and the amount of markup the SSRF-shaped external-URL scan (`xrm_docgen::ssrf`) has to walk. |
| `docgen.max_response_bytes` | integer | `25000000` |  | Cap on the rendered PDF response read back from the sidecar. |
| `docgen.render_service_url` | string | `"http://localhost:3000"` |  |  |
| `docgen.request_timeout_secs` | integer | `20` |  |  |

## `einvoice`

AG2 — e-invoicing. Ships dark (`enabled: false`): see `EinvoiceSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `einvoice.enabled` | boolean | `false` |  |  |
| `einvoice.key_encryption_key` | string \| object |  | yes |  |

## `email`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `email.enabled` | boolean | `false` |  | P-account-lifecycle — this section existed but nothing consumed it (dead config, audit finding E). `enabled` is the explicit opt-in: when false, `attome-email` is never constructed and reset/verification requests return 503 `feature_unavailable` instead of silently trying (and failing) to reach an SMTP host that was never meant to be live — same "ships dark behind a flag" pattern as `audit.chainer_enabled`. |
| `email.providers.by_sender` | map |  |  |  |
| `email.providers.default` | string, optional | `null` |  | `"smtp"`, `"ses"` or `"sendgrid"`. |
| `email.providers.sendgrid.api_key` | string |  | yes |  |
| `email.providers.sendgrid.endpoint` | string, optional | `null` |  | Overrides `https://api.sendgrid.com` (the EU region, a test double). |
| `email.providers.ses.access_key_id` | string |  |  |  |
| `email.providers.ses.endpoint` | string, optional | `null` |  | Overrides `https://email.{region}.amazonaws.com` (a VPC endpoint, a test double). |
| `email.providers.ses.region` | string |  |  | e.g. `"eu-west-1"`. |
| `email.providers.ses.secret_access_key` | string |  | yes |  |
| `email.providers.ses.session_token` | string, optional |  | yes | A temporary credential's session token. |
| `email.smtp_from_address` | string |  |  |  |
| `email.smtp_from_name` | string |  |  |  |
| `email.smtp_host` | string |  |  |  |
| `email.smtp_password` | string |  | yes |  |
| `email.smtp_port` | integer |  |  |  |
| `email.smtp_use_tls` | boolean, optional | `null` |  | **Deprecated** (BEM-5): `true` = implicit TLS, `false` = plaintext. Superseded by [`Self::tls_mode`], which wins when both are set; kept deserializable for one release so an existing `config.json` keeps booting, and warned about by `validate()` so operators migrate. `Option` rather than `bool` so "absent" is distinguishable from an explicit `false` — the old key was mandatory, so an absent one means the file was written after the `tls_mode` rename. |
| `email.smtp_user` | string |  |  |  |
| `email.test_mode_catch_all` | string, optional | `null` |  | Z8-T6: test mode. When set, every email goes to this one address instead of its recipients (named in an `X-Attome-Original-To` header), so a development or copied deployment never mails a real person. |
| `email.tls_mode` | string, optional | `null` |  | The SMTP transport security mode (BEM-5, attome-email plan §4.3): `"implicit"` (SMTPS, the default), `"starttls"` (upgrade required — lettre aborts if the relay does not offer it), or `"none"` (plaintext, refused outside `APP_ENV=debug`). Validated by `validate()`. |

## `events`

M62 Phase 1 — Event Bus subscriptions/webhook delivery. Ships dark (`webhooks_enabled: false`). See `EventsSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `events.dispatch_batch_size` | integer | `200` |  | Bound on how many outbox events one dispatcher tick reads per active subscription (M62 plan §3 "Bounded batch"). |
| `events.webhook_signing_key` | string \| object |  | yes | P-key-rotation-and-jwt (a) trust domain for signing outbound webhook deliveries, deliberately **separate** from `s2s.key_encryption_key` (D-069's "machine-auth secrets and human/other secrets are separate trust domains; a compromise or rotation of one key must never implicate the other" — S2S authenticates *inbound* machine calls, this key signs *outbound* payloads sent to a subscriber-controlled URL, so the two must be independently rotatable). |
| `events.webhooks_enabled` | boolean | `false` |  |  |

## `fleet`

D-792 — the fleet console (developer machine only). Empty by default; refused on the production profile. See `FleetSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `fleet.changesets_dir` | string | `"changesets"` |  | Where closed `attome-changeset/v1` files are read from (the developer runs the source tree, design §6.4). |
| `fleet.credential_encryption_key` | string \| object |  | yes | Encrypts each customer's rollout S2S secret at rest. Required (and checked) only when the console is requested with `ATTOME_FLEET_CONSOLE=1`; well formed whenever it is set. |
| `fleet.notify_user_refs` | array of string | `[]` |  | Who the F3 notifications go to. Empty: every active `system.admin` holder of the developer's database. |
| `fleet.poll_interval_secs` | integer | `900` |  | How often the gated `FleetPoll` scheduler syncs every customer. |
| `fleet.request_timeout_secs` | integer | `10` |  | Bound on one outbound call to a customer server. |

## `google_ai`

Only `api_key` is a real per-deployment credential today — no engine crate calls the Gemini API yet, so `base_url`/`default_model`/`timeout_seconds` were dropped (D-099-era scaffolding for a feature that was never wired up); reintroduce them alongside whatever crate actually builds the client once one exists.

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `google_ai.api_key` | string |  | yes |  |

## `idempotency`

P-idempotency-hardening §4.4/§4.5 — the durable-tier mandatory-operation policy. Additive/opt-in (empty by default): a deployment must explicitly name routes here before any request starts requiring `X-Idempotency-Key`, matching `audit.chainer_enabled`'s "ships dark behind a flag" precedent. D-327: that "empty by default" posture is deliberately narrowed under `app.deployment_profile = "production"` — `server::boot::init`'s `validate_operation_registries` additionally requires every `xrm_server::bulk:: MANDATORY_TIER_OPERATIONS` entry to be present here before a production process boots. `attome-config` can't express that floor itself (zero xrm-* knowledge, guidelines §1), so it isn't part of `validate_production_profile` below despite living right next to every other production-only requirement enforced there.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `idempotency.bulk_retention_hours` | integer | `168` |  | S9-T2: how long a bulk job's durable record is kept (a bulk job may be retried days later). Seven days by default. |
| `idempotency.durable_retention_hours` | integer | `24` |  | How long a completed `base_idempotency_record` row is kept before `PlatformJob::PruneIdempotencyRecords` soft-deletes it. Same default window as the Redis tier's TTL (`idempotency.rs::TTL_SECS`). |
| `idempotency.mandatory_operations` | array of string | `[]` |  | Operation-name strings (`"{METHOD} {route-template}"`, e.g. `"POST /api/v1/{entity}/bulk"` — the same string `attome_server::middleware::idempotency::operation_name` derives via axum's `MatchedPath`) that must go through the durable Postgres tier (`base_idempotency_record`, migration `0066`) instead of the default Redis-only gate, and must require `X-Idempotency-Key` outright (a missing header on a listed route is `422 Validation`, not a silent skip). Empty by default — a deployment opts in explicitly. |
| `idempotency.replay_max_bytes` | integer | `1048576` |  | Largest successful response body the Redis idempotency gate stores for replay. A larger response still reaches the client in full, but a same-key retry gets `idempotency_replay_unavailable` instead of a replay. Bounds how much a single cached response can put on the coordination Redis. Must be at least 1. |
| `idempotency.response_encryption_key` | string \| object, optional |  | yes | S9-T3: the key ring that seals a durable record's stored response (AES-256-GCM, tagged with the key id, bound to the record's id). Unset stores responses as they are; set it on any deployment whose responses carry personal data. Keep a retired key in the ring until the records it sealed are past `bulk_retention_hours`. |

## `inference`

D-360 / P-inference — model endpoints and the AI kill-switch (TODO-055). Ships dark: every surface defaults off, so a deployment that upgrades into a build containing AI code gets no AI behaviour and no model traffic until an operator opts in.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `inference.ai.chat` | boolean | `false` |  | The conversational agent (`MODULE_BOT`). |
| `inference.ai.enabled` | boolean | `false` |  | Master switch. `false` disables **every** AI surface regardless of the per-surface flags below — an operator reaching for the kill-switch during an incident must not have to reason about which of five flags they missed. |
| `inference.ai.fields` | boolean | `false` |  | AI form fields and components (`MODULE_AI`) — summarise, draft, classify, translate. Read-only suggestions. |
| `inference.ai.semantic_search` | boolean | `false` |  | Semantic/dense retrieval within search (`MODULE_SEARCH`). Turning this off leaves lexical search fully working — that degradation is a supported configuration, not an outage (P-inference §4.3). |
| `inference.ai.workflow_nodes` | boolean | `false` |  | AI nodes inside workflows (`MODULE_AUTOMATION`). |
| `inference.allow_external_provider` | boolean | `false` |  | Whether [`Self::generation`]/[`Self::embedding`] may point outside the data plane. |
| `inference.caller_token_budget_per_min` | integer, optional | `null` |  | BIN-D7 — deprecated: accepted and ignored, nothing enforces it (the per-caller budget lives in `xrm-ai`'s budget guard). Kept for one release so an existing config still loads; boot warns when it is set (`AppConfig::deprecated_keys`), then the field goes. |
| `inference.catalogue` | array of object |  |  | Z9-T3 — the model catalogue the router picks from: each model's capabilities, context size, cost and the data labels it may be sent. Empty by default: nothing is routed by catalogue, and every task runs on `generation` (or its `task_models` entry) as before. |
| `inference.embedding.api_key` | string, optional |  | yes | Optional bearer token. Local serving processes normally need none; this exists for a deployment fronting them with an authenticating proxy, and for the config-gated external-provider case below. |
| `inference.embedding.base_url` | string | `""` |  | Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`. Empty means "not configured", which the client reports as unavailable rather than attempting a request to an empty host. |
| `inference.embedding.model` | string | `""` |  | The model id to request. Recorded on every suggestion as provenance (`model_id`), so an auditor can answer "which model wrote this" — see TODO-054. |
| `inference.embedding.request_timeout_secs` | integer | `60` |  | Per-request timeout. Generation is slow by nature and a bare default would either cut off a legitimate long answer or hang a request thread for minutes; naming it per endpoint lets the embedding endpoint keep a tight bound while generation gets a loose one. |
| `inference.embedding_document_prefix` | string, optional | `null` |  | Prefix prepended to every **document** text before it is embedded. See [`Self::embedding_query_prefix`]. |
| `inference.embedding_query_prefix` | string, optional | `null` |  | Prefix prepended to every **query** text before it is embedded, overriding the model-family heuristic (BIN-D6/BIN-G5). |
| `inference.generation.api_key` | string, optional |  | yes | Optional bearer token. Local serving processes normally need none; this exists for a deployment fronting them with an authenticating proxy, and for the config-gated external-provider case below. |
| `inference.generation.base_url` | string | `""` |  | Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`. Empty means "not configured", which the client reports as unavailable rather than attempting a request to an empty host. |
| `inference.generation.model` | string | `""` |  | The model id to request. Recorded on every suggestion as provenance (`model_id`), so an auditor can answer "which model wrote this" — see TODO-054. |
| `inference.generation.request_timeout_secs` | integer | `60` |  | Per-request timeout. Generation is slow by nature and a bare default would either cut off a legitimate long answer or hang a request thread for minutes; naming it per endpoint lets the embedding endpoint keep a tight bound while generation gets a loose one. |
| `inference.knowledge_article_data_source` | string, optional | `null` |  | The Data Source (UUID, as text) new drafts are filed under. |
| `inference.knowledge_article_entity` | string, optional | `"knowledge_data_item"` |  | The entity `article.draft` writes into (TODO-060). |
| `inference.max_output_tokens` | integer | `2048` |  | Maximum tokens one request may generate. Bounds a runaway loop and makes latency predictable enough to set a timeout against. |
| `inference.ocr.api_key` | string, optional |  | yes | Optional bearer token. Local serving processes normally need none; this exists for a deployment fronting them with an authenticating proxy, and for the config-gated external-provider case below. |
| `inference.ocr.base_url` | string | `""` |  | Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`. Empty means "not configured", which the client reports as unavailable rather than attempting a request to an empty host. |
| `inference.ocr.model` | string | `""` |  | The model id to request. Recorded on every suggestion as provenance (`model_id`), so an auditor can answer "which model wrote this" — see TODO-054. |
| `inference.ocr.request_timeout_secs` | integer | `60` |  | Per-request timeout. Generation is slow by nature and a bare default would either cut off a legitimate long answer or hang a request thread for minutes; naming it per endpoint lets the embedding endpoint keep a tight bound while generation gets a loose one. |
| `inference.provider_credential_key` | string \| object |  | yes | Encrypts `xrm_ai_provider_credential.secret_encrypted` at rest — the API key an operator gives an `xrm_ai_provider` record so the platform can list that provider's models. |
| `inference.rerank.api_key` | string, optional |  | yes | Optional bearer token. Local serving processes normally need none; this exists for a deployment fronting them with an authenticating proxy, and for the config-gated external-provider case below. |
| `inference.rerank.base_url` | string | `""` |  | Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`. Empty means "not configured", which the client reports as unavailable rather than attempting a request to an empty host. |
| `inference.rerank.model` | string | `""` |  | The model id to request. Recorded on every suggestion as provenance (`model_id`), so an auditor can answer "which model wrote this" — see TODO-054. |
| `inference.rerank.request_timeout_secs` | integer | `60` |  | Per-request timeout. Generation is slow by nature and a bare default would either cut off a legitimate long answer or hang a request thread for minutes; naming it per endpoint lets the embedding endpoint keep a tight bound while generation gets a loose one. |
| `inference.speech.api_key` | string, optional |  | yes | Optional bearer token. Local serving processes normally need none; this exists for a deployment fronting them with an authenticating proxy, and for the config-gated external-provider case below. |
| `inference.speech.base_url` | string | `""` |  | Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`. Empty means "not configured", which the client reports as unavailable rather than attempting a request to an empty host. |
| `inference.speech.model` | string | `""` |  | The model id to request. Recorded on every suggestion as provenance (`model_id`), so an auditor can answer "which model wrote this" — see TODO-054. |
| `inference.speech.request_timeout_secs` | integer | `60` |  | Per-request timeout. Generation is slow by nature and a bare default would either cut off a legitimate long answer or hang a request thread for minutes; naming it per endpoint lets the embedding endpoint keep a tight bound while generation gets a loose one. |
| `inference.spend.agent_monthly` | number, optional | `null` |  |  |
| `inference.spend.caller_monthly` | number, optional | `null` |  |  |
| `inference.spend.degrade_at_percent` | integer | `80` |  | Percent of a cap at which generations are shortened. |
| `inference.spend.degraded_max_output_tokens` | integer, optional | `null` |  | The output ceiling near a cap; unset leaves generations unshortened. |
| `inference.spend.deployment_monthly` | number, optional | `null` |  |  |
| `inference.spend.feature_monthly` | map |  |  |  |
| `inference.spend.prices` | map |  |  | Price per million tokens, by model id (`inference.generation.model`). |
| `inference.task_models` | map |  |  | N25-T1 — which approved catalogue model (`ai_model` id) a task runs on, by action id (or `agent.turn` for chat and agent turns). A task not listed runs on `generation`. |
| `inference.translation.glossary` | map |  |  |  |

## `integration`

M59 Phase 1 — Integration & Connectors. Ships dark (`enabled: false`): see `IntegrationSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `integration.credential_encryption_key` | string \| object |  | yes |  |
| `integration.enabled` | boolean | `false` |  |  |
| `integration.request_timeout_secs` | integer | `15` |  | Bound on how long the REST adapter's outbound HTTP client waits for a pull/push/health call to an external system, mirroring `WebcrawlSection::request_timeout_secs`'s per-feature timeout convention rather than a shared global constant. |

## `jobs`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `jobs.batch_worker_concurrency` | integer | `3` |  | P-job-queue-hardening (D-165) — max in-flight jobs the *batch* queue's worker processes concurrently. The batch set is exactly the variants `PlatformJob::is_batch` returns `true` for — the open-ended, record-count-proportional kinds (`BulkEntityOperation`, `ApplyStagedImport`, `RewrapSecrets`, `ApplySchemaChangePlan`, `ApplyMetadataBundle`, `CrawlWebsite`, `CascadeDeactivateDependents`, `DataExport`, `DataProfile`, `DataBulkTransform`, `RollbackMigrationRun`, `ReportRun`, `LegalMatterCollect`, `LegalMatterRelease`). That method is the authority; this list is a reading aid, not a second copy to keep in sync. Lower default than the fast queue's: these are individually heavier per unit of concurrency. |
| `jobs.dead_letter_retention_days` | integer | `90` |  | BJB-15 (attome-jobs plan) — how long a dead-lettered (`Killed`) `apalis.jobs` row is kept before `PlatformJob::PruneApalisJobHistory` deletes it. The same sweep, a longer window: a `Done` row is history, but an untriaged dead letter is the operator's only record that a job kept failing, so it outlives the history window and its deletion is logged with a count. Every dead letter the sweep deletes is a row an operator never replayed, discarded or investigated (BJB-F9). |
| `jobs.history_retention_days` | integer | `30` |  | P-job-queue-hardening (D-165) — how long a terminal (`Done`/`Killed`) `apalis.jobs` row is kept before `PlatformJob::PruneApalisJobHistory` deletes it. Keeps the dead-letter admin list and the table itself bounded; apalis never vacuums a finished job on its own. |
| `jobs.run_worker_inline` | boolean | `true` |  | P-worker-process-split — `true` (default, today's behavior unchanged) runs the apalis job `Monitor` inline inside the `server` process, same as before this flag existed. A deployment that has split the worker out into its own process/container (`crates/server/src/bin/worker.rs`, scaled and deployed independently of the HTTP tier) sets this `false` so `server` never builds/runs the `Monitor` or spawns the partition/ upload-session maintenance schedulers — those move to `worker` entirely, avoiding double-enqueue from two schedulers ticking at once. Same "off by default until an operator opts in" posture as `database.migrate_on_boot`. |
| `jobs.worker_concurrency` | integer | `10` |  | Max in-flight `PlatformJob`s the fast-queue worker processes concurrently. Tuned against `database.connection_number` (§14.1) — the remaining fast-queue work is low-volume and low-CPU, not a pool hog. (The API-key/S2S "touch" writes that used to be the bulk of it moved off apalis onto the Redis stream / coalescing-hash path in D-164.) |
| `jobs.workflow_payload_retention_days` | integer | `30` |  | M3-T4 — how long a finished workflow step keeps its recorded input and output before the daily prune clears them (the step's summary stays). |

## `metadata`

Solution 7 Phase 1 (D-785) — how metadata admin writes are recorded as changesets. See `ChangesetsSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `metadata.backfill_batch_max` | integer, optional | `null` |  | Y12-T6: the largest batch a backfill grows to. Unset is 50,000. |
| `metadata.changesets.auto_layer` | `platform` \| `product` \| `project` \| `customer` |  |  | The layer of automatic changesets. Phase 1 accepts only `project`; Phase 3 adds `customer` together with its authoring rules. |
| `metadata.changesets.mode` | `required` \| `auto`, optional |  |  | `required`: a metadata admin write with no open changeset is refused (409 `changeset_required`). `auto`: each request's writes become one closed automatic changeset. Unset means `auto` on every profile, so a config written before changesets existed (the production templates, every hand-written test config) keeps working unchanged; a development deployment opts into `required` explicitly, as `config.example.json` does. Read it through [`Self::effective_mode`], never this field directly. |
| `metadata.quiet_hours` | string, optional | `null` |  | Y12-T6: the local hours (`"01-05"`, end not included) when a backfill may grow its batches. Unset is 01:00 to 05:00. |
| `metadata.recovery_archive_key_encryption_key` | string \| object |  | yes | Solution 7 Phase 2 (D-788 rule 9): the key-encryption-key ring of the 30-day recovery archive (`xrm_core_recovery_archive`), its own trust domain (D-069). Empty (the default) means "not configured": every operation that would archive a value (a field delete with values, a type change that nulls values) is refused with `archive_key_missing` (fail closed). When set, every entry must be 64 hex chars (a boot error otherwise). `KeyRing`'s `Debug` redacts the values. |
| `metadata.release_report.notify_roles` | array, optional | `null` |  | Who the post-apply notification goes to. Unset (the default) keeps today's recipients: the active holders of the admin privilege. Set, the notification goes to the active holders of these roles (by role `name`) instead; the recipient cap is unchanged. When none of the named roles has an active holder the notification falls back to the admin holders (logged at `warn`), so a stale name never silences it. A set list must be non-empty, without blanks or duplicates, at most [`MAX_NOTIFY_ROLES`] names (a boot error otherwise). |
| `metadata.storage_tuning_enabled` | boolean | `false` |  | Y2-T9: the daily table-health job also sets each entity table's fill factor from its measured updates (80 for a table whose updates miss heap-only updates, 100 for an append-only one). Off by default. |

## `notification`

In-app notification inbox lifecycle policy. Kept separate from audit retention because notification rows have different ownership.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `notification.email_from` | string, optional | `null` |  | M51 Phase 1 — the "From" header notification-engine email should appear to come from (e.g. `"Notifications <notifications@example.com>"`), distinct from the account-lifecycle "From" in `email.smtp_from_name`/ `smtp_from_address`. `None` (default) falls back to that same deployment-wide address -- this section reuses `config.email`'s SMTP transport (host/port/credentials/`enabled`) unconditionally; it never grows its own SMTP block. |
| `notification.recipient_retention_days` | integer | `0` |  | How many days recipient rows remain before old partitions are removed. `0` disables pruning. |

## `observability`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `observability.alert_emails` | array of string | `[]` |  | AB10-T2: who hears about a built-in alert firing or resolving, by email (sent through the job queue and the `email` section's relay). |
| `observability.alert_webhooks` | array of string | `[]` |  | AB10-T2: incoming-webhook URLs (Slack, Teams, any service that takes `{"text": ...}`) told about a built-in alert firing or resolving. |
| `observability.builtin_store` | boolean, optional | `null` |  | U4-T1: sample this process's metrics into `ops_metric_sample` every minute, kept 30 days. Unset: on for Solo (`cache.backend = "memory"`), off otherwise (several servers use Prometheus). |
| `observability.enable_distributed_tracing` | boolean |  |  | P-observability-completion — the enable switch for an OTLP trace exporter. `false` (every config file's value today) is byte-identical to today's tracing_subscriber::fmt()-only behavior: no OTel layer installed, no listener bound, no span exported anywhere. |
| `observability.metrics_port` | integer |  |  |  |
| `observability.otlp_endpoint` | string, optional | `null` |  | P-observability-completion — the OTLP collector this deployment's own exporter would send spans to (Grafana Tempo / Jaeger / the OpenTelemetry Collector — a per-deployment adoption decision, never a hosted/shared endpoint per D-002). Required (fail-closed, see `validate()`) whenever `enable_distributed_tracing = true`; `None` otherwise. Currently validated but not yet read by any exporter — see `enable_distributed_tracing`'s doc comment above. |
| `observability.profiler_enabled` | boolean | `false` |  | attome-profiler: live per-probe call count/avg/min/max dashboard (the Angular "Profiler" admin page). Default false — byte-identical behavior (no profiler middleware layer, no Redis writes) until a deployment opts in, same "dark unless configured" posture as `metrics_port == 0`. |
| `observability.server_timing` | string | `"dev"` |  | AA1-T5: who gets a `Server-Timing` header splitting each response's time into middleware, authentication, permissions, database, handler and outside calls. `dev` (the default): every response, in a debug environment (`APP_ENV=debug`) only. `admins`: responses to signed-in administrators. `off`: nobody. Measuring the database phase reads sqlx's per-statement events, which costs a little on every query while the header can be sent. |
| `observability.trace_sampling_rate` | number |  |  | P-observability-completion — `TraceIdRatioBased` sampler ratio once `enable_distributed_tracing = true`. Meaningless (and unread) while that flag is false, same "declared but inert until its gate flips" shape as most other flag-gated fields in this file. |
| `observability.worker_health_port` | integer | `9091` |  | P-worker-process-split follow-up (the TODO `crates/server/src/bin/ worker.rs` shipped with) — the dedicated `worker` binary has no HTTP listener at all today, so a split deployment's compose/k8s healthcheck can only prove the process exists (`pgrep`), not that it can actually reach Postgres/Redis. Unlike `metrics_port` (dark by default: every existing config has it at 0), this defaults **on** — a worker readiness probe should exist out of the box, not require every deployment to opt in. `0` still disables it, same "0 = off" convention as `metrics_port`, for a bare-metal/host-networking deployment that genuinely wants it off. Read by `crates/server/src/bin/worker.rs` only — `main.rs` never binds this (its own `/health/ready` already covers the inline-worker case via `app.port`). |

## `oidc`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `oidc.providers` | map |  |  | Keyed by an operator-chosen provider key (e.g. "entra", "okta", "keycloak", "google") — becomes the `{provider}` path segment in `/api/v1/auth/oidc/{provider}/login\|callback` and the `provider_key` stored in `xrm_core_user_identity`. Empty (the default) means no OIDC provider is configured — those routes 404 for any key looked up here. |

## `portal`

D-588 — external-audience web portals: the OIDC providers they may offer and the signup CAPTCHA. See `PortalSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `portal.captcha.pow_difficulty` | integer | `18` |  | Q20-T3: leading zero bits a proof-of-work answer needs, 1 to 24. |
| `portal.captcha.provider` | `none` \| `turnstile` \| `hcaptcha` \| `pow` |  |  |  |
| `portal.captcha.secret` | string |  | yes | The provider's server-side secret, `${VAR}`-expanded. |
| `portal.captcha.timeout_ms` | integer | `3000` |  |  |
| `portal.oidc_providers` | map |  |  |  |

## `query`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `query.cursor_default` | boolean | `true` |  | `true` (default): `query/execute` requests with neither `after_id` nor `include_total: true` run in keyset/cursor mode from the start of the result set, instead of OFFSET. Set `false` to restore the pre-P- stored-query-containment default (plain OFFSET, no total) for one release as a rollback switch (§7 of the plan) — `include_total: true` always gets `COUNT(*) OVER()` totals regardless of this flag. |
| `query.max_offset_rows` | integer | `10000` |  | AA4-T3: the deepest row an offset page may start at. OFFSET reads and throws away every row before it, so a deep page costs as much as reading them all; past this a request is refused with a pointer to `after_id` (keyset paging), which costs the same at any depth. |
| `query.timeouts_ms.interactive` | integer | `500` |  | A person waiting on a list or a view (default 500). |
| `query.timeouts_ms.report` | integer | `5000` |  | A stored query flagged as a report (default 5000). |
| `query.trigram_index_min_rows` | integer | `100000` |  | AA4-T5: a filterable text attribute gets a trigram (GIN) index, so a `contains` filter is index-backed, once its table's estimated row count reaches this. At least 1; default 100,000. |
| `query.validate_on_execute` | boolean | `false` |  | Phase 2's rollback switch: `query/execute` skips the per-request `EXPLAIN` cost check by default, trusting the cost estimate captured once in `xrm_core_sql_query_version` at publish time. `true` restores the pre-phase-2 behavior of re-running `EXPLAIN` on every execute call (defense against runtime plan drift the cached estimate can't see) — a kill switch, not a recommended steady-state setting. |

## `rate_limit`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `rate_limit.anonymous_rpm` | integer |  |  |  |
| `rate_limit.authenticated_rpm` | integer |  |  |  |
| `rate_limit.categories` | map |  |  | P-rate-limit-atomicity: keyed by category name (`credential`, `mfa`, `password_reset`, `api`, `export`, `expensive_query`, ...), resolved against `attome_server::middleware::rate_limit::RATE_LIMIT_CATEGORIES`' compile-time (method, route-template) → category table. Replaces the old `per_endpoint_limits` map outright — that map only ever changed which number was checked against one shared identity-only bucket, it never isolated a per-endpoint budget the way its name implied (see D-145). A deployment with a leftover `per_endpoint_limits` key fails to boot (below) rather than silently losing an override it believes still applies. |
| `rate_limit.ipv6_bucket_prefix` | integer | `64` |  | BSV-F16 (B6) — both per-IP limiters bucket an IPv6 client by this prefix length rather than its full /128, because one host usually controls a whole /64 and could otherwise rotate addresses inside it to dodge the limit. IPv4 is always bucketed per address. Range 32..=128; 128 restores per-address buckets. |
| `rate_limit.pre_auth_rpm` | integer | `1000` |  | Coarse, IP-only limit applied by `pre_auth_rate_limit` — the layer that runs before `s2s_authn`/`authn` so a flood of garbage JWTs/HMAC signatures gets rejected before burning crypto + a Redis denylist/nonce lookup per request. Deliberately looser than `anonymous_rpm` (a blunt pre-crypto backstop, not a business-logic limit) — an unmeasured starting guess; tune against real traffic once available. |

## `residency`

R7-T1 — where data may live and where each component holds it; see `crate::residency`.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `residency.allowed_regions` | array of string | `[]` |  | The regions data may live in; empty for no rule. |
| `residency.components` | map |  |  | A component's region, overriding what its configuration declares. |

## `retention`

P-retention-archive-completion — partition archive/drop, entity purge, and legal hold policy. See `RetentionSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `retention.audit_days` | integer, optional | `null` |  | Age (in days) past which a `xrm_audit_header`/`xrm_audit_detail`/ `xrm_audit_snapshot` partition becomes archive/drop-eligible. `None` (default) = keep forever, today's behavior. |
| `retention.disposition_action` | string | `"purge"` |  | M23 Records Management (D-456) — which disposition outcome the daily sweep proposes for a record past `entity_purge_grace_days`: `"purge"` (default — today's behavior, crypto-shred + field-scrub, no evidence kept) or `"archive"` (export to `attome-storage` first, evidence kept in `xrm_core_archive_record`, then the same field-scrub — see `xrm_compliance::archive::execute_entity_archive`). Deployment-wide, same D-002 single-deployment-per-customer convention as every other field in this section — not a per-record or per-entity policy table. An unrecognized value falls back to `"purge"` with a warning rather than failing the sweep (see `xrm_entity::purge::propose_purge_actions`), the same fail-safe posture `dry_run`'s default takes. |
| `retention.dry_run` | boolean | `true` |  | Safety default. While `true` (the default), the propose step always runs and always writes `xrm_audit_retention_action` rows so an operator can see exactly what a live run *would* do, but approve/execute are refused outright with a message naming this flag. Must be explicitly flipped to `false` before any partition can be dropped or any record purged. |
| `retention.entity_purge_grace_days` | integer, optional | `null` |  | How long (in days) a provisioned entity record may sit `is_active = false` before it becomes purge-eligible (crypto-shred + field-scrub, never a hard `DELETE` — see `xrm_entity::purge`). `None` (default) disables entity purge entirely. |
| `retention.legal_hold` | boolean | `false` |  | Deployment-wide kill switch (D-002: a litigation hold on a self-hosted, one-customer-per-deployment platform is realistically an all-or-nothing freeze for that deployment, not a per-record flag). While `true`, no archive/drop/purge action may execute regardless of how far past its window a partition or record is — proposals still compute, for visibility, but approve/execute are refused outright. |
| `retention.propose_interval_secs` | integer | `86400` |  | How often the daily proposal sweep re-checks (enqueues `PlatformJob::ProposeRetentionActions`), in seconds. Idempotent either way — a shorter interval only means more no-op re-checks once caught up, never duplicate proposals (migration 0067's partial unique index makes the insert idempotent). |
| `retention.s2s_access_log_days` | integer, optional | `null` |  | Age (in days) past which a `xrm_s2s_access_log` partition becomes archive/drop-eligible. `None` (default) = keep forever. |

## `s2s`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `s2s.access_log_enabled` | boolean | `true` |  | Write every S2S request to xrm_s2s_access_log. Default: true. |
| `s2s.enabled` | boolean | `false` |  | Enable S2S HMAC authentication. When false the middleware is a no-op. |
| `s2s.failure_alert_threshold` | integer | `100` |  | Number of 401 failures from one client in 5 minutes that triggers the admin failure alert. Default: 100. |
| `s2s.key_encryption_key` | string \| object |  | yes | 64-hex-char AES-256 master key(s) used to encrypt HMAC secrets at rest. Required when enabled = true. Generate with: openssl rand -hex 32. P-key-rotation-and-jwt (a): a `KeyRing` — see that type's doc. |
| `s2s.seeded_clients` | array of object |  |  | D-771: S2S clients declared here are reconciled at every boot (client, one key with a fixed `public_id`, permission rows), so a machine caller's credential survives a database reset and is rotated by editing `.env`. Empty by default. |

## `security`

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `security.csp_enforce` | boolean | `true` |  | P-frontend-hardening §4(d)/step 7 — report-only kill switch for the response `Content-Security-Policy` header, mirroring `csrf_enforce`'s pattern above. `true` (default) sends a real, enforcing `Content-Security-Policy`; `false` sends `Content-Security-Policy-Report-Only` instead (observe violations, block nothing) — the plan's own rollout guidance is to set this `false` as the *first* step in any real deployment, watch for violations during a burn-in period, then flip it on, precisely because (unlike `csrf_enforce`, which is safely additive against existing behavior) there was no prior CSP at all for this to be layered on top of. See `attome_server::middleware::security_headers` for the header value itself. |
| `security.csrf_enforce` | boolean | `true` |  | P-cookie-csrf-hardening kill switch for the Origin/Fetch-Metadata CSRF middleware (`attome_server::middleware::csrf`). Default true — the check only ever rejects a *cookie-authenticated* unsafe-method (POST/PUT/ PATCH/DELETE) request whose `Sec-Fetch-Site`/`Origin` don't match this deployment, so "on" is the safe default; S2S/ApiKey/no-cookie traffic is unaffected either way. Set false only to diagnose a reverse proxy that strips `Origin`/`Sec-Fetch-*` headers — false is log-only (rejections are `tracing::warn!`'d but the request still proceeds), never a silent bypass; remove the flag once burned in, never leave it off in a real deployment. |
| `security.external_effects_enabled` | boolean | `false` |  | I-7's deployment-wide air-gap switch: whether any `Effect::External` capability (`xrm-ai`'s `GateInputs::external_effects_enabled`) is allowed to reach outside this deployment at all. Default **false** — an air-gapped or freshly-provisioned deployment refuses every external-effect action until an operator opts in explicitly, the same fail-safe-closed posture every other toggle in this section documents. |
| `security.hsts_include_subdomains` | boolean | `false` |  | Appends `; includeSubDomains` to the header above. |
| `security.hsts_max_age_secs` | integer | `31536000` |  | `max-age` (seconds) for the response `Strict-Transport-Security` header; `0` omits the header entirely. Default one year. |
| `security.secret_max_age_days` | integer | `365` |  | Z1-T8: days a secret's active key may stay in use before administrators are reminded (once a day at most, and then once every 30 days per secret) to rotate it. `0` turns the reminder off; the inventory (`GET /api/v1/admin/secrets`) still shows every age. |
| `security.strict_privileged_authz` | boolean | `true` |  | P-authz-revocation-epoch (D-116): always-on synchronous epoch re-check (fail-closed, `redis_coordination`, 300ms timeout) ahead of the privileged/admin-gated route bundles (`admin`, `license_admin`, `s2s_admin`, `schema`, `sidebar`, plus xrm-security's own grant/revoke admin routes) — a just-revoked admin cannot keep using a still-live L1 cache entry to perform further privileged operations for the rest of the ordinary 60s TTL. Default true; false is the emergency rollback to pre-epoch behavior for exactly those bundles (kill switch — remove after one release of burn-in per the plan's rollout section). |
| `security.strict_revocation` | boolean | `true` |  | P-record-level-security item (b), implemented as a mode of this same epoch mechanism rather than a second implementation: when true, EVERY `SecurityContext` resolve — not just the privileged-bundle class above — pays the fail-closed epoch re-check, so even an ordinary CRUD request sees a revoked grant on its very next request instead of within the 60s TTL. Enabled by default for the enterprise security posture; development deployments may explicitly set it false when the per-request Redis round trip is unsuitable. |
| `security.trusted_proxy_cidrs` | array of string | `[]` |  | The only TCP peers allowed to supply a client address through `X-Forwarded-For`. Leave empty for direct deployments: forwarding headers are then ignored and the socket peer is used for rate limiting and audit IPs. Entries must be IPv4/IPv6 CIDRs, for example `"172.20.0.0/16"` or `"fd00:dead:beef::/64"`. An IPv4-mapped IPv6 peer (a dual-stack bind) is matched as its IPv4 address. |

## `shed`

AB5-T7 — priority load shedding: slots per request class.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `shed.interactive_high_water` | integer | `200` |  | Interactive requests in flight above which the other classes shrink to one at a time. |
| `shed.permits.ai` | integer | `8` |  |  |
| `shed.permits.background` | integer | `4` |  |  |
| `shed.permits.export` | integer | `4` |  |  |
| `shed.permits.report` | integer | `8` |  |  |

## `storage`

Required.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `storage.azure.access_key` | string |  | yes | The storage account's shared access key. Presigned links are signed with it, so it must be a key rather than a token. |
| `storage.azure.account` | string | `""` |  | The storage account name. |
| `storage.azure.container` | string | `""` |  | The blob container that holds the files. |
| `storage.azure.endpoint` | string | `""` |  | A custom endpoint (an Azurite emulator, a sovereign cloud). Empty (the default) is the public Azure endpoint for the account. |
| `storage.backend` | `s3` \| `local` \| `azure` \| `gcs` |  |  | `s3` (the default), `local`, `azure` or `gcs`. Only the chosen backend's settings are used; the `s3_*` settings may be left out for the others. |
| `storage.clamd_address` | string | `""` |  | `host:port` of a ClamAV `clamd` daemon (INSTREAM protocol) the async scan job submits uploaded bytes to. Empty (the default) means no scanner is configured — the scan job then fails closed (rejects, never promotes) rather than silently skipping malware scanning. |
| `storage.gcs.bucket` | string | `""` |  | The bucket that holds the files. |
| `storage.gcs.service_account_key` | string |  | yes | The service account key, as the JSON document Google issues. Presigned links are signed with its private key. |
| `storage.local.path` | string | `""` |  | The folder that holds the files. Created at boot when it does not exist. Required with the local backend. |
| `storage.local.public_base_url` | string | `""` |  | Address browsers reach the server at, put in front of the signed links (`https://crm.example.com`). Empty (the default) hands out links relative to the server, which a browser on the same origin follows. |
| `storage.local.url_signing_key` | string |  | yes | Key that signs the short-lived upload and download links the server hands out in place of presigned bucket URLs (at least 32 bytes). Every process of the deployment needs the same value, so a link one process mints is accepted by another. |
| `storage.max_deployment_storage_bytes` | integer, optional | `null` |  | Soft cap on the whole deployment's promoted (`clean`) file storage — meaningful because D-099's data-plane model is one dedicated deployment per customer, so this is that customer's total quota, not a cross-customer figure. `None` (the default) disables the check, same reasoning and TODO as `max_user_storage_bytes` above. |
| `storage.max_entity_storage_bytes` | map |  |  | Z6-T7: caps on the files of one entity's records, by the entity's logical name (`{"contract": 10737418240}`), counted like the user cap. An entity not named has no cap of its own; the user and deployment caps still apply. Empty (the default) sets none. |
| `storage.max_upload_size_bytes` | integer | `26214400` |  | Max `declared_size_bytes` an upload session may declare; enforced at finalize (HEAD-verified against what was actually PUT), not at presign time (§4.2's documented limitation). |
| `storage.max_user_storage_bytes` | integer, optional | `null` |  | Soft cap on one user's total upload-session footprint: the sum of `declared_max_size_bytes` across their non-terminal sessions (`pending`/`uploaded`/`scanning`) plus `actual_size_bytes` across their `clean` ones. Checked in `create_upload_session` before a new session is created (item 26 remediation — a per-user quota). `None` (the default) disables the check: an unmeasured cap would be a guess, not evidence (guidelines §14) — TODO(item 26): pick a real number with the ops/customer team once there is usage data, then set this in each deployment's `config.json`. |
| `storage.quota_warning_pct` | integer | `80` |  | Z6-T7: the share of a cap, in percent, past which administrators are told (once a day per cap). 80 by default. |
| `storage.s3_access_key` | string | `""` |  |  |
| `storage.s3_bucket` | string | `""` |  |  |
| `storage.s3_endpoint` | string | `""` |  |  |
| `storage.s3_public_endpoint` | string | `""` |  | Endpoint embedded in presigned upload/download URLs, which browsers (or any other client) request directly. SigV4 signs the `Host`, so the URL must be signed for the address the client will actually contact; a proxy rewriting the host afterwards invalidates the signature. |
| `storage.s3_region` | string | `""` |  |  |
| `storage.s3_secret_key` | string |  | yes |  |
| `storage.s3_verify_ssl` | boolean | `true` |  | Whether HTTPS certificates from the S3 endpoints are verified. It does not choose the transport: the endpoint's scheme does (`http://` is plaintext whatever this says; `https://`, or empty for AWS S3, is TLS). `false` accepts any certificate on a TLS endpoint. Production refuses `false`. |

## `webchat`

D-558 — the public web-chat assistant (chatbot plan C9). Ships dark (`enabled: false`), and enabling it requires an agent definition and both spend caps. See `WebchatSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `webchat.agent_definition_id` | string, optional | `null` |  |  |
| `webchat.daily_token_cap` | integer, optional | `null` |  |  |
| `webchat.deployment_daily_token_cap` | integer, optional | `null` |  |  |
| `webchat.enabled` | boolean | `false` |  |  |
| `webchat.session_token_cap` | integer, optional | `null` |  |  |

## `webcrawl`

D-365 — Web Crawling for Knowledge Base. Ships dark (`enabled: false`): the platform's first feature that makes an outbound HTTP request to an arbitrary, user-supplied URL. See `WebcrawlSection`'s doc comment.

| Key | Type | Default | Secret | Description |
|---|---|---|---|---|
| `webcrawl.enabled` | boolean | `false` |  |  |
| `webcrawl.max_depth` | integer | `6` |  | Default crawl depth when `POST /targets` doesn't specify one — each crawl can override this per request (clamped to a sane range by the handler), stored on its own `xrm_webcrawl_target.max_depth` row. |
| `webcrawl.max_page_bytes` | integer | `5000000` |  |  |
| `webcrawl.max_pages` | integer | `50` |  |  |
| `webcrawl.request_timeout_secs` | integer | `15` |  |  |
