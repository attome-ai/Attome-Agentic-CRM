//! Authentication/authorization policy: local password + API-key auth
//! (`AuthSection`), rate limiting, S2S HMAC auth, the `security` hardening
//! toggles, federation (`OidcSection`), and the CIDR helpers
//! `security.trusted_proxy_cidrs`/S2S allowlisting share.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Deserialize;

use crate::Secret;

use crate::config::helpers::{
    default_access_token_expiry_mins, default_mfa_challenge_max_attempts,
    default_refresh_absolute_lifetime_days, default_refresh_token_expiry_days,
    default_s2s_failure_threshold, default_true,
};
use crate::keyring::KeyRing;

#[derive(Clone, Deserialize)]
pub struct AuthSection {
    /// P-key-rotation-and-jwt (a)/(c): a `KeyRing` rather than a bare secret —
    /// see that type's doc. A plain config-file string still deserializes
    /// (wrapped into a single active/legacy entry), so an existing deployment
    /// that never touches this field sees zero behavior change. `kid` in
    /// every minted JWT's header names which ring entry signed it; a second
    /// (retired) entry left in the ring is accepted for verification during a
    /// rotation's overlap window and rejected once removed.
    pub jwt_secret: KeyRing,
    pub jwt_issuer: String,
    /// P-key-rotation-and-jwt (c) — the `aud` claim every session/pending
    /// token carries and is validated against. Empty (the default) means
    /// "use `jwt_issuer`" (`AppConfig::jwt_audience`) — a deployment only
    /// needs to set this explicitly if it wants a distinct audience string.
    #[serde(default)]
    pub jwt_audience: String,
    /// Access-token (session_token cookie) lifetime, in minutes. Deliberately
    /// short (Plan 1.6a) — the refresh flow is what makes that tolerable.
    #[serde(default = "default_access_token_expiry_mins")]
    pub access_token_expiry_mins: u64,
    /// Idle lifetime of one `base_refresh_token` row, in days: how long a
    /// refresh token stays valid without being rotated.
    #[serde(default = "default_refresh_token_expiry_days")]
    pub refresh_token_expiry_days: u64,
    /// D-504 — absolute lifetime of a refresh family, in days. A family ends
    /// this long after the credential verification that started it, however
    /// often it rotates. Default 30. `AppConfig::validate` requires 1 to 365;
    /// migration 0462's fallback anchor for an inconsistent lineage relies on
    /// that ceiling to be expired.
    #[serde(default = "default_refresh_absolute_lifetime_days")]
    pub refresh_absolute_lifetime_days: u64,
    /// Gates the `Secure` flag on both auth cookies (Plan 1.6a). Default true —
    /// only `config.debug.json` sets this false, so plain-http local dev keeps
    /// working. `SameSite=Strict`/`HttpOnly` apply unconditionally either way.
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
    #[serde(default)]
    pub oauth_google_client_id: String,
    #[serde(default)]
    pub oauth_google_client_secret: Secret,
    /// P-account-lifecycle — when true, `attome_auth::accounts::login` rejects
    /// (403) a local password account whose `email_verified` is still false.
    /// Default false so air-gapped/no-SMTP deployments are unaffected; only
    /// turn this on once `email.enabled` is also true, or every local account
    /// locks itself out with no way to receive a verification link.
    #[serde(default)]
    pub require_verified_email: bool,
    /// P-account-lifecycle — default `api_key.expires_at` for newly
    /// created keys, in days. `None` (the default) means new keys still get
    /// no expiry unless the caller passes one explicitly — existing
    /// deployments are unaffected until an operator opts in.
    #[serde(default)]
    pub apikey_default_expiry_days: Option<u64>,
    /// P2.8 step 7 — one of `"off"`/`"optional"`/`"required"` (see
    /// `VALID_MFA_POLICIES` in `validate()`). `"off"` (the default) is
    /// today's behavior unchanged. `"optional"` challenges only accounts
    /// that have self-enrolled TOTP; `"required"` blocks a password login
    /// for an unenrolled account until it completes enrollment
    /// (`attome_auth::mfa`/D-068). Same string-enum convention as
    /// `database.ssl_mode` — deliberately a plain `String`, not a Rust enum.
    #[serde(default = "default_mfa_policy")]
    pub mfa_policy: String,
    /// P2.8 step 7 — AES-256-GCM master key(s) (64 hex chars each) encrypting
    /// `base_user_mfa.secret_encrypted` at rest, same pattern as
    /// `s2s.key_encryption_key` (`xrm_s2s::crypto`) but a dedicated key: TOTP
    /// secrets and S2S client secrets are separate trust domains and must
    /// not share a key. Only required (`check_secret`-validated) when
    /// `mfa_policy != "off"`. P-key-rotation-and-jwt (a): a `KeyRing` — see
    /// that type's doc for the bare-string back-compat shape and how
    /// rotation works.
    #[serde(default)]
    pub mfa_encryption_key: KeyRing,
    /// P-mfa-challenge-hardening: per-challenge attempt ceiling enforced
    /// atomically against the `mfa:pending:{jti}` Redis marker (see
    /// `attome_auth::mfa`) — reaching it kills the challenge outright (the
    /// client must re-authenticate with the password for a fresh
    /// `pending_token`), independent of the general per-IP/user
    /// `rate_limit.categories.mfa` budget. Default `5`, same "additive,
    /// default-safe" posture as every other new config field in this
    /// section — a deployment that never touches this sees a sane default,
    /// not a behavior change requiring opt-in.
    #[serde(default = "default_mfa_challenge_max_attempts")]
    pub mfa_challenge_max_attempts: u32,
    /// P-api-key-hashing (D-112, revised by D-118) — HMAC-SHA256 pepper ring
    /// for `api_key.secret_hash`, superseding per-request Argon2 for
    /// api-key secrets only (user passwords stay Argon2, `password.rs`,
    /// untouched). The *current* pepper — every newly issued key and every
    /// rehash-on-use conversion writes with this one. Unconditionally
    /// `check_secret`-validated in `validate()` below — unlike
    /// `mfa_encryption_key`/`s2s.key_encryption_key`, there is no feature flag
    /// gating this: every deployment authenticates api-key requests, so an
    /// unset/short pepper is always a boot error (D-038), never a silent
    /// unkeyed-hash fallback. `#[serde(default)]` (empty string) only so a
    /// config file that omits it still deserializes — `validate()` is what
    /// actually enforces the requirement.
    #[serde(default)]
    pub apikey_hash_pepper: Secret,
    /// Id of `apikey_hash_pepper` above, stored inline in
    /// `api_key.secret_hash` as `hmac256:v{id}$<hex>`. **The very first
    /// pepper a deployment ever sets must use id 0** — id 0 doubles as the
    /// fallback for the original, pre-rotation D-112 rollout's unversioned
    /// `hmac256$<hex>` rows (see `attome_auth::apikey_hash`'s module doc), so a
    /// deployment that skips straight to id 1+ on its very first boot with no
    /// `hmac256$`-format rows in the database is fine, but one migrating
    /// forward from the original rollout MUST keep id 0 resolvable (either
    /// `apikey_hash_pepper_id = 0` or an `apikey_hash_previous_peppers` entry
    /// with `id = 0`) or its existing keys stop verifying. `validate()` below
    /// only enforces the id-collision/duplicate checks it can prove
    /// statically — it cannot know whether unversioned rows exist in a given
    /// database, so this precondition is operator-enforced, documented here
    /// and in D-112's revision entry, not boot-checked.
    #[serde(default)]
    pub apikey_hash_pepper_id: u32,
    /// Retired pepper(s), keyed by id, kept only long enough to verify
    /// already-issued keys that haven't rehashed to the current id yet —
    /// same "current + previous" dual-key-slot shape `s2s.key_encryption_key`
    /// already uses for the same reason. Empty (the default) means no
    /// rotation has ever happened. A row referencing an id present in
    /// neither this list nor `apikey_hash_pepper_id` fails closed (same
    /// "wrong secret" outcome as any other verify failure) rather than
    /// erroring — do not remove an id from this list while any
    /// `api_key` row might still reference it.
    #[serde(default)]
    pub apikey_hash_previous_peppers: Vec<ApiKeyPepper>,
    /// P-registration-gating — one of `"public"`/`"invite"`/`"disabled"` (see
    /// `VALID_REGISTRATION_MODES` in `validate()`). Default `"disabled"` —
    /// deliberately secure-by-default (D-128): a deployment upgrading without
    /// touching config loses public self-registration, not the other way
    /// around. `"public"` is today's pre-P-registration-gating behavior
    /// (anyone can `POST /api/v1/auth/register`); `"disabled"` rejects every
    /// registration attempt with `AppError::Forbidden` before any DB work;
    /// `"invite"` additionally requires a valid, unconsumed
    /// `base_invitation_token` bearer matching the submitted email (Phase 2).
    /// Same plain-`String` string-enum convention as `mfa_policy`/
    /// `database.ssl_mode` — not a Rust enum.
    #[serde(default = "default_registration_mode")]
    pub registration_mode: String,
    /// attome-auth plan BAU-15a (hardening 2.7) — the KDF executor and password
    /// policy, formerly constants in `attome_auth::password`. Defaults equal
    /// those constants, so a config without the block behaves as before.
    /// Floors and ceilings are enforced by `AppConfig::validate`.
    #[serde(default)]
    pub kdf: KdfSection,
    /// Q7-T1: an offline set of breached passwords (the Have I Been Pwned
    /// SHA-1 download, `HASH` or `HASH:COUNT` per line), checked locally
    /// when a password is set. Unset, only the small built-in list applies.
    /// Replace the file and restart to update it.
    #[serde(default)]
    pub breached_passwords_file: Option<String>,
}

/// `auth.kdf` — see [`AuthSection::kdf`]. Every default is the value the
/// release-build benchmark in `document/base/auth/kdf-benchmark-2026-09-14.md`
/// chose; raise the Argon2 costs only with a new measurement.
#[derive(Clone, Debug, Deserialize)]
pub struct KdfSection {
    /// Upper bound on concurrent KDF operations whatever the host (1..=64).
    #[serde(default = "default_kdf_hard_cap")]
    pub hard_cap: usize,
    /// Memory all concurrent KDF operations may use together; must fit at
    /// least one operation.
    #[serde(default = "default_kdf_memory_budget_bytes")]
    pub memory_budget_bytes: u64,
    /// How long a request waits for a KDF permit before a 503 (100..=30000).
    #[serde(default = "default_kdf_acquire_timeout_ms")]
    pub acquire_timeout_ms: u64,
    /// Argon2id memory cost in KiB for new hashes. OWASP floor 19456.
    #[serde(default = "default_argon2_m_cost")]
    pub argon2_m_cost: u32,
    /// Argon2id passes for new hashes. OWASP floor 2.
    #[serde(default = "default_argon2_t_cost")]
    pub argon2_t_cost: u32,
    /// Minimum password length in characters (floor 12, security contract I2).
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
}

impl Default for KdfSection {
    fn default() -> Self {
        Self {
            hard_cap: default_kdf_hard_cap(),
            memory_budget_bytes: default_kdf_memory_budget_bytes(),
            acquire_timeout_ms: default_kdf_acquire_timeout_ms(),
            argon2_m_cost: default_argon2_m_cost(),
            argon2_t_cost: default_argon2_t_cost(),
            password_min_length: default_password_min_length(),
        }
    }
}

fn default_kdf_hard_cap() -> usize {
    6
}

fn default_kdf_memory_budget_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_kdf_acquire_timeout_ms() -> u64 {
    2000
}

fn default_argon2_m_cost() -> u32 {
    19_456
}

fn default_argon2_t_cost() -> u32 {
    2
}

fn default_password_min_length() -> usize {
    12
}

/// Hand-rolled: the derived `Debug` would print `oauth_google_client_secret`
/// and `apikey_hash_pepper` (and, via `Vec<ApiKeyPepper>`'s own `Debug`,
/// every retired pepper) as raw secret material. `jwt_secret`/
/// `mfa_encryption_key` are `KeyRing`s, already redacted by that type's own
/// `Debug` impl, so they're safe to list plainly here. Every other field is
/// non-secret policy/config, listed unmodified so this stays useful for
/// debugging.
impl std::fmt::Debug for AuthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSection")
            .field("jwt_secret", &self.jwt_secret)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("access_token_expiry_mins", &self.access_token_expiry_mins)
            .field("refresh_token_expiry_days", &self.refresh_token_expiry_days)
            .field(
                "refresh_absolute_lifetime_days",
                &self.refresh_absolute_lifetime_days,
            )
            .field("secure_cookies", &self.secure_cookies)
            .field("oauth_google_client_id", &self.oauth_google_client_id)
            .field("oauth_google_client_secret", &"[REDACTED]")
            .field("require_verified_email", &self.require_verified_email)
            .field(
                "apikey_default_expiry_days",
                &self.apikey_default_expiry_days,
            )
            .field("mfa_policy", &self.mfa_policy)
            .field("mfa_encryption_key", &self.mfa_encryption_key)
            .field(
                "mfa_challenge_max_attempts",
                &self.mfa_challenge_max_attempts,
            )
            .field("apikey_hash_pepper", &"[REDACTED]")
            .field("apikey_hash_pepper_id", &self.apikey_hash_pepper_id)
            .field(
                "apikey_hash_previous_peppers",
                &self.apikey_hash_previous_peppers,
            )
            .field("registration_mode", &self.registration_mode)
            .field("kdf", &self.kdf)
            .finish()
    }
}

/// One retired entry in `auth.apikey_hash_previous_peppers`.
#[derive(Clone, Deserialize)]
pub struct ApiKeyPepper {
    pub id: u32,
    pub secret: Secret,
}

/// Hand-rolled: `id` is not secret (see the field's doc on `AuthSection`
/// above) but `secret` is retired key material — the derived `Debug` would
/// print it raw, including transitively through `AuthSection`'s
/// `apikey_hash_previous_peppers: Vec<ApiKeyPepper>` field.
impl std::fmt::Debug for ApiKeyPepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyPepper")
            .field("id", &self.id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

fn default_mfa_policy() -> String {
    "off".to_string()
}

fn default_registration_mode() -> String {
    "disabled".to_string()
}

/// Independent anonymous/authenticated budgets for one rate-limit category
/// (P-rate-limit-atomicity §4.3). A category absent from `categories` falls
/// back to `RateLimitSection`'s own top-level `anonymous_rpm`/
/// `authenticated_rpm` — an upgrading deployment that never touches this
/// block is unaffected except for the categories this plan deliberately
/// tightens (credential/mfa/password_reset ship a lower default than the
/// blanket `api` number).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitCategoryLimits {
    pub anonymous_rpm: u32,
    pub authenticated_rpm: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitSection {
    pub anonymous_rpm: u32,
    pub authenticated_rpm: u32,
    /// P-rate-limit-atomicity: keyed by category name (`credential`, `mfa`,
    /// `password_reset`, `api`, `export`, `expensive_query`, ...), resolved
    /// against `attome_server::middleware::rate_limit::RATE_LIMIT_CATEGORIES`'
    /// compile-time (method, route-template) → category table. Replaces the
    /// old `per_endpoint_limits` map outright — that map only ever changed
    /// which number was checked against one shared identity-only bucket, it
    /// never isolated a per-endpoint budget the way its name implied (see
    /// D-145). A deployment with a leftover `per_endpoint_limits` key fails
    /// to boot (below) rather than silently losing an override it believes
    /// still applies.
    #[serde(default)]
    pub categories: HashMap<String, RateLimitCategoryLimits>,
    /// Coarse, IP-only limit applied by `pre_auth_rate_limit` — the layer that
    /// runs before `s2s_authn`/`authn` so a flood of garbage JWTs/HMAC
    /// signatures gets rejected before burning crypto + a Redis
    /// denylist/nonce lookup per request. Deliberately looser than
    /// `anonymous_rpm` (a blunt pre-crypto backstop, not a business-logic
    /// limit) — an unmeasured starting guess; tune against real traffic once
    /// available.
    #[serde(default = "default_pre_auth_rpm")]
    pub pre_auth_rpm: u32,
    /// BSV-F16 (B6) — both per-IP limiters bucket an IPv6 client by this
    /// prefix length rather than its full /128, because one host usually
    /// controls a whole /64 and could otherwise rotate addresses inside it to
    /// dodge the limit. IPv4 is always bucketed per address. Range 32..=128;
    /// 128 restores per-address buckets.
    #[serde(default = "default_ipv6_bucket_prefix")]
    pub ipv6_bucket_prefix: u8,
}

impl RateLimitSection {
    /// Resolves the (anonymous, authenticated) rpm pair for `category`,
    /// falling back to the section's own top-level defaults when the
    /// category has no override configured.
    pub fn limits_for(&self, category: &str) -> (u32, u32) {
        match self.categories.get(category) {
            Some(overrides) => (overrides.anonymous_rpm, overrides.authenticated_rpm),
            None => (self.anonymous_rpm, self.authenticated_rpm),
        }
    }
}

fn default_pre_auth_rpm() -> u32 {
    1000
}

pub(crate) fn default_ipv6_bucket_prefix() -> u8 {
    64
}

// ── S2S section ───────────────────────────────────────────────────────────────

/// Hand-written: `key_encryption_key` holds the AES master key(s) protecting
/// every S2S HMAC secret at rest. `KeyRing`'s own `Debug` already redacts the
/// values; this keeps the whole section on a hand-written impl so the
/// structural redaction test (BCF-1) has one place that owns the answer.
impl std::fmt::Debug for S2SSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2SSection")
            .field("enabled", &self.enabled)
            .field("key_encryption_key", &self.key_encryption_key)
            .field("failure_alert_threshold", &self.failure_alert_threshold)
            .field("access_log_enabled", &self.access_log_enabled)
            .field("seeded_clients", &self.seeded_clients)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct S2SSection {
    /// Enable S2S HMAC authentication. When false the middleware is a no-op.
    #[serde(default)]
    pub enabled: bool,

    /// 64-hex-char AES-256 master key(s) used to encrypt HMAC secrets at
    /// rest. Required when enabled = true. Generate with: openssl rand -hex 32.
    /// P-key-rotation-and-jwt (a): a `KeyRing` — see that type's doc.
    #[serde(default)]
    pub key_encryption_key: KeyRing,

    /// Number of 401 failures from one client in 5 minutes that triggers
    /// the admin failure alert. Default: 100.
    #[serde(default = "default_s2s_failure_threshold")]
    pub failure_alert_threshold: u32,

    /// Write every S2S request to xrm_s2s_access_log. Default: true.
    #[serde(default = "default_true")]
    pub access_log_enabled: bool,

    /// D-771: S2S clients declared here are reconciled at every boot (client,
    /// one key with a fixed `public_id`, permission rows), so a machine
    /// caller's credential survives a database reset and is rotated by
    /// editing `.env`. Empty by default.
    #[serde(default)]
    pub seeded_clients: Vec<S2sSeededClient>,
}

/// One config-declared S2S client (D-771). `secret` is a `${VAR}` reference;
/// blank or unresolved means "not configured here" and the client is skipped.
#[derive(Clone, Deserialize)]
pub struct S2sSeededClient {
    /// Client slug, as `POST /admin/s2s/clients` takes it.
    pub client_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// The existing system user the client acts as. Never created here.
    pub service_user_email: String,
    /// Stable key id the caller sends; must start with `s2s_`.
    pub public_id: String,
    /// 64 hex chars (32 bytes), e.g. `openssl rand -hex 32`.
    #[serde(default)]
    pub secret: Secret,
    #[serde(default = "default_s2s_seed_slot")]
    pub slot: String,
    #[serde(default)]
    pub rate_limit_rpm: Option<i32>,
    #[serde(default)]
    pub max_concurrent: Option<i32>,
    /// Entity ceiling rows (D-766); empty leaves the client unbounded.
    #[serde(default)]
    pub permissions: Vec<S2sSeededPermission>,
}

impl S2sSeededClient {
    /// The secret when it is really configured: non-blank and not a
    /// `${VAR}` literal left behind by a debug-mode config load.
    pub fn configured_secret(&self) -> Option<&str> {
        let s = self.secret.expose().trim();
        (!s.is_empty() && !s.starts_with("${")).then_some(s)
    }
}

impl std::fmt::Debug for S2sSeededClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sSeededClient")
            .field("client_id", &self.client_id)
            .field("name", &self.name)
            .field("service_user_email", &self.service_user_email)
            .field("public_id", &self.public_id)
            .field("secret", &"<redacted>")
            .field("slot", &self.slot)
            .field("permissions", &self.permissions)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct S2sSeededPermission {
    pub entity: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub update: bool,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub export: bool,
    #[serde(default)]
    pub bulk: bool,
}

fn default_s2s_seed_slot() -> String {
    "primary".into()
}

// A bare `#[derive(Default)]` would silently zero `nonce_ttl_secs`/
// `failure_alert_threshold` and flip `access_log_enabled` to `false`
// whenever a config omits this whole `s2s` section — serde's per-field
// `default = "fn"` attributes only apply when the *section itself* is
// present but missing individual keys, not when the enclosing
// `AppConfig` field's own `#[serde(default)]` falls back to this section's
// `Default` impl wholesale. This manual impl keeps both paths agreeing with
// the documented defaults above (same footgun repeated at every section
// below with a `default = "fn"` field and no hand-rolled `Default`).
impl Default for S2SSection {
    fn default() -> Self {
        Self {
            enabled: false,
            key_encryption_key: KeyRing::default(),
            failure_alert_threshold: default_s2s_failure_threshold(),
            access_log_enabled: default_true(),
            seeded_clients: Vec::new(),
        }
    }
}

// ── Security section ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySection {
    /// The only TCP peers allowed to supply a client address through
    /// `X-Forwarded-For`. Leave empty for direct deployments: forwarding
    /// headers are then ignored and the socket peer is used for rate limiting
    /// and audit IPs. Entries must be IPv4/IPv6 CIDRs, for example
    /// `"172.20.0.0/16"` or `"fd00:dead:beef::/64"`. An IPv4-mapped IPv6 peer
    /// (a dual-stack bind) is matched as its IPv4 address.
    ///
    /// BSV-F18 (B7) — the proxies listed here **must** overwrite what the
    /// client sent: nginx `proxy_set_header X-Forwarded-For
    /// $proxy_add_x_forwarded_for;` (appends the real peer, which is the hop
    /// this crate trusts, walking from the last header line) and
    /// `proxy_set_header X-Forwarded-Host $host;` (replaces any client value;
    /// the last line wins). A trusted proxy is also the only peer whose
    /// inbound `traceparent` becomes the request's trace parent (BSV-D10), so
    /// the edge should strip or set that header too.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// P-cookie-csrf-hardening kill switch for the Origin/Fetch-Metadata CSRF
    /// middleware (`attome_server::middleware::csrf`). Default true — the check
    /// only ever rejects a *cookie-authenticated* unsafe-method (POST/PUT/
    /// PATCH/DELETE) request whose `Sec-Fetch-Site`/`Origin` don't match this
    /// deployment, so "on" is the safe default; S2S/ApiKey/no-cookie traffic
    /// is unaffected either way. Set false only to diagnose a reverse proxy
    /// that strips `Origin`/`Sec-Fetch-*` headers — false is log-only
    /// (rejections are `tracing::warn!`'d but the request still proceeds),
    /// never a silent bypass; remove the flag once burned in, never leave it
    /// off in a real deployment.
    #[serde(default = "default_true")]
    pub csrf_enforce: bool,

    /// P-authz-revocation-epoch (D-116): always-on synchronous epoch
    /// re-check (fail-closed, `redis_coordination`, 300ms timeout) ahead of
    /// the privileged/admin-gated route bundles (`admin`, `license_admin`,
    /// `s2s_admin`, `schema`, `sidebar`, plus xrm-security's own grant/revoke
    /// admin routes) — a just-revoked admin cannot keep using a still-live
    /// L1 cache entry to perform further privileged operations for the rest
    /// of the ordinary 60s TTL. Default true; false is the emergency
    /// rollback to pre-epoch behavior for exactly those bundles (kill
    /// switch — remove after one release of burn-in per the plan's rollout
    /// section).
    #[serde(default = "default_true")]
    pub strict_privileged_authz: bool,

    /// P-record-level-security item (b), implemented as a mode of this same
    /// epoch mechanism rather than a second implementation: when true, EVERY
    /// `SecurityContext` resolve — not just the privileged-bundle class
    /// above — pays the fail-closed epoch re-check, so even an ordinary CRUD
    /// request sees a revoked grant on its very next request instead of
    /// within the 60s TTL. Enabled by default for the enterprise security
    /// posture; development deployments may explicitly set it false when the
    /// per-request Redis round trip is unsuitable.
    #[serde(default = "default_true")]
    pub strict_revocation: bool,

    /// P-frontend-hardening §4(d)/step 7 — report-only kill switch for the
    /// response `Content-Security-Policy` header, mirroring `csrf_enforce`'s
    /// pattern above. `true` (default) sends a real, enforcing
    /// `Content-Security-Policy`; `false` sends
    /// `Content-Security-Policy-Report-Only` instead (observe violations,
    /// block nothing) — the plan's own rollout guidance is to set this
    /// `false` as the *first* step in any real deployment, watch for
    /// violations during a burn-in period, then flip it on, precisely
    /// because (unlike `csrf_enforce`, which is safely additive against
    /// existing behavior) there was no prior CSP at all for this to be
    /// layered on top of. See `attome_server::middleware::security_headers`
    /// for the header value itself.
    #[serde(default = "default_true")]
    pub csp_enforce: bool,

    /// `max-age` (seconds) for the response `Strict-Transport-Security`
    /// header; `0` omits the header entirely. Default one year.
    ///
    /// Audit finding: HSTS previously appeared nowhere in `crates/` or
    /// `deploy/`. The assumption was that the separate TLS-edge nginx (D-099
    /// — the one repo that stays outside this monorepo) set it, but nothing
    /// in audited scope pinned or tested that, which made it a control with
    /// no owner. Setting it here gives it one: this process emits it on
    /// every response it serves, exactly the way it already emits CSP, and
    /// `deploy/frontend/nginx.conf` emits the matching header for the static
    /// SPA responses this process never touches.
    ///
    /// Safe to leave on in local dev: RFC 6797 §8.1 requires a user agent to
    /// **ignore** an HSTS header received over a non-secure transport, so the
    /// plain-http `:7865` dev server is unaffected.
    #[serde(default = "default_hsts_max_age_secs")]
    pub hsts_max_age_secs: u64,

    /// Appends `; includeSubDomains` to the header above.
    ///
    /// Defaults to **false**, unlike every other security toggle in this
    /// section, and deliberately so: HSTS is cached by the browser for the
    /// full `max-age`, so switching this on while any sibling subdomain is
    /// still served over plain http makes that subdomain unreachable for up
    /// to a year, with no server-side way to undo it. Turn it on once every
    /// subdomain of the deployment's origin is confirmed TLS-only — that is
    /// the stronger posture and the recommended end state, just not a safe
    /// thing to inherit silently from a default.
    ///
    /// `preload` is deliberately not offered as a toggle: submitting to the
    /// browser preload list is an out-of-band, effectively irreversible
    /// action that must not be reachable by editing a config file.
    #[serde(default)]
    pub hsts_include_subdomains: bool,

    /// I-7's deployment-wide air-gap switch: whether any `Effect::External`
    /// capability (`xrm-ai`'s `GateInputs::external_effects_enabled`) is
    /// allowed to reach outside this deployment at all. Default **false** —
    /// an air-gapped or freshly-provisioned deployment refuses every
    /// external-effect action until an operator opts in explicitly, the
    /// same fail-safe-closed posture every other toggle in this section
    /// documents.
    ///
    /// Before this field existed, every one of `xrm-ai`'s three call
    /// sites (`engine.rs::gate_inputs`, `server::omnichannel`,
    /// `xrm-workflow::scheduler`) hardcoded `external_effects_enabled:
    /// false` with a comment noting no `Effect::External` action existed
    /// yet to make the gap visible — verified live 2026-09-09, grepping
    /// every call site in the workspace. This field is what those three now
    /// read instead of the literal `false`, and it is also the flag
    /// `trd-engine`'s execution pipeline reads directly (see that crate's
    /// `broker_submitter.rs`) to decide whether the router/adapter stage
    /// may submit a real broker order — **not** through
    /// `xrm_ai::dispatch`, because that path's `Initiator` is `User`/
    /// `Agent` only (I-3) and a LIVE strategy's automated order is neither
    /// (`document/TRADING-PLATFORM-PLAN.md` §6 rule 5, `Initiator::System`).
    /// Reusing this one config flag for both, rather than inventing a
    /// second air-gap switch, is what makes "I-7's deployment flag gates
    /// whether any external routing is enabled at all" (plan Phase 4) an
    /// honest sentence.
    #[serde(default)]
    pub external_effects_enabled: bool,
}

/// Not `#[derive(Default)]`: a derived impl would give `csrf_enforce`/
/// `strict_privileged_authz` the bare `bool::default()` (`false`) whenever
/// the whole `security` block is omitted from a config file
/// (`AppConfig.security` is itself `#[serde(default)]`) — the opposite of
/// the fail-safe-on default each field's doc above promises. This manual
/// impl keeps that promise regardless of whether the section is present at
/// all.
impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            trusted_proxy_cidrs: Vec::new(),
            csrf_enforce: true,
            strict_privileged_authz: true,
            strict_revocation: true,
            csp_enforce: true,
            hsts_max_age_secs: default_hsts_max_age_secs(),
            hsts_include_subdomains: false,
            external_effects_enabled: false,
        }
    }
}

/// One year, the value the HSTS preload list requires and the usual
/// recommended floor. See `SecuritySection::hsts_max_age_secs`.
pub(crate) fn default_hsts_max_age_secs() -> u64 {
    31_536_000
}

// ── OIDC section (P2.8 — D-065: config-driven, not a core_identity_provider
// admin-CRUD table; see that decision for why) ──────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OidcSection {
    /// Keyed by an operator-chosen provider key (e.g. "entra", "okta",
    /// "keycloak", "google") — becomes the `{provider}` path segment in
    /// `/api/v1/auth/oidc/{provider}/login|callback` and the `provider_key`
    /// stored in `xrm_core_user_identity`. Empty (the default) means no OIDC
    /// provider is configured — those routes 404 for any key looked up here.
    #[serde(default)]
    pub providers: HashMap<String, OidcProviderConfig>,
}

#[derive(Clone, Deserialize)]
pub struct OidcProviderConfig {
    /// Shown on the Angular login page's provider button.
    pub display_name: String,
    /// Issuer URL, no trailing slash, e.g.
    /// "https://login.microsoftonline.com/{tenant}/v2.0" or
    /// "https://accounts.google.com". `{issuer}/.well-known/openid-configuration`
    /// MUST resolve (OIDC discovery, RFC 8414).
    pub issuer: String,
    pub client_id: String,
    /// `${VAR}`-expanded like every other secret in this file (D-038) — never
    /// commit a real value. Length-checked by `AppConfig::validate` same as
    /// `auth.jwt_secret`/`s2s.key_encryption_key`.
    pub client_secret: Secret,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// ID-token claim carrying the user's email — almost always "email"; a
    /// knob only for a provider with a non-standard claim map.
    #[serde(default = "default_oidc_email_claim")]
    pub email_claim: String,
    /// Enterprise-audit remediation (Phase 2.2, revised): when `true`, a
    /// missing `email_verified` claim is rejected (`Unauthorized`) instead
    /// of defaulting to accepted. **On by default** — an omitted
    /// `email_verified` claim is indistinguishable at the protocol level
    /// from an IdP that never verifies email at all, so defaulting to
    /// "accept" fails open on exactly the ambiguity this flag exists to
    /// close. A provider whose IdP is confirmed to reliably omit the claim
    /// while still being fully trustworthy (`verify_claims`'s original
    /// reasoning) must opt back out explicitly
    /// (`"require_email_verified_claim": false`) rather than relying on a
    /// silent default.
    #[serde(default = "default_true")]
    pub require_email_verified_claim: bool,
}

/// Hand-rolled: `client_secret` is a live OIDC credential — the derived
/// `Debug` would print it raw, including transitively through
/// `OidcSection.providers: HashMap<String, OidcProviderConfig>`.
impl std::fmt::Debug for OidcProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProviderConfig")
            .field("display_name", &self.display_name)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("email_claim", &self.email_claim)
            .field(
                "require_email_verified_claim",
                &self.require_email_verified_claim,
            )
            .finish()
    }
}

/// Referenced by `OidcProviderConfig::scopes`'s `#[serde(default = ...)]` and
/// reused directly by tests to build a well-formed fixture — kept
/// crate-visible (not module-private) for that second reason.
pub(crate) fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}
pub(crate) fn default_oidc_email_claim() -> String {
    "email".into()
}

/// Parse a network in strict `address/prefix` CIDR notation (a bare address
/// is refused here, so `security.trusted_proxy_cidrs` stays explicit). The
/// parsing itself is [`crate::net::parse_ip_network`], the crate's one parser.
///
/// Crate-visible (not module-private): `loader.rs`'s `AppConfig::validate`
/// calls this directly for `security.trusted_proxy_cidrs` format-checking,
/// and the test module also exercises it directly.
pub(crate) fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    if !value.contains('/') {
        return None;
    }
    crate::net::parse_ip_network(value)
}

/// Whether `candidate` falls inside `cidr`; see [`crate::net::cidr_contains`].
/// A malformed `cidr` never matches (fail-closed) — used both for
/// trusted-proxy resolution and attome-server's IP allow-listing.
pub use crate::net::cidr_contains;
