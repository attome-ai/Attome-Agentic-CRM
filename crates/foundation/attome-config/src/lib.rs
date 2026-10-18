//! attome-config — the deployment's one validated configuration schema and,
//! since D-549 removed Vault, its only secret custody.
//!
//! ## Module map
//!
//! * [`AppConfig`] — the root struct, one field per section family.
//! * `config::loader` — `from_file`/`config_file_path`, the Postgres/Redis URL
//!   builders, and the fail-fast `validate()`/`validate_production_profile()`
//!   pass. Checks that need a live engine registry live in
//!   `crates/server/src/boot.rs` instead.
//! * `config::sections` — one file per section family; plain data only.
//! * `config::helpers` — `${VAR}` expansion, the shared `host_port`/
//!   `postgres_url` builders, and the shipped-template secret denylist.
//! * [`KeyRing`] — `key_id -> secret` rotation data. Key material is data
//!   here; every cryptographic operation stays in `attome-auth` (D-130).
//!
//! ## Guarantees this crate owns
//!
//! * **D-038** (as amended by D-615) — an unresolved `${VAR}` is a boot error
//!   outside `APP_ENV=debug`, and under
//!   `app.deployment_profile = "production"` whatever `APP_ENV` says.
//!   Expansion is structural: only JSON string values whose key path has no
//!   `_`-prefixed segment, so a secret containing a quote or a backslash
//!   arrives byte-for-byte and a `_readme`'s literal `${VAR}` is not a
//!   required variable (BCF-6).
//! * **D-172** (as amended by D-614) — the production profile refuses the
//!   templates' own defaults: plaintext cache/storage transport, weak HSTS,
//!   missing API-key expiry, audit signing/chaining/erasure off, the public
//!   development erasure key, shipped template secret values (BCF-3),
//!   `security.strict_privileged_authz = false` (BCF-4) and a non-https
//!   `app.public_frontend_url` (BCF-18).
//! * **D-287** — no secret appears in `Debug`. Redaction is structural: a
//!   secret-named field on a derived-`Debug` struct fails the crate's own test
//!   (BCF-1).
//!
//! **Boundary (BCF-14).** This crate owns the deployment schema as plain
//! data: no `xrm-*` dependency, no xrm types, no engine behaviour. Naming an
//! `xrm_*` table in a default (e.g. `inference.knowledge_article_entity`) is
//! data, not a dependency. Engine-registry cross-checks belong in
//! `crates/server/src/boot.rs`.

mod config;
mod env;
mod keyring;
/// AA9-T1 — every limit the platform enforces, with its range.
pub mod limits;
mod net;
pub mod secret;

pub use config::{
    AiEnablement, AiSurface, AnchorStoreSection, ApiKeyPepper, AppConfig, AppSection, AuthSection,
    BackupSection, CacheBackend, CacheRole, CacheRoleOverride, CacheRoles, CacheSection,
    CaptchaConfig, CaptchaProvider, ChangesetLayer, ChangesetMode, ChangesetsSection, ConfigError,
    DatabasePoolSize, DatabasePools, DatabaseSection, DocgenSection, EinvoiceSection,
    EmailProviders, EmailSection, EventsSection, FleetSection, GoogleAiSection, InferenceEndpoint,
    InferenceSection, IntegrationSection, KdfSection, MetadataSection, ModelPrice,
    NotificationSection, ObservabilitySection, OidcProviderConfig, OidcSection, PortalSection,
    RateLimitSection, ReleaseReportSection, S2SSection, S2sSeededClient, S2sSeededPermission,
    S3Target, SendGridSettings, SesSettings, SpendSection, StatementClassOverrides,
    StatementClassTimeouts, StorageSection, TranslationSection, WebchatSection, WebcrawlSection,
    cidr_contains, endpoint_is_in_deployment,
};
pub use env::{APP_ENV_VAR, DEBUG_APP_ENV, app_env, is_debug_app_env, is_debug_env};
pub use keyring::{BARE_STRING_KEY_ID, KeyRing};
pub use net::parse_ip_network;
pub use secret::Secret;
