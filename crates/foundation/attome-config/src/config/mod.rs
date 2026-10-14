//! `AppConfig` — the platform's root configuration struct — and the
//! `config::` module tree it's split across (item 25 of the platform's
//! file-size cleanup list): one file per section family under `sections/`,
//! the env/file loader + URL builders + `validate()` in `loader.rs`, shared
//! helpers in `helpers.rs`, `ConfigError` in `error.rs`, and the test suite
//! in `tests.rs`.
//!
//! Every name `lib.rs`'s `pub use config::{...}` re-exports is re-exported
//! here by explicit name (see the first `pub use` block below) — no blanket
//! globs cross a module boundary in this tree, mirroring the `entity_crud`/
//! `provision` directory-split precedent elsewhere in this repo.

use serde::Deserialize;

mod error;
mod helpers;
mod loader;
mod sections;

#[cfg(test)]
// The env-var tests need `set_var`/`remove_var`, unsafe in edition 2024; each carries a SAFETY note.
#[allow(unsafe_code)]
mod tests;

// ── Public surface — mirrors lib.rs's `pub use config::{...}` list, name for
// name. These `pub use`s also bring each type into this file's own scope,
// which `AppConfig` below needs regardless of re-export. ───────────────────
pub use error::ConfigError;
pub use sections::audit::{AnchorStoreSection, NotificationSection};
pub use sections::auth::{
    ApiKeyPepper, AuthSection, KdfSection, OidcProviderConfig, OidcSection, RateLimitSection,
    S2SSection, S2sSeededClient, S2sSeededPermission, cidr_contains,
};
pub use sections::cache::{CacheBackend, CacheRole, CacheRoleOverride, CacheRoles, CacheSection};
pub use sections::database::{AppSection, DatabasePoolSize, DatabasePools, DatabaseSection};
pub use sections::docgen::DocgenSection;
pub use sections::events::EventsSection;
pub use sections::fleet::FleetSection;
pub use sections::inference::{
    AiEnablement, AiSurface, InferenceEndpoint, InferenceSection, ModelPrice, SpendSection,
    TranslationSection, endpoint_is_in_deployment,
};
pub use sections::integration::IntegrationSection;
pub use sections::metadata::{
    ChangesetLayer, ChangesetMode, ChangesetsSection, MetadataSection, ReleaseReportSection,
};
pub use sections::observability::{EmailSection, GoogleAiSection, ObservabilitySection};
pub use sections::portal::{CaptchaConfig, CaptchaProvider, PortalSection};
pub use sections::storage::{S3Target, StorageSection};
pub use sections::webchat::WebchatSection;
pub use sections::webcrawl::WebcrawlSection;

// ── Not part of the crate's public surface (absent from lib.rs's list above)
// but still needed either to define `AppConfig` below, or — via a bare
// `super::NAME` reference — by `loader.rs`/`tests.rs`, both descendants of
// this module. Plain (non-`pub`) imports: the binding's default visibility
// (this module + descendants) is exactly what a child module's `super::NAME`
// needs, matching entity_crud/mod.rs's "brought into this module's own
// namespace purely so a child module can resolve it via super::NAME"
// precedent for its own test-only imports. ──────────────────────────────────

// Needed to define `AppConfig`'s fields below (not part of the public
// surface — see the module-level comment above).
use sections::audit::{AuditSection, RetentionSection};
use sections::auth::SecuritySection;
use sections::capability::CapabilitySection;
use sections::deployment::DeploymentSection;
use sections::platform::{
    ApprovalSection, ChangeFeedSection, CorsSection, IdempotencySection, JobsSection, QuerySection,
};

// Needed by `loader.rs`'s `impl AppConfig` block (a bare `super::NAME`
// reference there) AND by `tests.rs`'s `use super::{...}` list — not
// `#[cfg(test)]`-gated, since `loader.rs` needs these outside test builds
// too.
use helpers::{build_redis_sentinel_url, build_redis_url, urlencoding};
use sections::auth::parse_cidr;
use sections::cache::CacheSentinelConfig;

// Needed ONLY so `tests.rs`'s (verbatim, unmodified) `use super::{...}` list
// resolves — `loader.rs` never names these directly (each computation it
// needs from `sections::*` is reached through `self.<field>` access, not a
// literal type/fn name). `#[cfg(test)]`-gated so a non-test build doesn't
// warn (and, under `-D warnings`, fail) on an import nothing in a release
// binary references — same precedent as provision/mod.rs's identical
// test-only re-imports.
// Used only by `tests.rs` (the production-template tests expand a parsed
// document rather than splicing text, BCF-6), so gate them with the rest of
// this block.
#[cfg(test)]
use helpers::{expand_env_vars, expand_env_vars_in_value};
#[cfg(test)]
use sections::auth::{default_oidc_email_claim, default_oidc_scopes};
#[cfg(test)]
use sections::cache::CacheSentinelNode;
#[cfg(test)]
use sections::database::{MigratorDbCredentials, ReadonlyDbCredentials, RuntimeDbCredentials};

// ── Top-level ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub app: AppSection,
    pub database: DatabaseSection,
    pub cache: CacheSection,
    pub storage: StorageSection,
    pub auth: AuthSection,
    pub rate_limit: RateLimitSection,
    pub observability: ObservabilitySection,
    pub email: EmailSection,
    pub google_ai: GoogleAiSection,
    #[serde(default)]
    pub s2s: S2SSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub audit: AuditSection,
    /// In-app notification inbox lifecycle policy. Kept separate from audit
    /// retention because notification rows have different ownership.
    #[serde(default)]
    pub notification: NotificationSection,
    /// P-retention-archive-completion — partition archive/drop, entity
    /// purge, and legal hold policy. See `RetentionSection`'s doc comment.
    #[serde(default)]
    pub retention: RetentionSection,
    #[serde(default)]
    pub cors: CorsSection,
    #[serde(default)]
    pub jobs: JobsSection,
    #[serde(default)]
    pub query: QuerySection,
    #[serde(default)]
    pub oidc: OidcSection,
    /// P-idempotency-hardening §4.4/§4.5 — the durable-tier
    /// mandatory-operation policy. Additive/opt-in (empty by default): a
    /// deployment must explicitly name routes here before any request starts
    /// requiring `X-Idempotency-Key`, matching `audit.chainer_enabled`'s
    /// "ships dark behind a flag" precedent. D-327: that "empty by default"
    /// posture is deliberately narrowed under `app.deployment_profile =
    /// "production"` — `server::boot::init`'s `validate_operation_registries`
    /// additionally requires every `xrm_server::bulk::
    /// MANDATORY_TIER_OPERATIONS` entry to be present here before a
    /// production process boots. `attome-config` can't express that floor
    /// itself (zero xrm-* knowledge, guidelines §1), so it isn't part of
    /// `validate_production_profile` below despite living right next to
    /// every other production-only requirement enforced there.
    #[serde(default)]
    pub idempotency: IdempotencySection,
    /// D-195 / P-four-eyes-approval — which `attome_approval` action_type
    /// strings require dual-control approval instead of executing inline.
    /// Empty by default (opt-in, same "ships dark behind a flag" posture as
    /// `idempotency`/`audit.chainer_enabled`) — a deployment names an action
    /// here only once a customer's security policy or compliance framework
    /// actually requires it (the backlog's own trigger condition).
    #[serde(default)]
    pub approval: ApprovalSection,
    /// P-data-protection-governance §4 — data-residency declaration; see
    /// `DeploymentSection`'s doc comment.
    #[serde(default)]
    pub deployment: DeploymentSection,
    /// D-344 (amends D-167) — the durability-capability gate. Governs a
    /// *route-level* 503 for operations that cannot durably complete
    /// (upload, bulk import, mail resend), never node readiness. See
    /// `CapabilitySection`'s doc comment for why `enforcement_enabled`
    /// defaults on where most flags in this tree ship dark.
    #[serde(default)]
    pub capability: CapabilitySection,
    /// D-360 / P-inference — model endpoints and the AI kill-switch
    /// (TODO-055). Ships dark: every surface defaults off, so a deployment
    /// that upgrades into a build containing AI code gets no AI behaviour and
    /// no model traffic until an operator opts in.
    #[serde(default)]
    pub inference: InferenceSection,
    /// D-365 — Web Crawling for Knowledge Base. Ships dark (`enabled: false`):
    /// the platform's first feature that makes an outbound HTTP request to an
    /// arbitrary, user-supplied URL. See `WebcrawlSection`'s doc comment.
    #[serde(default)]
    pub webcrawl: WebcrawlSection,
    /// D-558 — the public web-chat assistant (chatbot plan C9). Ships dark
    /// (`enabled: false`), and enabling it requires an agent definition and
    /// both spend caps. See `WebchatSection`'s doc comment.
    #[serde(default)]
    pub webchat: WebchatSection,
    /// D-588 — external-audience web portals: the OIDC providers they may
    /// offer and the signup CAPTCHA. See `PortalSection`'s doc comment.
    #[serde(default)]
    pub portal: PortalSection,
    /// M62 Phase 1 — Event Bus subscriptions/webhook delivery. Ships dark
    /// (`webhooks_enabled: false`). See `EventsSection`'s doc comment.
    #[serde(default)]
    pub events: EventsSection,
    /// M59 Phase 1 — Integration & Connectors. Ships dark (`enabled: false`):
    /// see `IntegrationSection`'s doc comment.
    #[serde(default)]
    pub integration: IntegrationSection,
    /// M57 Phase 1 — Document Generation. The isolated render sidecar's
    /// address plus its explicit timeout/size caps. See `DocgenSection`'s
    /// doc comment.
    #[serde(default)]
    pub docgen: DocgenSection,
    /// M01 §7 C-04 — how long a change-feed row that every registered
    /// consumer has passed is kept before `PlatformJob::PruneChangeFeed`
    /// deletes it. See `ChangeFeedSection`'s doc comment.
    #[serde(default)]
    pub change_feed: ChangeFeedSection,
    /// Solution 7 Phase 1 (D-785) — how metadata admin writes are recorded
    /// as changesets. See `ChangesetsSection`'s doc comment.
    #[serde(default)]
    pub metadata: MetadataSection,
    /// D-792 — the fleet console (developer machine only). Empty by default;
    /// refused on the production profile. See `FleetSection`'s doc comment.
    #[serde(default)]
    pub fleet: FleetSection,

    /// BCF-5 (D-615) — the `${VAR}` names `from_file` left unresolved,
    /// recorded so the production profile can refuse boot even under
    /// `APP_ENV=debug` (BCF-F7). Not part of the on-disk schema: `serde`
    /// skips it, and `from_file` is the only writer.
    #[serde(skip)]
    pub(crate) unresolved_placeholders: Vec<String>,

    /// BCF-10 — the config keys `from_file` dropped as unknown (dotted JSON
    /// paths, `_`-prefixed prose keys excluded). Recorded by
    /// `serde_ignored`, so it hooks serde's own ignore path rather than a
    /// parallel parser. Boot warns on each; `preflight` fails on any.
    #[serde(skip)]
    pub(crate) ignored_keys: Vec<String>,
}
