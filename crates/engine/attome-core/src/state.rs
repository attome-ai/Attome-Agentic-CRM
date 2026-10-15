use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use attome_cache::{HotCache, MetadataCache, create_hot_cache};
use attome_config::KeyRing;
use attome_rules::Compiled;
use attome_server::AppState;
use axum::extract::FromRef;
// Glob import matches `attome_security::cache`'s own import for the identical
// `.next().publish(...)` call below (`ClientPool::next` + `PubsubInterface`
// aren't worth naming individually — fred's own convention is the prelude).
use attome_modules::ModuleSet;
use uuid::Uuid;

use crate::audit_signing::AuditSigner;
use crate::meta_registry::EntityMetaRegistry;
use crate::model::EntityModuleMap;
use crate::relationship_registry::RelationshipRegistry;
use crate::rule_registry::RuleRegistry;
use crate::services::{NoopNotifications, NotificationService};
use crate::state_registry::StateModelRegistry;

/// Cross-node invalidation doorbell for `EngineState::audit_users` — mirrors
/// `attome_security::SECURITY_VERSION_CHANNEL`'s D-051 shape (payload is the
/// invalidated `user_id`; there's no change-log table here for a remote node
/// to re-derive "what changed" from, so the message itself has to carry the
/// instruction). Added to close the gap the field doc below used to accept:
/// a user's denormalized display-name/email edit was otherwise invisible to
/// every OTHER node's L1 for up to the 60s TTL. Subscriber lives in
/// `attome-server/src/system.rs`, alongside the metadata/security ones. Still
/// not a security control — a lost publish (or a subscriber that never
/// wires up) only ever widens a cosmetic staleness window back to the
/// pre-existing 60s TTL, it never fails a mutation.
pub const AUDIT_USER_VERSION_CHANNEL: &str = "audit_user_version";

/// P1.15 §4(d)-style bound: the `audit_users` cache already degrades to a
/// DB re-query on any miss (cache concern, not a security control) — this
/// just keeps a slow/unreachable Redis from adding latency to the mutation
/// path that triggers the publish, same posture as `attome_security`'s
/// `OP_TIMEOUT`. Deliberately 200 ms, below `attome_cache::timeouts::REQUEST_PATH`
/// (300 ms): a best-effort doorbell on a mutation path, not a call anyone waits
/// on for its result.
const AUDIT_USER_INVALIDATE_TIMEOUT: Duration = Duration::from_millis(200);

/// C-18 — cross-node invalidation doorbell for `EngineState::feature_flags`,
/// the same shape `AUDIT_USER_VERSION_CHANNEL` already established: payload
/// is unused, a doorbell only. Before this, a feature-flag write handled by
/// one node left every OTHER node serving a stale cached evaluation for up
/// to the `feature_flags` cache's 30s TTL. Subscriber lives in
/// `attome-server/src/system.rs`, on the same shared connection as every other
/// doorbell channel.
pub const FEATURE_FLAG_VERSION_CHANNEL: &str = "feature_flag_version";

/// Same non-security-control posture as `AUDIT_USER_INVALIDATE_TIMEOUT` —
/// keeps a slow/unreachable Redis from adding latency to the write path
/// that triggers the publish. Deliberately 200 ms, as above, not
/// `attome_cache::timeouts::REQUEST_PATH`.
const FEATURE_FLAG_INVALIDATE_TIMEOUT: Duration = Duration::from_millis(200);

/// Single definition of the `audit_users` moka key shape (`"{user_id}:audit"`,
/// guidelines §5's two-part key convention) — shared by the cache's reader
/// (`attome-server/src/entity_crud.rs::fetch_audit_ctx`) and its two writers
/// (`EngineState::invalidate_audit_user`/`invalidate_audit_user_local` below) so
/// the format can't drift between them.
pub fn audit_user_cache_key(user_id: Uuid) -> String {
    format!("{user_id}:audit")
}

/// The denormalized `user_account` fields every audit event carries —
/// cached 60s per node (same freshness class as the authz SecurityContext,
/// D-012) so entity mutations don't re-query the user row per request.
#[derive(Clone, Debug, Default)]
pub struct AuditUserInfo {
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub organization_ref: Option<Uuid>,
}

/// XRM-specific application state.
/// Extends AppState with the license, metadata cache, and pluggable service backends.
/// Axum's blanket `FromRef<EngineState> for AppState` impl lets attome-server handlers
/// keep their `State<AppState>` extractors without change.
#[derive(Clone)]
pub struct EngineState {
    pub base: AppState,
    /// Active-model metadata cache (Plan 1.2). Pre-warmed and kept current by
    /// `EngineSystemBuilder::build()` via Redis pub/sub — see `attome-server/system.rs`.
    pub entities: MetadataCache<EntityMetaRegistry>,
    /// M02/D-412 — resolved `setting` rows, arc-swap cached the same
    /// tier as `entities`. Pre-warmed and kept current by
    /// `EngineSystemBuilder::build()`'s settings poll loop — see
    /// `attome-server/src/system.rs` and `setting_store.rs`'s module doc for why
    /// this cache is poll-driven (full reload) rather than the doorbell +
    /// per-key-patch shape `entities` uses.
    pub settings: MetadataCache<crate::setting_store::SettingsSnapshot>,
    /// M05 Phase 1 (D-426) — resolved `metadata_label` rows,
    /// arc-swap cached the same tier as `settings`. Pre-warmed and kept
    /// current by `EngineSystemBuilder::build()`'s label poll loop — see
    /// `attome-server/src/system.rs` and `label_store.rs`'s module doc for why
    /// this cache is poll-driven (full reload), same shape as `settings`.
    pub labels: MetadataCache<crate::label_store::LabelSnapshot>,
    /// The modules this deployment has on (attome-modules). Core only until
    /// boot reads the module configuration.
    pub modules: Arc<ArcSwap<ModuleSet>>,
    /// AG1-T3 — the Umm al-Qura calendar with this deployment's moon-sighting
    /// corrections; see `hijri_store`'s module doc for its refresh.
    pub hijri: Arc<ArcSwap<attome_calendar::hijri::HijriCalendar>>,
    /// D-383 — entity logical name -> owning engine, so generic entity CRUD
    /// can apply the same module check that engine's own routes
    /// already get. Built once from the registered models by
    /// `EngineSystemBuilder::build` and read-only thereafter; empty here, which
    /// gates nothing and so preserves the pre-D-383 behaviour for any caller
    /// that builds bare state.
    pub entity_modules: Arc<EntityModuleMap>,
    /// R-03 (`document/module-master-plans/M26-dashboard-remediation.md`) —
    /// `(entity_logicalname, attribute_logicalname)` pairs a model declared
    /// via `EngineModel::engine_managed_fields`, collected by
    /// `ModelRegistry::engine_managed_fields` and frozen here by
    /// `EngineSystemBuilder::build`, same lifecycle as `entity_modules` right
    /// above. `attome_records::entity_mutation::update_one` consults this
    /// to reject a generic-CRUD `PATCH` that tries to set a field a model's
    /// own bespoke route owns the transition of. Empty here (bare
    /// `EngineState`), which enforces nothing, same posture as `entity_modules`
    /// starting empty.
    pub engine_managed_fields: Arc<HashSet<(String, String)>>,
    /// D-524 — the initial value an engine-managed field may be created with,
    /// keyed by `(entity_logicalname, attribute_logicalname)`, collected from
    /// `EngineModel::engine_managed_initial_values` and frozen by
    /// `EngineSystemBuilder::build` alongside `engine_managed_fields`.
    /// `entity_mutation::create_one` writes the value when a body leaves the
    /// field out and rejects any other value. Empty here, like its sibling.
    pub engine_managed_initial_values: Arc<std::collections::HashMap<(String, String), String>>,
    /// D-535 — entity logical names a model declared through
    /// `EngineModel::engine_owned_entities`, collected by
    /// `ModelRegistry::engine_owned_entities` and frozen here by
    /// `EngineSystemBuilder::build`, same lifecycle as `engine_managed_fields`.
    /// `attome_records::entity_mutation` refuses to create, change or
    /// restore their records generically, for every caller. Empty here (bare
    /// `EngineState`), which enforces nothing.
    pub engine_owned_entities: Arc<HashSet<String>>,
    /// Dashboard 10/10 Phase 2.1 — per-entity write validators a model declared
    /// through `EngineModel::record_validators`, frozen by `EngineSystemBuilder::build`
    /// like `engine_owned_entities`. Empty here, which validates nothing extra.
    pub record_validators:
        Arc<std::collections::HashMap<String, Vec<crate::model::RecordValidator>>>,
    pub notifications: Arc<dyn NotificationService>,
    /// Audit-chain Ed25519 signer (P1.5b) — `None` when `audit.signing_enabled`
    /// is false. Read-only after construction: config-loaded once at startup,
    /// safe to share across the stateless request path per the multi-server rule.
    pub audit_signer: Option<Arc<AuditSigner>>,
    /// L1 moka cache for the audit user context (ex-audit-finding #43): keyed
    /// `"{user_id}:audit"`, 60s TTL — stale-tolerant denormalized display
    /// fields, not a security control (same freshness class as the authz
    /// cache, D-012). Cross-node staleness is now bounded by
    /// `AUDIT_USER_VERSION_CHANNEL` pub/sub (see `invalidate_audit_user`)
    /// rather than only by the TTL — a systemuser update/delete publishes so
    /// every other node drops its own stale entry immediately instead of
    /// serving it for up to 60s.
    pub audit_users: HotCache<AuditUserInfo>,
    /// D-107 (P-data-lifecycle item (d)) — crypto-shredding master key ring,
    /// cloned once at startup from `audit.erasure_key_encryption_key`.
    /// `None` when audit encryption is not active (`AuditSection::erasure_active`,
    /// D-540: an explicit `erasure_enabled = false`, or no key configured): every
    /// `AuditService::with_erasure_key(state.audit_erasure_key)` call site
    /// then no-ops, same as `audit_signer` being `None`. P-key-rotation-and-jwt
    /// (a): a `KeyRing`, not a parsed-once `[u8; 32]` — rotating this key no
    /// longer bricks every already-provisioned record's DEK.
    pub audit_erasure_key: Option<KeyRing>,
    /// M07 Phase 1 (D-406) — the state-lifecycle registry snapshot
    /// (`state_model`/`state_transition`), consulted by
    /// `attome-server::entity_mutation` on every create/update and by
    /// `attome-state`'s own admin/record routes. Pre-warmed and kept current by
    /// `EngineSystemBuilder::build` via Redis pub/sub
    /// (`state_registry::STATE_MODEL_VERSION_CHANNEL`) — see
    /// `attome-server/system.rs`. Empty here (bare `EngineState`), which enforces
    /// nothing, same posture as `entities` starting empty.
    pub state_models: MetadataCache<StateModelRegistry>,
    /// M01 Core P3 gap (D-455) — the generic many-to-many relationship
    /// metadata snapshot (`relationship_info`), consulted by
    /// `entity_crud`'s `/related/{relationship}` handlers and
    /// `query_exec`'s relationship-join support. Pre-warmed and kept current
    /// by `EngineSystemBuilder::build` via Redis pub/sub
    /// (`relationship_registry::RELATIONSHIP_VERSION_CHANNEL`) — see
    /// `attome-server/src/system.rs`. Empty here (bare `EngineState`), same
    /// posture as `state_models` starting empty.
    pub relationships: MetadataCache<RelationshipRegistry>,
    /// M45 Phase 2 (D-472) — the rule metadata snapshot (`rule`),
    /// consulted by `attome-server`'s `entity_mutation` create/update paths and
    /// by `rule_admin`'s test/publish actions. Pre-warmed and kept current by
    /// `EngineSystemBuilder::build` via Redis pub/sub
    /// (`rule_registry::RULE_VERSION_CHANNEL`) — see
    /// `attome-server/src/system.rs`. Empty here (bare `EngineState`), same posture
    /// as `state_models`/`relationships` starting empty.
    pub rules: MetadataCache<RuleRegistry>,
    /// M45 Phase 2 (D-472) — compiled-rule L1, keyed `"{rule_id}:{version}"`
    /// (`attome-server::rule_engine::cache_key`). Rebuildable at any time from
    /// `rules` + the entity's live attribute schema (`entities`), so this is
    /// a pure performance cache, not a source of truth — a miss just costs a
    /// re-parse + re-typecheck, never a wrong answer. No TTL: keying on
    /// `version` makes a stale entry for a superseded version simply
    /// unreachable (a fresh `compile` under the new key on next use),
    /// evicted by moka's bounded LRU capacity rather than time, same posture
    /// `feature_flags` below takes for its own derived-value cache.
    pub rule_compiled: HotCache<Arc<Compiled>>,
    /// M95/D-430 — computed `FeatureFlags::is_on` results, keyed
    /// `"{flag_key}:{user_id}"` (`feature_flag_store::feature_flag_cache_key`).
    /// Derived entirely from `settings` (already change-log + poll
    /// invalidated) and the live `license` arc-swap, both consulted fresh on
    /// every miss — this cache only ever saves the JSON-parse +
    /// policy-resolution work, never the license check itself. A feature-flag
    /// write invalidates it wholesale on the writing node
    /// (`invalidate_feature_flags`), which also best-effort publishes on
    /// `FEATURE_FLAG_VERSION_CHANNEL` (C-18) so every other node drops its
    /// own cached evaluations promptly too, rather than only bounding
    /// staleness by TTL, same posture as the D-012 authz L1's own
    /// cross-node doorbell.
    pub feature_flags: HotCache<bool>,
    /// Dashboard 10/10 Phase 6 — every registered `MyWorkProvider`, frozen by
    /// `EngineSystemBuilder::build` the same way `record_validators` is: a
    /// second, parallel registry to `ModelRegistry` (a provider and an
    /// `EngineModel` answer unrelated questions — `my_work.rs`'s module doc).
    /// Empty here (bare `EngineState`), which lists no work for anyone, same
    /// posture every other frozen-at-boot collection above starts from.
    pub my_work_providers: Arc<Vec<Box<dyn crate::my_work::MyWorkProvider>>>,
    /// C5 (chatbot plan) — the one `WorkflowStarter`, registered by the
    /// composition root on the `EngineSystem` builder and frozen at build, the
    /// same lifecycle as `my_work_providers`. `None` here (bare `EngineState`):
    /// no engine can start a workflow through the seam until `attome-workflow`'s
    /// implementation is registered — `workflow.start` then answers as
    /// absent, never as a silent no-op (`workflow_start.rs`).
    pub workflow_starter: Option<Arc<dyn crate::workflow_start::WorkflowStarter>>,
}

impl std::fmt::Debug for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState").finish_non_exhaustive()
    }
}

impl EngineState {
    /// Creates state with a degraded (free/no-module) license, an empty
    /// metadata registry, and noop service backends. EngineSystem::builder
    /// replaces/pre-warms these before the server starts.
    #[expect(
        clippy::expect_used,
        reason = "config.validate() has already proved the signing key parses"
    )]
    pub fn new(base: AppState) -> Self {
        let audit_signer = if base.config.audit.signing_enabled {
            Some(Arc::new(
                AuditSigner::from_config(
                    &base.config.audit.signing_key_id,
                    base.config.audit.signing_private_key.expose(),
                )
                // config.validate() already fail-fast-checks this at boot
                // (non-placeholder, 64 hex chars when signing is on — BCF-7)
                // before EngineState is built.
                .expect("audit.signing_private_key invalid despite passing config.validate()"),
            ))
        } else {
            None
        };

        let audit_erasure_key = if base.config.audit.erasure_active() {
            let ring = base.config.audit.erasure_key_encryption_key.clone();
            // config.validate() already fail-fast-checks this ring at boot
            // (every key non-placeholder and 64 hex chars — BCF-7's shape
            // table). This canary still runs as the decode-side double check
            // the envelope's own key parsing performs, so a key that passes
            // the shape check but cannot be decoded is caught before the node
            // ever takes traffic (D-038 fail-closed), with a message that
            // names the exact requirement rather than assuming validate()
            // already guaranteed it.
            if let Err(e) = attome_auth::envelope::canary("audit.erasure_key_encryption_key", &ring)
            {
                panic!(
                    "audit.erasure_key_encryption_key invalid: {e} — every key must be 64 hex \
                     chars (32 bytes); generate with: openssl rand -hex 32"
                );
            }
            Some(ring)
        } else {
            None
        };

        Self {
            base,
            entities: MetadataCache::new(EntityMetaRegistry::default()),
            settings: MetadataCache::new(crate::setting_store::SettingsSnapshot::default()),
            labels: MetadataCache::new(crate::label_store::LabelSnapshot::default()),
            modules: Arc::new(ArcSwap::from_pointee(ModuleSet::core_only())),
            hijri: Arc::new(ArcSwap::from_pointee(
                attome_calendar::hijri::HijriCalendar::umm_al_qura().clone(),
            )),
            entity_modules: Arc::new(EntityModuleMap::default()),
            engine_managed_fields: Arc::new(HashSet::new()),
            engine_managed_initial_values: Arc::new(std::collections::HashMap::new()),
            engine_owned_entities: Arc::new(HashSet::new()),
            record_validators: Arc::new(std::collections::HashMap::new()),
            notifications: Arc::new(NoopNotifications),
            audit_signer,
            audit_users: create_hot_cache(10_000, 60),
            audit_erasure_key,
            state_models: MetadataCache::new(StateModelRegistry::default()),
            relationships: MetadataCache::new(RelationshipRegistry::default()),
            rules: MetadataCache::new(RuleRegistry::default()),
            // M45 Phase 2 (D-472) — effectively no TTL (see the field's own
            // doc comment for why version-keying makes one unnecessary);
            // `create_hot_cache` has no "no expiry" option, so this uses a
            // 10-year ceiling rather than `Duration::MAX`, well past any
            // process's real uptime. Capacity mirrors `feature_flags`' own
            // bound below, a reasonable ceiling for a per-process L1 with no
            // persistence requirement.
            rule_compiled: create_hot_cache(10_000, 60 * 60 * 24 * 365 * 10),
            feature_flags: create_hot_cache(10_000, 30),
            my_work_providers: Arc::new(Vec::new()),
            workflow_starter: None,
        }
    }

    /// M95/D-430 — the evaluation-helper accessor:
    /// `state.feature_flags().is_on(key, &ctx)`.
    pub fn feature_flags(&self) -> crate::feature_flag_store::FeatureFlags<'_> {
        crate::feature_flag_store::FeatureFlags::new(self)
    }

    /// Call after a feature-flag write commits (same trigger point as the
    /// settings write path's own synchronous local cache refresh) — wholesale
    /// local invalidation, not per-key, since `feature_flags`' keys are
    /// `"{flag_key}:{user_id}"` and a single flag write can affect every
    /// cached user for that flag at once (a changed `deployment` default,
    /// role override, or rollout percentage). Cheap: moka's `invalidate_all`
    /// is a lazy watermark bump, not a synchronous per-entry sweep.
    ///
    /// C-18 — also best-effort publishes on `FEATURE_FLAG_VERSION_CHANNEL`
    /// so every other node's own `feature_flags` cache drops promptly too,
    /// the same cross-node doorbell shape `invalidate_audit_user` already
    /// uses. Failure here is logged and otherwise ignored: the worst case is
    /// the pre-existing 30s TTL staleness window on other nodes, never a
    /// failed request — this cache is a derived-value performance cache,
    /// not a security decision (the license/settings checks it wraps are
    /// still consulted fresh on every miss).
    pub async fn invalidate_feature_flags(&self) {
        self.feature_flags.invalidate_all();

        match tokio::time::timeout(
            FEATURE_FLAG_INVALIDATE_TIMEOUT,
            self.base.redis.publish(FEATURE_FLAG_VERSION_CHANNEL, "1"),
        )
        .await
        {
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "failed to publish feature_flag_version doorbell")
            }
            Err(_) => tracing::warn!("publishing feature_flag_version doorbell timed out"),
            Ok(Ok(_)) => {}
        }
    }

    /// L1-only purge, driven by the `feature_flag_version` subscriber
    /// (`attome-server/src/system.rs`) when a REMOTE node published an
    /// invalidation — no Redis publish here, the originating node already
    /// did that.
    pub fn invalidate_feature_flags_local(&self) {
        self.feature_flags.invalidate_all();
    }

    /// Purges this node's own `audit_users` entry for `user_id` and
    /// best-effort publishes on `AUDIT_USER_VERSION_CHANNEL` so every other
    /// node drops its own stale copy too. Call this AFTER a successful
    /// commit of an `user_account` update/delete — never from inside
    /// that mutation's own transaction (guidelines §4: no Redis I/O across a
    /// DB transaction). Failure here is logged and otherwise ignored: the
    /// worst case is the pre-existing 60s TTL staleness window, never a
    /// failed request — this cache backs denormalized audit display fields,
    /// not a security decision.
    pub async fn invalidate_audit_user(&self, user_id: Uuid) {
        self.audit_users
            .invalidate(&audit_user_cache_key(user_id))
            .await;

        match tokio::time::timeout(
            AUDIT_USER_INVALIDATE_TIMEOUT,
            self.base
                .redis
                .publish(AUDIT_USER_VERSION_CHANNEL, &user_id.to_string()),
        )
        .await
        {
            Ok(Err(e)) => {
                tracing::warn!(error = %e, %user_id, "failed to publish audit_user_version doorbell")
            }
            Err(_) => tracing::warn!(%user_id, "publishing audit_user_version doorbell timed out"),
            Ok(Ok(_)) => {}
        }
    }

    /// L1-only purge, driven by the `audit_user_version` subscriber
    /// (`attome-server/src/system.rs`) when a REMOTE node published an
    /// invalidation — no Redis publish here, the originating node already
    /// did that.
    pub async fn invalidate_audit_user_local(&self, user_id: Uuid) {
        self.audit_users
            .invalidate(&audit_user_cache_key(user_id))
            .await;
    }

    /// M05 Phase 1 (D-426) — the `core.locale` setting's deployment-scope
    /// value (or its code default, `"en-US"`, when unset). Shared by every
    /// label-resolving handler (`schema.rs::get_schema`, `sidebar::get_sidebar`)
    /// so "deployment default" means exactly that scope everywhere, never a
    /// caller's own user/organization override — a caller who wants their own
    /// locale passes it explicitly via `?locale=`.
    pub fn deployment_locale(&self) -> String {
        let Some(descriptor) = crate::setting_registry().get("core.locale") else {
            return "en-US".to_owned();
        };
        let (value, _source) = self.settings.load().resolve(descriptor, None, None);
        value.as_str().unwrap_or("en-US").to_owned()
    }
}

impl FromRef<EngineState> for AppState {
    fn from_ref(s: &EngineState) -> Self {
        s.base.clone()
    }
}

/// D-344 — the mirror of `attome-server`'s own `FromRef<AppState>` impl, which
/// has to live here because this crate owns `EngineState` (orphan rule). Without
/// it, no `Router<EngineState>` handler could name
/// `attome_server::capability::Available<C>` — and that is every route the gate
/// applies to.
///
/// Deliberately not `AppState::from_ref(s).capabilities`: that would clone
/// the whole `AppState` (a dozen pool/Arc bumps) on every gated request to
/// reach one field.
impl FromRef<EngineState> for attome_server::capability::CapabilityStatuses {
    fn from_ref(s: &EngineState) -> Self {
        attome_server::capability::CapabilityStatuses::new(Arc::clone(&s.base.capabilities))
    }
}
