use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use attome_cache::{MetadataCache, Store};
use attome_core::{
    EngineModel, EngineState, EntityMetaRegistry, MyWorkProvider,
    services::{NoopNotifications, NotificationService},
};
use attome_db::DbPool;
use attome_modules::{
    MODULE_AUDIT, MODULE_CONTENT, MODULE_CORE, MODULE_INTEGRATION, MODULE_OMNICHANNEL, ModuleId,
    ModuleSet,
};
use attome_types::AppError;
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
};

use crate::registry::ModelRegistry;

/// D-143: gates a router behind the live license's `module_id` bit, same
/// check/response shape as `ModelRegistry::mounted_routes` — used here for
/// the generic entity CRUD surface, which isn't registered as an `EngineModel`
/// (it's core-mounted, not a pluggable engine) but is still one of
/// `license-tool`'s named, independently-selectable modules (`entity`) and
/// must not be reachable on a license that never granted it. A license row
/// (or its absence — "free mode") that omits `entity` now genuinely hides
/// generic record CRUD, matching every other module's enforcement.
fn license_gate(
    router: Router<EngineState>,
    license: Arc<ArcSwap<ModuleSet>>,
    module_id: ModuleId,
    module_name: &'static str,
) -> Router<EngineState> {
    router.route_layer(middleware::from_fn(move |req: Request, next: Next| {
        let license = Arc::clone(&license);
        async move {
            if license.load().require(module_id).is_ok() {
                next.run(req).await
            } else {
                AppError::FeatureHidden(module_name.to_string()).into_response()
            }
        }
    }))
}

/// Redis channel + key name for metadata-registry invalidation (Plan 1.2).
const META_VERSION_KEY: &str = "meta_version";

/// Entry point for wiring the XRM platform.
///
/// Illustrative shape only (`SendGridService`/`OpenAiService`/`MyCustomModel`/
/// `auth_routes`/`state`/`config` are stand-ins, not real importable items) —
/// `ignore` rather than a real doctest; see `main.rs` for a compiling example
/// of the exact assembly sequence.
///
/// ```rust,ignore
/// let system = EngineSystem::builder(state)
///     .notifications(Arc::new(SendGridService::new()))  // defaults to noop
///     .register(MyCustomModel)                          // optional extra models
///     .build()
///     .await?;
///
/// let base_state = system.state().base.clone();
/// let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
///     .add_bundle(system.core_routes())
///     .add_bundle(attome_server::RouteBundle::new(auth_routes.with_state(base_state.clone())))
///     .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
/// ```
pub struct EngineSystem {
    pub(crate) state: EngineState,
    pub(crate) registry: ModelRegistry,
}

impl std::fmt::Debug for EngineSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineSystem").finish_non_exhaustive()
    }
}

pub struct EngineSystemBuilder {
    state: EngineState,
    registry: ModelRegistry,
    notifications: Arc<dyn NotificationService>,
    my_work_providers: Vec<Box<dyn MyWorkProvider>>,
    workflow_starter: Option<Arc<dyn attome_core::WorkflowStarter>>,
    workflow_step_handlers: std::collections::HashMap<
        &'static str,
        Arc<dyn attome_core::workflow_step::WorkflowStepHandler>,
    >,
    workflow_kind_guards: std::collections::HashMap<
        &'static str,
        Arc<dyn attome_core::workflow_step::WorkflowKindGuard>,
    >,
}

impl std::fmt::Debug for EngineSystemBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineSystemBuilder")
            .finish_non_exhaustive()
    }
}

// ── EngineSystem ──────────────────────────────────────────────────────────────────

impl EngineSystem {
    pub fn builder(state: EngineState) -> EngineSystemBuilder {
        EngineSystemBuilder {
            state,
            registry: ModelRegistry::new(),
            notifications: Arc::new(NoopNotifications),
            my_work_providers: Vec::new(),
            workflow_starter: None,
            workflow_step_handlers: std::collections::HashMap::new(),
            workflow_kind_guards: std::collections::HashMap::new(),
        }
    }

    /// Borrow state before consuming self via core_routes().
    pub fn state(&self) -> &EngineState {
        &self.state
    }

    /// Builds the bare-router bundle: health routes + admin/entity/model
    /// routes, merged together with **zero middleware**, wrapped as a
    /// `RouteBundle` (D-047) — opaque outside `attome_server::ServerBuilder`, so
    /// the caller cannot accidentally merge this onto an already-layered `app`
    /// and skip auth/s2s/rate-limiting the way `/api/v1/auth/api-keys` once did
    /// (Plan 1.3). The caller passes this to `ServerBuilder::add_bundle`
    /// alongside its own bundles (auth, …), then `ServerBuilder::build` applies
    /// the full middleware stack exactly once, in the fixed order — see the
    /// module doc example above.
    ///
    /// Consumes self — call `.state().clone()` before this if you need state for extra routes.
    pub fn core_routes(self) -> attome_server::RouteBundle {
        let model_routes = self.registry.mounted_routes(self.state.modules.clone());

        // P-authz-revocation-epoch (D-116) goal (a): layered ahead of exactly
        // the five privileged/admin-gated bundles the plan names
        // (admin/schema/sidebar/s2s_admin/license_admin) plus this crate's
        // own grant/revoke admin surface (attome_security::admin) — never the
        // ordinary entity_crud/model-registry/api-key/mfa routes, which keep
        // D-012's 60s-TTL class unchanged. Each `.layer()` call constructs
        // its own `from_fn_with_state` rather than sharing one `Clone`d
        // value — cheap (an `EngineState` clone is just its inner `Arc`/pool
        // clones) and keeps each merge call self-contained.
        let authed = model_routes
            .merge(attome_records::query_exec::routes())
            // S1-T7: several record operations in one request.
            .merge(attome_records::composite::routes())
            .merge(attome_records::query_admin::routes())
            .merge(crate::view_admin::routes())
            // Y1-T9: the metadata model's admin API (admin-gated in each handler).
            .merge(crate::model_admin::routes())
            // A1-T11: model-health findings (admin-gated in the handler).
            .merge(crate::model_health::routes())
            // Y2-T8: table health from the statistics views (admin-gated).
            .merge(crate::table_health::routes())
            .merge(crate::deployment_openapi::routes())
            // N30-T8/T9: approval figures and rubber-stamp warnings (admin-gated).
            .merge(crate::approval_metrics::routes())
            .merge(crate::live::routes())
            .merge(crate::calendar_admin::routes())
            // M65 Phase 1 — Application Builder: same "core, always-on,
            // Admin-privilege-gated" posture as `view_admin`/`calendar_admin`
            // immediately above — not wrapped in `license_gate` (core
            // platform capability, not a licensed module).
            .merge(crate::app_admin::routes())
            // AA13-T8: SLO budgets and the deployment's own targets.
            .merge(crate::slo_admin::routes())
            // AA9-T6: every limit and its use; a caller's own limits.
            .merge(crate::limits_admin::routes())
            .merge(crate::model_admin::cooked::routes())
            // C4-T1: mentions in text about a record.
            .merge(crate::mentions::routes())
            // Q20-T5: rate-limit bans (admin-gated in the handlers).
            .merge(crate::ratelimit_admin::routes())
            // AC7-T11: what this deployment runs.
            .merge(crate::sbom_admin::routes())
            // A30-T1: environment variable values.
            .merge(crate::env_variable_admin::routes())
            // Z15-T13: customer tests.
            .merge(crate::customer_test_admin::routes())
            .merge(crate::business_rule_admin::routes())
            .merge(crate::metadata_label_admin::routes())
            .merge(
                // P-environment-promotion: the bundle engine's admin surface
                // (export / plan / apply / status / drift) and the break-glass
                // window — `system.admin`-gated, under the one `/admin/metadata`
                // prefix the authoring gate exempts.
                crate::bundle::routes::routes()
                    .merge(crate::bundle::break_glass::routes())
                    .layer(middleware::from_fn_with_state(
                        self.state.clone(),
                        attome_security::strict_authz::strict_authz,
                    )),
            )
            .merge(
                // Solution 7 (D-785): changeset authoring — open, list, show,
                // close, abandon, export. `system.admin`-gated; under the
                // metadata-authoring prefix, so production refuses writes
                // outside a break-glass window.
                crate::changeset::routes::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // Solution 7 (D-785, design §5, §7): applying changesets —
                // plan / apply / adopt / ledger — next to the bundle routes,
                // under the `/admin/metadata` prefix the authoring gate
                // exempts (applying reviewed changesets is how production
                // metadata changes). `system.admin`-gated.
                crate::changeset::apply_routes::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(crate::admin::routes().layer(middleware::from_fn_with_state(
                self.state.clone(),
                attome_security::strict_authz::strict_authz,
            )))
            .merge(
                // M02/D-412 — `/api/v1/admin/settings` (Admin) +
                // `/api/v1/settings/me` (SelfService) share one bundle/layer,
                // same shape `crate::sidebar::routes()` uses for its mix of
                // admin and self-service routes below.
                crate::settings_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M95/D-430 — `/api/v1/admin/features` (Admin) +
                // `/api/v1/features` (SelfService) share one bundle/layer,
                // same shape as the settings bundle immediately above (its
                // stored values are, after all, `setting` rows too).
                crate::features_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::schema::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M18 Data Catalog Phase 1 (D-466) — same admin-gated shape
                // as `schema::routes()` immediately above, the closest
                // sibling read surface this builds on.
                crate::catalog_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::sidebar::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // Dashboard 10/10 Phase 6 — core, always-on aggregation
                // route over every registered `MyWorkProvider`, same
                // "authenticated-only, admin-gated middleware wraps it, the
                // handler itself narrows by caller" posture as `sidebar`
                // immediately above; not `license_gate`-wrapped since a
                // caller with no providers registered simply sees nothing,
                // same as an empty sidebar.
                crate::my_work::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(license_gate(
                attome_records::entity_crud::routes(),
                self.state.modules.clone(),
                MODULE_CORE,
                "core",
            ))
            .merge(license_gate(
                attome_records::bulk::routes(),
                self.state.modules.clone(),
                MODULE_CORE,
                "core",
            ))
            .merge(license_gate(
                // M12 — record export, same `{entity}`-scoped shape as
                // `bulk::routes()` immediately above.
                crate::data_export::routes(),
                self.state.modules.clone(),
                MODULE_CORE,
                "core",
            ))
            .merge(license_gate(
                // M12 — in-place bulk field transform, same shape.
                crate::bulk_transform::routes(),
                self.state.modules.clone(),
                MODULE_CORE,
                "core",
            ))
            .merge(license_gate(
                attome_content::admin::routes(),
                self.state.modules.clone(),
                MODULE_CONTENT,
                "content",
            ))
            .merge(license_gate(
                attome_content::space_admin::routes(),
                self.state.modules.clone(),
                MODULE_CONTENT,
                "content",
            ))
            .merge(license_gate(
                attome_content::template_admin::routes(),
                self.state.modules.clone(),
                MODULE_CONTENT,
                "content",
            ))
            // Public, anonymous page-view route — deliberately NOT wrapped
            // by `license_gate` (it does its own manual check, see that
            // handler's doc) and reachable at authn/authz time only because
            // its path is one of `bypass.rs`'s `EXACT_BYPASS_PATHS`.
            .merge(crate::content_public::routes())
            // Self-service portal (M70, D-423) — same "public, own manual
            // license check, bypass-listed" shape as content_public above.
            .merge(crate::service_public::routes())
            // Consent Management (M24, D-428) public capture endpoint — same
            // bypass-listed shape as content_public/service_public above,
            // except it does no manual license check of its own: this
            // crate's other admin bundles below aren't license-gated either
            // (pre-existing, not something this change introduces — see
            // `attome_compliance`'s own crate doc comment).
            .merge(attome_compliance::consent_admin::public_routes())
            // D16-T1: email open and click tracking, public by path shape.
            .merge(attome_notification::tracking::public_routes())
            // J4-T1: SMS delivery receipts (the token is the authority).
            .merge(attome_integration::sms::public_routes())
            // E10-T1: marketing form submissions (own license check, rate
            // limits and challenge; bypass by path shape).
            .merge(attome_marketing::forms::public_routes())
            // E14-T4: the website tracking script (own licence and flag
            // checks; an exact bypass path).
            .merge(attome_marketing::tracking_script::public_routes())
            // D-486 — M55 moved to `attome-document`. `files::routes()` stays
            // mounted HERE, ungated, because it serves
            // `/api/v1/{entity}/{id}/files/{field}/…` for a `file`-typed
            // attribute on ANY entity: gating the generic file-field path on
            // a paid bit would break `file` fields on a core-only licence.
            // `documents_tree::routes()` is the part that IS the module and
            // is mounted through `ModelRegistry` by `DocumentModel` instead,
            // gated on MODULE_DOCUMENT — see `attome_document`'s crate doc.
            .merge(attome_document::files::routes())
            // K1-T1: share links, and their public download routes.
            .merge(attome_document::share::routes())
            // K1-T2: check-out and check-in of a record's file.
            .merge(attome_document::checkout::routes())
            // N22-T2: a recording's transcript, and asking for one.
            .merge(attome_document::transcribe::routes())
            // M52 Phase 1 (D-465) — outbound compose/reply. No
            // `strict_authz` layer: authorization is per-record via
            // `RecordScoped<Update>` + `require_record_access`, same posture
            // as `files::routes()` just above.
            .merge(crate::communication::routes())
            .merge(attome_notification::admin::routes())
            .merge(
                // D-365
                crate::webcrawl_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                attome_s2s::admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M62 Phase 1 (D-403): license-gated on MODULE_INTEGRATION,
                // same shape as the S2S admin bundle just above (its own
                // infrastructure tables, not an EngineModel/provisioned-entity
                // engine) plus the same strict_authz freshness re-check every
                // other admin-gated bundle in this list gets.
                license_gate(
                    attome_events::admin::routes(),
                    self.state.modules.clone(),
                    MODULE_INTEGRATION,
                    "integration",
                )
                .layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M19 gap list — SIEM search/export over the audit ledger,
                // same shape as the M62 bundle just above (own
                // infrastructure/registered-entity tables, admin-only reads,
                // not a mutating EngineModel).
                license_gate(
                    attome_audit::admin::routes(),
                    self.state.modules.clone(),
                    MODULE_AUDIT,
                    "audit",
                )
                .layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // audit-10-10 Phase 6.1-6.3 — self-service record history and
                // my-activity. No `strict_authz` layer: authorization is
                // per-record via `require_record_access` (history) or a
                // per-row check (my activity), same posture as
                // `communication::routes()` just below.
                license_gate(
                    crate::audit_read::routes(),
                    self.state.modules.clone(),
                    MODULE_AUDIT,
                    "audit",
                ),
            )
            .merge(attome_compliance::erasure_admin::routes().layer(
                middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                ),
            ))
            .merge(attome_compliance::retention_admin::routes().layer(
                middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                ),
            ))
            .merge(
                // P-data-protection-governance
                attome_compliance::dsr_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // P-data-protection-governance
                attome_compliance::legal_hold_admin::routes().layer(
                    middleware::from_fn_with_state(
                        self.state.clone(),
                        attome_security::strict_authz::strict_authz,
                    ),
                ),
            )
            .merge(
                // M23 Records Management (D-456) — archive disposition
                // admin surface (list + restore).
                attome_compliance::archive_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M23 Records Management (D-456) — legal discovery
                // (collect/release) and the records posture report. Ordinary
                // reads/creates of a matter go through the generic
                // /api/v1/audit_legal_matter route (entity_crud::routes(),
                // merged elsewhere), same split consent_admin uses.
                attome_compliance::legal_matter_admin::routes().layer(
                    middleware::from_fn_with_state(
                        self.state.clone(),
                        attome_security::strict_authz::strict_authz,
                    ),
                ),
            )
            .merge(
                // M15 (Data Governance, D-413)
                attome_compliance::governance_admin::routes().layer(
                    middleware::from_fn_with_state(
                        self.state.clone(),
                        attome_security::strict_authz::strict_authz,
                    ),
                ),
            )
            .merge(
                attome_compliance::rewrap_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // Z1-T7: node starts and their configuration fingerprints.
                attome_compliance::config_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M24 (D-428) — /api/v1/consents/withdraw. Ordinary reads and
                // an authenticated create of a `granted` row already work
                // through the generic /api/v1/audit_consent entity route
                // (`entity_crud::routes()`, merged elsewhere); this is only
                // the append-only withdrawal workflow the generic engine
                // can't express.
                attome_compliance::consent_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::jobs_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::email_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::license_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // D-195 / P-four-eyes-approval
                crate::approval_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // D-421 / M10 (Approval & Governance)
                crate::approval_policy_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // D-442 / M58 Phase 1 (Digital Signature, internal sign-off)
                // — license-gated on MODULE_AUDIT per the module plan, same
                // shape as the M62/attome_events bundle above (own infra table,
                // not a provisioned-entity engine) plus the same strict_authz
                // freshness re-check every other admin-gated bundle here
                // gets.
                license_gate(
                    crate::signoff::routes(),
                    self.state.modules.clone(),
                    MODULE_AUDIT,
                    "audit",
                )
                .layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                crate::profiler_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M12 — the shared field-mapping model admin surface.
                crate::data_mapping_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M12 — data profiling admin surface.
                crate::data_profile_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M17 (data migration, D-433) — migration project/run admin
                // surface, built on top of M12's mapping model and staged
                // import.
                crate::migration::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // D-432 / M13 — match-rule/survivorship-rule admin CRUD and
                // the duplicate-candidate steward queue. Bundles the
                // record-scoped "possible duplicate" banner lookup alongside
                // the Admin-gated routes, same mixed-privilege-under-one-
                // layer shape `settings_admin::routes()` already uses.
                crate::duplicates_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M01 Core P3 gap (D-455) — `relationship_info`
                // admin CRUD, same posture as `duplicates_admin` immediately
                // above: `system.admin` only, no separate license gate (the
                // record-level `/related/{relationship}` routes this feeds
                // are already MODULE_CORE-gated through `entity_crud::routes()`).
                crate::relationship_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                attome_security::admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M61 Phase 1 (API Management, D-438) — the api-usage
                // rollup summary. Aggregate counts only, but still
                // system.admin-gated like every other admin surface here.
                crate::api_usage_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M89 Change Intelligence, item 1 — the unified change feed.
                // Read-only aggregation over already-audited data, still
                // system.admin-gated like every other admin surface here.
                crate::changes_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(
                // M14 Phase 1 (Data Quality) — the quality score/issue read
                // surface, same posture as `duplicates_admin`/
                // `api_usage_admin` immediately above.
                crate::quality_admin::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
            )
            .merge(license_gate(
                // M53 Phase 1 (Omnichannel, web chat only, D-474) — per-channel
                // metrics (M27). Both `license_gate` (hidden on an unlicensed
                // deployment) and `strict_authz` (admin-only), same double
                // protection every other admin surface in this block takes.
                crate::omnichannel_metrics::routes().layer(middleware::from_fn_with_state(
                    self.state.clone(),
                    attome_security::strict_authz::strict_authz,
                )),
                self.state.modules.clone(),
                MODULE_OMNICHANNEL,
                "omnichannel",
            ))
            .merge(attome_security::api_keys::routes())
            .merge(attome_security::mfa::routes());

        let router = attome_server::health_routes()
            // NOTE: pure liveness (`GET /health`) is NOT merged here — it's
            // mounted separately via `ServerBuilder::with_liveness_routes`
            // in main.rs so it skips the Redis-dependent pre-auth rate
            // limiter (see `attome_server::liveness_routes`'s doc comment).
            // `/health/ready` (above, via health_routes) is unauthenticated
            // but deliberately DOES depend on Redis/DB; `/health/dependencies`
            // (below) is for administrators (U9-T2) and probes storage, jobs,
            // email and audit; see system_health.rs's module doc.
            .merge(crate::system_health::routes())
            .merge(crate::autonumber_admin::routes())
            .merge(authed)
            .with_state(self.state);
        attome_server::RouteBundle::new(router)
    }
}

/// Applies the S2S HMAC authn layer (Plan 1.3 assembly). Kept as a free function
/// (not a method) so it can be called with just a cloned `base_state`, after
/// `core_routes(self)` has already consumed the `EngineSystem` — and so
/// `attome-website` never needs to depend on `attome-s2s` directly; it stays an
/// implementation detail of `attome-api`.
///
/// Must sit between `apply_inner_layers` (authn/authz/RateLimit/Idempotency,
/// which need `SessionClaims`) and `apply_outer_layers` (RequestId..BodyLimit) —
/// call it after the former and before the latter in the assembly sequence.
pub fn apply_s2s_layer(router: Router, base_state: attome_server::AppState) -> Router {
    router.layer(middleware::from_fn_with_state(
        base_state,
        attome_s2s::middleware::s2s_authn,
    ))
}

// ── EngineSystemBuilder ──────────────────────────────────────────────────────────

impl EngineSystemBuilder {
    /// Swap the no-op notification backend for a real provider (email, SMS, etc.)
    pub fn notifications(mut self, svc: Arc<dyn NotificationService>) -> Self {
        self.notifications = svc;
        self
    }

    /// Register an additional XRM model. Its routes are mounted at startup and
    /// gated by the live license on every request.
    pub fn register(mut self, model: impl EngineModel + 'static) -> Self {
        self.registry = self.registry.register(model);
        self
    }

    /// Dashboard 10/10 Phase 6 — register a `MyWorkProvider` so its items are
    /// listed by `GET /api/v1/my-work/*`. Unlike `register` above this has no
    /// license gate of its own: each provider consults whatever license/
    /// authorization check its own owning engine already applies (e.g.
    /// `ApprovalsMyWorkProvider` only ever surfaces what
    /// `attome_approval`/`attome_audit::approval` already say this caller may
    /// decide).
    pub fn register_my_work_provider(mut self, provider: impl MyWorkProvider + 'static) -> Self {
        self.my_work_providers.push(Box::new(provider));
        self
    }

    /// C5 (chatbot plan) — register the one `WorkflowStarter`, the seam
    /// `attome-ai`'s `workflow.start` starts a published workflow through
    /// without depending on `attome-workflow` (`attome_core::workflow_start`).
    /// A single slot, not a list: there is one start path. Like
    /// `register_my_work_provider` this carries no licence gate of its own —
    /// the caller checks `MODULE_WORKFLOW` and the admin boundary before
    /// starting anything.
    pub fn register_workflow_starter(
        mut self,
        starter: impl attome_core::WorkflowStarter + 'static,
    ) -> Self {
        self.workflow_starter = Some(Arc::new(starter));
        self
    }

    /// E8-T1 — adds an engine's workflow step handler, keyed by its node
    /// key. A second handler for one key is a programming error found at
    /// boot.
    ///
    /// # Panics
    ///
    /// When a handler for the same key is already registered.
    pub fn register_workflow_step_handler(
        mut self,
        handler: impl attome_core::workflow_step::WorkflowStepHandler + 'static,
    ) -> Self {
        let key = handler.key();
        insert_once(
            &mut self.workflow_step_handlers,
            key,
            Arc::new(handler),
            "workflow step handler",
        );
        self
    }

    /// E8-T1 — adds a workflow kind guard, keyed by its kind.
    ///
    /// # Panics
    ///
    /// When a guard for the same kind is already registered.
    pub fn register_workflow_kind_guard(
        mut self,
        guard: impl attome_core::workflow_step::WorkflowKindGuard + 'static,
    ) -> Self {
        let kind = guard.kind();
        insert_once(
            &mut self.workflow_kind_guards,
            kind,
            Arc::new(guard),
            "workflow kind guard",
        );
        self
    }

    /// Loads the module configuration (D-778), wires services into state, and
    /// spawns the background hourly module-configuration reload.
    pub async fn build(self) -> Result<EngineSystem, Box<dyn std::error::Error>> {
        let mut state = self.state;
        state.notifications = self.notifications;
        // D-383 — freeze the entity->owning-engine map from the models
        // registered by now, before anything can serve a request. Read-only
        // afterwards, so no arc-swap: `register()` is a builder method and
        // cannot run past this point.
        state.entity_modules = std::sync::Arc::new(self.registry.entity_modules());
        // R-03 — same freeze-at-boot lifecycle as `entity_modules` right
        // above, and for the same reason: compile-time data, rebuilt
        // identically on every node, so no arc-swap needed.
        state.engine_managed_fields = std::sync::Arc::new(self.registry.engine_managed_fields());
        // D-524 — the create-time allowance for those same fields, frozen the
        // same way.
        state.engine_managed_initial_values =
            std::sync::Arc::new(self.registry.engine_managed_initial_values());
        // D-535 — same freeze-at-boot lifecycle: the entities only their
        // owning engine may create, change or restore.
        state.engine_owned_entities = std::sync::Arc::new(self.registry.engine_owned_entities());
        // Dashboard 10/10 Phase 2.1 — model-declared write validators, frozen
        // the same way.
        state.record_validators = std::sync::Arc::new(self.registry.record_validators());
        // Dashboard 10/10 Phase 6 — registered `MyWorkProvider`s, frozen the
        // same way: `register_my_work_provider` is a builder method and
        // cannot run past this point either.
        state.my_work_providers = std::sync::Arc::new(self.my_work_providers);
        // C5 — the registered `WorkflowStarter`, frozen the same way.
        state.workflow_starter = self.workflow_starter;
        // E8-T1 — the registered step handlers and kind guards, frozen the
        // same way.
        state.workflow_step_handlers = std::sync::Arc::new(self.workflow_step_handlers);
        state.workflow_kind_guards = std::sync::Arc::new(self.workflow_kind_guards);

        // Loaded here, ahead of the platform-bundle applies below, not in its
        // original later position (next to the audit-signer/security-resolver
        // wiring): `apply_platform_bundle` checks each bundle's
        // `requires.modules` against `state.modules.load_full()` (D-478), and
        // `EngineState::new` seeds that field with `ModuleSet::core_only()`
        // (zero module bits) until this runs. With the load left later, every
        // platform bundle's `requires.modules: ["core"]` (or any other
        // module) saw the degraded license and was unconditionally `Blocked:
        // module 'X' is not included in this deployment's license` — on
        // every boot, not just a stale/mismatched one. Moving the load here
        // costs nothing: it only reads `module_configuration`/
        // `license`, both infra tables migrations already created,
        // with no dependency on the entity seeding this precedes.
        let license = load_license(&state.base.db).await;
        state.modules = Arc::new(ArcSwap::from_pointee(license));

        // Self-register system entities — idempotent, safe on every startup.
        // P-db-privilege-separation / D-117: boot seeding is schema-adjacent
        // work (ensure_entity/ensure_attribute DDL, plus the infra-table rows
        // that go with them), same category as admin.rs — runs on
        // `db_migrator`, not `db`.
        // D-478 (seeds-to-bundles) — replaces attome_audit::seed::seed, proven
        // a pure no-op against the old seed's output by
        // attome-api/tests/platform_bundle_apply.rs.
        crate::changeset::boot::apply_platform_definition(&state, "attome-audit").await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478) — pilot
        // conversion. `platform-bundles/attome-s2s.json` replaces
        // `attome_s2s::seed::seed`'s imperative provisioning calls; proven a
        // pure no-op against the old seed's output by
        // `attome-api/tests/platform_bundle_apply.rs` before this swap.
        crate::changeset::boot::apply_platform_definition(&state, "attome-s2s").await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478).
        crate::changeset::boot::apply_platform_definition(&state, "attome-notification").await?;
        // D-478 (seeds-to-bundles, second pass): `platform-bundles/
        // attome-metadata-autovalue.json` replaces `attome_metadata::autovalue::seed`,
        // same `attome-metadata-autovalue` watermark key; proven a pure no-op
        // against the old seed by `tests/platform_bundle_apply.rs` first.
        crate::changeset::boot::apply_platform_definition(&state, "attome-metadata-autovalue")
            .await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478). The static
        // half of what used to be `attome_security::seed::register_readonly_
        // entities` (organization/team/user/role/privilege entities,
        // attributes, queries, views, and both `privilege` rows)
        // applies from here, not from inside `attome-security` itself — that
        // crate sits below `attome-api` in the dependency graph, so it cannot
        // call `apply_platform_bundle` without creating a cycle. Nothing runs
        // after it for this crate: `attome_security::seed::seed` is gone, its two
        // `ensure_privilege` calls having been duplicates of what this bundle
        // declares, and its bootstrap-admin grant now belonging to
        // `server --bootstrap-admin <email>` (D-128) rather than to boot.
        crate::changeset::boot::apply_platform_definition(&state, "attome-security").await?;
        // D-365 — Web Crawling for Knowledge Base. Also (idempotently) seeds
        // D-363's knowledge_data_source/knowledge_data_item, which
        // previously had no seed() at all (see that module's doc comment).
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478).
        crate::changeset::boot::apply_platform_definition(&state, "attome-webcrawl").await?;
        // D-364's `attome_document`, which likewise had no seed() — the Documents
        // tab and the system-wide Documents page 500'd on every fresh
        // deployment because `/api/v1/documents/tree` selects straight from a
        // table nothing created (see that module's doc comment).
        //
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — see the attome-s2s
        // conversion's comment above for the pattern this follows. Proven a
        // pure no-op against the old seed's output by
        // `attome-api/tests/platform_bundle_apply.rs`.
        crate::changeset::boot::apply_platform_definition(&state, "attome-document").await?;
        // Same gap as D-363/D-364, found during the view-seeding audit: the
        // Notes tab (`note`) and Communications panel (`communication`)
        // are wired into every entity form but had no backend provisioning at
        // all — not even a one-off admin-API-created table. See each module's
        // own doc comment.
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — see the attome-s2s
        // conversion's comment above for the pattern this follows.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-note").await?;
        // Basic-units U2 (D-600): `activity`, the platform's task and
        // phone-call entity, plus its seeded open/completed/cancelled state
        // model. Polymorphic like `note` (text `entity_name` +
        // `record_id`, B-R2), so it is on D-593's
        // `POLYMORPHIC_CHILD_ENTITIES` list. No lookups, so no ordering
        // dependency; grouped with the note bundle it mirrors.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-activity").await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — bundle-converted;
        // see the attome-s2s conversion's comment above. `communication`'s
        // `thread_id`/`in_reply_to` are self-referencing lookups, resolved
        // by logical name at apply time same as any other lookup — no
        // ordering trick needed the way the raw `ensure_attribute` call
        // needed its own freshly-created `id`.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-communication")
            .await?;
        // M52 Phase 1 (D-465) — delivery-status timeline child entity; must
        // run after the communication bundle just above (its
        // `communication_id` lookup targets `communication` by logical
        // name, which must already be live). See
        // communication_event_seed.rs's original doc comment for why.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-communication-event")
            .await?;
        // M18 Data Catalog Phase 1 (D-466) — glossary_term. No dependency
        // on any prior seed's entity ids (`domain_ref` is plain text, not a
        // `lookup` — see `glossary_seed`'s original doc comment), same
        // placement reasoning as document/note/communication above.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-glossary").await?;
        // Generic cross-engine primitives (2026-08-25) — a two-sided
        // polymorphic link, a follow/watch row, and a person's skills/leave.
        // Same reasoning as document/note/communication above: more than one
        // engine wants each of these, so none of them is owned by whichever
        // engine happened to ask first. See each module's own doc comment.
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — bundle-converted;
        // `created_by`'s lookup to `user_account` is resolved by
        // logical name at apply time, same as any other lookup.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-relationship")
            .await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — bundle-converted;
        // see the attome-s2s conversion's comment above.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-follow").await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — bundle-converted;
        // both entities' `user_id` lookup to `user_account` is
        // resolved by logical name at apply time.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-resource").await?;
        // Tagging (`tag_category`/`tag_item`) — same generic
        // cross-engine grouping as the primitives above; see tag_seed's own
        // module doc.
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — bundle-converted;
        // `category_id`'s lookup to `tag_category` is resolved by
        // logical name at apply time. `retire_legacy_name` is the one piece
        // of the old seed body that isn't pure metadata (a one-time
        // historical cleanup, not steady-state provisioning) and so stays a
        // small residual function — see its own doc comment. Must run after
        // the bundle above: it looks up `tag_item`'s entity id, which
        // only exists once the bundle has applied.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-tag").await?;
        crate::tag_seed::retire_legacy_name(&state.base.db_migrator).await?;
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles) — see the attome-s2s
        // conversion's comment above for the pattern this follows.
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-license").await?;
        // D-602 (basic-units U4) — `reminder`. After attome-security: its
        // `user_ref` lookup targets `user_account` by logical name.
        // Delivered by the notification poller (`attome_notification::reminders`).
        crate::changeset::boot::apply_platform_definition(&state, "xrm-reminder").await?;
        // Consent Management (M24, D-428) — audit_consent_purpose/audit_consent.
        // No dependency on any prior seed's entity ids (both fields that
        // point elsewhere, `regarding_entity`/`regarding_id`, are plain
        // text, not `lookup` — see `consent_seed`'s own doc comment), so
        // placement here (after security, alongside the other generic
        // cross-engine primitives) is only for grouping, not correctness.
        // D-478 (seeds-to-bundles) — replaces attome_compliance::consent_seed::seed.
        crate::changeset::boot::apply_platform_definition(&state, "attome-compliance-consent")
            .await?;
        // Records Management (M23, D-456) — audit_legal_matter. Same
        // "no dependency on any prior seed's entity ids" placement reasoning
        // as consent above (`custodian`/`scope_entity` are plain text, not
        // `lookup`s — see `legal_matter_seed`'s own doc comment).
        // D-478 (seeds-to-bundles) — replaces attome_compliance::legal_matter_seed::seed.
        crate::changeset::boot::apply_platform_definition(&state, "attome-compliance-legal-matter")
            .await?;
        // Project Management (attome-project) — REVIEW-2026-09-02 item 11
        // (seeds-to-bundles, D-478): `platform-bundles/attome-project.json`
        // replaces `attome_project::seed::seed`'s ~2,100 lines of imperative
        // `ensure_entity`/`ensure_attribute`/`ensure_entity_list_views`
        // calls, proven a pure no-op against the old seed's output by
        // `attome-api/tests/platform_bundle_apply.rs`. Still must run here,
        // after `attome_security::seed::seed` above: several entities
        // (`attome_project`, `project_issue`, `project_work_item`)
        // carry an owner/user lookup to `user_account`, resolved by
        // logicalname at apply time, and that entity's `entity_
        // info` row only exists once the `attome_security::seed::seed` call
        // above has run.
        crate::changeset::boot::apply_platform_definition(&state, "attome-project").await?;
        // The one piece of `attome_project::seed`'s old body that isn't pure
        // metadata: `attome_project::utilization`'s code-seeded report query
        // needs `resource_allocation`'s live entity id, which only
        // exists once the bundle above has applied — resolved by
        // logicalname, same as the old code did, just from a smaller
        // residual function instead of the full seed body. Also the one
        // query D-478's second pass could NOT move into the bundle: its SQL
        // has a scalar subquery, which `reject_unsafe_default_query_sql`'s
        // single-`FROM` rule refuses on the bundle path.
        attome_project::seed::seed_utilization(&state.base.db_migrator).await?;
        // Work Intake & Service Management (attome-service) — after
        // attome-project's own seed: `service_ticket.linked_project_id` looks up
        // `attome_project`'s entity id, which only exists once the call above
        // has run. See `attome_service::seed`'s own module doc.
        crate::changeset::boot::apply_platform_definition(&state, "attome-service").await?;
        // Web portals (attome-portal, D-576): `webportal` and
        // `webportal_user`. After `attome_security`'s seed, because
        // `owning_team_ref` looks up `team`. `requires.modules` is
        // `core` only, never `portal`: a bundle that requires a module the
        // licence lacks blocks boot, and licences issued before module 31
        // existed do not carry it. Access stays gated by `PortalModel`'s
        // `owned_entities` (D-383) and route mounting (D-010).
        crate::changeset::boot::apply_platform_definition(&state, "attome-portal").await?;
        // (D-478 second pass: `analytics_seed`/`queue_analytics_seed`'s report
        // queries and the built-in `service_ticket` state model are all
        // in `attome-service.json` now — `queries[]` with `is_report`, and
        // `state_models[]`, reconciled through the same
        // `attome_state::reconcile::reconcile_state_model` the old
        // `seed_state_models` call used. Nothing residual remains here.)
        // Governance, Risk & Compliance (attome-grc), Phase 1 (M20-grc.md, D-427)
        // — must run after attome-project's own seed above: it adds an additive
        // `risk_ref` lookup attribute onto the already-existing
        // `project_issue` entity (the risk generalization), which needs
        // that entity already registered. REVIEW-2026-09-02 item 11
        // (seeds-to-bundles): `platform-bundles/attome-grc.json` replaces the
        // old imperative seed, verified a pure no-op against it (including
        // the cross-entity `risk_ref` patch) by
        // `attome-api/tests/platform_bundle_apply.rs`.
        crate::changeset::boot::apply_platform_definition(&state, "attome-grc").await?;
        // Decision Intelligence Platform (attome-dashboard), Phase 1 only —
        // dashboard CRUD + lifecycle, no pages/sections/widgets/query engine
        // yet (document/XRM-Dashboard-Module.md). Same ordering reason as
        // attome-project/attome-service above: `owner_id`/`organization_id` look up
        // `user_account`/`organization`, both only registered
        // by the `attome_security::seed::seed` call earlier in this function.
        // Doesn't need to run after attome-project/attome-service (no cross-entity
        // lookup between them), placed here only to keep every engine seed
        // call in one block.
        // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478) — the 8
        // entities `attome_dashboard::seed` used to provision imperatively
        // (dashboard/version/page/section/breakpoint/widget/variable/
        // parameter) live in `attome-dashboard.json`, and since D-478's second
        // pass so do the 7 decision/scenario entities `decision_seed`/
        // `scenario_seed` used to provision; `attome_metric::metric::seed`'s two
        // entities are `attome-metric.json`, applied first because the
        // decision/scenario lookups onto `dashboard_metric_definition`
        // resolve by logicalname at apply time. Both proven a pure no-op
        // against the old code by `attome-api/tests/platform_bundle_apply.rs`.
        // `attome_dashboard::seed::seed` below still runs after: it re-syncs
        // `widget_type`'s choice list from the live widget registry, which
        // no static bundle can own.
        crate::changeset::boot::apply_platform_definition(&state, "attome-metric").await?;
        crate::changeset::boot::apply_platform_definition(&state, "attome-dashboard").await?;
        attome_dashboard::seed::seed(&state.base.db_migrator).await?;
        // `profiler_finding` — the persisted configuration-cost ledger
        // (PROFILER-2026-09-09.md group G, #80/#86). No cross-entity lookup
        // onto anything provisioned above, so it has no ordering dependency;
        // placed here only to keep every entity-registering seed call in one
        // block, before `entity_privileges::seed_all` below picks it up.
        // D-478 second pass: `platform-bundles/attome-api-profiler-finding.json`
        // replaces `profiler_finding_seed::seed` (which carried no watermark
        // of its own; this key is new).
        crate::changeset::boot::apply_platform_definition(&state, "attome-api-profiler-finding")
            .await?;
        // M11 Search gap list — `saved_search`'s seed runs from
        // `crates/server/src/boot.rs`, BEFORE this `.build()` call, not here:
        // `attome-api`'s dependency on `attome-search` is dev-only (Cargo.toml,
        // `tests/license_gating.rs`'s edge), so this crate has no real
        // compile-time access to `attome_search::`. Same shape as the
        // `attome-ai-quality`/`attome-ai-model-catalog` platform-bundle applies,
        // made from `boot.rs` for the identical reason. `saved_search`
        // has no lookup attribute onto `user_account` (unlike xrm-
        // project/attome-service/attome-dashboard above), so it has no ordering
        // dependency on anything `.build()` does either.
        // AFTER every entity-registering seed above, not in the middle of
        // them: `seed_all` iterates whatever is registered in
        // `entity_info` *at the moment it runs* and mints the five
        // `{logicalname}.{read,create,update,delete,bulk}` privilege rows for
        // each.
        // It used to sit above the webcrawl/document/license seeds, so on a
        // genuinely fresh database those entities registered too late to be
        // seen and picked up their privileges only on the *second* boot —
        // invisible on a long-lived database (every boot after the first
        // fixes the previous one's stragglers) and exactly the kind of
        // first-boot-only gap a fresh-database check is for. Nothing between
        // here and there reads privileges, so the move is safe; idempotent
        // either way.
        attome_security::entity_privileges::seed_all(&state.base.db_migrator).await?;
        crate::sidebar_seed::seed(&state.base.db_migrator).await?;
        attome_s2s::db::warn_unbounded_clients(&state.base.db).await;

        // P-stored-query-containment phase 1(a) / D-126: re-grant
        // attome_readonly SELECT on every currently-registered entity table
        // on every boot — migration 0046 revoked the blanket grant, and the
        // seed calls above only re-provision their own fixed set of system
        // entities, not every admin-authored custom entity that exists by
        // now. Idempotent; a no-op once every entity's grant is current.
        attome_metadata::provision::backfill_readonly_grants(&state.base.db_migrator).await?;
        // Same "after every entity-registering seed" placement: the RLS
        // predicate's columns on tables registered before their backfill
        // existed (a non-admin read of one 500s without them).
        attome_metadata::provision::backfill_rls_columns(&state.base.db_migrator).await?;

        // D-372 UI grouping follow-up: gives every entity registered by now a
        // sensible default `category` (Role form's Privilege Grants tab)
        // instead of leaving it "Uncategorized" until an admin manually tags
        // dozens of entities by hand. Same "after every entity-registering
        // seed" placement as the readonly-grant backfill above, for the same
        // reason — newly-registered entities need to exist first. Never
        // overwrites an admin-set category (WHERE category IS NULL only).
        attome_metadata::provision::backfill_entity_category(&state.base.db_migrator).await?;

        // P-key-rotation-and-jwt (e): boot canary for every configured
        // envelope-encryption ring — a self-encrypt/decrypt round trip that
        // fails the whole boot (D-038 fail-closed) if a key is malformed
        // (bad hex, wrong length), rather than surfacing as a runtime 500 on
        // whichever request first happens to touch that domain. The erasure
        // ring's canary already ran synchronously inside `EngineState::new`
        // (it's needed there regardless, to construct `audit_erasure_key`);
        // these two are the domains with no other eager construction point.
        if state.base.config.s2s.enabled {
            attome_auth::envelope::canary(
                "s2s.key_encryption_key",
                &state.base.secrets.load().s2s_key_encryption_key,
            )?;
        }
        // D-771: config-declared S2S clients, after the canary so a bad ring
        // fails the boot before anything is sealed with it.
        attome_s2s::config_clients::reconcile(&state).await?;
        if state.base.config.auth.mfa_policy != "off" {
            attome_auth::envelope::canary(
                "auth.mfa_encryption_key",
                &state.base.secrets.load().mfa_encryption_key,
            )?;
        }

        // P-key-rotation-and-jwt (d): registers this deployment's currently
        // configured audit-signing keypair's public key in
        // `audit_signing_key` (insert-if-absent; a mismatched public key
        // for an already-registered key_id is a fail-closed boot error, see
        // `upsert_signing_key`'s doc). Plain DML against an already-migrated
        // infra table — the ordinary runtime pool, not `db_migrator`.
        if let Some(signer) = &state.audit_signer {
            attome_core::audit_signing::upsert_signing_key(
                &state.base.db,
                &signer.key_id,
                &signer.verifying_key_b64(),
            )
            .await?;
        }

        // Replace the fail-closed DenyAllResolver with the real attome-security
        // resolver now that the bootstrap-admin seed has run.
        let security_resolver = std::sync::Arc::new(attome_security::EngineSecurityResolver::new(
            state.base.db.clone(),
            state.base.redis.clone(),
            state.base.redis_coordination.clone(),
            state.base.config.security.strict_revocation,
        ));
        // Kept alongside the type-erased copy `.store()`d below — the
        // security_version subscriber (further down) needs the concrete type
        // to call `invalidate_local`, which isn't part of the `SecurityResolver`
        // trait object `state.base.security` holds.
        let security_resolver_concrete = security_resolver.clone();
        state.base.security.store(security_resolver);

        // Hourly reload — fully re-verifies from license every tick
        // (rather than only checking expiry against the cached value), so
        // any replica self-heals to the latest imported license within a
        // bounded window without needing a dedicated pub/sub channel.
        let license_arc = state.modules.clone();
        let db_bg = state.base.db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                // D-778: re-reads the module configuration; no licence check.
                let fresh = load_license(&db_bg).await;
                license_arc.store(Arc::new(fresh));
            }
        });

        // ── Metadata registry pre-warm + Redis pub/sub invalidation (Plan 1.2,
        // incremental catch-up Plan 1.14) ──
        // Fail startup rather than serve a half-ready node if the first build
        // is slow or errors out (guidelines §14.4: 10s pre-warm budget). The
        // common case is now one Redis GET (a snapshot) + a small incremental
        // catch-up, not a full database rebuild — see `full_rebuild`/
        // `catch_up` below.
        let (registry, last_id) = tokio::time::timeout(
            Duration::from_secs(10),
            pre_warm_registry(&state.base.db, &state.base.redis),
        )
        .await??;
        state.entities.swap(registry);
        // Y8-T7: the same counter the response header reads.
        let last_applied = state.base.metadata_version.clone();
        last_applied.store(last_id, Ordering::Release);

        // M07 Phase 1 (D-406) — state-lifecycle registry pre-warm. Small,
        // admin-authored table (state machines change by human edit, not by
        // request volume), so a full reload is cheap enough that this does
        // not need `EntityMetaRegistry`'s incremental catch-up machinery —
        // see `attome_core::state_registry`'s doc comment.
        let state_models = tokio::time::timeout(
            Duration::from_secs(10),
            attome_core::state_registry::load(&state.base.db),
        )
        .await??;
        state.state_models.swap(state_models);

        // M01 Core P3 gap (D-455) — relationship-metadata registry pre-warm.
        // Same small-admin-authored-table posture as state_models above.
        let relationships = tokio::time::timeout(
            Duration::from_secs(10),
            attome_core::relationship_registry::load(&state.base.db),
        )
        .await??;
        state.relationships.swap(relationships);

        // M45 Phase 2 (D-472) — rule registry pre-warm. Same small-admin-
        // authored-table posture as state_models/relationships above.
        let rules = tokio::time::timeout(
            Duration::from_secs(10),
            attome_core::rule_registry::load(&state.base.db),
        )
        .await??;
        state.rules.swap(rules);

        // AA9-T5: this node's limit-hit tally reaches the database every
        // five minutes.
        attome_server::limit_usage::spawn_flusher(state.base.db.clone());

        // Z3-T7: caches registered for warm start fill their L1 now, within
        // five seconds in all; any the budget cuts off start cold.
        let warmed = attome_cache::tiered::warm_registered(Duration::from_secs(5)).await;
        if warmed > 0 {
            tracing::info!(entries = warmed, "caches warmed at start");
        }

        // Confirmed ready only now that DB + Redis were reachable enough to
        // seed, load the license, and pre-warm the registry.
        state.base.registry_ready.store(true, Ordering::Relaxed);

        // Dedicated subscriber connection — never the request-path pool, so a
        // slow subscriber can't head-of-line-block ordinary command traffic.
        let subscriber =
            attome_cache::Subscriber::connect(&state.base.redis, &state.base.config).await?;

        let debounce_pending = Arc::new(AtomicBool::new(false));
        // Y8-T4: the name this node records its metadata version switches under.
        crate::model_admin::set_node(attome_server::metrics_store::node_name(
            state.base.config.app.port,
        ));

        {
            // C-18: `subscriber` is now shared across every channel this
            // node listens on, not just `META_VERSION_KEY` — filter here so
            // an unrelated doorbell (security_version, a state-model write,
            // …) does not also trigger a metadata catch-up scan.
            let pending = debounce_pending.clone();
            let entities = state.entities.clone();
            let db = state.base.db.clone();
            let redis = state.base.redis.clone();
            let watermark = last_applied.clone();
            subscriber.on_message(move |msg| {
                if msg.channel != META_VERSION_KEY {
                    return;
                }
                spawn_debounced_catch_up(
                    pending.clone(),
                    entities.clone(),
                    db.clone(),
                    redis.clone(),
                    watermark.clone(),
                );
            });
        }
        {
            // Redis pub/sub is fire-and-forget — a missed message is real, so
            // every reconnect re-checks too (this is what actually makes the
            // invalidation safe). Mirrors the license hourly self-heal
            // precedent above rather than trusting the last message.
            let pending = debounce_pending.clone();
            let entities = state.entities.clone();
            let db = state.base.db.clone();
            let redis = state.base.redis.clone();
            let watermark = last_applied.clone();
            subscriber.on_reconnect(move || {
                spawn_debounced_catch_up(
                    pending.clone(),
                    entities.clone(),
                    db.clone(),
                    redis.clone(),
                    watermark.clone(),
                );
            });
        }
        {
            // Y8-T6: the metadata-pin layer reads the change-log watermark
            // and starts this node's catch-up through these.
            let pending = debounce_pending.clone();
            let entities = state.entities.clone();
            let db = state.base.db.clone();
            let redis = state.base.redis.clone();
            let watermark = last_applied.clone();
            let watermark_db = state.base.db.clone();
            attome_server::middleware::metadata_pin::install(
                &state.base,
                attome_server::middleware::metadata_pin::MetadataHooks {
                    watermark: Box::new(
                        move || -> attome_server::middleware::metadata_pin::WatermarkFuture {
                            let db = watermark_db.clone();
                            Box::pin(async move { attome_core::log_watermark(&db).await })
                        },
                    ),
                    catch_up: Box::new(move || {
                        spawn_debounced_catch_up(
                            pending.clone(),
                            entities.clone(),
                            db.clone(),
                            redis.clone(),
                            watermark.clone(),
                        );
                    }),
                },
            );
        }
        {
            // Y8-T1: the Postgres doorbell. `append_change_log` rings
            // `METADATA_CHANGE_CHANNEL` in the writer's transaction, so this
            // fires on commit with or without Redis, into the same debounced
            // catch-up. A dropped connection waits a second, reconnects and
            // catches up, since a notice may have been missed meanwhile.
            let pending = debounce_pending.clone();
            let entities = state.entities.clone();
            let db = state.base.db.clone();
            let redis = state.base.redis.clone();
            let watermark = last_applied.clone();
            let config = state.base.config.clone();
            let ring = move || {
                spawn_debounced_catch_up(
                    pending.clone(),
                    entities.clone(),
                    db.clone(),
                    redis.clone(),
                    watermark.clone(),
                );
            };
            tokio::spawn(async move {
                loop {
                    match attome_db::notify::listen(&config, attome_core::METADATA_CHANGE_CHANNEL)
                        .await
                    {
                        Ok(mut listener) => {
                            ring();
                            loop {
                                match listener.try_recv().await {
                                    Ok(Some(_)) => ring(),
                                    Ok(None) => {
                                        tracing::warn!(
                                            "metadata listener: connection lost; reconnecting"
                                        );
                                        break;
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, "metadata listener failed; reconnecting");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "metadata listener could not connect; retrying");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
        {
            // Z3-T9: a cache purge announced by any node (in its audit
            // event's transaction) reaches this one. A dropped connection
            // waits a second and listens again; a purge sent meanwhile is
            // lost here, and the entries live out their TTL.
            let config = state.base.config.clone();
            tokio::spawn(async move {
                loop {
                    match attome_db::notify::listen(
                        &config,
                        crate::profiler_admin::CACHE_PURGE_CHANNEL,
                    )
                    .await
                    {
                        Ok(mut listener) => loop {
                            match listener.try_recv().await {
                                Ok(Some(notification)) => {
                                    crate::profiler_admin::apply_purge(notification.payload())
                                        .await;
                                }
                                Ok(None) => break,
                                Err(error) => {
                                    tracing::warn!(%error, "cache purge listener failed; reconnecting");
                                    break;
                                }
                            }
                        },
                        Err(error) => {
                            tracing::warn!(%error, "cache purge listener could not connect; retrying");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
        {
            // P-metadata-sync-hardening Phase 1 (a): a third trigger into the
            // *same* debounced catch-up entry point as on_message/on_reconnect
            // above — not a parallel mechanism. on_reconnect's comment already
            // notes "a missed message is real" and leans on reconnect to
            // self-heal; this closes the residual gap where a PUBLISH is lost
            // without ever tripping a full reconnect event (e.g. a stalled
            // subscriber task), which would otherwise leave this node's
            // EntityMetaRegistry silently stale until an unrelated future
            // edit happens to arrive. Reads log_watermark independently (not
            // just calling spawn_debounced_catch_up blindly every tick) so
            // the gap can be recorded as a gauge even on the healthy path —
            // staleness becomes an observable signal, not only a silent
            // self-heal.
            let entities = state.entities.clone();
            let db = state.base.db.clone();
            let redis = state.base.redis.clone();
            let watermark = last_applied.clone();
            // Y8-T2: the safety net under the doorbell, `cache.metadata_poll_
            // interval_secs` (default 5). The query is a single indexed
            // `MAX(id)` aggregate, negligible at this interval.
            let poll_secs = state.base.config.cache.metadata_poll_interval_secs.max(1);
            // Y8-T5: behind on two polls in a row reads as not ready.
            let lagging = state.base.metadata_lagging.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(poll_secs));
                interval.tick().await; // consume the immediate first tick — pre_warm_registry already caught up as of boot
                let mut behind_polls: u32 = 0;
                loop {
                    interval.tick().await;
                    // Y8-T4: the safety net for a lost version-switch doorbell.
                    crate::model_admin::follow_cooked(&db).await;
                    let applied = watermark.load(Ordering::Acquire);
                    match attome_core::log_watermark(&db).await {
                        Ok(db_watermark) if db_watermark < applied => {
                            // Impossible under normal operation (the change
                            // log is append-only) — Postgres and Redis have
                            // gone out of sync since this node last applied
                            // (e.g. Postgres restored to an earlier point
                            // independently of Redis). A plain catch-up
                            // can't fix this: `changes_since(db, applied)`
                            // would keep finding nothing since no row will
                            // ever exceed a now-impossibly-high `applied`.
                            // Same fail-loud-then-self-heal posture as
                            // `pre_warm_registry`'s own snapshot check.
                            tracing::error!(
                                applied,
                                db_watermark,
                                "metadata registry watermark poll found the applied watermark \
                                 ahead of the database's own current max id — Postgres/Redis \
                                 are out of sync; forcing a full registry rebuild",
                            );
                            metrics::counter!("registry_watermark_poll_forced_rebuild_total")
                                .increment(1);
                            match full_rebuild(&db, &redis).await {
                                Ok((fresh, fresh_watermark)) => {
                                    entities.swap(fresh);
                                    watermark.store(fresh_watermark, Ordering::Release);
                                    metrics::gauge!("registry_watermark_lag").set(0.0);
                                    behind_polls = 0;
                                    lagging.store(false, Ordering::Relaxed);
                                }
                                Err(e) => tracing::error!(
                                    error = %e,
                                    "metadata registry full rebuild failed after watermark \
                                     inversion — will retry next tick",
                                ),
                            }
                        }
                        Ok(db_watermark) => {
                            let mut lag = db_watermark - applied;
                            if lag > 0 {
                                tracing::warn!(
                                    applied,
                                    db_watermark,
                                    "metadata registry watermark poll found unapplied changes \
                                     the doorbell/reconnect triggers missed — forcing catch-up",
                                );
                                metrics::counter!("registry_watermark_poll_forced_catchup_total")
                                    .increment(1);
                                // Caught up here, then judged: a node still
                                // behind the change log after catching up
                                // (twice in a row) is lagging, not one that
                                // merely saw new changes arrive (a boot or a
                                // publish writes many in a row).
                                catch_up(&entities, &db, &redis, &watermark).await;
                                lag = db_watermark - watermark.load(Ordering::Acquire);
                            }
                            metrics::gauge!("registry_watermark_lag").set(lag.max(0) as f64);
                            behind_polls = if lag > 0 {
                                behind_polls.saturating_add(1)
                            } else {
                                0
                            };
                            lagging.store(behind_polls >= 2, Ordering::Relaxed);
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "metadata registry watermark poll failed to read log_watermark — will retry next tick",
                        ),
                    }
                }
            });
        }

        // ── Runtime settings cache pre-warm + poll (M02, D-412) ──
        // Poll-only, deliberately not pub/sub — see
        // `attome_core::setting_store`'s module doc for the trade-off
        // (small admin-configured table, same shape
        // `module_configuration`'s hourly self-heal already
        // establishes as accepted in this codebase, just at a tighter
        // interval since settings are read on every `/api/v1/settings/me`
        // call rather than only consulted for hourly license gating). The
        // writer's own node refreshes synchronously after commit
        // (`settings_admin::write_setting`), so this loop only needs to
        // catch up *other* nodes.
        {
            let db = state.base.db.clone();
            let settings_snapshot =
                tokio::time::timeout(Duration::from_secs(10), attome_core::load_all_settings(&db))
                    .await??;
            state.settings.swap(settings_snapshot);
            let applied_watermark = Arc::new(AtomicI64::new(
                attome_core::setting_log_watermark(&db).await.unwrap_or(0),
            ));

            let settings = state.settings.clone();
            let watermark = applied_watermark.clone();
            // Never varied per-deployment; not a config knob.
            const SETTINGS_POLL_INTERVAL_SECS: u64 = 20;
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(SETTINGS_POLL_INTERVAL_SECS));
                interval.tick().await; // consume the immediate first tick — pre-warm above already caught up
                loop {
                    interval.tick().await;
                    let applied = watermark.load(Ordering::Acquire);
                    match attome_core::setting_log_watermark(&db).await {
                        Ok(db_watermark) if db_watermark != applied => {
                            match attome_core::load_all_settings(&db).await {
                                Ok(snapshot) => {
                                    settings.swap(snapshot);
                                    watermark.store(db_watermark, Ordering::Release);
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "settings cache reload failed — will retry next tick",
                                ),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "settings watermark poll failed to read setting_log_watermark — will retry next tick",
                        ),
                    }
                }
            });
        }

        // ── Hijri sighting corrections (AG1-T3) ──
        // Same poll-only shape as the settings block above; see
        // `attome_core::hijri_store`'s module doc. The correcting node swaps
        // at once (`calendar_admin::correct_hijri_month`); others within 20 s.
        {
            let db = state.base.db.clone();
            match tokio::time::timeout(
                Duration::from_secs(10),
                attome_core::hijri_store::load_hijri(&db),
            )
            .await
            {
                Ok(Ok(calendar)) => state.hijri.store(Arc::new(calendar)),
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "Hijri corrections not loaded at boot; using the published table")
                }
                Err(_) => tracing::warn!(
                    "Hijri corrections load timed out at boot; using the published table"
                ),
            }
            let hijri = state.hijri.clone();
            tokio::spawn(async move {
                const HIJRI_POLL_INTERVAL_SECS: u64 = 20;
                let mut seen = attome_core::hijri_store::hijri_watermark(&db)
                    .await
                    .ok()
                    .flatten();
                let mut interval =
                    tokio::time::interval(Duration::from_secs(HIJRI_POLL_INTERVAL_SECS));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match attome_core::hijri_store::hijri_watermark(&db).await {
                        Ok(now) if now != seen => {
                            match attome_core::hijri_store::load_hijri(&db).await {
                                Ok(calendar) => {
                                    hijri.store(Arc::new(calendar));
                                    seen = now;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Hijri corrections reload failed; will retry")
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "Hijri corrections poll failed; will retry")
                        }
                    }
                }
            });
        }

        // ── Metadata-label cache pre-warm + poll (M05 Phase 1, D-426) ──
        // Poll-only, same trade-off and same shape as the settings block
        // right above (small admin-configured table, see
        // `attome_core::label_store`'s module doc). The writer's own node
        // refreshes synchronously after commit
        // (`metadata_label_admin::write_label`), so this loop only needs to
        // catch up *other* nodes.
        {
            let db = state.base.db.clone();
            let labels_snapshot =
                tokio::time::timeout(Duration::from_secs(10), attome_core::load_all_labels(&db))
                    .await??;
            state.labels.swap(labels_snapshot);
            let applied_watermark = Arc::new(AtomicI64::new(
                attome_core::label_log_watermark(&db).await.unwrap_or(0),
            ));

            let labels = state.labels.clone();
            let watermark = applied_watermark.clone();
            // Never varied per-deployment; not a config knob — same posture
            // as `SETTINGS_POLL_INTERVAL_SECS` above.
            const LABEL_POLL_INTERVAL_SECS: u64 = 20;
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(LABEL_POLL_INTERVAL_SECS));
                interval.tick().await; // consume the immediate first tick — pre-warm above already caught up
                loop {
                    interval.tick().await;
                    let applied = watermark.load(Ordering::Acquire);
                    match attome_core::label_log_watermark(&db).await {
                        Ok(db_watermark) if db_watermark != applied => {
                            match attome_core::load_all_labels(&db).await {
                                Ok(snapshot) => {
                                    labels.swap(snapshot);
                                    watermark.store(db_watermark, Ordering::Release);
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "metadata label cache reload failed — will retry next tick",
                                ),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "metadata label watermark poll failed to read label_log_watermark — will retry next tick",
                        ),
                    }
                }
            });
        }

        // ── Cross-node authz cache invalidation (D-046) — registered on the
        // ONE shared `subscriber` connection above (C-18: this used to open
        // its own dedicated client). Unlike meta_version, a security_version
        // message carries the user_id to invalidate directly in its payload
        // (no change-log table to re-derive "what changed" from), so it
        // still needs its own parsing/dispatch and filters on its own
        // channel rather than sharing meta_version's channel-agnostic
        // on_message handler — it just no longer needs a Redis connection of
        // its own to do that (`fred`'s `on_message` spawns one broadcast
        // listener per registration, so this composes with every other
        // handler below on the same client). No debounce — this is a single
        // targeted L1 key per message, not a full-registry rebuild.
        {
            let security_resolver = security_resolver_concrete.clone();
            subscriber.on_message(move |msg| {
                if msg.channel != attome_security::SECURITY_VERSION_CHANNEL {
                    return;
                }
                let security_resolver = security_resolver.clone();
                if let Some(payload) = msg.payload.as_deref()
                    && let Ok(user_id) = payload.parse::<uuid::Uuid>()
                {
                    tokio::spawn(async move {
                        security_resolver.invalidate_local(user_id).await;
                    });
                }
            });
        }

        // ── Cross-node audit_users cache invalidation — same shared
        // `subscriber` (C-18): a systemuser update/delete
        // (`entity_crud.rs`/`bulk.rs`) publishes the invalidated user_id via
        // `EngineState::invalidate_audit_user`, and every OTHER node drops its
        // own stale `audit_users` L1 entry here instead of waiting out the
        // 60s TTL. Closes the gap where a display-name/email edit handled by
        // one node left every other node serving the old denormalized audit
        // fields for up to 60s.
        {
            let state = state.clone();
            subscriber.on_message(move |msg| {
                if msg.channel != attome_core::AUDIT_USER_VERSION_CHANNEL {
                    return;
                }
                let state = state.clone();
                if let Some(payload) = msg.payload.as_deref()
                    && let Ok(user_id) = payload.parse::<uuid::Uuid>()
                {
                    tokio::spawn(async move {
                        state.invalidate_audit_user_local(user_id).await;
                    });
                }
            });
        }

        // ── Cross-node feature-flag cache invalidation (M95/D-430, C-18) —
        // same shared `subscriber`: `features_admin::put_feature_flag`
        // publishes via `EngineState::invalidate_feature_flags` after its
        // write commits, and every OTHER node drops its own cached
        // evaluations here instead of only bounding staleness by the 30s
        // TTL. Payload is unused, same doorbell-only posture as
        // state_models/relationships/rules below.
        {
            let state = state.clone();
            subscriber.on_message(move |msg| {
                if msg.channel == attome_core::FEATURE_FLAG_VERSION_CHANNEL {
                    state.invalidate_feature_flags_local();
                }
            });
        }

        // ── C-18: state_models/relationships/rules each used to open
        // their own always-on subscriber connection for a doorbell-ONLY
        // reload — a dropped message left a node stale until the table's
        // next unrelated write, with no self-heal (unlike `entities`'
        // doorbell + change-log catch-up, or `settings`/`labels`' watermark
        // poll). `spawn_doorbell_reload` registers each type's doorbell on
        // this one shared `subscriber` and adds the periodic catch-up tick
        // every one of these was missing. Never varied per-deployment,
        // not a config knob — same posture as `SETTINGS_POLL_INTERVAL_SECS`/
        // `LABEL_POLL_INTERVAL_SECS` above.
        const SNAPSHOT_CATCHUP_POLL_INTERVAL_SECS: u64 = 30;
        let snapshot_catchup_interval = Duration::from_secs(SNAPSHOT_CATCHUP_POLL_INTERVAL_SECS);
        attome_core::spawn_doorbell_reload::<attome_core::StateModelRegistry>(
            &subscriber,
            state.base.db.clone(),
            state.state_models.clone(),
            snapshot_catchup_interval,
        );
        attome_core::spawn_doorbell_reload::<attome_core::RelationshipRegistry>(
            &subscriber,
            state.base.db.clone(),
            state.relationships.clone(),
            snapshot_catchup_interval,
        );
        attome_core::spawn_doorbell_reload::<attome_core::RuleRegistry>(
            &subscriber,
            state.base.db.clone(),
            state.rules.clone(),
            snapshot_catchup_interval,
        );

        // Z3-T5: the dependency-aware caches follow the change feed on every
        // node, once a second and at once on a record write's doorbell.
        attome_core::cache_invalidation::bus().spawn(
            state.base.db.clone(),
            Some(&subscriber),
            attome_core::cache_invalidation::POLL_INTERVAL,
        );

        // P1.15 §4(d): bounded like the pre-warm above (guidelines §14.4's
        // 10s startup budget) — an unreachable Redis at boot fails startup
        // loudly instead of hanging it indefinitely. Every channel above
        // shares this ONE subscriber connection (C-18) — this used to be
        // seven separate `create_subscriber_client` calls (metadata,
        // security, audit_users, and one apiece for state_models/
        // relationships/forms/rules — forms since removed, D-790); `SUBSCRIBE` is additive per Redis
        // semantics, so subscribing to each channel in turn on the same
        // client is equivalent to subscribing to all of them at once.
        for channel in [
            META_VERSION_KEY,
            attome_security::SECURITY_VERSION_CHANNEL,
            attome_core::AUDIT_USER_VERSION_CHANNEL,
            attome_core::FEATURE_FLAG_VERSION_CHANNEL,
            attome_core::STATE_MODEL_VERSION_CHANNEL,
            attome_core::RELATIONSHIP_VERSION_CHANNEL,
            attome_core::RULE_VERSION_CHANNEL,
            attome_core::cache_invalidation::CACHE_INVALIDATE_CHANNEL,
        ] {
            tokio::time::timeout(Duration::from_secs(10), subscriber.subscribe(channel)).await??;
        }

        // Keep the one dedicated connection alive for the process lifetime.
        tokio::spawn(async move {
            let _subscriber = subscriber;
            std::future::pending::<()>().await;
        });

        // P2.11: Notification Engine background scanner (F163 dispatch,
        // F172 escalation) — a polling loop over notification_dispatch,
        // not an apalis EngineJob (see poller.rs's module doc for why).
        // D-602: the same tick delivers due record reminders, with the
        // entity engine's recipient read check.
        attome_notification::poller::spawn(
            state.clone(),
            Duration::from_secs(5),
            Arc::new(crate::reminder_access::EngineReminderAccess),
        );

        // P-environment-promotion §5 step 20 — this deployment's own
        // configuration hash, computed once here (after every seed/backfill
        // above has had its chance to change metadata) and again after every
        // successful bundle apply (`bundle::apply::run_apply_job`). Best-
        // effort: a failed export must never fail boot over a read-only
        // diagnostic value — `/version` simply keeps its release-version
        // fallback until the next successful computation.
        match crate::bundle::export_bundle(&state.base.db).await {
            Ok(bundle) => {
                let hash = crate::bundle::bundle_hash(&bundle);
                state.base.configuration_version.store(Some(Arc::new(hash)));
            }
            Err(error) => tracing::warn!(
                %error,
                "failed to compute the configuration hash at boot; /version will report the \
                 release version until the next successful computation"
            ),
        }

        // P-environment-promotion §5 step 23 — pull a signed bundle by
        // reference at first boot (the F273 loader, generalized). Runs only
        // when `deployment.bundle_ref` is configured, and only when this
        // deployment has never successfully applied a bundle before — a
        // restart must never silently re-apply on every boot (F273's own
        // semantics). `sync` itself still requires approval on a
        // production-profile deployment (it queues through the same gated
        // apply path `POST …/import?mode=apply` uses), so this is "notice
        // and plan", not "apply unattended", on that profile. Best-effort:
        // a failed pull must not fail boot — logged, and the admin `POST
        // …/metadata/sync` route (or another boot) can retry it.
        if state.base.config.deployment.bundle_ref.is_some() {
            match crate::bundle::ledger::latest_succeeded(&state.base.db).await {
                Ok(Some(row)) => tracing::info!(
                    plan_id = %row.id,
                    "deployment.bundle_ref is configured but a bundle has already been applied; \
                     skipping the first-boot pull (use POST /api/v1/admin/metadata/sync to re-check)"
                ),
                Ok(None) => match crate::bundle::pull::sync(&state, None).await {
                    Ok(outcome) => {
                        tracing::info!(?outcome, "first-boot bundle pull completed")
                    }
                    Err(error) => tracing::warn!(
                        %error,
                        "first-boot bundle pull failed; the deployment will boot without it"
                    ),
                },
                Err(error) => tracing::warn!(
                    %error,
                    "could not check for an already-applied bundle; skipping the first-boot pull"
                ),
            }
        }

        Ok(EngineSystem {
            state,
            registry: self.registry,
        })
    }
}

/// Number of change-log rows read per round trip during catch-up. Looping
/// while a batch comes back full bounds a single query's cost during a large
/// catch-up (e.g. a node that was offline for a while) without an unbounded
/// `IN (...)`/result set.
const CATCH_UP_BATCH_LIMIT: i64 = 1000;

/// Pre-warm entry point (Plan 1.14): try the Redis snapshot first — the
/// common-case path that turns pre-warm into one Redis GET instead of a
/// database rebuild — then catch up on anything committed since the
/// snapshot was taken. Falls back to `full_rebuild` on a cold/unusable
/// snapshot (first boot, cold Redis, a decode failure).
async fn pre_warm_registry(
    db: &DbPool,
    redis: &Store,
) -> Result<(EntityMetaRegistry, i64), AppError> {
    let (mut registry, mut last_id) = match attome_core::load_snapshot(redis).await {
        Ok(Some(snap)) => {
            // The change log is append-only (ids only ever grow), so a
            // snapshot watermark higher than the database's own current max
            // id is impossible under normal operation — it means Postgres
            // and Redis have gone out of sync (e.g. Postgres restored to an
            // earlier point in a DR drill while Redis kept its prior state,
            // or a shared Redis instance reused across differently-seeded
            // databases). Trusting it anyway would silently and permanently
            // wedge the registry: every future `changes_since(db, stale_id)`
            // call would find `id > stale_id` never true, so
            // catch-up would never see anything wrong and no error would
            // ever surface — see P-metadata-sync-hardening's "staleness
            // becomes an observable signal" goal, which this closes for the
            // one case its existing lag gauge's `.max(0)` clamp couldn't
            // (positive-only lag can't represent "Redis is ahead").
            match attome_core::log_watermark(db).await {
                Ok(db_watermark) if snap.1 > db_watermark => {
                    tracing::error!(
                        snapshot_watermark = snap.1,
                        db_watermark,
                        "metadata registry snapshot watermark exceeds the database's own \
                         current max id — Postgres/Redis are out of sync (e.g. a restore \
                         drill left Redis pointing at a different database's history); \
                         discarding the snapshot and rebuilding from Postgres",
                    );
                    full_rebuild(db, redis).await?
                }
                Ok(_) => snap,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read log watermark to validate metadata registry snapshot — falling back to full rebuild");
                    full_rebuild(db, redis).await?
                }
            }
        }
        Ok(None) => full_rebuild(db, redis).await?,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read metadata registry snapshot — falling back to full rebuild");
            full_rebuild(db, redis).await?
        }
    };

    loop {
        let rows = attome_core::changes_since(db, last_id, CATCH_UP_BATCH_LIMIT).await?;
        if rows.is_empty() {
            break;
        }
        let batch_len = rows.len();
        last_id = rows.last().map(|r| r.id).unwrap_or(last_id);
        registry = attome_core::apply_change_log(db, &registry, &rows).await?;
        if (batch_len as i64) < CATCH_UP_BATCH_LIMIT {
            break;
        }
    }

    // The watermark check above only catches Redis running *ahead* of
    // Postgres. It cannot catch Postgres being swapped out from under a
    // Redis instance that keeps running (a dev volume reset, or a restore
    // that reuses a shared Redis) while the new database's own change-log
    // sequence coincidentally reaches or passes the stale watermark — the
    // watermark comparison alone can't tell "the same history, further
    // along" from "an unrelated history that happens to have a similar-or-
    // higher id". A snapshot entity whose id no longer exists in Postgres at
    // all is the unambiguous signal that catch-up patched a name onto a
    // dangling id instead of a real row, so it gets the same treatment as a
    // stale watermark: discard and rebuild, never trust or hand back to a
    // caller that will pass the id straight into a foreign-key write.
    match attome_core::verify_ids_exist(db, &registry).await {
        Ok(true) => {
            if let Err(e) = attome_core::save_snapshot(redis, last_id, &registry).await {
                tracing::warn!(error = %e, "failed to save metadata registry snapshot after pre-warm");
            }
            Ok((registry, last_id))
        }
        Ok(false) => {
            tracing::error!(
                "metadata registry snapshot references at least one entity id Postgres no \
                 longer has (e.g. a Redis snapshot carried over from a different or reset \
                 Postgres volume) — discarding the snapshot and rebuilding from Postgres"
            );
            full_rebuild(db, redis).await
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to verify metadata registry snapshot ids against Postgres — \
                 proceeding with the pre-warmed registry as-is"
            );
            if let Err(e) = attome_core::save_snapshot(redis, last_id, &registry).await {
                tracing::warn!(error = %e, "failed to save metadata registry snapshot after pre-warm");
            }
            Ok((registry, last_id))
        }
    }
}

/// True last resort: reads `entity_info`/`attribute_info` in full,
/// same as pre-Plan-1.14 behavior. Only reached on a cold/unusable Redis
/// snapshot at pre-warm, or an unreadable change log during catch-up.
///
/// Reads the change-log watermark *before* the registry tables — that order
/// makes the returned id a safe lower bound on what the registry actually
/// reflects. Reading it after could instead overstate freshness: a write
/// that commits in the gap between the two reads would already be visible
/// in the registry read but not accounted for by a (then-stale) watermark
/// taken first, so a later incremental catch-up would permanently skip that
/// row. The reverse order can only under-state freshness (a write landing in
/// between makes the watermark read first slightly stale), which incremental
/// catch-up harmlessly re-applies — patching an entity to its current state
/// twice is a no-op, not a correctness issue.
async fn full_rebuild(db: &DbPool, redis: &Store) -> Result<(EntityMetaRegistry, i64), AppError> {
    let watermark = attome_core::log_watermark(db).await?;
    let registry = attome_core::build_registry(db).await?;

    if let Err(e) = attome_core::save_snapshot(redis, watermark, &registry).await {
        tracing::warn!(error = %e, "failed to save metadata registry snapshot after full rebuild");
    }

    Ok((registry, watermark))
}

/// Debounces a burst of `meta_version` doorbell messages/reconnects into a
/// single catch-up pass (~250ms coalescing window).
fn spawn_debounced_catch_up(
    pending: Arc<AtomicBool>,
    entities: MetadataCache<EntityMetaRegistry>,
    db: DbPool,
    redis: Store,
    last_applied: Arc<AtomicI64>,
) {
    if pending.swap(true, Ordering::AcqRel) {
        return; // a debounce window is already pending — this signal coalesces into it
    }

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        pending.store(false, Ordering::Release);
        catch_up(&entities, &db, &redis, &last_applied).await;
    });
}

/// Reads `metadata_change_log` for anything past `last_applied` and
/// patches just the touched entities into the registry — the incremental
/// counterpart of a full rebuild (Plan 1.14). Always re-derives truth from
/// the log table itself rather than trusting the pub/sub payload, same
/// self-heal philosophy as the license hourly reload.
async fn catch_up(
    entities: &MetadataCache<EntityMetaRegistry>,
    db: &DbPool,
    redis: &Store,
    last_applied: &AtomicI64,
) {
    // Y8-T4: a version switch moves only the pointer, not the change log.
    crate::model_admin::follow_cooked(db).await;
    loop {
        let after = last_applied.load(Ordering::Acquire);
        let rows = match attome_core::changes_since(db, after, CATCH_UP_BATCH_LIMIT).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "metadata change log unreadable — falling back to full registry rebuild");
                match full_rebuild(db, redis).await {
                    Ok((fresh, watermark)) => {
                        entities.swap(fresh);
                        last_applied.store(watermark, Ordering::Release);
                        tracing::info!(
                            watermark,
                            "metadata registry rebuilt (change log unreadable)"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "metadata registry full rebuild failed — will retry on next signal")
                    }
                }
                return;
            }
        };

        if rows.is_empty() {
            return; // already caught up
        }

        let batch_len = rows.len();
        let max_id = rows.last().map(|r| r.id).unwrap_or(after);
        let current = entities.load();

        match attome_core::apply_change_log(db, &current, &rows).await {
            Ok(patched) => {
                entities.swap(patched.clone());
                last_applied.store(max_id, Ordering::Release);
                if let Err(e) = attome_core::save_snapshot(redis, max_id, &patched).await {
                    tracing::warn!(error = %e, "failed to save metadata registry snapshot after incremental patch");
                }
                tracing::info!(
                    applied = batch_len,
                    watermark = max_id,
                    "metadata registry incrementally patched"
                );
                // P-observability-bcdr Track A
                metrics::counter!("registry_catchup_entities_total").increment(batch_len as u64);
            }
            Err(e) => {
                tracing::error!(error = %e, "incremental metadata patch failed — will retry on next signal");
                return;
            }
        }

        if (batch_len as i64) < CATCH_UP_BATCH_LIMIT {
            return; // drained everything available
        }
        // else loop again for the next batch
    }
}

// ── Module availability (D-778: no licence check; Module Management narrows) ──

/// `pub` (not the crate-private the other `build()` helpers stay) — D-478's
/// platform-bundle applies that run from `crates/server/src/boot.rs`, ahead
/// of `EngineSystem::build()` (documented there: several engines' seeds must
/// run before `.build()`'s `entity_privileges::seed_all`), each check
/// `requires.modules` against `state.modules`. `boot.rs` calls this directly
/// right after constructing `EngineState`, the same way `build()` does just
/// below, so neither call site's platform bundles see the
/// `ModuleSet::core_only()` `EngineState::new` seeds that field with.
///
/// D-778 (supersedes D-635): no signed licence is ever checked. The result is
/// [`ModuleSet::all_modules`] narrowed by the runtime module configuration
/// (`license_admin::narrow_by_runtime_configuration`), so Module Management is
/// the only switch that hides a module.
pub async fn load_license(db: &DbPool) -> ModuleSet {
    crate::license_admin::narrow_by_runtime_configuration(db, &ModuleSet::all()).await
}

/// E8-T1 — inserts `value` under `key`, panicking (naming the key) when the
/// key is taken: a duplicate registration is a boot-time programming error.
#[expect(
    clippy::panic,
    reason = "a duplicate workflow step key or kind is a boot-time programming error (E8-T1)"
)]
fn insert_once<V>(
    map: &mut std::collections::HashMap<&'static str, V>,
    key: &'static str,
    value: V,
    what: &str,
) {
    if map.insert(key, value).is_some() {
        panic!("{what} {key:?} is registered twice");
    }
}

#[cfg(test)]
mod workflow_step_registration {
    use super::*;

    #[test]
    #[should_panic(expected = "\"marketing.send_email\" is registered twice")]
    fn duplicate_step_handler_key_rejected() {
        let mut map = std::collections::HashMap::new();
        insert_once(&mut map, "marketing.send_email", 1, "workflow step handler");
        insert_once(&mut map, "marketing.send_email", 2, "workflow step handler");
    }

    #[test]
    fn distinct_keys_are_kept() {
        let mut map = std::collections::HashMap::new();
        insert_once(&mut map, "a", 1, "workflow kind guard");
        insert_once(&mut map, "b", 2, "workflow kind guard");
        assert_eq!(map.len(), 2);
    }
}
