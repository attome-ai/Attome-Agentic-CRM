//! The bundle engine's HTTP surface (P-environment-promotion §3 Phase 1 /
//! §5 steps 14, 15, 21), under `/api/v1/admin/metadata/…` — the one admin
//! prefix the authoring gate exempts, because promoting a bundle *is* how a
//! production deployment's metadata changes.
//!
//! | route | does |
//! |---|---|
//! | `GET  …/export` | the live metadata as canonical `attome-bundle/v1` bytes |
//! | `POST …/import?mode=plan` | plan a bundle, persist the plan row (`planned`), return the diff |
//! | `POST …/import?mode=apply` | re-check the basis, approval-gate, queue the durable apply job |
//! | `GET  …/plans` | the ledger, newest first — `succeeded` rows are the applied-bundle history |
//! | `GET  …/plans/{id}` | one row: status, cursor, applied count, error — the job's status endpoint |
//! | `GET  …/drift` | live metadata planned against the newest `succeeded` bundle |
//! | `GET  …/manifest` | every bundle name ever `succeeded` here, at its highest applied version |
//! | `POST …/bundles/{name}/rollback` | M92 Phase 1 — plan + gate + queue the ledger's own prior snapshot of a named bundle |
//!
//! Every handler is `system.admin`-gated (`Authorized<Admin>`, same as every
//! neighbouring admin surface) and thin: parse, call `super::{export, plan,
//! ledger, apply}`, respond. Mutations happen in the worker
//! (`super::apply::run_apply_job`), never on the request thread; the only
//! writes here are ledger rows.
//!
//! **Approval.** `mode=apply` goes through `approval_admin::gate` with action
//! type [`ACTION_BUNDLE_APPLY`] — on a production-profile deployment that
//! action is mandatory, so a second `system.admin` must approve before the
//! job is queued. The queueing itself is `ledger::mark_queued` +
//! `ledger::enqueue_apply`, the same two calls `approval_admin::
//! execute_approved` makes once a gated request is approved (D-195: one
//! execution path per action); [`do_apply_plan`] is that pair for the
//! ungated case.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::canonical::{bundle_hash, canonical_json};
use super::export::{PLATFORM_VERSION, export_bundle};
use super::ledger::{self, ACTION_BUNDLE_APPLY, MAX_LIST_LIMIT, PlanRow, PlanStatus};
use super::model::{BUNDLE_FORMAT, Bundle};
use super::plan::{BundlePlan, PlanAction, PlanEntry, PlanOptions, PlanSummary, plan_bundle};
use super::pull::SyncOutcome;

const DEFAULT_LIST_LIMIT: i64 = 50;

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
struct ImportQuery {
    /// `plan` or `apply`.
    mode: String,
}

/// Body of `POST /api/v1/admin/metadata/import`. `mode=plan` reads `bundle`
/// (+ `allow_retire`); `mode=apply` reads `plan_id`.
#[derive(Deserialize, ToSchema)]
struct ImportBody {
    #[serde(default)]
    bundle: Option<Bundle>,
    /// Without it every would-be retire is reported as `blocked` (§4).
    #[serde(default)]
    allow_retire: bool,
    #[serde(default)]
    plan_id: Option<Uuid>,
}

/// `mode=plan` response — the persisted plan, as the approver sees it.
#[derive(Serialize, ToSchema)]
struct PlanResponse {
    plan_id: Uuid,
    /// Hash of the live export the plan was computed against; `mode=apply`
    /// refuses (409) once live metadata no longer hashes to it.
    basis_hash: String,
    bundle_hash: String,
    summary: PlanSummary,
    entries: Vec<PlanEntry>,
    retires: Vec<PlanEntry>,
    blocked: Vec<PlanEntry>,
    /// `blocked` is empty — apply would run this plan to completion.
    applicable: bool,
}

/// `mode=apply` response (202).
#[derive(Serialize, ToSchema)]
pub struct ApplyAccepted {
    pub plan_id: Uuid,
    /// `queued` once the job is durably enqueued; `planned` while an approval
    /// request is pending.
    pub status: PlanStatus,
    /// D-195 — `true` when this call only submitted an approval request; a
    /// second, different `system.admin` must decide it before the apply is
    /// queued.
    pub approval_pending: bool,
    pub approval_request_id: Option<Uuid>,
}

impl std::fmt::Debug for ApplyAccepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyAccepted").finish_non_exhaustive()
    }
}

/// One ledger row without its `bundle`/`plan` payloads — the list shape the
/// M92 Phase 1 lifecycle UI reads. `bundle_name`/`bundle_version` are pulled
/// out of the row's already-fetched `bundle` JSONB (no extra query) so the
/// UI can group applied plans into "installed bundles" and offer rollback
/// targets without a second endpoint — `None` for an anonymous
/// whole-deployment plan (`Bundle.name` unset).
#[derive(Serialize, ToSchema)]
struct PlanListItem {
    id: Uuid,
    status: PlanStatus,
    bundle_hash: String,
    basis_hash: String,
    format_version: String,
    platform_version: String,
    allow_retire: bool,
    bundle_name: Option<String>,
    bundle_version: Option<String>,
    requested_by: Option<Uuid>,
    approval_ref: Option<Uuid>,
    cursor: i32,
    applied_count: i32,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
    claimed_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

impl From<PlanRow> for PlanListItem {
    fn from(r: PlanRow) -> Self {
        let bundle_name = r
            .bundle
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let bundle_version = r
            .bundle
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        PlanListItem {
            id: r.id,
            status: r.status,
            bundle_hash: r.bundle_hash,
            basis_hash: r.basis_hash,
            format_version: r.format_version,
            platform_version: r.platform_version,
            allow_retire: r.allow_retire,
            bundle_name,
            bundle_version,
            requested_by: r.requested_by,
            approval_ref: r.approval_ref,
            cursor: r.cursor,
            applied_count: r.applied_count,
            error_message: r.error_message,
            created_at: r.created_at,
            claimed_at: r.claimed_at,
            finished_at: r.finished_at,
        }
    }
}

#[derive(Deserialize, IntoParams)]
struct ListQuery {
    /// Newest first; default 50, max 200.
    limit: Option<i64>,
    /// Filter to one status (e.g. `planned`/`queued` for "pending plans" in
    /// the lifecycle UI). Unset lists every status, as before.
    #[serde(default)]
    status: Option<PlanStatus>,
}

/// The newest `succeeded` plan the drift was computed against.
#[derive(Serialize, ToSchema)]
struct AppliedRef {
    plan_id: Uuid,
    bundle_hash: String,
    finished_at: Option<DateTime<Utc>>,
}

/// Live metadata planned against the last applied bundle.
#[derive(Serialize, ToSchema)]
struct DriftDiff {
    /// Hash of the live export at the time of the call.
    live_hash: String,
    summary: PlanSummary,
    entries: Vec<PlanEntry>,
    retires: Vec<PlanEntry>,
    blocked: Vec<PlanEntry>,
    /// Every line is `noop` — nothing differs from the applied bundle.
    clean: bool,
}

#[derive(Serialize, ToSchema)]
struct DriftReport {
    /// `None` when nothing has ever been applied — then there is no drift
    /// to speak of, and `drift` is `None` too.
    applied: Option<AppliedRef>,
    drift: Option<DriftDiff>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/admin/metadata/export` — the live metadata as canonical
/// bundle bytes (byte-identical on a second call with no intervening change).
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/export",
    tag = "admin-metadata",
    responses(
        (status = 200, description = "Canonical attome-bundle/v1 JSON", body = Bundle),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Response, AppError> {
    let bundle = export_bundle(&state.base.db_migrator).await?;
    let bytes = canonical_json(&bundle);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

/// `POST /api/v1/admin/metadata/import?mode=plan|apply`.
///
/// `plan`: diff `bundle` against live metadata, persist the result as a
/// `planned` ledger row, return it. Mutates nothing but the ledger. Record
/// sets (Phase 3) are resolved against live data as part of the same plan.
///
/// `apply`: the `plan_id` must be `planned` and unblocked, live metadata must
/// still hash to its `basis_hash` (409 otherwise), then — subject to the
/// D-195 gate — the row is queued and the durable job enqueued (202).
/// Progress and outcome: `GET …/plans/{id}`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/import",
    tag = "admin-metadata",
    params(ImportQuery),
    request_body = ImportBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::ApplyMetadataBundle (bundle/apply.rs::audit_entity_change)"), "mode=plan only computes and persists a proposal (no live metadata change); mode=apply enqueues the durable job, which writes a per-entity Entity audit event (AuditSource::Import) for every schema change it actually applies")))),
    responses(
        (status = 200, description = "Plan computed and persisted (mode=plan)", body = PlanResponse),
        (status = 202, description = "Apply queued, or approval request submitted (mode=apply)", body = ApplyAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Plan not found", body = ErrorResponse),
        (status = 409, description = "Metadata changed since the plan, or the plan is not in the planned state", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or the plan has blocked entries", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn import(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Query(query): Query<ImportQuery>,
    Json(body): Json<ImportBody>,
) -> Result<Response, AppError> {
    match query.mode.as_str() {
        "plan" => {
            let bundle = body.bundle.ok_or_else(|| {
                AppError::Validation("mode=plan requires a `bundle` in the body".to_owned())
            })?;
            let response = plan_and_persist(&state, bundle, body.allow_retire, ctx.user_id).await?;
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        "apply" => {
            let plan_id = body.plan_id.ok_or_else(|| {
                AppError::Validation("mode=apply requires a `plan_id` in the body".to_owned())
            })?;
            let accepted = apply_with_gate(&state, plan_id, ctx.user_id).await?;
            Ok((StatusCode::ACCEPTED, Json(accepted)).into_response())
        }
        other => Err(AppError::Validation(format!(
            "mode must be `plan` or `apply`, got {other:?}"
        ))),
    }
}

async fn plan_and_persist(
    state: &EngineState,
    mut bundle: Bundle,
    allow_retire: bool,
    requested_by: Uuid,
) -> Result<PlanResponse, AppError> {
    // Format gate first, on the declared string (the body already parsed as
    // this binary's model, but a bundle that says it is v2 is still refused).
    super::model::check_format(&bundle.format).map_err(|e| AppError::Validation(e.to_string()))?;
    bundle.normalize();

    let license = state.modules.load_full();
    let plan: BundlePlan = plan_bundle(
        &state.base.db_migrator,
        &license,
        &bundle,
        PlanOptions {
            allow_retire,
            additive_only: false,
        },
    )
    .await?;

    // Persist the canonical bundle (not the body as sent) so the worker
    // re-reads exactly what was hashed.
    let bundle_json: serde_json::Value = serde_json::from_slice(&canonical_json(&bundle))
        .map_err(|e| AppError::internal(format!("canonical bundle is not JSON: {e}")))?;
    let plan_json = serde_json::to_value(&plan).map_err(AppError::internal)?;
    let plan_id = ledger::insert_plan(
        &state.base.db,
        &bundle_json,
        &plan_json,
        &plan.bundle_hash,
        &plan.basis_hash,
        BUNDLE_FORMAT,
        PLATFORM_VERSION,
        allow_retire,
        Some(requested_by),
    )
    .await?;

    tracing::info!(
        plan_id = %plan_id,
        bundle_hash = %plan.bundle_hash,
        basis_hash = %plan.basis_hash,
        creates = plan.summary.creates,
        updates = plan.summary.updates,
        retires = plan.summary.retires,
        noops = plan.summary.noops,
        blocked = plan.summary.blocked,
        "bundle plan persisted"
    );

    let applicable = plan.is_applicable();
    Ok(PlanResponse {
        plan_id,
        basis_hash: plan.basis_hash,
        bundle_hash: plan.bundle_hash,
        summary: plan.summary,
        entries: plan.entries,
        retires: plan.retires,
        blocked: plan.blocked,
        applicable,
    })
}

/// Pre-flight shared by the gated and the approved path: the row exists, is
/// `planned`, has nothing blocked, and live metadata still matches its
/// basis. Read-only.
async fn preflight_apply(state: &EngineState, plan_id: Uuid) -> Result<PlanRow, AppError> {
    let row = ledger::get_plan(&state.base.db, plan_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != PlanStatus::Planned {
        return Err(AppError::Conflict("plan is not in the planned state"));
    }
    let blocked = row
        .plan
        .get("blocked")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if blocked > 0 {
        return Err(AppError::Validation(format!(
            "plan has {blocked} blocked entr{}; fix the bundle and plan again",
            if blocked == 1 { "y" } else { "ies" }
        )));
    }
    let live = export_bundle(&state.base.db_migrator).await?;
    if bundle_hash(&live) != row.basis_hash {
        return Err(AppError::Conflict("metadata changed since plan"));
    }
    Ok(row)
}

/// The gated handler path: pre-flight, then either submit an approval
/// request (when `ACTION_BUNDLE_APPLY` is required) or queue right away.
/// `pub(crate)` (not module-private) so [`super::pull::sync`] can reuse the
/// exact same approval-gate + queue behavior a pulled bundle goes through as
/// an operator-pushed one — never a second, parallel "apply" path.
pub(crate) async fn apply_with_gate(
    state: &EngineState,
    plan_id: Uuid,
    requester: Uuid,
) -> Result<ApplyAccepted, AppError> {
    let row = preflight_apply(state, plan_id).await?;

    if let Some(request) = crate::approval_admin::gate(
        state,
        ACTION_BUNDLE_APPLY,
        serde_json::json!({
            "plan_id": plan_id,
            "bundle_hash": row.bundle_hash,
            "basis_hash": row.basis_hash,
        }),
        requester,
    )
    .await?
    {
        return Ok(ApplyAccepted {
            plan_id,
            status: PlanStatus::Planned,
            approval_pending: true,
            approval_request_id: Some(request.id),
        });
    }

    do_apply_plan(state, plan_id, None).await
}

/// "Queue this plan": `planned → queued` recording the approval reference
/// (if any), then the durable `ApplyMetadataBundle` job through
/// [`ledger::enqueue_apply`] — one transaction, dedup-keyed on the plan id,
/// so a double click cannot queue it twice. The approved path
/// (`approval_admin::execute_approved` for [`ACTION_BUNDLE_APPLY`]) calls the
/// same two ledger functions; the worker re-checks the basis hash when it
/// claims the row, so a plan whose basis moved while the approval was
/// pending fails there ("basis changed since plan") rather than applying
/// against metadata nobody reviewed.
pub async fn do_apply_plan(
    state: &EngineState,
    plan_id: Uuid,
    approval_ref: Option<Uuid>,
) -> Result<ApplyAccepted, AppError> {
    if !ledger::mark_queued(&state.base.db, plan_id, approval_ref).await? {
        return Err(AppError::Conflict("plan is not in the planned state"));
    }
    ledger::enqueue_apply(state, plan_id).await?;

    tracing::info!(plan_id = %plan_id, approval_ref = ?approval_ref, "bundle apply queued");
    Ok(ApplyAccepted {
        plan_id,
        status: PlanStatus::Queued,
        approval_pending: false,
        approval_request_id: approval_ref,
    })
}

/// `GET /api/v1/admin/metadata/plans?limit=` — the ledger, newest first.
/// `succeeded` rows are the applied-bundle history.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/plans",
    tag = "admin-metadata",
    params(ListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PlanListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_plans(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListQuery>,
) -> Result<Json<PaginatedResponse<PlanListItem>>, AppError> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let rows = ledger::list_plans(&state.base.db, limit, query.status).await?;
    let total: i64 = match query.status {
        Some(s) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM metadata_bundle_plan WHERE status = $1")
                .bind(s.as_str())
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)?
        }
        None => sqlx::query_scalar("SELECT COUNT(*) FROM metadata_bundle_plan")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?,
    };
    let items = rows.into_iter().map(PlanListItem::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, 0, limit)))
}

/// `GET /api/v1/admin/metadata/plans/{id}` — one ledger row in full: the
/// status endpoint for a running apply (status, cursor, applied_count,
/// error_message) and the stored bundle/plan for an approver.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/plans/{id}",
    tag = "admin-metadata",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PlanRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Plan not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_plan(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PlanRow>, AppError> {
    let row = ledger::get_plan(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// `GET /api/v1/admin/metadata/drift` — live metadata planned against the
/// newest `succeeded` bundle (with `allow_retire`, so an object added by hand
/// shows as a retire rather than a blocked line). Read-only; no scheduler —
/// `fleetctl drift` is the scheduled check, by way of `/version`'s
/// configuration hash.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/drift",
    tag = "admin-metadata",
    responses(
        (status = 200, description = "Success", body = DriftReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn drift(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<DriftReport>, AppError> {
    let Some(row) = ledger::latest_succeeded(&state.base.db).await? else {
        return Ok(Json(DriftReport {
            applied: None,
            drift: None,
        }));
    };
    let mut applied: Bundle = serde_json::from_value(row.bundle.clone()).map_err(|e| {
        AppError::internal(format!(
            "stored bundle on plan {} does not parse: {e}",
            row.id
        ))
    })?;
    applied.normalize();

    let license = state.modules.load_full();
    let plan = plan_bundle(
        &state.base.db_migrator,
        &license,
        &applied,
        PlanOptions {
            allow_retire: true,
            additive_only: false,
        },
    )
    .await?;
    let clean = plan.retires.is_empty()
        && plan.blocked.is_empty()
        && plan.entries.iter().all(|e| e.action == PlanAction::Noop);

    Ok(Json(DriftReport {
        applied: Some(AppliedRef {
            plan_id: row.id,
            bundle_hash: row.bundle_hash,
            finished_at: row.finished_at,
        }),
        drift: Some(DriftDiff {
            live_hash: plan.basis_hash,
            summary: plan.summary,
            entries: plan.entries,
            retires: plan.retires,
            blocked: plan.blocked,
            clean,
        }),
    }))
}

/// Body of `POST /api/v1/admin/metadata/bundles/{name}/rollback`.
#[derive(Deserialize, ToSchema)]
struct RollbackBody {
    /// The named bundle's [`super::model::Bundle::version`] to roll back to.
    /// Must match a `succeeded` ledger row's stored `bundle.version` for this
    /// `name` — i.e. a version that was itself successfully applied before.
    to_version: String,
    /// Same meaning as `import?mode=plan`'s `allow_retire`: without it, any
    /// object present live (added by a version newer than `to_version`) but
    /// absent from the target snapshot is reported `Blocked` rather than
    /// retired.
    #[serde(default)]
    allow_retire: bool,
}

/// `POST /api/v1/admin/metadata/bundles/{name}/rollback` — undo = re-apply
/// the ledger's own record of an earlier successful application of the
/// named bundle (verticals skill, "Undoing an applied bundle": "find the
/// succeeded plan immediately before the one being undone, take its bundle
/// field, run it through the ordinary plan/apply flow"). This endpoint
/// automates exactly that manual procedure for a *named* bundle
/// ([`super::model::Bundle::name`]/[`super::model::Bundle::version`]):
///
/// 1. find the newest `succeeded` ledger row for `name` whose stored bundle
///    declares `version == to_version` (404 if none — either the name was
///    never applied, or never at that version);
/// 2. plan that stored snapshot against *current* live metadata, through the
///    same [`plan_and_persist`] every `import?mode=plan` call uses (so a
///    rollback plan is reviewable exactly like any other plan, and is
///    persisted as its own ledger row — never a hidden, unaudited apply);
/// 3. queue it through [`apply_with_gate`] — the same D-195 approval gate
///    `import?mode=apply` and [`super::pull::sync`] use, so a production
///    deployment still needs a second `system.admin` to approve
///    (`ACTION_BUNDLE_APPLY`). This is the documented manual procedure,
///    automated — never a bypass of the ordinary plan/apply/approval gates.
///
/// **TODO(M18):** the plan's rollback checklist calls for a dependents check
/// here — refuse the rollback when live records depend on objects the
/// target snapshot would retire, sourced from M18 Data Catalog's
/// `metadata_reference` lineage table. Not built in Phase 1: M18
/// does not exist yet (built by a sibling module in the same batch). Wire it
/// in as an additional blocked-entry check on `plan_response` once M18
/// merges and that table exists.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/bundles/{name}/rollback",
    tag = "admin-metadata",
    params(("name" = String, Path, description = "The target bundle's `Bundle.name`")),
    request_body = RollbackBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::ApplyMetadataBundle (bundle/apply.rs::audit_entity_change)"), "automates plan_and_persist + apply_with_gate, the same path as import?mode=plan/apply; the queued job writes a per-entity Entity audit event for every schema change it actually applies")))),
    responses(
        (status = 202, description = "Rollback plan queued, or approval request submitted", body = ApplyAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No succeeded application of this bundle name/version exists in the ledger", body = ErrorResponse),
        (status = 422, description = "The rollback plan has blocked entries (resolve them, or retry with allow_retire)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rollback(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(name): Path<String>,
    Json(body): Json<RollbackBody>,
) -> Result<Response, AppError> {
    let candidates = ledger::succeeded_bundles_by_name(&state.base.db, &name).await?;
    let target = candidates
        .into_iter()
        .find(|row| {
            row.bundle
                .get("version")
                .and_then(serde_json::Value::as_str)
                == Some(body.to_version.as_str())
        })
        .ok_or(AppError::NotFound)?;

    let bundle: Bundle = serde_json::from_value(target.bundle.clone()).map_err(|e| {
        AppError::internal(format!(
            "stored bundle on plan {} does not parse: {e}",
            target.id
        ))
    })?;

    let plan_response = plan_and_persist(&state, bundle, body.allow_retire, ctx.user_id).await?;
    if !plan_response.applicable {
        return Err(AppError::Validation(format!(
            "rollback plan has {} blocked entr{}; resolve them (allow_retire may help) and retry",
            plan_response.blocked.len(),
            if plan_response.blocked.len() == 1 {
                "y"
            } else {
                "ies"
            }
        )));
    }

    let accepted = apply_with_gate(&state, plan_response.plan_id, ctx.user_id).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)).into_response())
}

/// `POST /api/v1/admin/metadata/sync` — re-check `deployment.bundle_ref`
/// (P-environment-promotion §5 step 23): fetch, Ed25519-verify, plan against
/// live metadata, and — unless it is all-noop or has blocked entries — queue
/// it through the same gated apply path `mode=apply` uses. Idempotent:
/// calling this repeatedly with nothing new upstream keeps returning
/// `no_change`. `404`-shaped "not configured" is deliberately a 200 with
/// `status: not_configured` rather than an error — asking a deployment that
/// never opted into a pull source to sync is a no-op, not a mistake.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/sync",
    tag = "admin-metadata",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::ApplyMetadataBundle (bundle/apply.rs::audit_entity_change)"), "fetches, verifies and plans the deployment's configured bundle source, then queues through the same apply_with_gate path as import?mode=apply; the queued job writes a per-entity Entity audit event for every schema change it actually applies")))),
    responses(
        (status = 200, description = "Success", body = SyncOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "The pulled artifact failed to verify or parse", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn sync(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<Json<SyncOutcome>, AppError> {
    let outcome = super::pull::sync(&state, Some(ctx.user_id)).await?;
    Ok(Json(outcome))
}

/// One named bundle's currently-applied state — the highest-version
/// `succeeded` ledger row for that name.
#[derive(Serialize, ToSchema)]
struct ManifestEntry {
    name: String,
    version: String,
    bundle_hash: String,
    applied_at: Option<DateTime<Utc>>,
    status: PlanStatus,
}

#[derive(Serialize, ToSchema)]
struct MetadataManifest {
    bundles: Vec<ManifestEntry>,
}

/// `GET /api/v1/admin/metadata/manifest` — document/xrm/pending_full_plan/
/// plan.md Phase 2: "what bundle configuration is currently applied to this
/// deployment", answerable from one call instead of hand-walking `…/plans`.
/// Thin read over the same per-name query
/// [`super::plan::check_bundle_dependencies`] already runs internally to
/// verify `requires.depends_on_bundles` — reused here, not duplicated: one
/// query for the distinct bundle names that have ever `succeeded`, then
/// [`ledger::succeeded_bundles_by_name`] + the same version-floor semver
/// parser per name to pick the highest applied version. Bundle counts per
/// deployment are small (a handful of verticals/modules), so the N+1 shape
/// here trades a few extra round trips for reusing already-proven logic
/// rather than duplicating a version-aware `ORDER BY` in SQL against a JSONB
/// field.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/manifest",
    tag = "admin-metadata",
    responses(
        (status = 200, description = "Success", body = MetadataManifest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn manifest(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<MetadataManifest>, AppError> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT bundle ->> 'name' FROM metadata_bundle_plan \
         WHERE status = 'succeeded' AND bundle ->> 'name' IS NOT NULL \
         ORDER BY 1",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut bundles = Vec::with_capacity(names.len());
    for name in names {
        let rows = ledger::succeeded_bundles_by_name(&state.base.db, &name).await?;
        let highest = rows.iter().max_by_key(|row| {
            row.bundle
                .get("version")
                .and_then(serde_json::Value::as_str)
                .and_then(super::plan::parse_semver)
        });
        if let Some(row) = highest {
            let version = row
                .bundle
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            bundles.push(ManifestEntry {
                name,
                version,
                bundle_hash: row.bundle_hash.clone(),
                applied_at: row.finished_at,
                status: row.status,
            });
        }
    }
    Ok(Json(MetadataManifest { bundles }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/metadata/export", get(export))
        .route("/api/v1/admin/metadata/import", post(import))
        .route("/api/v1/admin/metadata/plans", get(list_plans))
        .route("/api/v1/admin/metadata/plans/{id}", get(get_plan))
        .route("/api/v1/admin/metadata/drift", get(drift))
        .route("/api/v1/admin/metadata/sync", post(sync))
        .route("/api/v1/admin/metadata/manifest", get(manifest))
        .route(
            "/api/v1/admin/metadata/bundles/{name}/rollback",
            post(rollback),
        )
}

/// This file's slice of the workspace OpenAPI document (P-api-contract
/// Phase 1) — merged by `crate::openapi::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(export, import, list_plans, get_plan, drift, sync, manifest, rollback))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
