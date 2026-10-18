//! `/api/v1/admin/metadata/changesets/{plan,apply,adopt,ledger}` — applying
//! changesets to this deployment (Solution 7 design §5, §7).
//!
//! Under the `/api/v1/admin/metadata` prefix the production authoring gate
//! exempts (as the bundle routes are): applying reviewed changesets is how a
//! production deployment's metadata changes. Plan, apply and the ledger reads
//! take `Authorized<Privilege<MetadataRollout>>` — `system.admin` or the
//! fleet console's rollout credential (`metadata.rollout`, D-792; an S2S
//! client bound to the password-less `attome-rollout` user); adopt stays
//! `Authorized<Admin>` (development only, never the console). Session, API
//! key or S2S; thin — parse, call `super::{plan, ledger, adopt}`, respond. Metadata is written by the worker
//! (`EngineJob::ApplyChangesets`, [`super::apply::run_apply_job`]), never
//! on the request thread.
//!
//! | route | does | audit |
//! |---|---|---|
//! | `POST …/plan` | check, order and plan documents; persist `planned` ledger rows | Configuration / Create, in the ledger transaction |
//! | `POST …/apply` | approval-gate (`metadata.changeset_apply`), queue, enqueue | delegated to the job (per-entity Entity events) |
//! | `POST …/adopt` | record this deployment's own closed changesets as applied | Configuration / Import, in the ledger transaction |
//! | `GET  …/ledger` | the ledger, newest first | — |
//! | `GET  …/ledger/{apply_id}` | one row with its plan and progress | — |
//! | `GET  /api/v1/admin/metadata/rollout/status` | the fleet poll's one call ([`super::rollout_status`]) | — |
//!
//! **Approval.** `apply` goes through `approval_admin::gate` with
//! [`super::ACTION_CHANGESET_APPLY`], production-mandatory like
//! `metadata.bundle_apply` (D-376): a second `system.admin` approves before
//! the rows are queued. The rollout credential can request an apply but never
//! approve one: the decide route is `system.admin` only, and
//! `attome_approval::decide` refuses the requester itself (separation of
//! duties). [`do_apply`] is the one queueing path, called by this
//! route when no approval is required and by `approval_admin::
//! execute_approved` once one is granted (D-195).
//!
//! **Snapshot.** On the production profile an apply must name the verified
//! backup taken before it (`backup_ref`, 422 `backup_ref_required`, §5.5);
//! the reference is recorded on every ledger row it queues.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_security::MetadataRollout;
use attome_server::authz::{Admin, Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::adopt::{self, AdoptedChangeset};
use super::ledger::{self, ApplyPhase, ApplySource, ApplyStatus, LedgerFilter, LedgerRow};
use super::plan::{self, ChangesetPlan, PlanContext};

/// Most rows one apply request queues.
const MAX_APPLY_IDS: usize = 200;
/// Longest accepted `backup_ref`.
const MAX_BACKUP_REF_CHARS: usize = 500;

// ── Wire types ──────────────────────────────────────────────────────────────

/// `POST …/plan` and `POST …/adopt`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangesetDocumentsBody {
    /// `attome-changeset/v1` documents, any order.
    #[schema(value_type = Vec<Object>)]
    pub changesets: Vec<Value>,
}

/// `POST …/apply`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApplyChangesetsBody {
    /// Ledger row ids from a plan, in the order to apply them.
    pub apply_ids: Vec<Uuid>,
    /// The phase every row covers.
    pub phase: ApplyPhase,
    /// The verified backup taken before this apply; required on the
    /// production profile.
    #[serde(default)]
    pub backup_ref: Option<String>,
}

/// `POST …/apply` (202).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplyChangesetsAccepted {
    /// `queued` once the job is durably enqueued; `planned` while an
    /// approval request is pending.
    pub status: String,
    pub apply_ids: Vec<Uuid>,
    /// `true` when this call only submitted an approval request; a second,
    /// different `system.admin` must approve it before the rows are queued.
    pub approval_pending: bool,
    pub approval_request_id: Option<Uuid>,
}

/// `POST …/adopt`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdoptResponse {
    pub changesets: Vec<AdoptedChangeset>,
}

/// `GET …/ledger` filters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LedgerQuery {
    /// `platform`, `product`, `project` or `customer`.
    pub layer: Option<String>,
    pub scope: Option<String>,
    /// `planned`, `queued`, `claimed`, `applying`, `succeeded`, `failed` or
    /// `adopted`.
    pub status: Option<String>,
}

/// One ledger row without its document and plan.
#[derive(Debug, Serialize, ToSchema)]
pub struct LedgerSummary {
    pub id: Uuid,
    pub changeset_id: Uuid,
    #[serde(rename = "ref")]
    pub changeset_ref: String,
    pub layer: String,
    pub scope: String,
    pub seq: i32,
    pub phase: ApplyPhase,
    pub checksum: String,
    pub status: ApplyStatus,
    pub source: ApplySource,
    pub platform_version: String,
    pub backup_ref: Option<String>,
    pub approval_ref: Option<Uuid>,
    pub cursor: i32,
    pub applied_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl From<LedgerRow> for LedgerSummary {
    fn from(r: LedgerRow) -> Self {
        Self {
            id: r.id,
            changeset_id: r.changeset_id,
            changeset_ref: r.changeset_ref,
            layer: r.layer,
            scope: r.scope,
            seq: r.seq,
            phase: r.phase,
            checksum: r.checksum,
            status: r.status,
            source: r.source,
            platform_version: r.platform_version,
            backup_ref: r.backup_ref,
            approval_ref: r.approval_ref,
            cursor: r.cursor,
            applied_count: r.applied_count,
            error_message: r.error_message,
            created_at: r.created_at,
            finished_at: r.finished_at,
        }
    }
}

// ── The one queueing path ───────────────────────────────────────────────────

fn is_production(state: &EngineState) -> bool {
    state.base.config.app.deployment_profile == "production"
}

/// Checks an apply request against the ledger without writing: ids present,
/// distinct and bounded; every row of `phase`, queueable (`planned`,
/// `failed`, or already `queued`) and planned applicable; a contract row's
/// expand row done; `backup_ref` present on the production profile.
async fn check_apply(state: &EngineState, body: &ApplyChangesetsBody) -> Result<(), AppError> {
    if body.apply_ids.is_empty() || body.apply_ids.len() > MAX_APPLY_IDS {
        return Err(AppError::Validation(format!(
            "apply_ids: between 1 and {MAX_APPLY_IDS} ledger row ids"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    if !body.apply_ids.iter().all(|id| seen.insert(*id)) {
        return Err(AppError::Validation(
            "apply_ids: an id appears twice".into(),
        ));
    }
    match body.backup_ref.as_deref().map(str::trim) {
        Some(r) if r.chars().count() > MAX_BACKUP_REF_CHARS => {
            return Err(AppError::Validation(format!(
                "backup_ref: at most {MAX_BACKUP_REF_CHARS} characters"
            )));
        }
        Some("") | None if is_production(state) => {
            return Err(AppError::Validation(ledger::BACKUP_REF_REQUIRED.into()));
        }
        _ => {}
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    for id in &body.apply_ids {
        let row = ledger::get(&state.base.db, *id)
            .await?
            .ok_or(AppError::NotFound)?;
        if row.phase != body.phase {
            return Err(AppError::Validation(format!(
                "apply_ids: row {id} is the {} phase, not {}",
                row.phase.as_str(),
                body.phase.as_str()
            )));
        }
        if !matches!(
            row.status,
            ApplyStatus::Planned | ApplyStatus::Failed | ApplyStatus::Queued
        ) {
            return Err(AppError::Conflict(
                "a changeset apply row is already running or finished",
            ));
        }
        if row.plan.get("applicable").and_then(Value::as_bool) != Some(true) {
            return Err(AppError::Validation(format!(
                "apply_ids: the plan of row {id} ({}) has blocked operations",
                row.changeset_ref
            )));
        }
        if row.phase == ApplyPhase::Contract {
            let expand = ledger::find(&mut conn, row.changeset_id, ApplyPhase::Expand).await?;
            let expand_needed = row
                .document
                .get("operations")
                .and_then(Value::as_array)
                .is_some_and(|ops| ops.iter().any(|o| o["phase"] == "expand"));
            if expand_needed && !expand.is_some_and(|e| e.status.is_done()) {
                return Err(AppError::Conflict(
                    "a changeset's contract phase applies only after its expand phase succeeded",
                ));
            }
        }
    }
    Ok(())
}

/// Queues the rows and enqueues the job. Shared by the ungated route and
/// the approved `metadata.changeset_apply` request (`approval_ref` names it).
pub async fn do_apply(
    state: &EngineState,
    body: &ApplyChangesetsBody,
    approval_ref: Option<Uuid>,
) -> Result<ApplyChangesetsAccepted, AppError> {
    check_apply(state, body).await?;
    let backup_ref = body
        .backup_ref
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    ledger::enqueue_apply(state, &body.apply_ids, approval_ref, backup_ref).await?;
    tracing::info!(
        rows = body.apply_ids.len(),
        phase = body.phase.as_str(),
        approval_ref = ?approval_ref,
        "changeset apply queued"
    );
    Ok(ApplyChangesetsAccepted {
        status: ApplyStatus::Queued.as_str().to_owned(),
        apply_ids: body.apply_ids.clone(),
        approval_pending: false,
        approval_request_id: None,
    })
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/changesets/plan",
    tag = "admin-changesets",
    request_body = ChangesetDocumentsBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The plan, in apply order, with the ledger row ids to apply", body = ChangesetPlan),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 409, description = "changeset_checksum_mismatch: a changeset id is in the ledger with a different checksum", body = ErrorResponse),
        (status = 422, description = "A document fails its shape or checksum check, or the order has a cycle", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn plan_changesets(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Json(body): Json<ChangesetDocumentsBody>,
) -> Result<Json<ChangesetPlan>, AppError> {
    let plan_ctx = PlanContext {
        source: ApplySource::Admin,
        requested_by: Some(ctx.user_id),
        trusted: false,
    };
    let mut planned = plan::plan(&state, &body.changesets, plan_ctx).await?;
    let mut stx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "changeset_apply",
            None,
        )
        .named("changeset.plan"),
    )
    .await?;
    plan::persist(stx.tx(), &mut planned, plan_ctx).await?;
    stx.commit().await?;
    Ok(Json(planned.plan))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/changesets/apply",
    tag = "admin-changesets",
    request_body = ApplyChangesetsBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::ApplyChangesets (changeset/apply.rs::Ctx::audit)"), "queues planned ledger rows (behind the metadata.changeset_apply approval where required); the job writes a per-entity Entity audit event for every schema change it applies, as bundle import does")))),
    responses(
        (status = 202, description = "Queued, or an approval request was submitted", body = ApplyChangesetsAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "An apply id is not in the ledger", body = ErrorResponse),
        (status = 409, description = "A row is running or finished, or a contract row's expand phase has not succeeded", body = ErrorResponse),
        (status = 422, description = "backup_ref_required on the production profile, a phase mismatch, a blocked plan, or customer_tests_failed (blocking customer tests failed while customer_tests.require_pass_before_publish is on)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn apply_changesets(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Json(body): Json<ApplyChangesetsBody>,
) -> Result<(StatusCode, Json<ApplyChangesetsAccepted>), AppError> {
    check_apply(&state, &body).await?;
    // Z15-T14: with the guard on, blocking customer tests pass first.
    attome_records::customer_tests::publish_guard(&state, &ctx).await?;
    let payload = serde_json::to_value(&body).map_err(AppError::internal)?;
    if let Some(request) =
        crate::approval_admin::gate(&state, super::ACTION_CHANGESET_APPLY, payload, ctx.user_id)
            .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(ApplyChangesetsAccepted {
                status: ApplyStatus::Planned.as_str().to_owned(),
                apply_ids: body.apply_ids,
                approval_pending: true,
                approval_request_id: Some(request.id),
            }),
        ));
    }
    let accepted = do_apply(&state, &body, None).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/changesets/adopt",
    tag = "admin-changesets",
    request_body = ChangesetDocumentsBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Import)])))),
    responses(
        (status = 200, description = "The changesets recorded as applied (adopted) in this deployment's ledger", body = AdoptResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No local changeset has a document's id", body = ErrorResponse),
        (status = 409, description = "adopt_requires_development, changeset_not_closed, changeset_ops_differ or changeset_checksum_mismatch", body = ErrorResponse),
        (status = 422, description = "A document fails its shape or checksum check", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn adopt_changesets(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<ChangesetDocumentsBody>,
) -> Result<Json<AdoptResponse>, AppError> {
    if !adopt::adopt_allowed(&state.base.config) {
        return Err(AppError::Conflict(adopt::ADOPT_REQUIRES_DEVELOPMENT));
    }
    let mut stx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Import,
            ctx.user_id,
            "changeset_apply",
            None,
        )
        .named("changeset.adopt"),
    )
    .await?;
    let changesets = adopt::adopt(stx.tx(), &body.changesets, ctx.user_id).await?;
    stx.commit().await?;
    Ok(Json(AdoptResponse { changesets }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/changesets/ledger",
    tag = "admin-changesets",
    params(LedgerQuery, OnePageQuery),
    responses(
        (status = 200, description = "Applied-changeset ledger rows, newest first", body = PaginatedResponse<LedgerSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 422, description = "An unknown layer or status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_ledger(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
    Query(filter): Query<LedgerQuery>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<LedgerSummary>>, AppError> {
    if let Some(l) = filter.layer.as_deref()
        && attome_core::changeset::Layer::parse(l).is_none()
    {
        return Err(AppError::Validation(
            "layer: must be platform, product, project or customer".into(),
        ));
    }
    if let Some(s) = filter.status.as_deref()
        && ApplyStatus::parse(s).is_none()
    {
        return Err(AppError::Validation(
            "status: must be planned, queued, claimed, applying, succeeded, failed or adopted"
                .into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let (rows, total) = ledger::list(
        &state.base.db,
        &LedgerFilter {
            layer: filter.layer,
            scope: filter.scope,
            status: filter.status,
        },
        page_size,
        offset,
    )
    .await?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(LedgerSummary::from).collect(),
        total,
        page,
        page_size,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/changesets/ledger/{apply_id}",
    tag = "admin-changesets",
    params(("apply_id" = Uuid, Path, description = "Ledger row id")),
    responses(
        (status = 200, description = "One ledger row with its document, plan and progress", body = LedgerRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such ledger row", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_ledger_row(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
    Path(apply_id): Path<Uuid>,
) -> Result<Json<LedgerRow>, AppError> {
    let row = ledger::get(&state.base.db, apply_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/metadata/changesets/plan",
            post(plan_changesets),
        )
        .route(
            "/api/v1/admin/metadata/changesets/apply",
            post(apply_changesets),
        )
        .route(
            "/api/v1/admin/metadata/changesets/adopt",
            post(adopt_changesets),
        )
        .route("/api/v1/admin/metadata/changesets/ledger", get(list_ledger))
        .route(
            "/api/v1/admin/metadata/changesets/ledger/{apply_id}",
            get(get_ledger_row),
        )
        // D-792: the fleet poll's one call, same bundle and layer.
        .merge(super::rollout_status::routes())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    plan_changesets,
    apply_changesets,
    adopt_changesets,
    list_ledger,
    get_ledger_row
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(super::rollout_status::openapi_fragment());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fragment_documents_every_route_with_its_audit_declaration() {
        let value = serde_json::to_value(openapi_fragment()).expect("serializes");
        for path in [
            "/api/v1/admin/metadata/changesets/plan",
            "/api/v1/admin/metadata/changesets/apply",
            "/api/v1/admin/metadata/changesets/adopt",
            "/api/v1/admin/metadata/changesets/ledger",
            "/api/v1/admin/metadata/changesets/ledger/{apply_id}",
            "/api/v1/admin/metadata/rollout/status",
        ] {
            assert!(value["paths"][path].is_object(), "{path}");
        }
        for path in [
            "/api/v1/admin/metadata/changesets/plan",
            "/api/v1/admin/metadata/changesets/adopt",
        ] {
            let audit = &value["paths"][path]["post"]["x-audit"];
            assert_eq!(audit["events"][0]["category"], "configuration", "{path}");
        }
        assert!(
            value["paths"]["/api/v1/admin/metadata/changesets/apply"]["post"]["x-audit-exempt"]
                .is_object()
        );
    }

    #[test]
    fn the_apply_body_round_trips_through_the_approval_payload() {
        let body = ApplyChangesetsBody {
            apply_ids: vec![Uuid::now_v7()],
            phase: ApplyPhase::Contract,
            backup_ref: Some("snap-1".into()),
        };
        let payload = serde_json::to_value(&body).expect("serializes");
        assert_eq!(payload["phase"], "contract");
        let back: ApplyChangesetsBody = serde_json::from_value(payload).expect("deserializes");
        assert_eq!(back.apply_ids, body.apply_ids);
        assert_eq!(back.backup_ref.as_deref(), Some("snap-1"));
    }
}
