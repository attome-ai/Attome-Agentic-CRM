//! M03 (Security & Identity) gap 1 / D-434 — access review campaigns.
//!
//! A campaign (`access_review`) names one population of currently-held
//! grants to re-certify: every direct role holder of one role
//! (`scope = "role"`), every member of one team (`scope = "team"`), or every
//! user-principal record share on one entity (`scope = "entity_share"`).
//! Creating a campaign snapshots that population into one
//! `access_review_item` row per grant — the population is resolved
//! once, at creation time, never re-derived later, so an item's meaning
//! never shifts under a reviewer mid-campaign.
//!
//! **Decisions reuse `attome-approval` (D-195), not a bespoke decision table.**
//! Each item's `approval_request_ref` names one `approval_request`
//! row whose `requested_by` is set to the *subject* of that grant — not the
//! campaign's creator. That is deliberate: `attome_approval::decide`'s
//! separation-of-duties check (`approver_id != requested_by`) then makes "a
//! reviewer cannot decide their own access" a property of the same tested
//! code path every other four-eyes flow in this codebase already relies on,
//! instead of a second hand-written self-review guard that could drift from
//! it. `Decision::Approve` maps to `keep` (no action); `Decision::Reject`
//! maps to `revoke` (the underlying grant is removed, see
//! [`execute_revoke`]).
//!
//! **Reviewer resolution is informational, not the authorization boundary.**
//! `reviewer_user_ref` names the subject's manager via the existing F138
//! position hierarchy (`resolve_manager` below) purely for display/routing —
//! consistent with every other surface in this file, every route here is
//! gated on the coarse `system.admin` privilege (security-model skill: "a
//! scope choice, not a gap"), not on whether the caller matches this field.
//! What IS enforced, unconditionally, is that the decider is never the
//! subject themselves (via `attome_approval::decide`, above).

use attome_approval::{ApprovalStatus, Decision};
use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::shared::resolve_entity_ref;

/// A campaign population larger than this is refused at creation
/// (`Validation`) rather than accepted and processed inline — guidelines §9's
/// "bounded batch sizes" for a synchronous request-thread operation. A real
/// access-review population (role holders, team members, shares on one
/// entity) is expected to be one to a few hundred rows; a deployment that
/// genuinely needs more should scope the campaign more narrowly (e.g. by
/// entity rather than a blanket review) rather than this limit being raised
/// casually.
const MAX_CAMPAIGN_ITEMS: i64 = 2_000;

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateAccessReviewBody {
    name: String,
    /// `"role"`, `"team"`, or `"entity_share"`.
    scope: String,
    #[serde(default)]
    scope_role_id: Option<Uuid>,
    #[serde(default)]
    scope_team_id: Option<Uuid>,
    #[serde(default)]
    scope_entity: Option<String>,
    due_date: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct AccessReviewItem {
    id: Uuid,
    subject_user_id: Uuid,
    grant_id: Uuid,
    reviewer_user_id: Option<Uuid>,
    approval_request_id: Uuid,
    decision: Option<String>,
    decided_by: Option<Uuid>,
    decided_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    /// Q11-T1: why the reviewer kept or revoked it.
    decision_reason: Option<String>,
}

impl std::fmt::Debug for AccessReviewItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessReviewItem").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct AccessReviewCampaign {
    id: Uuid,
    name: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_role_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_team_id: Option<Uuid>,
    /// `entity_info.id` (real FK — see this module's doc comment),
    /// not the entity's logicalname; resolve via the entities admin API for
    /// display.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_entity_id: Option<Uuid>,
    due_date: DateTime<Utc>,
    status: String,
    item_count: i64,
    decided_count: i64,
    created_by: Uuid,
    created_at: DateTime<Utc>,
}

impl std::fmt::Debug for AccessReviewCampaign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessReviewCampaign")
            .finish_non_exhaustive()
    }
}

/// One `(grant row id, subject user id)` pair for whichever scope table the
/// campaign names — the population `create_access_review` snapshots into
/// items.
async fn resolve_population(
    db: &attome_db::DbPool,
    scope: &str,
    scope_role_id: Option<Uuid>,
    scope_team_id: Option<Uuid>,
    scope_entity_ref: Option<Uuid>,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    match scope {
        "role" => {
            let role_id = scope_role_id.ok_or_else(|| {
                AppError::Validation("scope_role_id is required for scope 'role'".into())
            })?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM role WHERE id = $1 AND is_deleted = false)",
            )
            .bind(role_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if !exists {
                return Err(AppError::Validation(
                    "no active role found with this scope_role_id".into(),
                ));
            }
            sqlx::query_as(
                "SELECT id, user_ref FROM user_account_mm_role \
                 WHERE role_ref = $1 AND is_deleted = false ORDER BY created_at",
            )
            .bind(role_id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)
        }
        "team" => {
            let team_id = scope_team_id.ok_or_else(|| {
                AppError::Validation("scope_team_id is required for scope 'team'".into())
            })?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM team WHERE id = $1 AND is_deleted = false)",
            )
            .bind(team_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if !exists {
                return Err(AppError::Validation(
                    "no active team found with this scope_team_id".into(),
                ));
            }
            sqlx::query_as(
                "SELECT id, user_ref FROM user_account_mm_team \
                 WHERE team_ref = $1 AND is_deleted = false ORDER BY created_at",
            )
            .bind(team_id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)
        }
        "entity_share" => {
            let entity_ref = scope_entity_ref.ok_or_else(|| {
                AppError::Validation("scope_entity is required for scope 'entity_share'".into())
            })?;
            // principal_type = 0 (user) only — a team-principal share has no
            // single "subject" to review individually here; capability IN
            // (0, 1) (view/action) only — a deny row (2) is not an access
            // grant to re-certify.
            sqlx::query_as(
                "SELECT id, principal_id FROM record_share \
                 WHERE entity_ref = $1 AND principal_type = 0 AND capability IN (0, 1) \
                 ORDER BY granted_at NULLS LAST",
            )
            .bind(entity_ref)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)
        }
        other => Err(AppError::Validation(format!(
            "scope must be 'role', 'team', or 'entity_share', got '{other}'"
        ))),
    }
}

/// F138 position-hierarchy manager of `subject_user_id`: the first active
/// holder of the parent of any position `subject_user_id` holds. `None` when
/// the subject holds no position, their position has no parent, or the
/// parent position currently has no holder — informational only (see this
/// module's doc comment), so an absent manager never blocks item creation.
async fn resolve_manager(
    db: &attome_db::DbPool,
    subject_user_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let manager: Option<Uuid> = sqlx::query_scalar(
        "SELECT holder.user_ref \
         FROM user_account_mm_position subject_pos \
         JOIN position pos ON pos.id = subject_pos.position_ref AND pos.is_deleted = false \
         JOIN user_account_mm_position holder \
             ON holder.position_ref = pos.parent_position_ref AND holder.is_deleted = false \
         WHERE subject_pos.user_ref = $1 AND subject_pos.is_deleted = false \
           AND pos.parent_position_ref IS NOT NULL \
         ORDER BY holder.created_at \
         LIMIT 1",
    )
    .bind(subject_user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(manager)
}

/// Start an access review
///
/// Opens an access review campaign over one role's holders, one team's members or one entity's user shares: one item per grant held now, to keep or revoke. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/access-reviews",
    tag = "admin-security",
    request_body = CreateAccessReviewBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = AccessReviewCampaign),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_access_review(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateAccessReviewBody>,
) -> Result<(StatusCode, Json<AccessReviewCampaign>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    if body.due_date <= Utc::now() {
        return Err(AppError::Validation(
            "due_date must be in the future".into(),
        ));
    }

    // Resolved once, upfront: access_review.scope_entity_ref is a
    // real FK (see this file's migration/doc comment) — the caller's
    // logicalname is only ever meaningful as input, never stored.
    let scope_entity_ref = match body.scope_entity.as_deref() {
        Some(logicalname) => Some(resolve_entity_ref(&state.base.db, logicalname).await?),
        None => None,
    };

    let population = resolve_population(
        &state.base.db,
        &body.scope,
        body.scope_role_id,
        body.scope_team_id,
        scope_entity_ref,
    )
    .await?;
    if population.len() as i64 > MAX_CAMPAIGN_ITEMS {
        return Err(AppError::Validation(format!(
            "this campaign's population ({} grants) exceeds the {MAX_CAMPAIGN_ITEMS}-item limit — \
             scope the campaign more narrowly",
            population.len()
        )));
    }

    let review_id = Uuid::now_v7();
    let ttl = body.due_date - Utc::now();
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "access_review",
        Some(review_id),
    )
    .await?;
    sqlx::query(
        "INSERT INTO access_review \
             (id, name, scope, scope_role_ref, scope_team_ref, scope_entity_ref, \
              due_date, status, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8)",
    )
    .bind(review_id)
    .bind(name)
    .bind(&body.scope)
    .bind(body.scope_role_id)
    .bind(body.scope_team_id)
    .bind(scope_entity_ref)
    .bind(body.due_date)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    // Item creation loops sequentially (bounded by MAX_CAMPAIGN_ITEMS above)
    // rather than batching every INSERT into one statement — each item also
    // submits its own attome_approval request, which is itself a multi-step
    // transaction (advisory lock + insert), so there is no single query to
    // batch this into. A real campaign population is small enough (a few
    // hundred rows at most) for this to be an acceptable one-time cost on
    // the admin's create request.
    for (grant_id, subject_user_id) in population {
        let reviewer = resolve_manager(&state.base.db, subject_user_id).await?;
        let payload = serde_json::json!({
            "review_id": review_id,
            "scope": body.scope,
            "grant_id": grant_id,
            "subject_user_id": subject_user_id,
        });
        let request = attome_approval::submit(
            &state.base.db,
            "security.access_review_item",
            payload,
            subject_user_id,
            1,
            ttl,
        )
        .await?;

        sqlx::query(
            "INSERT INTO access_review_item \
                 (id, review_ref, subject_user_ref, grant_ref, reviewer_user_ref, \
                  approval_request_ref) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(review_id)
        .bind(subject_user_id)
        .bind(grant_id)
        .bind(reviewer)
        .bind(request.id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }

    let campaign = fetch_campaign(&state.base.db, review_id)
        .await?
        .ok_or_else(|| AppError::internal("access review vanished immediately after insert"))?;
    Ok((StatusCode::CREATED, Json(campaign)))
}

async fn fetch_campaign(
    db: &attome_db::DbPool,
    review_id: Uuid,
) -> Result<Option<AccessReviewCampaign>, AppError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        Uuid,
        String,
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        DateTime<Utc>,
        String,
        Uuid,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, name, scope, scope_role_ref, scope_team_ref, scope_entity_ref, \
                due_date, status, created_by, created_at \
         FROM access_review WHERE id = $1 AND is_deleted = false",
    )
    .bind(review_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((
        id,
        name,
        scope,
        scope_role_id,
        scope_team_id,
        scope_entity_id,
        due_date,
        status,
        created_by,
        created_at,
    )) = row
    else {
        return Ok(None);
    };

    let item_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_review_item WHERE review_ref = $1")
            .bind(review_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let decided_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM access_review_item \
         WHERE review_ref = $1 AND decision IS NOT NULL",
    )
    .bind(review_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(Some(AccessReviewCampaign {
        id,
        name,
        scope,
        scope_role_id,
        scope_team_id,
        scope_entity_id,
        due_date,
        status,
        item_count,
        decided_count,
        created_by,
        created_at,
    }))
}

/// List access reviews
///
/// Every access review campaign and its status. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/access-reviews",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AccessReviewCampaign>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_access_reviews(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AccessReviewCampaign>>, AppError> {
    let window = query.window();

    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM access_review WHERE is_deleted = false \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_review WHERE is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(campaign) = fetch_campaign(&state.base.db, id).await? {
            items.push(campaign);
        }
    }
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// One access review
///
/// One access review campaign: its scope and status. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/access-reviews/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The access review")),
    responses(
        (status = 200, description = "Success", body = AccessReviewCampaign),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such access review", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_access_review(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(review_id): Path<Uuid>,
) -> Result<Json<AccessReviewCampaign>, AppError> {
    fetch_campaign(&state.base.db, review_id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// An access review's items
///
/// The grants under review in a campaign, each with its decision so far. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/access-reviews/{id}/items",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The access review"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AccessReviewItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_access_review_items(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(review_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AccessReviewItem>>, AppError> {
    let window = query.window();

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        Uuid,
        Uuid,
        Option<Uuid>,
        Uuid,
        Option<String>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, subject_user_ref, grant_ref, reviewer_user_ref, approval_request_ref, \
                decision, decided_by, decided_at, revoked_at, decision_reason \
         FROM access_review_item WHERE review_ref = $1 \
         ORDER BY created_at LIMIT $2 OFFSET $3",
    )
    .bind(review_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_review_item WHERE review_ref = $1")
            .bind(review_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                subject_user_id,
                grant_id,
                reviewer_user_id,
                approval_request_id,
                decision,
                decided_by,
                decided_at,
                revoked_at,
                decision_reason,
            )| AccessReviewItem {
                id,
                subject_user_id,
                grant_id,
                reviewer_user_id,
                approval_request_id,
                decision,
                decided_by,
                decided_at,
                revoked_at,
                decision_reason,
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct DecideAccessReviewItemBody {
    /// `"keep"` or `"revoke"`.
    decision: String,
    /// Q11-T1: why, up to 1000 characters; kept on the item and in the
    /// decision's audit event.
    #[serde(default)]
    reason: Option<String>,
}

/// Q11-T1: a decision's reason, trimmed; empty is none. Pure.
fn checked_reason(reason: Option<&str>) -> Result<Option<String>, AppError> {
    match reason.map(str::trim).filter(|r| !r.is_empty()) {
        None => Ok(None),
        Some(r) if r.chars().count() <= 1_000 => Ok(Some(r.to_owned())),
        Some(_) => Err(AppError::Validation(
            "reason is at most 1000 characters".into(),
        )),
    }
}

/// One already-reviewed item's row, minus decision fields — what
/// `decide_access_review_item` needs before calling `attome_approval::decide`.
#[derive(sqlx::FromRow)]
struct ItemForDecide {
    review_ref: Uuid,
    subject_user_ref: Uuid,
    grant_ref: Uuid,
    reviewer_user_ref: Option<Uuid>,
    approval_request_ref: Uuid,
    decision: Option<String>,
}

/// Executes the actual revoke once an item's decision is `revoke` — soft-
/// deletes the underlying grant row for whichever table `scope` names, the
/// same idempotent `UPDATE ... WHERE is_deleted = false` shape
/// `user_roles::remove_user_role`/`teams::remove_team_member` already use.
/// **Idempotent**: called again on an already-revoked grant (`is_deleted`
/// already true, or the record-share row already deleted) finds zero rows
/// and returns `Ok(())` rather than erroring — safe to call more than once
/// for the same item, which is exactly what happens if a caller retries a
/// decide request after a network timeout whose first attempt actually
/// landed.
async fn execute_revoke<'c, E>(
    db: E,
    scope: &str,
    grant_ref: Uuid,
    subject_user_ref: Uuid,
) -> Result<(), AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    match scope {
        "role" => {
            sqlx::query(
                "UPDATE user_account_mm_role SET is_deleted = true, updated_at = NOW() \
                 WHERE id = $1 AND is_deleted = false",
            )
            .bind(grant_ref)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
        "team" => {
            sqlx::query(
                "UPDATE user_account_mm_team SET is_deleted = true, updated_at = NOW() \
                 WHERE id = $1 AND is_deleted = false",
            )
            .bind(grant_ref)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
        "entity_share" => {
            sqlx::query("DELETE FROM record_share WHERE id = $1")
                .bind(grant_ref)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
        }
        other => {
            return Err(AppError::internal(format!(
                "access review item carries an unknown scope '{other}'"
            )));
        }
    }
    let _ = subject_user_ref; // invalidation happens in the caller, once
    Ok(())
}

/// Decide an access review item
///
/// Keeps or revokes one grant under review, through the approval engine: nobody decides their own access, and a revoke removes the grant. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/access-reviews/{id}/items/{item_id}/decide",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The access review"), ("item_id" = Uuid, Path, description = "The review item")),
    request_body = DecideAccessReviewItemBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update), (AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 200, description = "Success", body = AccessReviewItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or is the item's own subject", body = ErrorResponse),
        (status = 404, description = "No such access review item", body = ErrorResponse),
        (status = 409, description = "This item was already decided", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn decide_access_review_item(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((review_id, item_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<DecideAccessReviewItemBody>,
) -> Result<Json<AccessReviewItem>, AppError> {
    let decision = match body.decision.as_str() {
        "keep" => Decision::Approve,
        "revoke" => Decision::Reject,
        other => {
            return Err(AppError::Validation(format!(
                "decision must be 'keep' or 'revoke', got '{other}'"
            )));
        }
    };
    let reason = checked_reason(body.reason.as_deref())?;

    let item: Option<ItemForDecide> = sqlx::query_as(
        "SELECT review_ref, subject_user_ref, grant_ref, reviewer_user_ref, \
                approval_request_ref, decision \
         FROM access_review_item WHERE id = $1 AND review_ref = $2",
    )
    .bind(item_id)
    .bind(review_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let item = item.ok_or(AppError::NotFound)?;
    if item.decision.is_some() {
        return Err(AppError::Conflict(
            "this access review item was already decided",
        ));
    }

    let scope: String = sqlx::query_scalar("SELECT scope FROM access_review WHERE id = $1")
        .bind(item.review_ref)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;

    // Reads the request fresh to get its current row_version — `decide`'s
    // own advisory lock + row_version CAS is what actually makes this safe
    // under concurrency (a lost race here surfaces as `VersionConflict`, not
    // a corrupted decision); this is not itself the concurrency guard.
    let request = attome_approval::get(&state.base.db, item.approval_request_ref).await?;
    // Separation-of-duties (the required negative-path property: "reviewer
    // cannot review their own access") is enforced by `decide` itself —
    // `request.requested_by` was set to the item's subject at creation time
    // (see create_access_review), so `decide` returns `Forbidden` here
    // whenever `ctx.user_id == subject_user_id`, with no separate check
    // needed on this side.
    let decided_request = attome_approval::decide(
        &state.base.db,
        item.approval_request_ref,
        ctx.user_id,
        decision,
        request.row_version,
    )
    .await?;

    let decision_str = match decision {
        Decision::Approve => "keep",
        Decision::Reject => "revoke",
    };
    // Audit plan 3.3: the recorded decision, any revocation it causes, and
    // their mandatory `Access` events commit together. The approval decision
    // above is `attome_approval`'s own transaction (a base-layer crate that
    // cannot take the audit writer).
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "access_review_item",
        Some(item_id),
    )
    .await?;
    tx.event_mut()
        .set_event_name(format!("access_review_decision:{decision_str}"));
    if let Some(reason) = &reason {
        tx.event_mut().set_comment(reason.clone());
    }
    sqlx::query(
        "UPDATE access_review_item \
         SET decision = $1, decided_by = $2, decided_at = NOW(), decision_reason = $4, \
             row_version = row_version + 1 \
         WHERE id = $3 AND decision IS NULL",
    )
    .bind(decision_str)
    .bind(ctx.user_id)
    .bind(item_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mut revoked_at = None;
    let revoked = decided_request.status == ApprovalStatus::Rejected;
    if revoked {
        execute_revoke(&mut *tx, &scope, item.grant_ref, item.subject_user_ref).await?;
        sqlx::query(
            "UPDATE access_review_item SET revoked_at = NOW() \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(item_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let revoke_event = attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Access,
            AuditOperation::Revoke,
            ctx.user_id,
            match scope.as_str() {
                "role" => "user_account_mm_role",
                "team" => "user_account_mm_team",
                _ => "record_share",
            },
            Some(item.grant_ref),
        )
        .named("access_review_revoke");
        attome_audit::security::write_security_event(
            tx.tx(),
            &attome_audit::audit_service(&state),
            revoke_event,
        )
        .await?;
        revoked_at = Some(Utc::now());
    }
    tx.commit().await?;
    if revoked {
        state
            .base
            .security
            .invalidate_sync(item.subject_user_ref)
            .await?;
    }

    Ok(Json(AccessReviewItem {
        id: item_id,
        subject_user_id: item.subject_user_ref,
        grant_id: item.grant_ref,
        reviewer_user_id: item.reviewer_user_ref,
        approval_request_id: item.approval_request_ref,
        decision: Some(decision_str.to_string()),
        decided_by: Some(ctx.user_id),
        decided_at: Some(Utc::now()),
        revoked_at,
        decision_reason: reason,
    }))
}

/// M03 gap 1 / D-434 — scheduled sweep: auto-completes an `active` campaign
/// once its `due_date` has passed, whatever state its items are in. Bare,
/// re-derive-current-state shape (same convention as
/// `attome_workflow::sla_sweep::sweep`/`attome_compliance::retention::
/// propose_retention_actions`) — a retry after a crash just re-scans the
/// same `(status, due_date)`-indexed predicate rather than replaying an
/// enqueue-time snapshot. Deliberately does not touch any item — an
/// undecided item on a completed campaign stays undecided, visible to an
/// operator via `list_access_review_items`, not silently auto-revoked (an
/// unreviewed grant defaulting to "revoke" would be a far riskier failure
/// mode than one defaulting to "still needs a human").
pub async fn sweep_due_campaigns(db: &attome_db::DbPool) -> Result<u64, AppError> {
    let result = sqlx::query(
        "UPDATE access_review SET status = 'completed', updated_at = NOW(), \
             row_version = row_version + 1 \
         WHERE status = 'active' AND is_deleted = false AND due_date <= NOW()",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(result.rows_affected())
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/access-reviews",
            get(list_access_reviews).post(create_access_review),
        )
        .route(
            "/api/v1/admin/security/access-reviews/{id}",
            get(get_access_review),
        )
        .route(
            "/api/v1/admin/security/access-reviews/{id}/items",
            get(list_access_review_items),
        )
        .route(
            "/api/v1/admin/security/access-reviews/{id}/items/{item_id}/decide",
            post(decide_access_review_item),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_access_review,
    list_access_reviews,
    get_access_review,
    list_access_review_items,
    decide_access_review_item
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_review_reason_is_trimmed_and_bounded() {
        assert_eq!(checked_reason(None).unwrap(), None);
        assert_eq!(checked_reason(Some("  ")).unwrap(), None);
        assert_eq!(
            checked_reason(Some(" left the team ")).unwrap().as_deref(),
            Some("left the team")
        );
        assert!(checked_reason(Some(&"x".repeat(1001))).is_err());
    }
}
