//! Direct user↔role assignment (D-111's user_account_mm_role, admin
//! surface added post-D-134) ─────────────────────────────────────────────────
//! D-134 shipped everything else in Phase 4 (roles.access_level, teams,
//! record/entity-default shares) but left direct user→role assignment
//! reachable only through the team-mediated path (`teams::add_team_role`) or
//! raw SQL — every integration test that needed a direct assignment used to
//! say so explicitly in its own comment ("no per-user role-assignment
//! endpoint exists yet"). This closes that gap with the same shape as every
//! other assignment endpoint here (idempotent upsert via the table's unique
//! constraint, `invalidate_sync` on the affected user, `system.admin` gate).

use attome_audit::security::x_audit;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use attome_types::{OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct UserRoleItem {
    id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    role_name: String,
}

impl std::fmt::Debug for UserRoleItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRoleItem").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct AssignUserRoleBody {
    role_id: Uuid,
    /// Q10-T6: when the grant ends (it is removed then, ending the user's
    /// sessions); absent means it does not end. Must be in the future.
    #[serde(default)]
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Q10-T6: why the role was given.
    #[serde(default)]
    reason: Option<String>,
}

/// D-195/P-four-eyes-approval §5 step 9 — the `action_type` string for direct
/// user->role assignment. The gate is the shared `attome_audit::approval::gate`
/// (ARCH-5 moved it down from `attome-server`, where this crate could not
/// reach it and carried a line-for-line duplicate); dispatch stays in
/// `attome_server::approval_admin::execute_approved`, which calls
/// `do_assign_user_role` below by name, because `attome-server` depends on
/// `attome-security` and never the reverse.
pub const ACTION_ROLE_GRANT: &str = "security.role_grant";

#[derive(Serialize, ToSchema)]
pub(super) struct AssignUserRoleResponse {
    /// `None` when this call only submitted a four-eyes approval request —
    /// mirrors `retention_admin::ActionTransitionResult`'s
    /// `approval_pending`/`approval_request_id` pair.
    id: Option<Uuid>,
    user_id: Uuid,
    role_id: Uuid,
    role_name: Option<String>,
    approval_pending: bool,
    approval_request_id: Option<Uuid>,
}

/// A user's roles
///
/// Lists roles directly assigned to `user_id` via `user_account_mm_role`
/// only — team-mediated roles (`role_mm_team` via
/// `user_account_mm_team`, unioned in by `resolve_entity_access_level`/
/// `resolve_privileges`) are a separate path, visible instead through
/// `teams::list_team_roles` (`/teams/{id}/roles`).
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/users/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<UserRoleItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_user_roles(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<UserRoleItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT ur.id, ur.role_ref, r.name \
         FROM user_account_mm_role ur \
         JOIN role r ON r.id = ur.role_ref \
         WHERE ur.user_ref = $1 AND ur.is_deleted = false \
         ORDER BY r.name LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account_mm_role WHERE user_ref = $1 AND is_deleted = false",
    )
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, role_id, role_name)| UserRoleItem {
            id,
            user_id,
            role_id,
            role_name,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// The real mutation, factored out so `assign_user_role` (the direct,
/// un-gated path) and `attome-server::approval_admin::execute_approved` (the
/// approved-and-executed path) call the exact same code — one execution
/// path per action, same convention as `retention_admin::
/// do_approve_retention_action`/`rewrap_admin::do_trigger_rewrap`.
///
/// Audit plan 3.3 (D-542 rule 4): `event` is required — build it with
/// [`role_grant_event`] — and is written in the assignment's own transaction,
/// so neither path can assign a role without its `Access` + `Grant` event.
pub async fn do_assign_user_role(
    state: &EngineState,
    user_id: Uuid,
    role_id: Uuid,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<&str>,
    event: SecurityEvent,
) -> Result<UserRoleItem, AppError> {
    crate::grant_expiry::valid_end(valid_until, chrono::Utc::now())?;
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !user_exists {
        return Err(AppError::NotFound);
    }

    let role_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM role WHERE id = $1 AND is_deleted = false")
            .bind(role_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let role_name = role_name
        .ok_or_else(|| AppError::Validation("no active role found with this role_id".into()))?;

    let mut tx = SecurityTx::begin(state, event).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_account_mm_role (id, user_ref, role_ref, valid_until, grant_reason) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (user_ref, role_ref) DO UPDATE SET is_deleted = false, updated_at = NOW(), \
             valid_until = EXCLUDED.valid_until, grant_reason = EXCLUDED.grant_reason \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(role_id)
    .bind(valid_until)
    .bind(reason.map(str::trim).filter(|r| !r.is_empty()))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;

    Ok(UserRoleItem {
        id,
        user_id,
        role_id,
        role_name,
    })
}

/// The `Access` + `Grant` event [`do_assign_user_role`] requires, naming the
/// acting administrator (the approver, on the four-eyes path).
pub fn role_grant_event(actor_user_id: Uuid) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Access,
        AuditOperation::Grant,
        actor_user_id,
        "user_account_mm_role",
        None,
    )
}

/// What [`grant_role_as`] did.
#[derive(Debug)]
pub enum RoleGrantOutcome {
    /// The role is the user's now.
    Assigned(UserRoleItem),
    /// Waiting for a second administrator (D-195), as this approval request.
    Pending(Uuid),
}

/// L4-T4: the one way to give a user a role on a granter's say: the
/// role-change step-up for a session caller, the grant ceiling (no role
/// carrying privileges the granter lacks, Q12-T3), the D-195 approval gate,
/// then [`do_assign_user_role`] with its `Access` + `Grant` event. The admin
/// route and the data catalog's access decision both grant through it, so
/// neither skips a check.
pub async fn grant_role_as(
    state: &EngineState,
    caller: attome_auth::step_up::Caller,
    granter: &attome_server::security::SecurityContext,
    user_id: Uuid,
    role_id: Uuid,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<&str>,
) -> Result<RoleGrantOutcome, AppError> {
    role_change_step_up(state, caller, granter.user_id).await?;
    crate::grant_expiry::valid_end(valid_until, chrono::Utc::now())?;
    crate::grants::require_role_within_ceiling(&state.base.db, granter, role_id).await?;
    let payload = serde_json::json!({
        "user_id": user_id,
        "role_id": role_id,
        "valid_until": valid_until,
        "reason": reason,
    });
    if let Some(request) =
        attome_audit::approval::gate(state, ACTION_ROLE_GRANT, payload, granter.user_id).await?
    {
        return Ok(RoleGrantOutcome::Pending(request.id));
    }
    let item = do_assign_user_role(
        state,
        user_id,
        role_id,
        valid_until,
        reason,
        role_grant_event(granter.user_id),
    )
    .await?;
    Ok(RoleGrantOutcome::Assigned(item))
}

/// Assigns `role_id` directly to `user_id` — the single-user counterpart to
/// `teams::add_team_role` (role → every current/future team member).
/// Idempotent via `user_account_mm_role`'s `(user_ref, role_ref)` unique
/// constraint (migration 0040): re-assigning an already-held role reactivates
/// a previously soft-deleted row instead of erroring.
///
/// D-195: gated behind `approval.required_actions` (empty/off by default,
/// same opt-in shape as every other wired action). When gated, submits an
/// approval request for `{user_id, role_id}` instead of assigning anything
/// and returns `202` with `approval_pending: true` — the actual assignment
/// only happens once a different `system.admin` approves it
/// (`do_assign_user_role` via `execute_approved`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user")),
    request_body = AssignUserRoleBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = AssignUserRoleResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn assign_user_role(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AssignUserRoleBody>,
) -> Result<(StatusCode, Json<AssignUserRoleResponse>), AppError> {
    // Step-up, the Q12-T3 ceiling and the D-195 gate, in one shared path.
    let item = match grant_role_as(
        &state,
        caller,
        &ctx,
        user_id,
        body.role_id,
        body.valid_until,
        body.reason.as_deref(),
    )
    .await?
    {
        RoleGrantOutcome::Pending(request) => {
            return Ok((
                StatusCode::ACCEPTED,
                Json(AssignUserRoleResponse {
                    id: None,
                    user_id,
                    role_id: body.role_id,
                    role_name: None,
                    approval_pending: true,
                    approval_request_id: Some(request),
                }),
            ));
        }
        RoleGrantOutcome::Assigned(item) => item,
    };
    Ok((
        StatusCode::CREATED,
        Json(AssignUserRoleResponse {
            id: Some(item.id),
            user_id: item.user_id,
            role_id: item.role_id,
            role_name: Some(item.role_name),
            approval_pending: false,
            approval_request_id: None,
        }),
    ))
}

/// Take a role from a user
///
/// Revokes a direct role assignment (soft-delete). Team-mediated access to
/// the same role, if any, is untouched — see `teams::remove_team_role` for
/// that path.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/users/{id}/roles/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The user"),
        ("role_id" = Uuid, Path, description = "The role"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn remove_user_role(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    role_change_step_up(&state, caller, ctx.user_id).await?;
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "user_account_mm_role",
        None,
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account_mm_role SET is_deleted = true, updated_at = NOW() \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false RETURNING id",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut()
        .set_record_id(removed.ok_or(AppError::NotFound)?);
    // Q8-T7: losing a role ends the user's sessions everywhere, in this same
    // transaction: refresh families revoked and the auth epoch bumped, so a
    // live access token is refused at its next request.
    attome_auth::refresh::revoke_all_for_user_in_tx(tx.tx(), user_id).await?;
    attome_auth::epoch::bump_in_tx(tx.tx(), user_id).await?;
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, user_id).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Q5-T7: with `auth.step_up_phishing_resistant` on, a session that grants
/// or takes a role needs a fresh passkey step-up (`role_change`). API-key and
/// S2S callers have no session to step up with, so they keep the access their
/// key gives (the task's stop condition, decided in V2-D).
async fn role_change_step_up(
    state: &EngineState,
    caller: attome_auth::step_up::Caller,
    actor: Uuid,
) -> Result<(), AppError> {
    if !state.base.config.auth.step_up_phishing_resistant
        || !matches!(caller, attome_auth::step_up::Caller::Session(_))
    {
        return Ok(());
    }
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        actor,
        attome_auth::step_up::Operation::RoleChange,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/users/{id}/roles",
            get(list_user_roles).post(assign_user_role),
        )
        .route(
            "/api/v1/admin/security/users/{id}/roles/{role_id}",
            axum::routing::delete(remove_user_role),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_user_roles, assign_user_role, remove_user_role))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
