//! Q14-T1: a user shares a record they can reach, without admin rights.
//!
//! `GET/POST /api/v1/{entity}/{id}/shares` and
//! `DELETE /api/v1/{entity}/{id}/shares/{share_id}` need the entity's
//! `{entity}.share` privilege (seeded beside the CRUD verbs) and access to
//! the record itself, and never let a sharer give more than they hold: a
//! `view` share needs read access to the record, an `action` share update
//! access. `deny` rows and the creator's own share stay admin business
//! (`/api/v1/admin/security/record-shares`). Every grant and revoke is a
//! security event in the same transaction.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_security::record_action::Share;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::access::require_record_access;
use super::resolve::resolve_entity;

/// `record_share` as listed: id, principal type and id, capability,
/// granted by, granted at.
type ShareRow = (Uuid, i16, Uuid, i16, Option<Uuid>, DateTime<Utc>);

/// Most shares one record lists.
pub const MAX_RECORD_SHARES: i64 = 200;

/// One share on a record.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordShare {
    pub id: Uuid,
    /// `user` or `team`.
    pub principal_type: &'static str,
    pub principal_id: Uuid,
    /// `view` or `action` (`deny` rows are listed too, read-only).
    pub capability: &'static str,
    pub granted_by: Option<Uuid>,
    pub granted_at: DateTime<Utc>,
}

/// `POST /api/v1/{entity}/{id}/shares`: exactly one of `user_id` and
/// `team_id`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ShareRecordBody {
    /// `view` or `action`.
    pub capability: String,
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

fn capability_str(level: i16) -> &'static str {
    match level {
        0 => "view",
        1 => "action",
        2 => "deny",
        _ => "unknown",
    }
}

/// The capability a sharer asks to give, and the record access that
/// level needs: nobody gives more than they hold.
pub fn requested_capability(capability: &str) -> Result<(i16, RecordAction), AppError> {
    match capability {
        "view" => Ok((0, RecordAction::Read)),
        "action" => Ok((1, RecordAction::Update)),
        "deny" => Err(AppError::Forbidden),
        other => Err(AppError::Validation(format!(
            "capability must be 'view' or 'action', got '{other}'"
        ))),
    }
}

async fn principal(
    state: &EngineState,
    body: &ShareRecordBody,
    sharer: Uuid,
) -> Result<(i16, Uuid), AppError> {
    match (body.user_id, body.team_id) {
        (Some(user), None) => {
            if user == sharer {
                return Err(AppError::Validation(
                    "a record cannot be shared with yourself".into(),
                ));
            }
            let active: Option<bool> =
                sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
                    .bind(user)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
            match active {
                Some(true) => Ok((0, user)),
                _ => Err(AppError::Validation("no active user with that id".into())),
            }
        }
        (None, Some(team)) => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM team WHERE id = $1 AND is_deleted = false)",
            )
            .bind(team)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if exists {
                Ok((1, team))
            } else {
                Err(AppError::Validation("no team with that id".into()))
            }
        }
        _ => Err(AppError::Validation(
            "specify exactly one of user_id or team_id".into(),
        )),
    }
}

async fn reachable(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    action: RecordAction,
) -> Result<(Uuid, String), AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(state, entity_input).await?;
    require_record_access(state, ctx, entity_id, &entity_name, record_id, action).await?;
    Ok((entity_id, entity_name))
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/shares",
    tag = "entity",
    operation_id = "list_record_shares_for_record",
    description = "The record's shares, newest first (Q14-T1). Needs `{entity}.share` and read access to the record.",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The record's shares (page 1 holds them all)", body = PaginatedResponse<RecordShare>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's share privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_shares(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Share>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
) -> Result<Json<PaginatedResponse<RecordShare>>, AppError> {
    let (entity_id, _) =
        reachable(&state, &ctx, &entity_input, record_id, RecordAction::Read).await?;
    let rows: Vec<ShareRow> = sqlx::query_as(
        "SELECT id, principal_type, principal_id, capability, granted_by, granted_at \
         FROM record_share WHERE record_id = $1 AND entity_ref = $2 \
         ORDER BY granted_at DESC, id DESC LIMIT $3",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(MAX_RECORD_SHARES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<RecordShare> = rows
        .into_iter()
        .map(
            |(id, principal_type, principal_id, capability, granted_by, granted_at)| RecordShare {
                id,
                principal_type: if principal_type == 0 { "user" } else { "team" },
                principal_id,
                capability: capability_str(capability),
                granted_by,
                granted_at,
            },
        )
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_RECORD_SHARES,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/shares",
    tag = "entity",
    operation_id = "share_record",
    description = "Shares the record with a user or a team (Q14-T1). Needs `{entity}.share`; a `view` share needs read access to the record and an `action` share update access, so nobody gives more than they hold.",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = ShareRecordBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "The share", body = RecordShare),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the share privilege, or asks for `deny`", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller lacks the access the share would give", body = ErrorResponse),
        (status = 422, description = "Unknown capability or principal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn share_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Share>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Json(body): Json<ShareRecordBody>,
) -> Result<(StatusCode, Json<RecordShare>), AppError> {
    let (capability, needs) = requested_capability(body.capability.trim())?;
    let (entity_id, entity_name) = reachable(&state, &ctx, &entity_input, record_id, needs).await?;
    let (principal_type, principal_id) = principal(&state, &body, ctx.user_id).await?;

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Grant,
            ctx.user_id,
            &entity_name,
            Some(record_id),
        )
        .named("record.share")
        .comment(format!(
            "shared {} with {} {principal_id}",
            capability_str(capability),
            if principal_type == 0 { "user" } else { "team" },
        )),
    )
    .await?;
    let (id, granted_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) \
         DO UPDATE SET granted_by = record_share.granted_by \
         RETURNING id, granted_at",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    // A user's cached context is refreshed; a team's members read shares
    // live on their next request.
    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }
    Ok((
        StatusCode::CREATED,
        Json(RecordShare {
            id,
            principal_type: if principal_type == 0 { "user" } else { "team" },
            principal_id,
            capability: capability_str(capability),
            granted_by: Some(ctx.user_id),
            granted_at,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/shares/{share_id}",
    tag = "entity",
    operation_id = "unshare_record",
    description = "Removes a share from the record (Q14-T1). Needs `{entity}.share` and the access the share gives; a deny row and the creator's own share are left to administrators.",
    params(("entity" = String, Path), ("id" = Uuid, Path), ("share_id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "The share is gone"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the share privilege, or the share is a deny row or the creator's own", body = ErrorResponse),
        (status = 404, description = "No such share on this record, or the caller lacks its access", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn unshare_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Share>>,
    Path((entity_input, record_id, share_id)): Path<(String, Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    let share: Option<(i16, Uuid, i16, Option<Uuid>)> = sqlx::query_as(
        "SELECT principal_type, principal_id, capability, granted_by FROM record_share \
         WHERE id = $1 AND record_id = $2 AND entity_ref = $3",
    )
    .bind(share_id)
    .bind(record_id)
    .bind(entity_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (principal_type, principal_id, capability, granted_by) = share.ok_or(AppError::NotFound)?;
    let creators_own = principal_type == 0 && granted_by == Some(principal_id);
    if capability == 2 || creators_own {
        return Err(AppError::Forbidden);
    }
    let needs = if capability == 1 {
        RecordAction::Update
    } else {
        RecordAction::Read
    };
    require_record_access(&state, &ctx, entity_id, &entity_name, record_id, needs).await?;

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Revoke,
            ctx.user_id,
            &entity_name,
            Some(record_id),
        )
        .named("record.unshare")
        .comment(format!(
            "removed {} share of {} {principal_id}",
            capability_str(capability),
            if principal_type == 0 { "user" } else { "team" },
        )),
    )
    .await?;
    let removed = sqlx::query("DELETE FROM record_share WHERE id = $1 AND capability = $2")
        .bind(share_id)
        .bind(capability)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_shares, share_record, unshare_record))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_share_owner_cannot_give_more_than_they_hold() {
        assert!(matches!(
            requested_capability("view"),
            Ok((0, RecordAction::Read))
        ));
        assert!(matches!(
            requested_capability("action"),
            Ok((1, RecordAction::Update))
        ));
        assert!(matches!(
            requested_capability("deny"),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            requested_capability("owner"),
            Err(AppError::Validation(_))
        ));
    }
}
