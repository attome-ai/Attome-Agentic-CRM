//! Deal owner change (roadmap D7-T6, the route): one transaction under the
//! deal's team lock that
//!
//! 1. moves `owner_ref` and gives the new owner an act share of the deal,
//!    with an owner-change Access event (as the admin reassign does);
//! 2. puts the new owner on the team with edit access if they are not on it;
//! 3. keeps the old owner as a member with the given role, or removes them
//!    and their share;
//! 4. moves the old owner's splits to the new owner, or keeps them, and
//!    recalculates the stored split amounts.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::split_store::OpportunityUpdate;
use crate::team::{NewMember, TeamAccess};

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesChangeOwnerBody {
    pub new_owner: Uuid,
    /// Keep the old owner on the team with this team role; absent removes
    /// them and their share.
    #[serde(default)]
    pub old_owner_role: Option<Uuid>,
    /// Move the old owner's splits to the new owner (else they stay).
    #[serde(default)]
    pub move_splits: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesOwnerChanged {
    pub opportunity_id: Uuid,
    pub owner_id: Uuid,
    pub splits_moved: u64,
}

/// Change a deal's owner
///
/// In one transaction: moves the owner and gives the new owner edit access and a place on the team,
/// keeps the old owner as a member with the role given or removes them, and moves or keeps their
/// splits. Needs update rights on the opportunity. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/change-owner",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesChangeOwnerBody,
    responses(
        (status = 200, description = "The deal has its new owner, team and splits", body = SalesOwnerChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "The team is being changed by another request", body = ErrorResponse),
        (status = 422, description = "The new owner is already the owner, or their roles do not allow editing deals", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::OwnerChange)])))),
)]
pub(crate) async fn post_sales_change_owner(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    Json(body): Json<SalesChangeOwnerBody>,
) -> Result<Json<SalesOwnerChanged>, AppError> {
    let entity = crate::team::opportunity_entity_id(&state)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity,
        "opportunity",
        opportunity,
        RecordAction::Update,
    )
    .await?;
    if !crate::team::member_access_allowed(&state, body.new_owner, TeamAccess::Edit).await? {
        return Err(AppError::Validation(
            "access_above_role: the new owner's roles do not hold opportunity.update".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::team::lock_team(&mut tx, opportunity).await?;
    let old: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT owner_ref FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(opportunity)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(old) = old else {
        return Err(AppError::NotFound);
    };
    if old == Some(body.new_owner) {
        return Err(AppError::Validation(
            "that user already owns the deal".into(),
        ));
    }
    sqlx::query(
        "UPDATE opportunity SET owner_ref = $2, owner_type = 0, modified_by = $3, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(opportunity)
    .bind(body.new_owner)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_records::entity_crud::grant_user_share_in_tx(
        &mut tx,
        entity,
        opportunity,
        body.new_owner,
        1,
        ctx.user_id,
    )
    .await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::OwnerChange,
            ctx.user_id,
            "opportunity",
            Some(opportunity),
        )
        .comment(format!("owner {:?} -> {}", old, body.new_owner)),
    )
    .await?;

    // The new owner on the team, with edit access.
    type MemberRow = (Uuid, Option<Uuid>, Option<String>);
    let members: Vec<MemberRow> = sqlx::query_as(
        "SELECT id, user_ref, share_id FROM opportunity_team_member \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let new_member = match members
        .iter()
        .find(|(_, user, _)| *user == Some(body.new_owner))
    {
        Some((id, _, _)) => *id,
        None => {
            crate::team::add_member_in_tx(
                &mut tx,
                &state,
                entity,
                opportunity,
                NewMember {
                    user: Some(body.new_owner),
                    partner_contact: None,
                    team_role: None,
                    access: TeamAccess::Edit,
                },
                ctx.user_id,
            )
            .await?
        }
    };

    // The old owner's splits, then their membership.
    let old_member = members
        .iter()
        .find(|(_, user, _)| old.is_some() && *user == old)
        .cloned();
    let mut splits_moved = 0;
    if body.move_splits
        && let Some((old_id, _, _)) = &old_member
    {
        splits_moved = sqlx::query(
            "UPDATE opportunity_split SET member_ref = $2, modified_at = now(), \
                 row_version = row_version + 1 WHERE opportunity_ref = $1 AND member_ref = $3",
        )
        .bind(opportunity)
        .bind(new_member)
        .bind(old_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    if let Some((old_id, _, share)) = &old_member {
        match body.old_owner_role {
            Some(role) => {
                sqlx::query(
                    "UPDATE opportunity_team_member SET team_role_ref = $2, modified_at = now(), \
                         row_version = row_version + 1 WHERE id = $1",
                )
                .bind(old_id)
                .bind(role)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
            None => {
                let still_split: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM opportunity_split WHERE member_ref = $1)",
                )
                .bind(old_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                if still_split {
                    return Err(AppError::Validation(
                        "the old owner still holds splits: move them or keep the old owner on the team"
                            .into(),
                    ));
                }
                if let Some(share) = share.as_deref().and_then(|s| Uuid::parse_str(s).ok()) {
                    attome_records::entity_crud::revoke_share_in_tx(&mut tx, share).await?;
                }
                sqlx::query("DELETE FROM opportunity_team_member WHERE id = $1")
                    .bind(old_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            }
        }
    }
    crate::split_store::recalculate_in_tx(&mut tx, opportunity).await?;
    attome_db::tx::commit(tx).await?;
    crate::team::invalidate(&state, Some(body.new_owner)).await?;
    crate::team::invalidate(&state, old).await?;
    Ok(Json(SalesOwnerChanged {
        opportunity_id: opportunity,
        owner_id: body.new_owner,
        splits_moved,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_change_owner),
    components(schemas(SalesChangeOwnerBody, SalesOwnerChanged))
)]
pub(crate) struct ApiDocFragment;
