//! Deal teams (roadmap D7-T2): add, change and remove the members of an
//! opportunity's team. A member who is a user gets a share of the deal in
//! the same transaction (`record_share`, view for `read`, act for `edit`),
//! whose id the member row keeps in `share_id`; removing the member removes
//! the share. A partner contact is a member without a share (partners reach
//! deals through the portal).
//!
//! Every change runs under the deal's lock (`attome-sales/opportunity-team:{id}`)
//! and needs update access on the deal. A member may not be given more than
//! their own roles allow: `edit` needs `opportunity.update` in the member's
//! roles and `read` needs `opportunity.read` (`422 access_above_role`). The
//! deal's owner cannot be removed. Each change writes an Access security
//! event in its transaction.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::split_store::OpportunityUpdate;

/// The access a member gets to the deal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamAccess {
    Read,
    Edit,
}

impl TeamAccess {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Edit => "edit",
        }
    }

    /// The `record_share` capability: 0 to view, 1 to act.
    pub fn capability(self) -> i16 {
        match self {
            Self::Read => 0,
            Self::Edit => 1,
        }
    }

    /// The privilege the member's own roles must hold.
    pub fn required_privilege(self) -> &'static str {
        match self {
            Self::Read => "opportunity.read",
            Self::Edit => "opportunity.update",
        }
    }
}

fn lock_key(opportunity: Uuid) -> String {
    format!("attome-sales/opportunity-team:{opportunity}")
}

async fn lock(tx: &mut attome_db::Tx<'_>, opportunity: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(opportunity))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "this deal's team is being changed by another request",
        ))
    }
}

fn opportunity_entity(state: &EngineState) -> Result<Uuid, AppError> {
    state
        .entities
        .load()
        .get("opportunity")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)
}

async fn require_deal_update(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
) -> Result<Uuid, AppError> {
    crate::flags::require(state, ctx, crate::flags::DEAL_TEAMS).await?;
    let entity = opportunity_entity(state)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity,
        "opportunity",
        opportunity,
        RecordAction::Update,
    )
    .await?;
    Ok(entity)
}

/// Refuses access above what the member's own roles allow.
async fn check_member_access(
    state: &EngineState,
    user: Uuid,
    access: TeamAccess,
) -> Result<(), AppError> {
    let privileges = attome_security::db::resolve_privileges(&state.base.db, user).await?;
    if privileges.contains(attome_security::context::ADMIN_PRIVILEGE_KEY)
        || privileges.contains(access.required_privilege())
    {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "access_above_role: the member's roles do not hold {}",
            access.required_privilege()
        )))
    }
}

/// After commit, drops the member's cached security context, as the admin
/// share routes do, so the share counts on their next request.
pub(crate) async fn invalidate(state: &EngineState, user: Option<Uuid>) -> Result<(), AppError> {
    if let Some(user) = user {
        state.base.security.invalidate_sync(user).await?;
    }
    Ok(())
}

fn access_event(actor: Uuid, member: Uuid, operation: AuditOperation) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Access,
        operation,
        actor,
        "opportunity_team_member",
        Some(member),
    )
}

/// A member to add.
#[derive(Debug, Clone, Copy)]
pub struct NewMember {
    pub user: Option<Uuid>,
    pub partner_contact: Option<Uuid>,
    pub team_role: Option<Uuid>,
    pub access: TeamAccess,
}

/// Adds a member inside a transaction that holds the team lock: a user
/// member's share of the deal, the member row and its Access event. The
/// caller has already checked the member's own roles allow `access`.
pub async fn add_member_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    entity: Uuid,
    opportunity: Uuid,
    new: NewMember,
    actor: Uuid,
) -> Result<Uuid, AppError> {
    let member = Uuid::now_v7();
    let share = match new.user {
        Some(user) => Some(
            attome_records::entity_crud::grant_user_share_in_tx(
                tx,
                entity,
                opportunity,
                user,
                new.access.capability(),
                actor,
            )
            .await?,
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO opportunity_team_member \
           (id, opportunity_ref, user_ref, partner_contact_ref, team_role_ref, access_level, \
            share_id, owner_ref) \
         SELECT $1, o.id, $3, $4, $5, $6, $7, o.owner_ref FROM opportunity o WHERE o.id = $2",
    )
    .bind(member)
    .bind(opportunity)
    .bind(new.user)
    .bind(new.partner_contact)
    .bind(new.team_role)
    .bind(new.access.as_str())
    .bind(share.map(|s| s.to_string()))
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        tx,
        &attome_audit::audit_service(state),
        access_event(actor, member, AuditOperation::Grant).comment(format!(
            "deal {opportunity}: {} access",
            new.access.as_str()
        )),
    )
    .await?;
    Ok(member)
}

/// Whether a user's own roles allow `access` to deals.
pub(crate) async fn member_access_allowed(
    state: &EngineState,
    user: Uuid,
    access: TeamAccess,
) -> Result<bool, AppError> {
    match check_member_access(state, user, access).await {
        Ok(()) => Ok(true),
        Err(AppError::Validation(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(crate) fn opportunity_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    opportunity_entity(state)
}

pub(crate) async fn lock_team(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<(), AppError> {
    lock(tx, opportunity).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesTeamMemberBody {
    /// A user on the team; give this or `partner_contact_ref`.
    #[serde(default)]
    pub user_ref: Option<Uuid>,
    /// A partner contact on the team.
    #[serde(default)]
    pub partner_contact_ref: Option<Uuid>,
    pub team_role_ref: Uuid,
    pub access_level: TeamAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesTeamMember {
    pub id: Uuid,
    pub opportunity_id: Uuid,
    pub user_ref: Option<Uuid>,
    pub partner_contact_ref: Option<Uuid>,
    pub team_role_ref: Option<Uuid>,
    pub access_level: Option<String>,
    pub share_id: Option<String>,
}

type MemberRow = (
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

async fn read_member(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
    member: Uuid,
) -> Result<SalesTeamMember, AppError> {
    let row: Option<MemberRow> = sqlx::query_as(
        "SELECT id, opportunity_ref, user_ref, partner_contact_ref, team_role_ref, \
                access_level, share_id \
         FROM opportunity_team_member \
         WHERE id = $1 AND opportunity_ref = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(member)
    .bind(opportunity)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((id, opp, user, partner, role, access, share)) = row else {
        return Err(AppError::NotFound);
    };
    Ok(SalesTeamMember {
        id,
        opportunity_id: opp.unwrap_or(opportunity),
        user_ref: user,
        partner_contact_ref: partner,
        team_role_ref: role,
        access_level: access,
        share_id: share,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/team",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesTeamMemberBody,
    responses(
        (status = 201, description = "The member is on the team, with their share of the deal", body = SalesTeamMember),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "The team is being changed by another request", body = ErrorResponse),
        (status = 422, description = "Neither or both of user_ref and partner_contact_ref, or access above the member's roles (access_above_role)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
)]
pub(crate) async fn post_sales_team_member(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    Json(body): Json<SalesTeamMemberBody>,
) -> Result<(StatusCode, Json<SalesTeamMember>), AppError> {
    if body.user_ref.is_some() == body.partner_contact_ref.is_some() {
        return Err(AppError::Validation(
            "give user_ref or partner_contact_ref, not both".into(),
        ));
    }
    let entity = require_deal_update(&state, &ctx, opportunity).await?;
    if body.partner_contact_ref.is_some() {
        crate::flags::require(&state, &ctx, crate::flags::PARTNER_MEMBERS).await?;
    }
    if let Some(user) = body.user_ref {
        check_member_access(&state, user, body.access_level).await?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, opportunity).await?;
    let member = add_member_in_tx(
        &mut tx,
        &state,
        entity,
        opportunity,
        NewMember {
            user: body.user_ref,
            partner_contact: body.partner_contact_ref,
            team_role: Some(body.team_role_ref),
            access: body.access_level,
        },
        ctx.user_id,
    )
    .await?;
    let created = read_member(&mut tx, opportunity, member).await?;
    attome_db::tx::commit(tx).await?;
    invalidate(&state, body.user_ref).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesTeamMemberPatch {
    #[serde(default)]
    pub team_role_ref: Option<Uuid>,
    #[serde(default)]
    pub access_level: Option<TeamAccess>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/sales/opportunities/{id}/team/{member_id}",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("member_id" = Uuid, Path, description = "The team member"),
    ),
    request_body = SalesTeamMemberPatch,
    responses(
        (status = 200, description = "The member is changed, and their share with them", body = SalesTeamMember),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such member on this opportunity", body = ErrorResponse),
        (status = 409, description = "The team is being changed by another request", body = ErrorResponse),
        (status = 422, description = "Access above the member's roles (access_above_role)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn patch_sales_team_member(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path((opportunity, member)): Path<(Uuid, Uuid)>,
    Json(body): Json<SalesTeamMemberPatch>,
) -> Result<Json<SalesTeamMember>, AppError> {
    let entity = require_deal_update(&state, &ctx, opportunity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, opportunity).await?;
    let current = read_member(&mut tx, opportunity, member).await?;
    let mut share = current
        .share_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok());
    if let (Some(access), Some(user)) = (body.access_level, current.user_ref)
        && current.access_level.as_deref() != Some(access.as_str())
    {
        check_member_access(&state, user, access).await?;
        if let Some(old) = share {
            attome_records::entity_crud::revoke_share_in_tx(&mut tx, old).await?;
        }
        share = Some(
            attome_records::entity_crud::grant_user_share_in_tx(
                &mut tx,
                entity,
                opportunity,
                user,
                access.capability(),
                ctx.user_id,
            )
            .await?,
        );
    }
    sqlx::query(
        "UPDATE opportunity_team_member SET \
             team_role_ref = COALESCE($2, team_role_ref), \
             access_level = COALESCE($3, access_level), share_id = $4, \
             modified_at = now(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(member)
    .bind(body.team_role_ref)
    .bind(body.access_level.map(TeamAccess::as_str))
    .bind(share.map(|s| s.to_string()))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        access_event(ctx.user_id, member, AuditOperation::Update)
            .comment(format!("deal {opportunity}: member changed")),
    )
    .await?;
    let changed = read_member(&mut tx, opportunity, member).await?;
    attome_db::tx::commit(tx).await?;
    invalidate(&state, changed.user_ref).await?;
    Ok(Json(changed))
}

#[utoipa::path(
    delete,
    path = "/api/v1/sales/opportunities/{id}/team/{member_id}",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("member_id" = Uuid, Path, description = "The team member"),
    ),
    responses(
        (status = 204, description = "The member and their share are gone"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such member on this opportunity", body = ErrorResponse),
        (status = 409, description = "The member is the deal's owner, or the team is being changed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Revoke)])))),
)]
pub(crate) async fn delete_sales_team_member(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path((opportunity, member)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    require_deal_update(&state, &ctx, opportunity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, opportunity).await?;
    let current = read_member(&mut tx, opportunity, member).await?;
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_ref FROM opportunity WHERE id = $1")
        .bind(opportunity)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if current.user_ref.is_some() && current.user_ref == owner {
        return Err(AppError::Conflict(
            "the deal's owner cannot be removed from its team",
        ));
    }
    if let Some(share) = current
        .share_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        attome_records::entity_crud::revoke_share_in_tx(&mut tx, share).await?;
    }
    sqlx::query("DELETE FROM opportunity_team_member WHERE id = $1")
        .bind(member)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        access_event(ctx.user_id, member, AuditOperation::Revoke)
            .comment(format!("deal {opportunity}: member removed")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    invalidate(&state, current.user_ref).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_sales_team_member,
        patch_sales_team_member,
        delete_sales_team_member
    ),
    components(schemas(TeamAccess, SalesTeamMemberBody, SalesTeamMember, SalesTeamMemberPatch))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_maps_to_share_capability_and_required_privilege() {
        assert_eq!(TeamAccess::Read.capability(), 0);
        assert_eq!(TeamAccess::Edit.capability(), 1);
        assert_eq!(TeamAccess::Edit.required_privilege(), "opportunity.update");
        assert_eq!(TeamAccess::Read.required_privilege(), "opportunity.read");
    }

    #[test]
    fn the_lock_key_names_the_crate_and_deal() {
        assert_eq!(
            lock_key(Uuid::nil()),
            "attome-sales/opportunity-team:00000000-0000-0000-0000-000000000000"
        );
    }
}
