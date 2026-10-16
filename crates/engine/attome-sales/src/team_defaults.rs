//! Default deal teams (roadmap D7-T3).
//!
//! - A new deal gets its owner's default team (`user_default_team_member`):
//!   [`sweep_new_deals`] reads opportunity creates off the change feed (its
//!   own cursor, `attome-sales/default-team`) and adds each default member
//!   through [`crate::team::add_member_in_tx`], share and Access event
//!   included. A member whose own roles do not allow the default access is
//!   skipped and logged, never raised.
//! - `POST .../team/copy-account-team` copies the account team's members
//!   with the given account roles onto one deal, on request only: being on
//!   an account's team never grants deal access by itself.
//! - `POST /api/v1/sales/default-team/preview` lists the open deals of the
//!   caller's own that their default team would change, and `.../apply`
//!   queues a job that adds the missing members in batches of
//!   [`APPLY_BATCH`].

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, SelfService};
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
use crate::team::{NewMember, TeamAccess};

/// The change-feed consumer that gives new deals their default team.
pub const DEFAULT_TEAM_CONSUMER: &str = "attome-sales/default-team";

/// Change events read per sweep.
const SWEEP_BATCH: i64 = 200;

/// Deals one apply job handles per batch.
pub const APPLY_BATCH: i64 = 200;

fn access_of(text: Option<&str>) -> TeamAccess {
    if text == Some("edit") {
        TeamAccess::Edit
    } else {
        TeamAccess::Read
    }
}

/// An owner's default members: member user, team role, access.
type DefaultRow = (Option<Uuid>, Option<Uuid>, Option<String>);

async fn defaults_of(db: &attome_db::DbPool, owner: Uuid) -> Result<Vec<DefaultRow>, AppError> {
    sqlx::query_as(
        "SELECT member_user_ref, team_role_ref, access_level FROM user_default_team_member \
         WHERE owner_user_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(owner)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Adds the owner's default members missing from one deal; how many were
/// added. Members already on the team, the owner, and members whose roles
/// do not allow the access are left out.
pub async fn apply_defaults_to_deal(
    state: &EngineState,
    opportunity: Uuid,
    actor: Option<Uuid>,
) -> Result<u64, AppError> {
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT owner_ref FROM opportunity WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(Some(owner)) = owner else {
        return Ok(0);
    };
    let defaults = defaults_of(&state.base.db, owner).await?;
    if defaults.is_empty() {
        return Ok(0);
    }
    let mut allowed = Vec::new();
    for (user, role, access) in defaults {
        let Some(user) = user.filter(|u| *u != owner) else {
            continue;
        };
        let access = access_of(access.as_deref());
        if crate::team::member_access_allowed(state, user, access).await? {
            allowed.push(NewMember {
                user: Some(user),
                partner_contact: None,
                team_role: role,
                access,
            });
        } else {
            tracing::info!(%opportunity, %user, "default team: member skipped, their roles do not allow the access");
        }
    }
    // A sweep acts for the owner: the default team is the owner's own.
    add_missing(state, opportunity, &allowed, actor.unwrap_or(owner)).await
}

async fn add_missing(
    state: &EngineState,
    opportunity: Uuid,
    members: &[NewMember],
    actor: Uuid,
) -> Result<u64, AppError> {
    if members.is_empty() {
        return Ok(0);
    }
    let entity = crate::team::opportunity_entity_id(state)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::team::lock_team(&mut tx, opportunity).await?;
    let present: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM opportunity_team_member \
         WHERE opportunity_ref = $1 AND user_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut added = 0;
    for member in members {
        if member.user.is_some_and(|u| present.contains(&u)) {
            continue;
        }
        crate::team::add_member_in_tx(&mut tx, state, entity, opportunity, *member, actor).await?;
        added += 1;
    }
    attome_db::tx::commit(tx).await?;
    Ok(added)
}

/// Gives every newly created deal its owner's default team; the number of
/// members added. Idempotent: a replayed event adds nobody twice.
pub async fn sweep_new_deals(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, DEFAULT_TEAM_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut deals: Vec<Uuid> = events
        .iter()
        .filter(|e| {
            e.entity_logicalname == "opportunity"
                && e.operation() == Some(attome_core::change_feed::ChangeOperation::Create)
        })
        .map(|e| e.record_id)
        .collect();
    deals.dedup();
    let mut added = 0;
    for deal in deals {
        added += apply_defaults_to_deal(state, deal, None).await?;
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, DEFAULT_TEAM_CONSUMER, &last).await?;
    Ok(added)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesCopyAccountTeamBody {
    /// The account team roles to copy, e.g. `["account_manager", "pre_sales"]`.
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesTeamChange {
    pub added: u64,
    /// Members left out because their own roles do not allow the access.
    pub skipped: u64,
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/team/copy-account-team",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesCopyAccountTeamBody,
    responses(
        (status = 200, description = "The account team's members with those roles are on the deal's team", body = SalesTeamChange),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "The team is being changed by another request", body = ErrorResponse),
        (status = 422, description = "No roles given", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
)]
pub(crate) async fn post_sales_copy_account_team(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    Json(body): Json<SalesCopyAccountTeamBody>,
) -> Result<Json<SalesTeamChange>, AppError> {
    if body.roles.is_empty() {
        return Err(AppError::Validation(
            "give at least one account role".into(),
        ));
    }
    let entity = crate::team::opportunity_entity_id(&state)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity,
        "opportunity",
        opportunity,
        attome_security::RecordAction::Update,
    )
    .await?;
    let members: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT m.user_ref, m.access FROM account_team_member m \
         JOIN opportunity o ON o.account_ref = m.account_ref \
         WHERE o.id = $1 AND m.team_role = ANY($2) \
           AND (m.is_active IS NULL OR m.is_active = true)",
    )
    .bind(opportunity)
    .bind(&body.roles)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut allowed = Vec::new();
    let mut skipped = 0;
    for (user, access) in members {
        let Some(user) = user else { continue };
        let access = access_of(access.as_deref());
        if crate::team::member_access_allowed(&state, user, access).await? {
            allowed.push(NewMember {
                user: Some(user),
                partner_contact: None,
                team_role: None,
                access,
            });
        } else {
            skipped += 1;
        }
    }
    let added = add_missing(&state, opportunity, &allowed, ctx.user_id).await?;
    Ok(Json(SalesTeamChange { added, skipped }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesDefaultTeamPreview {
    /// The caller's open deals that miss at least one default member.
    pub opportunity_ids: Vec<Uuid>,
}

/// The caller's open deals that miss one of their default members.
async fn deals_to_change(db: &attome_db::DbPool, owner: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT o.id FROM opportunity o \
         WHERE o.owner_ref = $1 AND (o.is_active IS NULL OR o.is_active = true) \
           AND (o.stage IS NULL OR o.stage NOT IN ('closed_won', 'closed_lost')) \
           AND EXISTS (SELECT 1 FROM user_default_team_member d \
               WHERE d.owner_user_ref = $1 AND d.member_user_ref IS NOT NULL \
                 AND d.member_user_ref <> $1 \
                 AND (d.is_active IS NULL OR d.is_active = true) \
                 AND NOT EXISTS (SELECT 1 FROM opportunity_team_member m \
                     WHERE m.opportunity_ref = o.id AND m.user_ref = d.member_user_ref \
                       AND (m.is_active IS NULL OR m.is_active = true))) \
         ORDER BY o.id LIMIT 5000",
    )
    .bind(owner)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/default-team/preview",
    tag = "sales",
    responses(
        (status = 200, description = "The caller's open deals their default team would change", body = SalesDefaultTeamPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "lists the deals an apply would change; writes nothing",
    )))),
)]
pub(crate) async fn post_sales_default_team_preview(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<SalesDefaultTeamPreview>, AppError> {
    Ok(Json(SalesDefaultTeamPreview {
        opportunity_ids: deals_to_change(&state.base.db, ctx.user_id).await?,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesDefaultTeamApply {
    pub queued: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/default-team/apply",
    tag = "sales",
    responses(
        (status = 202, description = "A job adds the caller's default members to their open deals", body = SalesDefaultTeamApply),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("the default-team job -> team::add_member_in_tx"),
        "queues the job only; every member it adds writes its own Access event in the add's transaction",
    )))),
)]
pub(crate) async fn post_sales_default_team_apply(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<(StatusCode, Json<SalesDefaultTeamApply>), AppError> {
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::SalesDefaultTeamApply {
            owner_id: ctx.user_id,
        },
    )
    .await
    .map_err(AppError::internal)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SalesDefaultTeamApply { queued: true }),
    ))
}

/// The apply job: every open deal of `owner` that misses a default member,
/// in batches of [`APPLY_BATCH`]; members added.
pub async fn run_apply(state: &EngineState, owner: Uuid) -> Result<u64, AppError> {
    let deals = deals_to_change(&state.base.db, owner).await?;
    let mut added = 0;
    for batch in deals.chunks(APPLY_BATCH as usize) {
        for deal in batch {
            added += apply_defaults_to_deal(state, *deal, Some(owner)).await?;
        }
    }
    Ok(added)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_sales_copy_account_team,
        post_sales_default_team_preview,
        post_sales_default_team_apply
    ),
    components(schemas(
        SalesCopyAccountTeamBody,
        SalesTeamChange,
        SalesDefaultTeamPreview,
        SalesDefaultTeamApply
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_edit_grants_edit() {
        assert_eq!(access_of(Some("edit")), TeamAccess::Edit);
        assert_eq!(access_of(Some("read")), TeamAccess::Read);
        assert_eq!(access_of(None), TeamAccess::Read);
        assert_eq!(access_of(Some("admin")), TeamAccess::Read);
    }
}
