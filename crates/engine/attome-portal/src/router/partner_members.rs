//! F9-T8: a partner's own administrator manages its portal members.
//!
//! Every route needs a portal user who holds the `partner_admin` role on
//! this portal and whose contact is at a partner account; the account comes
//! from that contact, never from the request. 403 for anyone else.
//!
//! - `GET /{keyword}/api/v1/partner/members` lists the partner's members on
//!   this portal with their role and status.
//! - `POST /{keyword}/api/v1/partner/members` `{contact_id, role}` invites a
//!   contact at the partner's own account (with an email address and no
//!   portal account yet) as `partner_admin`, `partner_sales` or
//!   `partner_service`: the portal user is created, bound to the partner
//!   through the role assignment (which refuses past `partner_user_limit`),
//!   and sent the invitation email, in one transaction.
//! - `POST /{keyword}/api/v1/partner/members/{id}/deactivate` disables
//!   another member of the same partner on this portal; every session they
//!   hold ends at once. A member of another partner answers 404.
//!
//! Each change writes its security event (Credential for the invitation,
//! Access for the deactivation) in its own transaction, with the portal
//! user as the actor.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{authenticate, portal_for, whole_list};

/// The most members one list answers.
const MAX_MEMBERS: i64 = 500;
use crate::auth::PortalPrincipal;
use crate::partner_roles::{PARTNER_ADMIN, PARTNER_SALES, PARTNER_SERVICE};
use crate::provision::{NewPortalUser, PortalDetail};

/// One member of the caller's partner on this portal.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PartnerMember {
    pub id: Uuid,
    pub name: String,
    pub email: Option<String>,
    /// The member's partner role; none when they hold none.
    pub role: Option<String>,
    /// `invited`, `active` or `disabled`.
    pub status: String,
}

/// An invitation.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PartnerMemberInvite {
    /// A contact at the caller's own partner account.
    pub contact_id: Uuid,
    /// `partner_admin`, `partner_sales` or `partner_service`.
    pub role: String,
}

/// The partner the signed-in person administers on `portal`.
async fn administered_partner(
    state: &EngineState,
    portal: &PortalDetail,
    principal: &PortalPrincipal,
) -> Result<Uuid, AppError> {
    let is_admin = match principal.role_id {
        Some(role) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM webportal_role \
              WHERE id = $1 AND webportal_id = $2 AND name = $3)",
        )
        .bind(role)
        .bind(portal.id)
        .bind(PARTNER_ADMIN)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        None => false,
    };
    if !is_admin {
        return Err(AppError::Forbidden);
    }
    attome_partner::leads::partner_of_portal_user(state, principal.user_id)
        .await?
        .ok_or(AppError::Forbidden)
}

async fn signed_in_admin(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
) -> Result<(PortalDetail, PortalPrincipal, Uuid), AppError> {
    if !state.modules.load().has(attome_modules::MODULE_PARTNER) {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    let principal = authenticate(state, &portal, headers, false).await?;
    let partner = administered_partner(state, &portal, &principal).await?;
    Ok((portal, principal, partner))
}

const MEMBER_SELECT: &str = "SELECT u.id, u.name, u.email, r.name AS role, u.status \
       FROM webportal_user u \
       LEFT JOIN webportal_user_role ur ON ur.webportal_user_id = u.id \
       LEFT JOIN webportal_role r ON r.id = ur.role_id \
      WHERE u.webportal_ref = $1 AND u.partner_account_ref = $2 AND u.is_active IS NOT FALSE";

/// The partner's members
///
/// F9-T8: the members of the signed-in partner administrator's own partner on this portal.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/partner/members",
    operation_id = "portal_partner_members",
    tag = "partner",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The members, at most 500", body = attome_types::PaginatedResponse<PartnerMember>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 403, description = "Not the administrator of a partner", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn list_members(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<attome_types::PaginatedResponse<PartnerMember>>, AppError> {
    let (portal, _, partner) = signed_in_admin(&state, &keyword, &headers).await?;
    let members: Vec<PartnerMember> = sqlx::query_as(&format!(
        "{MEMBER_SELECT} ORDER BY u.name, u.id LIMIT {MAX_MEMBERS}"
    ))
    .bind(portal.id)
    .bind(partner)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(whole_list(members, Some(MAX_MEMBERS))))
}

/// Invite a partner member
///
/// F9-T8: invites a contact at the partner administrator's own account with a partner role; refused
/// past the partner's user limit. Audited.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/partner/members",
    operation_id = "portal_partner_invite_member",
    tag = "partner",
    params(("keyword" = String, Path, description = "The portal")),
    request_body = PartnerMemberInvite,
    extensions(("x-audit" = json!(x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Invited", body = PartnerMember),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 403, description = "Not the administrator of a partner", body = ErrorResponse),
        (status = 404, description = "No such portal, or no such contact at the partner", body = ErrorResponse),
        (status = 409, description = "The contact already has a portal account", body = ErrorResponse),
        (status = 422, description = "Not a partner role, no email address, or the user limit is reached", body = ErrorResponse),
        (status = 503, description = "Email is not configured", body = ErrorResponse),
    ),
)]
async fn invite_member(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PartnerMemberInvite>,
) -> Result<(StatusCode, Json<PartnerMember>), AppError> {
    let (portal, principal, partner) = signed_in_admin(&state, &keyword, &headers).await?;
    let role_name = body.role.trim();
    if ![PARTNER_ADMIN, PARTNER_SALES, PARTNER_SERVICE].contains(&role_name) {
        return Err(AppError::Validation(
            "role is partner_admin, partner_sales or partner_service".into(),
        ));
    }
    if !state.base.config.email.enabled {
        return Err(AppError::FeatureUnavailable);
    }
    let contact: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT COALESCE(full_name, ''), email FROM contact \
          WHERE id = $1 AND account_ref = $2 AND is_active IS NOT FALSE",
    )
    .bind(body.contact_id)
    .bind(partner)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (name, email) = contact.ok_or(AppError::NotFound)?;
    let email = email
        .map(|e| e.trim().to_owned())
        .filter(|e| e.contains('@'))
        .ok_or_else(|| AppError::Validation("the contact has no email address".into()))?;
    let name = if name.trim().is_empty() {
        email.clone()
    } else {
        name.trim().to_owned()
    };

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            principal.user_id,
            "webportal_user",
            None,
        ),
    )
    .await?;
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_user \
          WHERE webportal_ref = $1 AND contact_ref = $2 AND is_active IS NOT FALSE)",
    )
    .bind(portal.id)
    .bind(body.contact_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if taken {
        return Err(AppError::Conflict(
            "the contact already has an account on this portal",
        ));
    }
    let role: Uuid =
        sqlx::query_scalar("SELECT id FROM webportal_role WHERE webportal_id = $1 AND name = $2")
            .bind(portal.id)
            .bind(role_name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::Validation(format!("this portal has no {role_name} role")))?;
    let user = crate::provision::create_user(
        &mut tx,
        principal.user_id,
        portal.id,
        NewPortalUser {
            name,
            email: Some(email),
            username: None,
        },
    )
    .await?;
    sqlx::query("UPDATE webportal_user SET contact_ref = $2 WHERE id = $1")
        .bind(user.id)
        .bind(body.contact_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    crate::roles::assign_role(&mut tx, portal.id, user.id, role).await?;
    crate::partner_roles::bind_member(&mut tx, user.id, role).await?;
    let (to, token) =
        crate::auth::issue_invitation(&mut tx, &state.base.pepper_ring(), portal.id, user.id)
            .await?
            .ok_or(AppError::NotFound)?;
    let link = format!(
        "{}/{}/accept-invitation?token={}",
        crate::router::portal_base_url(&state),
        portal.keyword,
        token.bearer
    );
    let (subject, text_body, html_body) = crate::email::invitation(&portal.name, &link);
    attome_jobs::enqueue_in_tx(
        tx.tx(),
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to,
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
            stream: Default::default(),
            list_unsubscribe: None,
        })),
    )
    .await
    .map_err(AppError::internal)?;
    let member: PartnerMember = sqlx::query_as(&format!("{MEMBER_SELECT} AND u.id = $3"))
        .bind(portal.id)
        .bind(partner)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(user.id);
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok((StatusCode::CREATED, Json(member)))
}

/// Deactivate a partner member
///
/// F9-T8: disables another member of the partner administrator's own partner on this portal; every
/// session they hold ends. Audited.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/partner/members/{id}/deactivate",
    operation_id = "portal_partner_deactivate_member",
    tag = "partner",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("id" = Uuid, Path, description = "The member"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(attome_audit::AuditCategory::Access, AuditOperation::AccountDisabled)])))),
    responses(
        (status = 200, description = "Disabled; every session ended", body = PartnerMember),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 403, description = "Not the administrator of a partner", body = ErrorResponse),
        (status = 404, description = "No such member of the caller's partner", body = ErrorResponse),
        (status = 422, description = "An administrator cannot deactivate themselves", body = ErrorResponse),
    ),
)]
async fn deactivate_member(
    State(state): State<EngineState>,
    Path((keyword, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PartnerMember>, AppError> {
    let (portal, principal, partner) = signed_in_admin(&state, &keyword, &headers).await?;
    if id == principal.user_id {
        return Err(AppError::Validation(
            "a partner administrator cannot deactivate themselves".into(),
        ));
    }
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::AccountDisabled,
            principal.user_id,
            "webportal_user",
            Some(id),
        ),
    )
    .await?;
    let member: Option<PartnerMember> = sqlx::query_as(&format!("{MEMBER_SELECT} AND u.id = $3"))
        .bind(portal.id)
        .bind(partner)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if member.is_none() {
        return Err(AppError::NotFound);
    }
    crate::provision::set_user_enabled(&mut tx, principal.user_id, portal.id, id, false).await?;
    let member: PartnerMember = sqlx::query_as(&format!("{MEMBER_SELECT} AND u.id = $3"))
        .bind(portal.id)
        .bind(partner)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(Json(member))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/{keyword}/api/v1/partner/members",
            get(list_members).post(invite_member),
        )
        .route(
            "/{keyword}/api/v1/partner/members/{id}/deactivate",
            post(deactivate_member),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_members, invite_member, deactivate_member),
    components(schemas(PartnerMember, PartnerMemberInvite))
)]
pub(super) struct PartnerMembersApiDoc;
