//! Web portal admin API (D-576): the only way to create a portal, change its
//! security-relevant settings, or provision its users. Thin handlers: parse,
//! open a `SecurityTx`, call [`crate::provision`], commit. Every route is
//! `Admin`-only and writes its D-542 security event in the same transaction as
//! the change.
//!
//! G-9: every mutating handler calls [`crate::cache::invalidate`] right after
//! its commit (never inside the transaction), so every node's portal cache
//! misses on its next request. A new mutating route does the same.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
};
use uuid::Uuid;

use crate::policy::{self, AuthPolicy};
use crate::provision::{
    self, NewPortal, NewPortalUser, PortalDetail, PortalSettingsPatch, PortalUserDetail,
};

fn event(
    category: MandatoryCategory,
    operation: AuditOperation,
    actor: Uuid,
    entity: &str,
    record: Option<Uuid>,
) -> SecurityEvent {
    SecurityEvent::new(category, operation, actor, entity, record)
}

/// Create a web portal
///
/// A portal with its URL keyword, type, owning team (the staff team that owns what its users create)
/// and MFA policy. User administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_create_portal",
    path = "/api/v1/admin/webportals",
    tag = "admin-security",
    request_body = NewPortal,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Portal created", body = PortalDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Keyword already in use", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_portal(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Json(body): Json<NewPortal>,
) -> Result<(StatusCode, Json<PortalDetail>), AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "webportal",
            None,
        ),
    )
    .await?;
    let portal = provision::create_portal(&mut tx, ctx.user_id, body).await?;
    tx.event_mut().set_record_id(portal.id);
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok((StatusCode::CREATED, Json(portal)))
}

/// The deployment's configured portal OIDC provider keys.
fn configured_providers(state: &EngineState) -> Vec<String> {
    state
        .base
        .config
        .portal
        .oidc_providers
        .keys()
        .cloned()
        .collect()
}

/// `webportal_user`'s attributes, for checking the self-editable list.
fn profile_fields(state: &EngineState) -> Vec<attome_core::AttrInfo> {
    state
        .entities
        .load()
        .get("webportal_user")
        .map(|m| m.attrs.clone())
        .unwrap_or_default()
}

async fn require_portal(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<(), AppError> {
    provision::load_portal(conn, id).await.map(|_| ())
}

/// A portal's account policy
///
/// The account policy of one web portal: who may sign up, with which role,
/// and how its accounts sign in (D-588). Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/webportals/{id}/auth-policy",
    operation_id = "portal_admin_get_auth_policy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    responses(
        (status = 200, description = "The portal's account policy (D-588)", body = AuthPolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_auth_policy(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Security>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AuthPolicy>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    require_portal(&mut conn, id).await?;
    Ok(Json(policy::load(&mut conn, id).await?))
}

/// Set a portal's account policy
///
/// Replaces the account policy of one web portal: who may sign up, with
/// which role, and how its accounts sign in (D-588). Administrators only.
/// Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/webportals/{id}/auth-policy",
    operation_id = "portal_admin_put_auth_policy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    request_body = AuthPolicy,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Replaced", body = AuthPolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_auth_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path(id): Path<Uuid>,
    Json(body): Json<AuthPolicy>,
) -> Result<Json<AuthPolicy>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "webportal",
            Some(id),
        ),
    )
    .await?;
    require_portal(&mut tx, id).await?;
    let saved = policy::save(
        &mut tx,
        id,
        &body,
        &configured_providers(&state),
        &profile_fields(&state),
    )
    .await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(Json(saved))
}

/// Change a web portal's settings
///
/// Changes the keyword, type, on or off, owning team (`null` clears it) or MFA policy given, when
/// `row_version` is the stored one. User administrators only. Audited.
#[utoipa::path(
    patch,
    operation_id = "portal_admin_update_portal_settings",
    path = "/api/v1/admin/webportals/{id}/settings",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    request_body = PortalSettingsPatch,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Settings updated", body = PortalDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or keyword already in use", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_portal_settings(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PortalSettingsPatch>,
) -> Result<Json<PortalDetail>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "webportal",
            Some(id),
        ),
    )
    .await?;
    let portal = provision::update_portal_settings(&mut tx, ctx.user_id, id, body).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(Json(portal))
}

/// Add a portal user
///
/// A portal user with a name and an email or username (at least one), in `invited` status with no
/// password; the password is set when the invitation is accepted. User administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_create_user",
    path = "/api/v1/admin/webportals/{id}/users",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    request_body = NewPortalUser,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Portal user provisioned as invited", body = PortalUserDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Email already used in this portal", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
    Json(body): Json<NewPortalUser>,
) -> Result<(StatusCode, Json<PortalUserDetail>), AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "webportal_user",
            None,
        ),
    )
    .await?;
    let user = provision::create_user(&mut tx, ctx.user_id, id, body).await?;
    tx.event_mut().set_record_id(user.id);
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn set_enabled(
    state: &EngineState,
    actor: Uuid,
    portal_id: Uuid,
    user_id: Uuid,
    enabled: bool,
) -> Result<Json<PortalUserDetail>, AppError> {
    let operation = if enabled {
        AuditOperation::AccountEnabled
    } else {
        AuditOperation::AccountDisabled
    };
    let mut tx = SecurityTx::begin(
        state,
        event(
            MandatoryCategory::Access,
            operation,
            actor,
            "webportal_user",
            Some(user_id),
        ),
    )
    .await?;
    let user = provision::set_user_enabled(&mut tx, actor, portal_id, user_id, enabled).await?;
    tx.commit().await?;
    crate::cache::invalidate(state).await;
    Ok(Json(user))
}

/// Disable a portal user
///
/// The user cannot sign in, and every session they hold ends at once. User administrators only.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/disable",
    operation_id = "portal_admin_disable_user",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Web portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::AccountDisabled)])))),
    responses(
        (status = 200, description = "User disabled; every session ended", body = PortalUserDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn disable_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PortalUserDetail>, AppError> {
    set_enabled(&state, ctx.user_id, id, user_id, false).await
}

/// Enable a portal user
///
/// Returns the user to `active` when a password is set, otherwise to `invited`. User administrators
/// only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/enable",
    operation_id = "portal_admin_enable_user",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Web portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::AccountEnabled)])))),
    responses(
        (status = 200, description = "User enabled", body = PortalUserDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn enable_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PortalUserDetail>, AppError> {
    set_enabled(&state, ctx.user_id, id, user_id, true).await
}

/// Remove a portal user
///
/// Deletes the user's credentials, ending every session, and marks the profile deleted and disabled;
/// a restored profile has no credential and cannot sign in. User administrators only. Audited.
#[utoipa::path(
    delete,
    operation_id = "portal_admin_delete_user",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Web portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "User removed and credential deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Credential,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "webportal_user",
            Some(user_id),
        ),
    )
    .await?;
    provision::delete_user(&mut tx, ctx.user_id, id, user_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct InvitationSent {
    /// When the emailed link stops working. The link itself is never returned.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for InvitationSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationSent").finish_non_exhaustive()
    }
}

/// Invite a portal user
///
/// Emails the user an invitation link to set a password, the token and the email queued in one
/// transaction; refused when email is switched off. User administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_invite_user",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/invite",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Web portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 202, description = "Invitation emailed; older unused links are void", body = InvitationSent),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
        (status = 409, description = "The user has already accepted an invitation", body = ErrorResponse),
        (status = 503, description = "Email is not configured on this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn invite_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<InvitationSent>), AppError> {
    if !state.base.config.email.enabled {
        return Err(AppError::FeatureUnavailable);
    }
    // A plain transaction rather than `SecurityTx`: the email is queued in the
    // same transaction as the token and the event, so a rolled-back invite
    // never sends, and the job queue needs the transaction itself.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (keyword, portal_name): (String, String) = sqlx::query_as(
        "SELECT keyword, name FROM webportal WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (email, token) =
        crate::auth::issue_invitation(&mut tx, &state.base.pepper_ring(), id, user_id)
            .await?
            .ok_or(AppError::NotFound)?;
    // On a portal host (D-585), never the staff frontend: a staff host serves
    // no portal page, and the bearer must not travel to a staff origin (T-34).
    let link = format!(
        "{}/{keyword}/accept-invitation?token={}",
        crate::router::portal_base_url(&state),
        token.bearer
    );
    let (subject, text_body, html_body) = crate::email::invitation(&portal_name, &link);
    let delivery_id = Uuid::now_v7();
    attome_email::delivery::record_queued_in_tx(
        &mut tx,
        delivery_id,
        attome_email::delivery::EmailDeliveryKind::Invitation,
        &email,
        &subject,
        None,
        Some(ctx.user_id),
        None,
    )
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: email,
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: Some(delivery_id),
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
    let auditor = attome_audit::security::SecurityAuditor::from_state(&state);
    attome_audit::security::write_security_event(
        &mut tx,
        &auditor.service(),
        event(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "webportal_user",
            Some(user_id),
        )
        .named("portal invitation issued"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    crate::cache::invalidate(&state).await;
    Ok((
        StatusCode::ACCEPTED,
        Json(InvitationSent {
            expires_at: token.expires_at,
        }),
    ))
}

// ── Roles and grants (D-574, D-575, D-579) ────────────────────────────────────

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct NewRole {
    pub name: String,
}

impl std::fmt::Debug for NewRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewRole").finish_non_exhaustive()
    }
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub role_id: Uuid,
}

impl std::fmt::Debug for RoleAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleAssignment").finish_non_exhaustive()
    }
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct EntityConfig {
    /// A lookup on the entity to `webportal_user`, set to the portal user
    /// on every portal create. `null` to clear.
    #[serde(default)]
    pub portal_user_field: Option<String>,
}

impl std::fmt::Debug for EntityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityConfig").finish_non_exhaustive()
    }
}

/// Create a portal role
///
/// A named role of the portal, with no grants yet. Role administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_create_role",
    path = "/api/v1/admin/webportals/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    request_body = NewRole,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Role created", body = crate::roles::RoleDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Name already used in this portal", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(id): Path<Uuid>,
    Json(body): Json<NewRole>,
) -> Result<(StatusCode, Json<crate::roles::RoleDetail>), AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::Create,
            ctx.user_id,
            "webportal_role",
            None,
        ),
    )
    .await?;
    let role = crate::roles::create_role(&mut tx, id, &body.name).await?;
    tx.event_mut().set_record_id(role.id);
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok((StatusCode::CREATED, Json(role)))
}

/// Grant a portal role access to an entity
///
/// Sets what the role may do on the entity (read, create, update, delete), on which records (one to
/// three conditions, ANDed, such as `account_ref` equal to `@portal_user.account_ref`) and on which
/// fields (read, write, filter). Replaces any grant it had there. Role administrators only. Audited.
#[utoipa::path(
    put,
    operation_id = "portal_admin_put_grant",
    path = "/api/v1/admin/webportals/{id}/roles/{role_id}/grants/{entity}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("role_id" = Uuid, Path, description = "Portal role id"),
        ("entity" = String, Path, description = "Entity logical name"),
    ),
    request_body = crate::roles::GrantSpec,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 204, description = "Grant replaced"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role in this portal", body = ErrorResponse),
        (status = 422, description = "Invalid grant: no condition, a denied entity or field, and so on", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, role_id, entity)): Path<(Uuid, Uuid, String)>,
    Json(body): Json<crate::roles::GrantSpec>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::Grant,
            ctx.user_id,
            "webportal_role",
            Some(role_id),
        )
        .named(if crate::roles::is_public(&body) {
            format!("portal grant on {entity} (public, read-only)")
        } else {
            format!("portal grant on {entity}")
        }),
    )
    .await?;
    let registry = state.entities.load();
    crate::roles::put_grant(
        &mut tx,
        &registry,
        &state.engine_owned_entities,
        id,
        role_id,
        &entity,
        &body,
    )
    .await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove a portal role's grant on an entity
///
/// The role's users may do nothing more on that entity. Role administrators only. Audited.
#[utoipa::path(
    delete,
    operation_id = "portal_admin_delete_grant",
    path = "/api/v1/admin/webportals/{id}/roles/{role_id}/grants/{entity}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("role_id" = Uuid, Path, description = "Portal role id"),
        ("entity" = String, Path, description = "Entity logical name"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Grant removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such grant", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, role_id, entity)): Path<(Uuid, Uuid, String)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::Revoke,
            ctx.user_id,
            "webportal_role",
            Some(role_id),
        )
        .named(format!("portal grant on {entity} removed")),
    )
    .await?;
    crate::roles::delete_grant(&mut tx, id, role_id, &entity).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Give a portal user a role
///
/// Sets the user's role in the portal. Role administrators only. Audited.
#[utoipa::path(
    put,
    operation_id = "portal_admin_assign_role",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/role",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Web portal user id"),
    ),
    request_body = RoleAssignment,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::RoleChange)])))),
    responses(
        (status = 204, description = "The user's one role is set"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user or role in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn assign_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleAssignment>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::RoleChange,
            ctx.user_id,
            "webportal_user",
            Some(user_id),
        ),
    )
    .await?;
    crate::roles::assign_role(&mut tx, id, user_id, body.role_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Set a portal's entity settings
///
/// Sets, or clears with `null`, the lookup field on the entity that a portal create fills with the
/// portal user. Role administrators only. Audited.
#[utoipa::path(
    put,
    operation_id = "portal_admin_put_entity_config",
    path = "/api/v1/admin/webportals/{id}/entities/{entity}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("entity" = String, Path, description = "Entity logical name"),
    ),
    request_body = EntityConfig,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Configuration saved"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Not a lookup to webportal_user, or made writable by a grant", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_entity_config(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, entity)): Path<(Uuid, String)>,
    Json(body): Json<EntityConfig>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "webportal",
            Some(id),
        )
        .named(format!("portal entity configuration for {entity}")),
    )
    .await?;
    let registry = state.entities.load();
    crate::roles::put_entity_config(
        &mut tx,
        &registry,
        id,
        &entity,
        body.portal_user_field.as_deref(),
    )
    .await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Reads, role lifecycle and erasure (plan §9.5 G-8, G-14) ──────────────────

/// List web portals
///
/// Every web portal with its keyword, type, whether it is on, its owning team and MFA policy,
/// one-based pages. User administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_list_portals",
    path = "/api/v1/admin/webportals",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Portals, newest first", body = PaginatedResponse<PortalDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_portals(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PortalDetail>>, AppError> {
    // D-347/BTY-8: the admin lists use the platform's one-based paging
    // query now, so the offset provision binds is (page - 1) * page_size.
    let (page, page_size) = {
        let w = q.window();
        (w.page, w.page_size)
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let (items, total) = provision::list_portals(&mut conn, page, page_size).await?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page,
        page_size,
        warnings: Vec::new(),
    }))
}

/// Get a web portal
///
/// One portal's settings and `row_version`. User administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_get_portal",
    path = "/api/v1/admin/webportals/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    responses(
        (status = 200, description = "The portal", body = PortalDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_portal(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PortalDetail>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(Json(provision::load_portal(&mut conn, id).await?))
}

/// List a portal's users
///
/// The portal's users with their name, email or username and status, one-based pages. User
/// administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_list_users",
    path = "/api/v1/admin/webportals/{id}/users",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id"), OnePageQuery),
    responses(
        (status = 200, description = "The portal's users, newest first", body = PaginatedResponse<PortalUserDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_users(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PortalUserDetail>>, AppError> {
    // D-347/BTY-8: the admin lists use the platform's one-based paging
    // query now, so the offset provision binds is (page - 1) * page_size.
    let (page, page_size) = {
        let w = q.window();
        (w.page, w.page_size)
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let (items, total) = provision::list_users(&mut conn, id, page, page_size).await?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page,
        page_size,
        warnings: Vec::new(),
    }))
}

/// List a portal's roles
///
/// The portal's roles with how many users hold each. Role administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_list_roles",
    path = "/api/v1/admin/webportals/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    responses(
        (status = 200, description = "Every role of the portal, by name (one page)", body = PaginatedResponse<crate::roles::RoleSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_roles(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<crate::roles::RoleSummary>>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let items = crate::roles::list_roles(&mut conn, id).await?;
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        page_size: total.max(1),
        items,
        total,
        page: 0,
        warnings: Vec::new(),
    }))
}

/// Get a portal role
///
/// One role with how many users hold it and its entity grants. Role administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_get_role",
    path = "/api/v1/admin/webportals/{id}/roles/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("role_id" = Uuid, Path, description = "Portal role id"),
    ),
    responses(
        (status = 200, description = "The role with every grant, condition and field row", body = crate::roles::RoleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_role(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<crate::roles::RoleView>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(Json(crate::roles::get_role(&mut conn, id, role_id).await?))
}

/// Rename a portal role
///
/// Role administrators only. Audited.
#[utoipa::path(
    patch,
    operation_id = "portal_admin_rename_role",
    path = "/api/v1/admin/webportals/{id}/roles/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("role_id" = Uuid, Path, description = "Portal role id"),
    ),
    request_body = NewRole,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Renamed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role in this portal", body = ErrorResponse),
        (status = 409, description = "Name already used in this portal", body = ErrorResponse),
        (status = 422, description = "Invalid name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rename_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<NewRole>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::Update,
            ctx.user_id,
            "webportal_role",
            Some(role_id),
        )
        .named("portal role renamed"),
    )
    .await?;
    crate::roles::rename_role(&mut tx, id, role_id, &body.name).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete a portal role
///
/// Removes the role and its grants. Role administrators only. Audited.
#[utoipa::path(
    delete,
    operation_id = "portal_admin_delete_role",
    path = "/api/v1/admin/webportals/{id}/roles/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("role_id" = Uuid, Path, description = "Portal role id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Deleted with its grants"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role in this portal", body = ErrorResponse),
        (status = 409, description = "Users still hold it, or the signup policy hands it out", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::HardDelete,
            ctx.user_id,
            "webportal_role",
            Some(role_id),
        )
        .named("portal role deleted"),
    )
    .await?;
    crate::roles::delete_role(&mut tx, id, role_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Take a portal user's role away
///
/// The user keeps their account but holds no role, and so none of its grants. Role administrators
/// only. Audited.
#[utoipa::path(
    delete,
    operation_id = "portal_admin_unassign_role",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/role",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "The user holds no role now and reaches no records"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "The user holds no role in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn unassign_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Access,
            AuditOperation::Revoke,
            ctx.user_id,
            "webportal_user",
            Some(user_id),
        )
        .named("portal role unassigned"),
    )
    .await?;
    crate::roles::unassign_role(&mut tx, id, user_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// List a portal's entity settings
///
/// Per entity, the lookup field to the portal user that a portal create fills in. Role
/// administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_list_entity_configs",
    path = "/api/v1/admin/webportals/{id}/entities",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    responses(
        (status = 200, description = "The portal's per-entity configuration (one page)", body = PaginatedResponse<crate::roles::EntityConfigView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_entity_configs(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<crate::roles::EntityConfigView>>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let items = crate::roles::list_entity_configs(&mut conn, id).await?;
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        page_size: total.max(1),
        items,
        total,
        page: 0,
        warnings: Vec::new(),
    }))
}

/// List a portal's erasure requests
///
/// The erasure requests of the portal's users, with their status, one-based pages. Compliance
/// administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_list_erasure_requests",
    path = "/api/v1/admin/webportals/{id}/erasure-requests",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id"), OnePageQuery),
    responses(
        (status = 200, description = "Erasure requests, open ones first", body = PaginatedResponse<provision::ErasureRequest>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_erasure_requests(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<provision::ErasureRequest>>, AppError> {
    // D-347/BTY-8: the admin lists use the platform's one-based paging
    // query now, so the offset provision binds is (page - 1) * page_size.
    let (page, page_size) = {
        let w = q.window();
        (w.page, w.page_size)
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let (items, total) = provision::list_erasure_requests(&mut conn, id, page, page_size).await?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page,
        page_size,
        warnings: Vec::new(),
    }))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErasureDone {
    /// The completed erasure request.
    pub erasure_request_id: Uuid,
}

impl std::fmt::Debug for ErasureDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureDone").finish_non_exhaustive()
    }
}

/// Erase a portal user
///
/// Scrubs the user's personal fields in place, keeping the id so their records and audit rows still
/// resolve (to "Erased user"), and removes every credential, session, token, role and pending
/// signup; consent records stay as evidence. The open erasure request is completed, or one is
/// recorded. Compliance administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_erase_user",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/erase",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Erasure)])))),
    responses(
        (status = 200, description = "Personal data scrubbed in place; credentials, sessions and links removed", body = ErasureDone),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn erase_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ErasureDone>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Erasure,
            ctx.user_id,
            "webportal_user",
            Some(user_id),
        )
        .named("portal user erased"),
    )
    .await?;
    let registry = state.entities.load();
    let erasure_request_id =
        provision::erase_user(&mut tx, &registry, ctx.user_id, id, user_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(Json(ErasureDone { erasure_request_id }))
}

/// Export a portal user's data
///
/// Records a data subject access request for the user and fulfils it, so the export stays in the
/// request list as evidence. Compliance administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_export_user",
    path = "/api/v1/admin/webportals/{id}/users/{user_id}/export",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("user_id" = Uuid, Path, description = "Portal user id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Export)])))),
    responses(
        (status = 200, description = "A data-subject access request was recorded under the user's email and fulfilled: masked NDJSON files for the profile (every portal account with that email), the consent history and any memory rows, each checksum-verified", body = attome_compliance::dsr_admin::FulfillExportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// G-14: a portal user's data export. Not a second exporter: it records a DSR
// `access` request and fulfils it through `attome-compliance`
// (`record_and_fulfill_access`), which writes the `Security`/`Export` event
// and keeps the request in the DSR list as evidence.
async fn export_user(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<attome_compliance::dsr_admin::FulfillExportResult>, AppError> {
    let (field, subject, consent) = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        provision::export_inputs(&mut conn, id, user_id).await?
    };
    let supplements = [attome_compliance::dsr_admin::DsrSupplement {
        name: "webportal_consent".to_owned(),
        rows: consent,
    }];
    let result = attome_compliance::dsr_admin::record_and_fulfill_access(
        &state,
        &subject,
        vec![attome_compliance::dsr_admin::DsrScope::new(
            "webportal_user",
            field,
        )],
        &supplements,
        ctx.user_id,
    )
    .await?;
    Ok(Json(result))
}

/// Reject an erasure request
///
/// Closes an open erasure request without erasing, for example under a legal hold; the account is
/// untouched. Compliance administrators only. Audited.
#[utoipa::path(
    post,
    operation_id = "portal_admin_reject_erasure_request",
    path = "/api/v1/admin/webportals/{id}/erasure-requests/{request_id}/reject",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "Web portal id"),
        ("request_id" = Uuid, Path, description = "Erasure request id"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Rejected)])))),
    responses(
        (status = 204, description = "Rejected; the account is untouched"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No open request with this id in this portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn reject_erasure_request(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path((id, request_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Rejected,
            ctx.user_id,
            "webportal_user",
            None,
        )
        .named("portal erasure request rejected"),
    )
    .await?;
    provision::reject_erasure(&mut tx, ctx.user_id, id, request_id).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/webportals",
            get(list_portals).post(create_portal),
        )
        .route("/api/v1/admin/webportals/{id}", get(get_portal))
        .route(
            "/api/v1/admin/webportals/{id}/settings",
            patch(update_portal_settings),
        )
        .route(
            "/api/v1/admin/webportals/{id}/auth-policy",
            get(get_auth_policy).put(put_auth_policy),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users",
            get(list_users).post(create_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/erase",
            post(erase_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/export",
            post(export_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/erasure-requests",
            get(list_erasure_requests),
        )
        .route(
            "/api/v1/admin/webportals/{id}/erasure-requests/{request_id}/reject",
            post(reject_erasure_request),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}",
            delete(delete_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/disable",
            post(disable_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/enable",
            post(enable_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/invite",
            post(invite_user),
        )
        .route(
            "/api/v1/admin/webportals/{id}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/api/v1/admin/webportals/{id}/roles/{role_id}",
            get(get_role).patch(rename_role).delete(delete_role),
        )
        .route(
            "/api/v1/admin/webportals/{id}/entities",
            get(list_entity_configs),
        )
        .route(
            "/api/v1/admin/webportals/{id}/roles/{role_id}/grants/{entity}",
            axum::routing::put(put_grant).delete(delete_grant),
        )
        .route(
            "/api/v1/admin/webportals/{id}/users/{user_id}/role",
            axum::routing::put(assign_role).delete(unassign_role),
        )
        .route(
            "/api/v1/admin/webportals/{id}/entities/{entity}",
            axum::routing::put(put_entity_config),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_portal,
    update_portal_settings,
    get_auth_policy,
    put_auth_policy,
    create_user,
    disable_user,
    enable_user,
    delete_user,
    invite_user,
    create_role,
    put_grant,
    delete_grant,
    assign_role,
    put_entity_config,
    list_portals,
    get_portal,
    list_users,
    list_roles,
    get_role,
    rename_role,
    delete_role,
    unassign_role,
    list_entity_configs,
    list_erasure_requests,
    erase_user,
    export_user,
    reject_erasure_request
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
