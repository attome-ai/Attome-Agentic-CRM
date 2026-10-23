//! L3-T2: governance roles, policies, exceptions and certifications
//! (`governance_role`, `governance_policy`, `governance_policy_enforcement`,
//! `governance_policy_exception`, `governance_certification`, migration
//! 0059; the exception's request and requester, migration 0222).
//!
//! Who may do what:
//! - a domain's **owner** or **steward** edits its roles and policies,
//!   certifies its entities, and reads everything in it; `system.admin` does
//!   so in every domain;
//! - anyone holding a governance role in the domain (deputies, custodians
//!   and consumers included) reads its roles, policies and exceptions, and
//!   may ask for an exception;
//! - everyone else gets 403 (404 for a policy they cannot see).
//!
//! A policy edit raises its `version` (and `row_version`, the concurrency
//! guard); its enforcement links (a check, a label, attribute security,
//! retention, residency, each naming its target) are replaced with the
//! edit. Asking for an exception stores it as `requested` and submits an
//! approval request (M9, action `governance_policy.exception`) that the
//! domain's owners and stewards decide, the requester excluded. Approving
//! it runs [`approve_exception`] (status `approved`, `approved_by`); a
//! rejected or expired request shows on the exception as `rejected` or
//! `expired`. A certification stores the SHA-256 of the asset's definition
//! (an entity: its columns and its active attributes); reading it reports
//! `stale` when the definition has changed since.
//!
//! Every mutation writes its Configuration security event in its own
//! transaction. Policies are deployment governance records and are not
//! written into changesets.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The approval action an exception request runs.
pub const ACTION_POLICY_EXCEPTION: &str = "governance_policy.exception";

const ROLES: &[&str] = &["owner", "steward", "deputy", "custodian", "consumer"];
const ENFORCEMENT_KINDS: &[&str] = &[
    "check",
    "label",
    "attribute_security",
    "retention",
    "residency",
];
/// Most rows a list returns.
const LIST_CAP: i64 = 500;

// ── Authorization ────────────────────────────────────────────────────────

async fn roles_in(state: &EngineState, domain: Uuid, user: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar("SELECT role FROM governance_role WHERE domain_ref = $1 AND user_id = $2")
        .bind(domain)
        .bind(user)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

async fn domain_exists(state: &EngineState, domain: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM data_domain WHERE id = $1 AND is_deleted = false)",
    )
    .bind(domain)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The caller edits `domain`: `system.admin`, or its owner or steward.
async fn require_domain_editor(
    state: &EngineState,
    ctx: &SecurityContext,
    domain: Uuid,
) -> Result<(), AppError> {
    if !domain_exists(state, domain).await? {
        return Err(AppError::NotFound);
    }
    if ctx.is_admin {
        return Ok(());
    }
    let roles = roles_in(state, domain, ctx.user_id).await?;
    if roles.iter().any(|r| r == "owner" || r == "steward") {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// The caller reads `domain`: `system.admin`, or any governance role in it.
async fn require_domain_reader(
    state: &EngineState,
    ctx: &SecurityContext,
    domain: Uuid,
) -> Result<(), AppError> {
    if !domain_exists(state, domain).await? {
        return Err(AppError::NotFound);
    }
    if ctx.is_admin || !roles_in(state, domain, ctx.user_id).await?.is_empty() {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    actor: Uuid,
    operation: AuditOperation,
    target: (&'static str, Uuid),
    name: &'static str,
    comment: String,
) -> Result<(), AppError> {
    write_security_event(
        tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            target.0,
            Some(target.1),
        )
        .named(name)
        .comment(comment),
    )
    .await
}

// ── Roles ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct GovernanceRole {
    pub user_id: Uuid,
    /// `owner`, `steward`, `deputy`, `custodian` or `consumer`.
    pub role: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RoleQuery {
    pub user_id: Uuid,
    pub role: String,
}

fn check_role(role: &str) -> Result<(), AppError> {
    if ROLES.contains(&role) {
        Ok(())
    } else {
        Err(AppError::Validation(
            "role is owner, steward, deputy, custodian or consumer".into(),
        ))
    }
}

/// Lists a domain's governance roles.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/domains/{id}/roles",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<GovernanceRole>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller holds no role in the domain", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_roles(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(domain): Path<Uuid>,
) -> Result<Json<PaginatedResponse<GovernanceRole>>, AppError> {
    require_domain_reader(&state, &ctx, domain).await?;
    let items: Vec<GovernanceRole> = sqlx::query_as(
        "SELECT user_id, role FROM governance_role WHERE domain_ref = $1 \
          ORDER BY role, user_id LIMIT $2",
    )
    .bind(domain)
    .bind(LIST_CAP)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, LIST_CAP)))
}

/// Gives a person a governance role in a domain.
///
/// The domain's owner or steward, or `system.admin`. Giving a role the
/// person already holds changes nothing.
#[utoipa::path(
    put,
    path = "/api/v1/admin/governance/domains/{id}/roles",
    tag = "admin",
    params(("id" = Uuid, Path)),
    request_body = GovernanceRole,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The role is held", body = GovernanceRole),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the domain's owner or steward", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
        (status = 422, description = "Unknown role, or not an active user", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_role(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(domain): Path<Uuid>,
    Json(body): Json<GovernanceRole>,
) -> Result<Json<GovernanceRole>, AppError> {
    require_domain_editor(&state, &ctx, domain).await?;
    check_role(&body.role)?;
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(body.user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if active != Some(true) {
        return Err(AppError::Validation("user_id is an active user".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO governance_role (domain_ref, user_id, role) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(domain)
    .bind(body.user_id)
    .bind(&body.role)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        ("data_domain", domain),
        "governance_role.put",
        format!("{} holds {} in domain {domain}", body.user_id, body.role),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(body))
}

/// Takes a governance role away.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/governance/domains/{id}/roles",
    tag = "admin",
    params(("id" = Uuid, Path), RoleQuery),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
    responses(
        (status = 204, description = "The role is no longer held"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the domain's owner or steward", body = ErrorResponse),
        (status = 404, description = "Domain not found, or the role is not held", body = ErrorResponse),
        (status = 422, description = "Unknown role", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_role(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(domain): Path<Uuid>,
    Query(q): Query<RoleQuery>,
) -> Result<StatusCode, AppError> {
    require_domain_editor(&state, &ctx, domain).await?;
    check_role(&q.role)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "DELETE FROM governance_role WHERE domain_ref = $1 AND user_id = $2 AND role = $3",
    )
    .bind(domain)
    .bind(q.user_id)
    .bind(&q.role)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Delete,
        ("data_domain", domain),
        "governance_role.delete",
        format!(
            "{} no longer holds {} in domain {domain}",
            q.user_id, q.role
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Policies ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema, PartialEq, Eq)]
pub struct Enforcement {
    /// `check`, `label`, `attribute_security`, `retention` or `residency`.
    pub kind: String,
    /// What enforces it: a check's id, a label, an `entity.attribute`, ...
    pub target_ref: String,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct GovernancePolicy {
    pub id: Uuid,
    pub domain_ref: Uuid,
    pub name_en: String,
    pub name_ar: Option<String>,
    pub body_en: String,
    pub body_ar: Option<String>,
    /// Raised by every edit.
    pub version: i32,
    pub row_version: i64,
    #[sqlx(skip)]
    pub enforcements: Vec<Enforcement>,
}

const POLICY_COLUMNS: &str =
    "id, domain_ref, name_en, name_ar, body_en, body_ar, version, row_version";

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyBody {
    pub domain_ref: Uuid,
    pub name_en: String,
    #[serde(default)]
    pub name_ar: Option<String>,
    #[serde(default)]
    pub body_en: String,
    #[serde(default)]
    pub body_ar: Option<String>,
    #[serde(default)]
    pub enforcements: Vec<Enforcement>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyBody {
    pub row_version: i64,
    pub name_en: Option<String>,
    pub name_ar: Option<String>,
    pub body_en: Option<String>,
    pub body_ar: Option<String>,
    /// Replaces the links when given.
    pub enforcements: Option<Vec<Enforcement>>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PolicyListQuery {
    pub domain: Option<Uuid>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RowVersionQuery {
    pub row_version: i64,
}

fn check_text(name: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{name} is at most {max} characters"
        )));
    }
    Ok(())
}

fn check_enforcements(links: &[Enforcement]) -> Result<(), AppError> {
    if links.len() > 100 {
        return Err(AppError::Validation(
            "a policy has at most 100 enforcement links".into(),
        ));
    }
    for link in links {
        if !ENFORCEMENT_KINDS.contains(&link.kind.as_str()) {
            return Err(AppError::Validation(
                "an enforcement kind is check, label, attribute_security, retention or residency"
                    .into(),
            ));
        }
        if link.target_ref.trim().is_empty() || link.target_ref.len() > 300 {
            return Err(AppError::Validation(
                "an enforcement names its target (at most 300 characters)".into(),
            ));
        }
    }
    Ok(())
}

async fn write_enforcements(
    tx: &mut attome_db::Tx<'_>,
    policy: Uuid,
    links: &[Enforcement],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM governance_policy_enforcement WHERE policy_id = $1")
        .bind(policy)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    for link in links {
        sqlx::query(
            "INSERT INTO governance_policy_enforcement (policy_id, kind, target_ref) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(policy)
        .bind(&link.kind)
        .bind(link.target_ref.trim())
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn load_policy(state: &EngineState, id: Uuid) -> Result<GovernancePolicy, AppError> {
    let mut policy: GovernancePolicy = sqlx::query_as(&format!(
        "SELECT {POLICY_COLUMNS} FROM governance_policy WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    policy.enforcements = sqlx::query_as(
        "SELECT kind, target_ref FROM governance_policy_enforcement WHERE policy_id = $1 \
          ORDER BY kind, target_ref",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(policy)
}

/// A policy the caller may read; 404 when they may not see it.
async fn readable_policy(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<GovernancePolicy, AppError> {
    let policy = load_policy(state, id).await?;
    match require_domain_reader(state, ctx, policy.domain_ref).await {
        Ok(()) => Ok(policy),
        Err(AppError::Forbidden) => Err(AppError::NotFound),
        Err(e) => Err(e),
    }
}

/// Lists governance policies.
///
/// With `domain`, that domain's (the caller holds a role in it, or is
/// `system.admin`); without, every domain the caller holds a role in (every
/// domain for `system.admin`).
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/policies",
    tag = "admin",
    params(PolicyListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<GovernancePolicy>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller holds no role in the domain", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_policies(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<PolicyListQuery>,
) -> Result<Json<PaginatedResponse<GovernancePolicy>>, AppError> {
    if let Some(domain) = q.domain {
        require_domain_reader(&state, &ctx, domain).await?;
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT p.id FROM governance_policy p \
          WHERE ($1::uuid IS NULL OR p.domain_ref = $1) \
            AND ($2 OR EXISTS (SELECT 1 FROM governance_role g \
                                WHERE g.domain_ref = p.domain_ref AND g.user_id = $3)) \
          ORDER BY p.name_en, p.id LIMIT $4",
    )
    .bind(q.domain)
    .bind(ctx.is_admin)
    .bind(ctx.user_id)
    .bind(LIST_CAP)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(load_policy(&state, id).await?);
    }
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, LIST_CAP)))
}

/// Writes a governance policy.
///
/// The domain's owner or steward, or `system.admin`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/governance/policies",
    tag = "admin",
    request_body = CreatePolicyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = GovernancePolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the domain's owner or steward", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_policy(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<CreatePolicyBody>,
) -> Result<(StatusCode, Json<GovernancePolicy>), AppError> {
    require_domain_editor(&state, &ctx, body.domain_ref).await?;
    let name = body.name_en.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name_en is required".into()));
    }
    check_text("name_en", name, 200)?;
    check_text("body_en", &body.body_en, 20_000)?;
    if let Some(ar) = &body.body_ar {
        check_text("body_ar", ar, 20_000)?;
    }
    check_enforcements(&body.enforcements)?;
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO governance_policy (id, domain_ref, name_en, name_ar, body_en, body_ar) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(body.domain_ref)
    .bind(name)
    .bind(body.name_ar.as_deref().map(str::trim))
    .bind(&body.body_en)
    .bind(&body.body_ar)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_enforcements(&mut tx, id, &body.enforcements).await?;
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Create,
        ("governance_policy", id),
        "governance_policy.create",
        format!("policy {name:?} in domain {}", body.domain_ref),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(load_policy(&state, id).await?)))
}

/// Reads a governance policy.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = GovernancePolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such policy the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_policy(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<GovernancePolicy>, AppError> {
    Ok(Json(readable_policy(&state, &ctx, id).await?))
}

/// Edits a governance policy, raising its version.
///
/// The domain's owner or steward, or `system.admin`. Send the policy's
/// `row_version`.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/governance/policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    request_body = UpdatePolicyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = GovernancePolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the domain's owner or steward", body = ErrorResponse),
        (status = 404, description = "No such policy the caller may read", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_policy(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePolicyBody>,
) -> Result<Json<GovernancePolicy>, AppError> {
    let current = readable_policy(&state, &ctx, id).await?;
    require_domain_editor(&state, &ctx, current.domain_ref).await?;
    let name = body
        .name_en
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.name_en)
        .to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name_en is required".into()));
    }
    check_text("name_en", &name, 200)?;
    let body_en = body.body_en.clone().unwrap_or(current.body_en.clone());
    check_text("body_en", &body_en, 20_000)?;
    let body_ar = body.body_ar.clone().or(current.body_ar.clone());
    if let Some(ar) = &body_ar {
        check_text("body_ar", ar, 20_000)?;
    }
    let name_ar = body.name_ar.clone().or(current.name_ar.clone());
    if let Some(links) = &body.enforcements {
        check_enforcements(links)?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE governance_policy \
            SET name_en = $2, name_ar = $3, body_en = $4, body_ar = $5, \
                version = version + 1, row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $6",
    )
    .bind(id)
    .bind(&name)
    .bind(&name_ar)
    .bind(&body_en)
    .bind(&body_ar)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict("row_version mismatch"));
    }
    if let Some(links) = &body.enforcements {
        write_enforcements(&mut tx, id, links).await?;
    }
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        ("governance_policy", id),
        "governance_policy.update",
        format!("policy {name:?} version {}", current.version + 1),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(load_policy(&state, id).await?))
}

/// Removes a governance policy.
///
/// Refused while it has exceptions; they are its history.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/governance/policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path), RowVersionQuery),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the domain's owner or steward", body = ErrorResponse),
        (status = 404, description = "No such policy the caller may read", body = ErrorResponse),
        (status = 409, description = "row_version conflict, or the policy has exceptions", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_policy(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<RowVersionQuery>,
) -> Result<StatusCode, AppError> {
    let current = readable_policy(&state, &ctx, id).await?;
    require_domain_editor(&state, &ctx, current.domain_ref).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let has_exceptions: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM governance_policy_exception WHERE policy_id = $1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if has_exceptions {
        return Err(AppError::Conflict(
            "the policy has exceptions; edit it instead",
        ));
    }
    let done = sqlx::query("DELETE FROM governance_policy WHERE id = $1 AND row_version = $2")
        .bind(id)
        .bind(q.row_version)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict("row_version mismatch"));
    }
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Delete,
        ("governance_policy", id),
        "governance_policy.delete",
        format!("policy {:?}", current.name_en),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Exceptions ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct PolicyException {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub target_ref: String,
    pub reason: String,
    /// `requested` while its approval waits, then `approved`, `rejected` or
    /// `expired`.
    pub status: String,
    pub approved_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub requested_by: Option<Uuid>,
    pub approval_request_ref: Option<Uuid>,
    pub created_at: Option<DateTime<Utc>>,
}

/// The exception's status, with its approval request's outcome folded in.
const EXCEPTION_SELECT: &str = "SELECT x.id, x.policy_id, x.target_ref, x.reason, \
        CASE WHEN x.status = 'requested' AND r.status IN ('rejected', 'expired') THEN r.status \
             WHEN x.status = 'approved' AND x.expires_at IS NOT NULL AND x.expires_at < now() \
                  THEN 'expired' \
             ELSE x.status END AS status, \
        x.approved_by, x.expires_at, x.requested_by, x.approval_request_ref, x.created_at \
   FROM governance_policy_exception x \
   LEFT JOIN approval_request r ON r.id = x.approval_request_ref";

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExceptionBody {
    /// What the exception covers (an entity, an `entity.attribute`, a
    /// record id, ...).
    pub target_ref: String,
    pub reason: String,
    /// When the exception ends once approved; none for no end.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// The approval plan of an exception: one step any of the domain's owners
/// and stewards decides, the requester excluded.
pub fn exception_plan(approvers: &[Uuid]) -> attome_approval::ApprovalPlan {
    serde_json::from_value(json!({
        "steps": [{
            "mode": "any",
            "approvers": approvers.iter().map(|u| format!("user:{u}")).collect::<Vec<_>>(),
            "sla_minutes": null
        }]
    }))
    .unwrap_or(attome_approval::ApprovalPlan { steps: Vec::new() })
}

/// Asks for an exception to a policy.
///
/// Anyone with a governance role in the policy's domain, or `system.admin`.
/// The exception is stored as `requested` and goes to the domain's owners
/// and stewards for approval (the requester excluded).
#[utoipa::path(
    post,
    path = "/api/v1/admin/governance/policies/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path)),
    request_body = ExceptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Submitted)])))),
    responses(
        (status = 201, description = "Requested; waits for approval", body = PolicyException),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such policy the caller may read", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or nobody may approve it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_exception(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ExceptionBody>,
) -> Result<(StatusCode, Json<PolicyException>), AppError> {
    let policy = readable_policy(&state, &ctx, id).await?;
    let target = body.target_ref.trim();
    let reason = body.reason.trim();
    if target.is_empty() || reason.is_empty() {
        return Err(AppError::Validation(
            "target_ref and reason are required".into(),
        ));
    }
    check_text("target_ref", target, 300)?;
    check_text("reason", reason, 2000)?;
    if body.expires_at.is_some_and(|at| at <= Utc::now()) {
        return Err(AppError::Validation("expires_at is in the future".into()));
    }
    let approvers: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_id FROM governance_role \
          WHERE domain_ref = $1 AND role IN ('owner', 'steward') AND user_id <> $2 \
          ORDER BY user_id LIMIT 50",
    )
    .bind(policy.domain_ref)
    .bind(ctx.user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if approvers.is_empty() {
        return Err(AppError::Validation(
            "the domain has no owner or steward, other than the requester, to approve an exception"
                .into(),
        ));
    }
    let plan = exception_plan(&approvers);
    let exception = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO governance_policy_exception \
             (id, policy_id, target_ref, reason, expires_at, requested_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(exception)
    .bind(id)
    .bind(target)
    .bind(reason)
    .bind(body.expires_at)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let backstop = attome_audit::approval::plan_backstop_ttl(&plan);
    let request = attome_approval::submit_with_plan_regarding_in_tx(
        &mut tx,
        ACTION_POLICY_EXCEPTION,
        json!({
            "exception_id": exception,
            "policy_id": id,
            "policy": policy.name_en,
            "target_ref": target,
            "reason": reason,
        }),
        ctx.user_id,
        plan,
        backstop,
        None,
        None,
    )
    .await?;
    sqlx::query("UPDATE governance_policy_exception SET approval_request_ref = $2 WHERE id = $1")
        .bind(exception)
        .bind(request.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Submitted,
        ("governance_policy", id),
        "governance_policy.exception_request",
        format!("exception for {target:?} submitted for approval"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(load_exception(&state, exception).await?),
    ))
}

async fn load_exception(state: &EngineState, id: Uuid) -> Result<PolicyException, AppError> {
    sqlx::query_as(&format!("{EXCEPTION_SELECT} WHERE x.id = $1"))
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// Lists a policy's exceptions.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/policies/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PolicyException>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such policy the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_exceptions(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<PolicyException>>, AppError> {
    readable_policy(&state, &ctx, id).await?;
    let items: Vec<PolicyException> = sqlx::query_as(&format!(
        "{EXCEPTION_SELECT} WHERE x.policy_id = $1 ORDER BY x.id DESC LIMIT $2"
    ))
    .bind(id)
    .bind(LIST_CAP)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, LIST_CAP)))
}

/// Runs an approved exception request: the exception is `approved` by
/// `approver`. Called by the approval executor for
/// [`ACTION_POLICY_EXCEPTION`].
pub async fn approve_exception(
    state: &EngineState,
    payload: &Value,
    approver: Uuid,
) -> Result<Value, AppError> {
    let id = payload["exception_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("approval payload missing \"exception_id\""))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE governance_policy_exception SET status = 'approved', approved_by = $2 \
          WHERE id = $1 AND status = 'requested'",
    )
    .bind(id)
    .bind(approver)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "the exception is no longer waiting for approval",
        ));
    }
    let policy: Uuid =
        sqlx::query_scalar("SELECT policy_id FROM governance_policy_exception WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        approver,
        AuditOperation::Approved,
        ("governance_policy", policy),
        "governance_policy.exception_approved",
        format!("exception {id} approved"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(json!({ "exception_id": id, "status": "approved" }))
}

// ── Certifications ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CertifyBody {
    /// `entity` today.
    pub asset_kind: String,
    /// The entity's logical name.
    pub asset_ref: String,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Certification {
    pub asset_kind: String,
    pub asset_ref: String,
    pub certified_by: Option<Uuid>,
    pub certified_at: DateTime<Utc>,
    pub definition_hash: String,
    /// `certified`, or `stale` once the definition changed; `revoked`.
    pub status: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CertificationQuery {
    pub asset_kind: String,
    pub asset_ref: String,
}

/// The SHA-256 of an entity's definition: its own columns and its active
/// attributes, in name order. `None` when there is no such entity.
pub async fn entity_definition_hash(
    state: &EngineState,
    entity: &str,
) -> Result<Option<(String, Option<Uuid>)>, AppError> {
    sqlx::query_as(
        "SELECT encode(sha256(convert_to(jsonb_build_object( \
                    'logicalname', e.logicalname, 'name', e.name, \
                    'primary_name_attribute', e.primary_name_attribute, \
                    'is_append_only', COALESCE(e.is_append_only, false), \
                    'attributes', COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                         'logicalname', a.logicalname, 'type', a.type, 'required', a.required, \
                         'max_length', a.max_length, 'default_value', a.default_value, \
                         'lookup_entity_ref', a.lookup_entity_ref, 'options', a.options, \
                         'is_sensitive', a.is_sensitive, \
                         'data_classification', a.data_classification) \
                       ORDER BY a.logicalname) \
                      FROM attribute_info a \
                     WHERE a.entity_ref = e.id AND (a.is_active IS NULL OR a.is_active)), \
                     '[]'::jsonb))::text, 'UTF8')), 'hex'), \
                e.domain_ref \
           FROM entity_info e \
          WHERE e.logicalname = $1 AND (e.is_active IS NULL OR e.is_active)",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Certifies an asset against its current definition.
///
/// An entity: its domain's owner or steward, or `system.admin` (for an
/// entity in no domain, `system.admin` only). Certifying again replaces the
/// earlier certification.
#[utoipa::path(
    post,
    path = "/api/v1/admin/governance/certifications",
    tag = "admin",
    request_body = CertifyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Certified", body = Certification),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not certify the asset", body = ErrorResponse),
        (status = 404, description = "No such asset", body = ErrorResponse),
        (status = 422, description = "An asset kind that is not certified yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn certify(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<CertifyBody>,
) -> Result<Json<Certification>, AppError> {
    if body.asset_kind != "entity" {
        return Err(AppError::Validation(
            "asset_kind is entity (other assets are not certified yet)".into(),
        ));
    }
    let (hash, domain) = entity_definition_hash(&state, &body.asset_ref)
        .await?
        .ok_or(AppError::NotFound)?;
    match domain {
        Some(domain) => require_domain_editor(&state, &ctx, domain).await?,
        None if ctx.is_admin => {}
        None => return Err(AppError::Forbidden),
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Certification = sqlx::query_as(
        "INSERT INTO governance_certification \
             (asset_kind, asset_ref, certified_by, definition_hash, status) \
         VALUES ($1, $2, $3, $4, 'certified') \
         ON CONFLICT (asset_kind, asset_ref) DO UPDATE \
            SET certified_by = EXCLUDED.certified_by, certified_at = now(), \
                definition_hash = EXCLUDED.definition_hash, status = 'certified' \
         RETURNING asset_kind, asset_ref, certified_by, certified_at, definition_hash, status",
    )
    .bind(&body.asset_kind)
    .bind(&body.asset_ref)
    .bind(ctx.user_id)
    .bind(&hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let entity_id: Uuid = sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(&body.asset_ref)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        ("entity_info", entity_id),
        "governance_certification.certify",
        format!("entity {} certified at {hash}", body.asset_ref),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(row))
}

/// Reads an asset's certification, `stale` when its definition changed.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/certifications",
    tag = "admin",
    params(CertificationQuery),
    responses(
        (status = 200, description = "Success", body = Certification),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller holds no role in the asset's domain", body = ErrorResponse),
        (status = 404, description = "Not certified", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_certification(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<CertificationQuery>,
) -> Result<Json<Certification>, AppError> {
    let mut row: Certification = sqlx::query_as(
        "SELECT asset_kind, asset_ref, certified_by, certified_at, definition_hash, status \
           FROM governance_certification WHERE asset_kind = $1 AND asset_ref = $2",
    )
    .bind(&q.asset_kind)
    .bind(&q.asset_ref)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if row.asset_kind == "entity" {
        let current = entity_definition_hash(&state, &row.asset_ref).await?;
        match current.as_ref().and_then(|(_, d)| *d) {
            Some(domain) => require_domain_reader(&state, &ctx, domain).await?,
            None if ctx.is_admin => {}
            None => return Err(AppError::Forbidden),
        }
        if row.status == "certified"
            && current
                .as_ref()
                .is_none_or(|(hash, _)| *hash != row.definition_hash)
        {
            row.status = "stale".into();
        }
    } else if !ctx.is_admin {
        return Err(AppError::Forbidden);
    }
    Ok(Json(row))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/governance/domains/{id}/roles",
            get(list_roles).put(put_role).delete(delete_role),
        )
        .route(
            "/api/v1/admin/governance/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/admin/governance/policies/{id}",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .route(
            "/api/v1/admin/governance/policies/{id}/exceptions",
            post(request_exception).get(list_exceptions),
        )
        .route(
            "/api/v1/admin/governance/certifications",
            post(certify).get(get_certification),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_roles,
    put_role,
    delete_role,
    list_policies,
    create_policy,
    get_policy,
    update_policy,
    delete_policy,
    request_exception,
    list_exceptions,
    certify,
    get_certification
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_exception_plan_is_any_of_the_domain_approvers() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let plan = exception_plan(&[a, b]);
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(
            plan.steps[0].approvers,
            vec![format!("user:{a}"), format!("user:{b}")]
        );
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn governance_enforcement_links_are_checked() {
        let ok = Enforcement {
            kind: "retention".into(),
            target_ref: "invoice".into(),
        };
        assert!(check_enforcements(std::slice::from_ref(&ok)).is_ok());
        let bad = Enforcement {
            kind: "magic".into(),
            ..ok.clone()
        };
        assert!(check_enforcements(&[bad]).is_err());
        let blank = Enforcement {
            target_ref: " ".into(),
            ..ok
        };
        assert!(check_enforcements(&[blank]).is_err());
        assert!(check_role("steward").is_ok() && check_role("king").is_err());
    }
}
