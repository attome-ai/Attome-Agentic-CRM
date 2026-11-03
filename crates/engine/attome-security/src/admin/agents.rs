//! AH3-T4: agent principals, administered — `/api/v1/admin/agents`.
//!
//! An agent principal is an account of kind 2 (`user_account.principal_kind`,
//! migration 0389) with its `agent_principal` row (0390): the person who
//! sponsors it (the creator unless named), its lifecycle state and an
//! optional entity scope. It never signs in interactively (AH3-T3); it acts
//! through API keys issued here, each secret shown once.
//!
//! Lifecycle: `pause` (active → paused), `suspend` (active or paused →
//! suspended), `resume` (paused or suspended → active, bumping the account's
//! auth epoch, D-116), `revoke` (any state → revoked, final: its keys and
//! sessions end and the epoch moves). Every mutation takes
//! `If-Match: "<row_version>"`, serialises on
//! `attome-security/agent_principal:{id}` and writes its security event in
//! its own transaction. An agent never holds `system.admin`
//! ([`refuse_admin_grant`], checked where privileges and roles are granted).

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{delete, get, post, put},
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::accounts::SERVICE_PRINCIPAL_EMAIL_DOMAIN;
use crate::api_keys::{ApiKeyCreated, CreateApiKeyBody};

/// `user_account.principal_kind` of an agent.
pub const AGENT_KIND: i16 = 2;

/// An agent principal.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AgentPrincipal {
    /// The agent's account id.
    pub id: Uuid,
    pub name: String,
    pub sponsor_user_ref: Uuid,
    /// `active`, `paused`, `suspended` or `revoked`.
    pub lifecycle_state: String,
    pub state_reason: Option<String>,
    pub persona_ref: Option<Uuid>,
    pub policy_ref: Option<Uuid>,
    /// The entities it may act on; absent for no narrowing.
    pub entity_scope: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Send back as `If-Match` on the next change.
    pub row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAgentBody {
    pub name: String,
    /// The person answerable for it; the caller when absent.
    #[serde(default)]
    pub sponsor: Option<Uuid>,
    #[serde(default)]
    pub persona_ref: Option<Uuid>,
    #[serde(default)]
    pub policy_ref: Option<Uuid>,
    #[serde(default)]
    pub entity_scope: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StateBody {
    /// Why, shown with the state.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SponsorBody {
    pub sponsor: Uuid,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AgentListQuery {
    /// Only agents in this lifecycle state.
    pub state: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// A lifecycle move and whether it is allowed from `from`. Pure.
pub fn next_state(action: &str, from: &str) -> Option<&'static str> {
    match (action, from) {
        ("pause", "active") => Some("paused"),
        ("suspend", "active" | "paused") => Some("suspended"),
        ("resume", "paused" | "suspended") => Some("active"),
        ("revoke", "active" | "paused" | "suspended") => Some("revoked"),
        _ => None,
    }
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?
        .to_str()
        .ok()
        .map(|s| s.trim().trim_matches('"'))
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AppError::Validation("If-Match must be a row_version integer".into()))
}

fn scope_ok(scope: &Option<Vec<String>>) -> Result<(), AppError> {
    if let Some(entities) = scope {
        if entities.is_empty() || entities.len() > 200 {
            return Err(AppError::Validation(
                "entity_scope: one to 200 entities, or absent".into(),
            ));
        }
        if entities.iter().any(|e| {
            e.is_empty()
                || !e
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }) {
            return Err(AppError::Validation(
                "entity_scope: entity logical names".into(),
            ));
        }
    }
    Ok(())
}

const SELECT: &str = "SELECT a.user_ref, u.user_name, a.sponsor_user_ref, a.lifecycle_state, \
     a.state_reason, a.persona_ref, a.policy_ref, a.entity_scope, a.created_at, a.created_by, \
     a.revoked_at, a.row_version \
     FROM agent_principal a JOIN user_account u ON u.id = a.user_ref";

type Row = (
    Uuid,
    Option<String>,
    Uuid,
    String,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<Vec<String>>,
    DateTime<Utc>,
    Uuid,
    Option<DateTime<Utc>>,
    i64,
);

fn from_row(r: Row) -> AgentPrincipal {
    AgentPrincipal {
        id: r.0,
        name: r.1.unwrap_or_default(),
        sponsor_user_ref: r.2,
        lifecycle_state: r.3,
        state_reason: r.4,
        persona_ref: r.5,
        policy_ref: r.6,
        entity_scope: r.7,
        created_at: r.8,
        created_by: r.9,
        revoked_at: r.10,
        row_version: r.11,
    }
}

async fn find<'e, E: sqlx::PgExecutor<'e>>(db: E, id: Uuid) -> Result<AgentPrincipal, AppError> {
    sqlx::query_as::<_, Row>(&format!("{SELECT} WHERE a.user_ref = $1"))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .map(from_row)
        .ok_or(AppError::NotFound)
}

/// An active person, to sponsor an agent.
async fn require_sponsor(db: &sqlx::PgPool, sponsor: Uuid) -> Result<(), AppError> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account \
          WHERE id = $1 AND is_active AND principal_kind = 0)",
    )
    .bind(sponsor)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if ok {
        Ok(())
    } else {
        Err(AppError::Validation(
            "the sponsor is an active person's account".into(),
        ))
    }
}

/// Takes the agent's lock in `tx`; `Conflict` when another change holds it.
async fn lock(tx: &mut sqlx::PgConnection, id: Uuid) -> Result<(), AppError> {
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-security/agent_principal:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if got {
        Ok(())
    } else {
        Err(AppError::Conflict("the agent is being changed; retry"))
    }
}

fn event(op: AuditOperation, actor: Uuid, id: Uuid, name: &'static str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Access,
        op,
        actor,
        "agent_principal",
        Some(id),
    )
    .named(name)
}

/// Refuses `system.admin` for an agent account: as a direct privilege
/// (`privilege_key`) or through a role holding it (`role`). AH3-T4.
pub async fn refuse_admin_grant(
    db: &sqlx::PgPool,
    user: Uuid,
    privilege_key: Option<&str>,
    role: Option<Uuid>,
) -> Result<(), AppError> {
    let kind: Option<i16> =
        sqlx::query_scalar("SELECT principal_kind FROM user_account WHERE id = $1")
            .bind(user)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if kind != Some(AGENT_KIND) {
        return Ok(());
    }
    let admin = crate::context::ADMIN_PRIVILEGE_KEY;
    let via_role = match role {
        Some(role) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM role_mm_privilege rp \
               JOIN privilege p ON p.id = rp.privilege_ref \
              WHERE rp.role_ref = $1 AND p.key = $2)",
        )
        .bind(role)
        .bind(admin)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?,
        None => false,
    };
    if privilege_key == Some(admin) || via_role {
        return Err(AppError::Validation(format!(
            "an agent principal never holds {admin}"
        )));
    }
    Ok(())
}

/// Create an agent principal
///
/// Makes an agent account (kind 2, no password, no sign-in) and its principal row in one transaction. The sponsor is the caller unless named, and must be an active person. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/agents",
    tag = "admin-security",
    request_body = CreateAgentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = AgentPrincipal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_agent(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Json(body): Json<CreateAgentBody>,
) -> Result<(StatusCode, Json<AgentPrincipal>), AppError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation("name: 1 to 200 characters".into()));
    }
    scope_ok(&body.entity_scope)?;
    let sponsor = body.sponsor.unwrap_or(ctx.user_id);
    require_sponsor(&state.base.db, sponsor).await?;
    let id = Uuid::now_v7();
    // The reserved service domain: no password, federated or reset flow
    // accepts an address there (D-786), beside the kind's own refusal.
    let email = format!("agent-{}{SERVICE_PRINCIPAL_EMAIL_DOMAIN}", id.simple());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active, email_verified, principal_kind, created_by) \
         VALUES ($1, $2, $3, true, false, $4, $5)",
    )
    .bind(id)
    .bind(&email)
    .bind(&name)
    .bind(AGENT_KIND)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO agent_principal (user_ref, sponsor_user_ref, persona_ref, policy_ref, entity_scope, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(sponsor)
    .bind(body.persona_ref)
    .bind(body.policy_ref)
    .bind(&body.entity_scope)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            id,
            "agent_principal_created",
        ),
    )
    .await?;
    let agent = find(&mut *tx, id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(agent)))
}

/// List agent principals
///
/// The deployment's agent principals, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents",
    tag = "admin-security",
    params(AgentListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AgentPrincipal>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_agents(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Query(query): Query<AgentListQuery>,
) -> Result<Json<PaginatedResponse<AgentPrincipal>>, AppError> {
    let window = OnePageQuery {
        page: query.page,
        page_size: query.page_size,
    }
    .window();
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_principal WHERE ($1::text IS NULL OR lifecycle_state = $1)",
    )
    .bind(&query.state)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "{SELECT} WHERE ($1::text IS NULL OR a.lifecycle_state = $1) \
         ORDER BY a.created_at DESC, a.user_ref DESC LIMIT $2 OFFSET $3"
    ))
    .bind(&query.state)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(from_row).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

/// Get an agent principal
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The agent's account id")),
    responses(
        (status = 200, description = "Success", body = AgentPrincipal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such agent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_agent(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentPrincipal>, AppError> {
    Ok(Json(find(&state.base.db, id).await?))
}

/// Moves an agent through its lifecycle (`action`: pause, suspend, resume
/// or revoke).
async fn move_state(
    state: &EngineState,
    actor: Uuid,
    id: Uuid,
    expected: i64,
    action: &'static str,
    reason: Option<String>,
) -> Result<AgentPrincipal, AppError> {
    let reason = reason
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty());
    if reason.as_ref().is_some_and(|r| r.chars().count() > 500) {
        return Err(AppError::Validation(
            "reason: at most 500 characters".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, id).await?;
    let current = find(&mut *tx, id).await?;
    if current.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    let to = next_state(action, &current.lifecycle_state).ok_or(AppError::Conflict(
        "the agent's state does not allow this change",
    ))?;
    let moved = sqlx::query(
        "UPDATE agent_principal SET lifecycle_state = $2, state_reason = $3, \
             revoked_at = CASE WHEN $2 = 'revoked' THEN now() ELSE revoked_at END, \
             row_version = row_version + 1 \
          WHERE user_ref = $1 AND row_version = $4",
    )
    .bind(id)
    .bind(to)
    .bind(&reason)
    .bind(expected)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() != 1 {
        return Err(AppError::VersionConflict);
    }
    // D-116: every move changes what the agent may do, so its tokens'
    // epoch moves; a revoke also ends its keys and its account.
    attome_auth::epoch::bump_in_tx(&mut tx, id).await?;
    if to == "revoked" {
        sqlx::query("UPDATE api_key SET is_active = false WHERE user_ref = $1 AND is_active")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    let (op, name) = match action {
        "resume" => (AuditOperation::AccountEnabled, "agent_principal_resumed"),
        "revoke" => (AuditOperation::Revoke, "agent_principal_revoked"),
        "pause" => (AuditOperation::AccountDisabled, "agent_principal_paused"),
        _ => (AuditOperation::AccountDisabled, "agent_principal_suspended"),
    };
    let mut ev = event(op, actor, id, name);
    if let Some(r) = &reason {
        ev = ev.comment(r.clone());
    }
    write_security_event(&mut tx, &attome_audit::audit_service(state), ev).await?;
    let agent = find(&mut *tx, id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    if to == "revoked" {
        attome_auth::refresh::revoke_all_for_user(&state.base.db, id).await?;
    }
    state.base.security.invalidate_sync(id).await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, id).await;
    Ok(agent)
}

macro_rules! lifecycle_route {
    ($fn:ident, $action:literal, $path:literal, $op:ident, $summary:literal) => {
        #[doc = $summary]
        #[utoipa::path(
            post,
            path = $path,
            tag = "admin-security",
            params(("id" = Uuid, Path, description = "The agent's account id")),
            request_body = StateBody,
            extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::$op)])))),
            responses(
                (status = 200, description = "Success", body = AgentPrincipal),
                (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
                (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
                (status = 404, description = "No such agent", body = ErrorResponse),
                (status = 409, description = "Its state does not allow this, it changed since `If-Match`, or another change holds it", body = ErrorResponse),
                (status = 422, description = "No `If-Match`, or the reason failed validation", body = ErrorResponse),
            ),
            security(("session_cookie" = []), ("api_key" = [])),
        )]
        async fn $fn(
            State(state): State<EngineState>,
            ctx: Authorized<Privilege<area::Users>>,
            headers: HeaderMap,
            Path(id): Path<Uuid>,
            body: Option<Json<StateBody>>,
        ) -> Result<Json<AgentPrincipal>, AppError> {
            let expected = if_match(&headers)?;
            let reason = body.and_then(|Json(b)| b.reason);
            Ok(Json(
                move_state(&state, ctx.user_id, id, expected, $action, reason).await?,
            ))
        }
    };
}

lifecycle_route!(
    pause_agent,
    "pause",
    "/api/v1/admin/agents/{id}/pause",
    AccountDisabled,
    "Pause an agent principal\n\nAn active agent stops acting until resumed. Takes `If-Match`. Audited."
);
lifecycle_route!(
    suspend_agent,
    "suspend",
    "/api/v1/admin/agents/{id}/suspend",
    AccountDisabled,
    "Suspend an agent principal\n\nAn active or paused agent is held, for review. Takes `If-Match`. Audited."
);
lifecycle_route!(
    resume_agent,
    "resume",
    "/api/v1/admin/agents/{id}/resume",
    AccountEnabled,
    "Resume an agent principal\n\nA paused or suspended agent acts again; its auth epoch moves (D-116). Takes `If-Match`. Audited."
);
lifecycle_route!(
    revoke_agent,
    "revoke",
    "/api/v1/admin/agents/{id}/revoke",
    Revoke,
    "Revoke an agent principal\n\nFinal: its keys, sessions and account end. Takes `If-Match`. Audited."
);

/// Reassign an agent's sponsor
///
/// Names another active person as the agent's sponsor. Takes `If-Match`. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/agents/{id}/sponsor",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The agent's account id")),
    request_body = SponsorBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::OwnerChange)])))),
    responses(
        (status = 200, description = "Success", body = AgentPrincipal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such agent", body = ErrorResponse),
        (status = 409, description = "Revoked, changed since `If-Match`, or another change holds it", body = ErrorResponse),
        (status = 422, description = "No `If-Match`, or the sponsor is not an active person", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_sponsor(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<SponsorBody>,
) -> Result<Json<AgentPrincipal>, AppError> {
    let expected = if_match(&headers)?;
    require_sponsor(&state.base.db, body.sponsor).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, id).await?;
    let current = find(&mut *tx, id).await?;
    if current.lifecycle_state == "revoked" {
        return Err(AppError::Conflict("a revoked agent keeps its last sponsor"));
    }
    let moved = sqlx::query(
        "UPDATE agent_principal SET sponsor_user_ref = $2, row_version = row_version + 1 \
          WHERE user_ref = $1 AND row_version = $3",
    )
    .bind(id)
    .bind(body.sponsor)
    .bind(expected)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() != 1 {
        return Err(AppError::VersionConflict);
    }
    // What the agent may do is bounded by its sponsor's grants (AH3-T5).
    attome_auth::epoch::bump_in_tx(&mut tx, id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::OwnerChange,
            ctx.user_id,
            id,
            "agent_principal_sponsor_changed",
        ),
    )
    .await?;
    let agent = find(&mut *tx, id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    state.base.security.invalidate_sync(id).await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, id).await;
    Ok(Json(agent))
}

fn generate(prefix: &str) -> String {
    let random = Alphanumeric.sample_string(&mut rand::thread_rng(), 40);
    format!("{prefix}_{random}")
}

/// Issue an API key for an agent principal
///
/// The agent's key, hashed with the versioned pepper like any user's; the secret is in this answer only. An agent that is not active gets none. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/agents/{id}/keys",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The agent's account id")),
    request_body = CreateApiKeyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created; the secret is shown only here", body = ApiKeyCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such agent", body = ErrorResponse),
        (status = 409, description = "The agent is not active", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn issue_key(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), AppError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let expires_at = body
        .expires_in_days
        .or(state.base.config.auth.apikey_default_expiry_days)
        .map(|days| {
            Utc::now() + ChronoDuration::days(i64::try_from(days.min(36_500)).unwrap_or(36_500))
        });
    let public_key = generate("atk_pub");
    let secret = generate("atk_sec");
    let secret_hash = state.base.pepper_ring().hash(&secret);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, id).await?;
    let agent = find(&mut *tx, id).await?;
    if agent.lifecycle_state != "active" {
        return Err(AppError::Conflict("only an active agent gets a key"));
    }
    let (key_id, created_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at",
    )
    .bind(id)
    .bind(&name)
    .bind(&public_key)
    .bind(&secret_hash)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "api_key",
            Some(key_id),
        )
        .named("agent_principal_key_issued"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreated {
            id: key_id,
            name,
            public_key,
            secret,
            created_at,
            expires_at,
        }),
    ))
}

/// Revoke an agent principal's API key
///
/// Ends one of the agent's keys at once. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/agents/{id}/keys/{key_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The agent's account id"),
        ("key_id" = Uuid, Path, description = "The key"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live key of this agent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn revoke_key(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let ended = sqlx::query(
        "UPDATE api_key SET is_active = false \
          WHERE id = $1 AND user_ref = $2 AND is_active \
            AND EXISTS (SELECT 1 FROM agent_principal WHERE user_ref = $2)",
    )
    .bind(key_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if ended.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "api_key",
            Some(key_id),
        )
        .named("agent_principal_key_revoked"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/agents", get(list_agents).post(create_agent))
        .route("/api/v1/admin/agents/{id}", get(get_agent))
        .route("/api/v1/admin/agents/{id}/pause", post(pause_agent))
        .route("/api/v1/admin/agents/{id}/suspend", post(suspend_agent))
        .route("/api/v1/admin/agents/{id}/resume", post(resume_agent))
        .route("/api/v1/admin/agents/{id}/revoke", post(revoke_agent))
        .route("/api/v1/admin/agents/{id}/sponsor", put(set_sponsor))
        .route("/api/v1/admin/agents/{id}/keys", post(issue_key))
        .route(
            "/api/v1/admin/agents/{id}/keys/{key_id}",
            delete(revoke_key),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_agent,
        list_agents,
        get_agent,
        pause_agent,
        suspend_agent,
        resume_agent,
        revoke_agent,
        set_sponsor,
        issue_key,
        revoke_key
    ),
    components(schemas(AgentPrincipal, CreateAgentBody, StateBody, SponsorBody))
)]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_moves() {
        assert_eq!(next_state("pause", "active"), Some("paused"));
        assert_eq!(next_state("pause", "paused"), None);
        assert_eq!(next_state("suspend", "paused"), Some("suspended"));
        assert_eq!(next_state("resume", "suspended"), Some("active"));
        assert_eq!(next_state("resume", "active"), None);
        assert_eq!(next_state("revoke", "paused"), Some("revoked"));
        assert_eq!(next_state("revoke", "revoked"), None);
        assert_eq!(next_state("resume", "revoked"), None);
    }

    #[test]
    fn if_match_and_scope_are_checked() {
        let mut headers = HeaderMap::new();
        assert!(if_match(&headers).is_err());
        headers.insert(IF_MATCH, "\"7\"".parse().unwrap());
        assert_eq!(if_match(&headers).unwrap(), 7);
        assert!(scope_ok(&None).is_ok());
        assert!(scope_ok(&Some(vec!["account".into(), "sales_order".into()])).is_ok());
        assert!(scope_ok(&Some(vec![])).is_err());
        assert!(scope_ok(&Some(vec!["Account; drop".into()])).is_err());
    }
}
