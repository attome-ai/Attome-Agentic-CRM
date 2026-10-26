//! E24-T1: which contact an identifier belongs to — the identity link
//! table and its deterministic linking rules.
//!
//! An identifier is an email address, a tracking visitor id, a portal user
//! or a phone number. Only deterministic events link one to a contact
//! ([`LinkSource`]): a portal sign-in, a form submitted with an email, and a
//! tracked email clicked. Each link is a row of `marketing_identity_link`
//! (migration 0287) with its source and time; emails are kept lower-cased
//! and trimmed, so `Sara@Acme.sa` and `sara@acme.sa` are one identifier.
//!
//! An identifier has at most one live link (a partial unique index). Linking
//! it again to the same contact only refreshes the time; linking it to a
//! different contact never moves it: the new pairing is stored as a
//! `conflict` naming the contact it clashes with, for a person to review
//! (`GET /api/v1/marketing/identity/conflicts`) and settle
//! (`POST /api/v1/marketing/identity/conflicts/{id}/resolve`: keep the
//! existing link, or move it to the new contact).

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// What an identifier is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierType {
    Email,
    Visitor,
    PortalUser,
    Phone,
}

impl IdentifierType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Visitor => "visitor",
            Self::PortalUser => "portal_user",
            Self::Phone => "phone",
        }
    }
}

/// The deterministic events that link an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSource {
    Login,
    FormEmail,
    EmailClick,
}

impl LinkSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::FormEmail => "form_email",
            Self::EmailClick => "email_click",
        }
    }
}

/// An identifier's stored form, or `None` when it is not one. Pure.
pub fn normalize(kind: IdentifierType, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 320 {
        return None;
    }
    match kind {
        IdentifierType::Email => {
            let lower = value.to_lowercase();
            let (local, domain) = lower.split_once('@')?;
            (!local.is_empty() && domain.contains('.') && !domain.starts_with('.')).then_some(lower)
        }
        IdentifierType::Phone => {
            let digits: String = value.chars().filter(char::is_ascii_digit).collect();
            (digits.len() >= 7).then(|| {
                if value.starts_with('+') {
                    format!("+{digits}")
                } else {
                    digits
                }
            })
        }
        IdentifierType::Visitor | IdentifierType::PortalUser => {
            Uuid::parse_str(value).ok().map(|u| u.to_string())
        }
    }
}

/// What linking an identifier to a contact does, given the contact it is
/// linked to now. Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Not linked yet: link it.
    Link,
    /// Already linked to this contact: refresh the time.
    Same,
    /// Linked to another contact: record a conflict, move nothing.
    Conflict(Uuid),
}

pub fn decide(current: Option<Uuid>, contact: Uuid) -> Decision {
    match current {
        None => Decision::Link,
        Some(c) if c == contact => Decision::Same,
        Some(other) => Decision::Conflict(other),
    }
}

/// What [`link`] did for one identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LinkOutcome {
    pub identifier_type: IdentifierType,
    pub identifier_value: String,
    /// `linked`, `same` or `conflict`.
    pub outcome: String,
}

async fn current_link(
    tx: &mut attome_db::Tx<'_>,
    kind: IdentifierType,
    value: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT contact_id FROM marketing_identity_link \
          WHERE identifier_type = $1 AND identifier_value = $2 AND status = 'linked' \
          FOR UPDATE",
    )
    .bind(kind.as_str())
    .bind(value)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Links each identifier to `contact` by the rules; one transaction per
/// identifier. An identifier that does not normalize is skipped.
pub async fn link(
    state: &EngineState,
    contact: Uuid,
    source: LinkSource,
    identifiers: &[(IdentifierType, String)],
) -> Result<Vec<LinkOutcome>, AppError> {
    let mut out = Vec::new();
    for (kind, raw) in identifiers {
        let Some(value) = normalize(*kind, raw) else {
            continue;
        };
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let lock_key = format!("attome-marketing/identity:{}:{value}", kind.as_str());
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict("this identifier is being linked"));
        }
        let outcome = match decide(current_link(&mut tx, *kind, &value).await?, contact) {
            Decision::Link => {
                sqlx::query(
                    "INSERT INTO marketing_identity_link \
                         (identifier_type, identifier_value, contact_id, source, status) \
                     VALUES ($1, $2, $3, $4, 'linked') \
                     ON CONFLICT (identifier_type, identifier_value, contact_id) \
                     DO UPDATE SET status = 'linked', conflict_with = NULL, \
                                   source = EXCLUDED.source, linked_at = now()",
                )
                .bind(kind.as_str())
                .bind(&value)
                .bind(contact)
                .bind(source.as_str())
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                "linked"
            }
            Decision::Same => {
                sqlx::query(
                    "UPDATE marketing_identity_link SET linked_at = now() \
                      WHERE identifier_type = $1 AND identifier_value = $2 AND contact_id = $3",
                )
                .bind(kind.as_str())
                .bind(&value)
                .bind(contact)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                "same"
            }
            Decision::Conflict(other) => {
                sqlx::query(
                    "INSERT INTO marketing_identity_link \
                         (identifier_type, identifier_value, contact_id, source, status, \
                          conflict_with) \
                     VALUES ($1, $2, $3, $4, 'conflict', $5) \
                     ON CONFLICT (identifier_type, identifier_value, contact_id) \
                     DO UPDATE SET status = 'conflict', conflict_with = EXCLUDED.conflict_with, \
                                   source = EXCLUDED.source, linked_at = now()",
                )
                .bind(kind.as_str())
                .bind(&value)
                .bind(contact)
                .bind(source.as_str())
                .bind(other)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                tracing::info!(identifier = kind.as_str(), %contact, %other, "identity conflict for review");
                "conflict"
            }
        };
        attome_db::tx::commit(tx).await?;
        out.push(LinkOutcome {
            identifier_type: *kind,
            identifier_value: value,
            outcome: outcome.to_owned(),
        });
    }
    Ok(out)
}

/// The contact an identifier is linked to.
pub async fn resolve(
    state: &EngineState,
    kind: IdentifierType,
    value: &str,
) -> Result<Option<Uuid>, AppError> {
    let Some(value) = normalize(kind, value) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT contact_id FROM marketing_identity_link \
          WHERE identifier_type = $1 AND identifier_value = $2 AND status = 'linked'",
    )
    .bind(kind.as_str())
    .bind(&value)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

// ── Review ───────────────────────────────────────────────────────────────────

/// `contact.update`: reviewing identity links.
#[derive(Debug)]
pub struct ContactUpdate;

impl PrivilegeKey for ContactUpdate {
    const KEY: &'static str = "contact.update";
}

/// An identifier claimed by two contacts.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct IdentityConflict {
    pub id: Uuid,
    pub identifier_type: String,
    pub identifier_value: String,
    /// The contact the identifier was last seen with.
    pub contact_id: Uuid,
    /// The contact it is linked to.
    pub conflict_with: Option<Uuid>,
    pub source: String,
    pub linked_at: DateTime<Utc>,
}

/// The open conflicts, newest first.
pub async fn conflicts(
    state: &EngineState,
    ctx: &SecurityContext,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<IdentityConflict>, AppError> {
    ctx.require("contact", "update")?;
    let window = page.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM marketing_identity_link WHERE status = 'conflict'",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<IdentityConflict> = sqlx::query_as(
        "SELECT id, identifier_type, identifier_value, contact_id, conflict_with, source, \
                linked_at \
           FROM marketing_identity_link WHERE status = 'conflict' \
          ORDER BY linked_at DESC, id DESC LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// How a conflict is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Keep {
    /// The identifier stays with the contact it is linked to.
    Existing,
    /// The identifier moves to the conflicting contact.
    New,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResolveBody {
    pub keep: Keep,
}

/// The settled conflict.
#[derive(Debug, Serialize, ToSchema)]
pub struct Resolved {
    pub identifier_type: String,
    pub identifier_value: String,
    /// The contact the identifier is linked to now.
    pub contact_id: Uuid,
}

/// Settles one conflict.
pub async fn resolve_conflict(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    keep: Keep,
) -> Result<Resolved, AppError> {
    ctx.require("contact", "update")?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(String, String, Uuid)> = sqlx::query_as(
        "SELECT identifier_type, identifier_value, contact_id FROM marketing_identity_link \
          WHERE id = $1 AND status = 'conflict' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (kind, value, challenger) = row.ok_or(AppError::NotFound)?;
    let lock_key = format!("attome-marketing/identity:{kind}:{value}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this identifier is being linked"));
    }
    let linked_to: Option<Uuid> = sqlx::query_scalar(
        "SELECT contact_id FROM marketing_identity_link \
          WHERE identifier_type = $1 AND identifier_value = $2 AND status = 'linked' FOR UPDATE",
    )
    .bind(&kind)
    .bind(&value)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let winner = match keep {
        Keep::Existing => {
            sqlx::query("UPDATE marketing_identity_link SET status = 'dismissed' WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            linked_to.unwrap_or(challenger)
        }
        Keep::New => {
            sqlx::query(
                "UPDATE marketing_identity_link SET status = 'dismissed' \
                  WHERE identifier_type = $1 AND identifier_value = $2 AND status = 'linked'",
            )
            .bind(&kind)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "UPDATE marketing_identity_link \
                    SET status = 'linked', conflict_with = NULL, linked_at = now() \
                  WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            challenger
        }
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contact",
            winner,
            attome_audit::AuditOperation::Update,
            "marketing.identity.resolved",
            ctx.user_id,
        )
        .comment(format!("{kind} link kept with this contact")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Resolved {
        identifier_type: kind,
        identifier_value: value,
        contact_id: winner,
    })
}

/// Identity conflicts to review
///
/// Identifiers (email, visitor, portal user, phone) a deterministic event
/// tied to a second contact. Nothing moved; each waits for a decision.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/identity/conflicts",
    operation_id = "list_identity_conflicts",
    tag = "marketing",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Open conflicts, newest first", body = PaginatedResponse<IdentityConflict>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contact.update", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_conflicts(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ContactUpdate>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<IdentityConflict>>, AppError> {
    conflicts(&state, &ctx, &page).await.map(Json)
}

/// Settle an identity conflict
///
/// Keep the identifier with the contact it is linked to, or move it to the
/// conflicting contact.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/identity/conflicts/{id}/resolve",
    operation_id = "resolve_identity_conflict",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The conflict")),
    request_body = ResolveBody,
    responses(
        (status = 200, description = "Settled", body = Resolved),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contact.update", body = ErrorResponse),
        (status = 404, description = "No such open conflict", body = ErrorResponse),
        (status = 409, description = "The identifier is being linked", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_resolve(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ContactUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveBody>,
) -> Result<Json<Resolved>, AppError> {
    resolve_conflict(&state, &ctx, id, body.keep)
        .await
        .map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/identity/conflicts", get(get_conflicts))
        .route(
            "/api/v1/marketing/identity/conflicts/{id}/resolve",
            post(post_resolve),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_conflicts, post_resolve),
    components(schemas(
        IdentityConflict,
        ResolveBody,
        Keep,
        Resolved,
        IdentifierType,
        LinkOutcome
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_emails_and_phones_normalize() {
        assert_eq!(
            normalize(IdentifierType::Email, "  Sara@Acme.SA "),
            Some("sara@acme.sa".into())
        );
        assert_eq!(normalize(IdentifierType::Email, "not-an-email"), None);
        assert_eq!(normalize(IdentifierType::Email, "a@b"), None);
        assert_eq!(
            normalize(IdentifierType::Phone, "+966 55 123 4567"),
            Some("+966551234567".into())
        );
        assert_eq!(normalize(IdentifierType::Phone, "12-34"), None);
        let id = Uuid::now_v7();
        assert_eq!(
            normalize(IdentifierType::Visitor, &id.to_string().to_uppercase()),
            Some(id.to_string())
        );
        assert_eq!(normalize(IdentifierType::Visitor, "visitor-1"), None);
    }

    #[test]
    fn identity_link_never_moves_on_its_own() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert_eq!(decide(None, a), Decision::Link);
        assert_eq!(decide(Some(a), a), Decision::Same);
        assert_eq!(decide(Some(a), b), Decision::Conflict(a));
    }
}
