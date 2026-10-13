//! Self-service portal (M70 target design §3, D-423) — public offering
//! browsing and request-status-by-token lookup. **Business logic only.**
//! The HTTP handlers live in `attome-api`'s `service_public.rs`, mirroring
//! `content_public.rs`'s split for the same reason: both are anonymous,
//! bypass routes (`attome_server::middleware::bypass::EXACT_BYPASS_PATHS`)
//! that must run their own manual license check and give a uniform response
//! regardless of the reason for a miss — that requires being merged
//! directly in `system.rs`, never through `ServiceModel::routes()`, which
//! `ModelRegistry` wraps with an automatic per-module license-gate
//! middleware (`AppError::FeatureHidden`) that would leak licensing state to
//! an anonymous caller.
use attome_db::DbPool;
use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::token;

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct PublicOffering {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub fulfilment: String,
}

/// Public, is_public=true, active offerings only — deliberately a narrower
/// projection than `offering::OfferingSummary` (no `default_priority`,
/// nothing about SLA/queue/approval internals): this is what an anonymous
/// requester browses, not the internal catalog admin view.
pub async fn list_public_offerings(db: &DbPool) -> Result<Vec<PublicOffering>, AppError> {
    sqlx::query_as::<_, PublicOffering>(
        "SELECT id, name, category, description, fulfilment \
         FROM service_offering \
         WHERE is_public = true AND (is_active IS NULL OR is_active = true) \
         ORDER BY name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PortalStatus {
    pub title: String,
    pub status: String,
    /// Set once the work request is converted (`convert.rs`) — `ticket |
    /// project_work_item | project`, mirroring `resolved_entity_name`.
    /// Deliberately NOT `resolved_record_id`: an anonymous caller holding
    /// only a status token has no privilege on whatever that id names, and
    /// handing it out would invite probing the destination record directly.
    pub resolved_entity_name: Option<String>,
}

/// Looks up a work request by its presented portal bearer token
/// (`{public_id}.{secret}`). `Ok(None)` covers every failure mode
/// identically — malformed token, unknown public_id, wrong secret, or a
/// work request with no portal token at all (created via plain generic
/// CRUD, never through `offering::create_work_request_from_offering`) — the
/// caller (the public HTTP handler) must return the exact same response for
/// all of them, never distinguishing one from another. Same anti-enumeration
/// discipline `attome_auth::reset::confirm` already applies to password-reset
/// tokens, including running the same verifier work on every miss branch so a
/// malformed/unknown/wrong-secret token isn't distinguishable by timing.
pub async fn lookup_status(
    db: &DbPool,
    bearer: &str,
    ring: &attome_auth::PepperRing,
) -> Result<Option<PortalStatus>, AppError> {
    let Some((public_id, secret)) = token::parse_bearer(bearer) else {
        token::verify(bearer, None, ring).await?;
        return Ok(None);
    };

    let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT title, status, resolved_entity_name, portal_secret_hash \
         FROM service_work_request \
         WHERE portal_public_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(public_id.to_string())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    match row {
        Some((title, status, resolved_entity_name, Some(secret_hash))) => {
            if !token::verify(secret, Some(&secret_hash), ring).await? {
                return Ok(None);
            }
            Ok(Some(PortalStatus {
                title,
                status,
                resolved_entity_name,
            }))
        }
        // A row exists (matching public_id) but carries no secret hash — a
        // work request created without a portal token at all (plain generic
        // CRUD). No secret could ever verify against it; take the same
        // timing-equalized dummy-hash branch as "no such public_id".
        Some((_, _, _, None)) | None => {
            token::verify(secret, None, ring).await?;
            Ok(None)
        }
    }
}
