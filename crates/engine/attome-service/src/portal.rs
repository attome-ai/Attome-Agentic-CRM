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

/// G2-T1: what an anonymous web form sends.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AnonymousRequest {
    /// 1 to 200 characters.
    pub title: String,
    /// At most 10,000 characters.
    #[serde(default)]
    pub description: Option<String>,
    /// How to reach the person, kept with the description; at most 200
    /// characters each.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// The solved challenge (`{challenge}:{answer}` for proof-of-work, or the
    /// CAPTCHA provider's token) when the deployment asks for one.
    #[serde(default)]
    pub captcha_token: Option<String>,
}

/// What an anonymous submitter gets back: the status token, once.
#[derive(Debug, Serialize, ToSchema)]
pub struct AnonymousRequestAccepted {
    /// The `{public_id}.{secret}` bearer for `GET /api/v1/service-portal/status`.
    pub status_token: String,
    /// G2-T2: the request's reference, to quote when following it up.
    pub reference: Option<String>,
}

/// The deployment's anonymous-intake settings: the offerings that take
/// anonymous requests and the service account they are filed as. `None`
/// while either is unset.
fn intake_settings(state: &attome_core::EngineState) -> Option<(Vec<Uuid>, Uuid)> {
    let read = |key: &str| {
        attome_core::setting_registry()
            .get(key)
            .map(|d| state.settings.load().resolve(d, None, None).0)
    };
    let user = read("service.anonymous_intake.user")?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let offerings: Vec<Uuid> = read("service.anonymous_intake.offerings")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
        .collect();
    (!offerings.is_empty()).then_some((offerings, user))
}

/// The request's description with the submitter's contact, as the work
/// request keeps it. Pure.
pub fn anonymous_description(body: &AnonymousRequest) -> Result<Option<String>, AppError> {
    let title = body.title.trim();
    if title.is_empty() || title.chars().count() > 200 {
        return Err(AppError::Validation("title is 1 to 200 characters".into()));
    }
    let short = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let name = short(&body.name);
    let email = short(&body.email);
    if name.as_ref().is_some_and(|s| s.chars().count() > 200)
        || email.as_ref().is_some_and(|s| s.chars().count() > 200)
    {
        return Err(AppError::Validation(
            "name and email are at most 200 characters".into(),
        ));
    }
    if email.as_ref().is_some_and(|e| !e.contains('@')) {
        return Err(AppError::Validation("email is not an address".into()));
    }
    let description = short(&body.description);
    if description
        .as_ref()
        .is_some_and(|d| d.chars().count() > 10_000)
    {
        return Err(AppError::Validation(
            "description is at most 10,000 characters".into(),
        ));
    }
    let contact = match (name, email) {
        (Some(n), Some(e)) => Some(format!("{n} <{e}>")),
        (Some(n), None) => Some(n),
        (None, Some(e)) => Some(e),
        (None, None) => None,
    };
    Ok(match (description, contact) {
        (Some(d), Some(c)) => Some(format!("{d}\n\nFrom: {c} (anonymous web form)")),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(format!("From: {c} (anonymous web form)")),
        (None, None) => None,
    })
}

/// Files an anonymous request on `offering_id` (G2-T1) as the configured
/// intake service account, through the same create path a staff request
/// takes (`offering::create_work_request_from_offering`: validation, routing,
/// SLA defaults, audit). `NotFound` for every reason the offering does not
/// take one (not listed, not public, inactive, settings unset), so an
/// anonymous caller cannot tell them apart. Rate limits and the challenge are
/// the caller's (the public route's).
pub async fn submit_anonymous(
    state: &attome_core::EngineState,
    offering_id: Uuid,
    body: &AnonymousRequest,
    ring: &attome_auth::PepperRing,
) -> Result<AnonymousRequestAccepted, AppError> {
    let description = anonymous_description(body)?;
    let Some((offerings, user)) = intake_settings(state) else {
        return Err(AppError::NotFound);
    };
    if !offerings.contains(&offering_id) {
        return Err(AppError::NotFound);
    }
    let public: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM service_offering \
          WHERE id = $1 AND is_public = true AND (is_active IS NULL OR is_active = true))",
    )
    .bind(offering_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !public {
        return Err(AppError::NotFound);
    }
    let ctx = match attome_security::resolve_uncached(&state.base.db, user).await {
        Ok(ctx) => ctx,
        Err(error) => {
            tracing::warn!(%error, "anonymous intake: the configured service account cannot sign in");
            return Err(AppError::NotFound);
        }
    };
    let request = crate::offering::CreateWorkRequestFromOfferingRequest {
        title: body.title.trim().to_owned(),
        description,
        request_type: "custom".to_owned(),
        requester_id: user,
        channel: Some("portal".to_owned()),
    };
    match crate::offering::create_work_request_from_offering(
        state,
        &ctx,
        offering_id,
        request,
        ring,
    )
    .await
    {
        // Every anonymous request shares one service account as requester,
        // so `open_requests` would list strangers' requests: not passed on.
        Ok(created) => Ok(AnonymousRequestAccepted {
            status_token: created.portal_token,
            reference: created.reference,
        }),
        Err(AppError::Forbidden) => {
            tracing::warn!(
                "anonymous intake: the configured service account may not create work requests"
            );
            Err(AppError::NotFound)
        }
        Err(other) => Err(other),
    }
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

#[cfg(test)]
mod anonymous_tests {
    use super::*;

    fn body(
        title: &str,
        description: Option<&str>,
        name: Option<&str>,
        email: Option<&str>,
    ) -> AnonymousRequest {
        AnonymousRequest {
            title: title.to_owned(),
            description: description.map(str::to_owned),
            name: name.map(str::to_owned),
            email: email.map(str::to_owned),
            captcha_token: None,
        }
    }

    #[test]
    fn the_contact_is_kept_with_the_description() {
        let d = anonymous_description(&body(
            "Printer",
            Some("It jams"),
            Some("Sara"),
            Some("sara@example.com"),
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            d.as_deref(),
            Some("It jams\n\nFrom: Sara <sara@example.com> (anonymous web form)")
        );
        let only_email = anonymous_description(&body("Printer", None, None, Some("a@b.c")))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            only_email.as_deref(),
            Some("From: a@b.c (anonymous web form)")
        );
        assert_eq!(
            anonymous_description(&body("Printer", None, None, None))
                .unwrap_or_else(|e| panic!("{e}")),
            None
        );
    }

    #[test]
    fn bad_input_is_refused() {
        assert!(anonymous_description(&body("  ", None, None, None)).is_err());
        assert!(anonymous_description(&body(&"x".repeat(201), None, None, None)).is_err());
        assert!(anonymous_description(&body("T", None, None, Some("not-an-address"))).is_err());
        assert!(anonymous_description(&body("T", Some(&"x".repeat(10_001)), None, None)).is_err());
    }
}
