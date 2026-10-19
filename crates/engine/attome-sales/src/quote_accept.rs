//! D9-T3: a customer accepts or rejects a quote online, from a link.
//!
//! **The link.** A salesperson who may change a sent quote asks for its
//! guest link (`POST /api/v1/sales/quotes/{id}/guest-link`). The token is a
//! `signed_link` over the quote's id **and version**, expiring at the
//! sooner of the requested days (30 by default, at most 90) and the quote's
//! own `expires_on`. A new version of the quote ends every link to the old
//! one, so a customer never accepts terms that have since changed.
//!
//! **The page** (`GET /api/v1/quote-acceptance/{token}`) shows only what a
//! customer reads on a quote: its number, name, currency, dates, terms,
//! totals and lines. **The decision** (`POST`) takes the person's name and
//! an optional note. While the quote is still `sent` and the link's version
//! is the quote's, it records who decided, when and their note, then moves
//! the quote to `accepted` or `rejected` through its state model. Both
//! writes go through the generic mutation path as the quote's owner, with
//! one business event. The pack's `quote_locked_after_decision` rule then
//! locks the decided quote's terms, amounts and decision.

use attome_auth::signed_link;
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

const LINK_DOMAIN: &str = "attome-sales/quote";
const DEFAULT_DAYS: i64 = 30;
const MAX_DAYS: i64 = 90;

/// The token's subject: the quote and the version it shows. Pure.
pub fn subject(quote: Uuid, version: i64) -> String {
    format!("{quote}:{version}")
}

/// Reads a subject back. Pure.
pub fn parse_subject(subject: &str) -> Option<(Uuid, i64)> {
    let (id, version) = subject.split_once(':')?;
    Some((Uuid::parse_str(id).ok()?, version.parse().ok()?))
}

/// When a link made now expires: the requested days (1 to 90, 30 by
/// default), and never after the quote's own expiry. Pure.
pub fn link_expiry(
    now: DateTime<Utc>,
    days: Option<i64>,
    quote_expires: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    let wanted = now + Duration::days(days.unwrap_or(DEFAULT_DAYS).clamp(1, MAX_DAYS));
    match quote_expires {
        Some(end) if end < wanted => end.max(now),
        _ => wanted,
    }
}

/// A guest link request.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct GuestLinkRequest {
    /// How long the link works, 1 to 90 days (30 by default); never past the
    /// quote's own expiry.
    pub expires_in_days: Option<i64>,
}

/// A guest link.
#[derive(Debug, Serialize, ToSchema)]
pub struct GuestLink {
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// One line as the customer sees it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct QuoteLineView {
    pub product: Option<String>,
    /// Decimal text, exact.
    pub quantity: Option<String>,
    pub unit_price: Option<String>,
    pub discount_amount: Option<String>,
    pub tax_amount: Option<String>,
    pub line_total: Option<String>,
}

/// A quote as the customer sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuoteView {
    pub quote_number: Option<String>,
    pub name: Option<String>,
    pub currency: Option<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub expires_on: Option<DateTime<Utc>>,
    pub payment_terms: Option<String>,
    pub terms: Option<String>,
    /// Decimal text, exact.
    pub subtotal: Option<String>,
    pub discount_total: Option<String>,
    pub vat_estimate: Option<String>,
    pub grand_total: Option<String>,
    /// `sent`, `accepted`, `rejected` or `expired`.
    pub status: String,
    pub accepted_by_name: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub lines: Vec<QuoteLineView>,
}

/// A customer's decision.
#[derive(Debug, Deserialize, ToSchema)]
pub struct QuoteDecision {
    /// `accept` or `reject`.
    pub decision: String,
    /// The person deciding, as they sign.
    pub name: String,
    pub note: Option<String>,
}

/// The validated decision: the status it leads to, the name and the note.
/// Pure.
pub fn validate(
    decision: &QuoteDecision,
) -> Result<(&'static str, String, Option<String>), AppError> {
    let status = match decision.decision.as_str() {
        "accept" => "accepted",
        "reject" => "rejected",
        _ => return Err(AppError::Validation("decision: accept or reject".into())),
    };
    let name = decision.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation("name: 1 to 200 characters".into()));
    }
    let note = decision
        .note
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    if note.is_some_and(|n| n.chars().count() > 2000) {
        return Err(AppError::Validation("note: at most 2000 characters".into()));
    }
    Ok((status, name.to_owned(), note.map(str::to_owned)))
}

fn secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

#[derive(sqlx::FromRow)]
struct QuoteRow {
    status: Option<String>,
    version: Option<f64>,
    expires_on: Option<DateTime<Utc>>,
    owner_ref: Option<Uuid>,
    created_by: Option<Uuid>,
}

async fn quote_row(state: &EngineState, id: Uuid) -> Result<Option<QuoteRow>, AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('quote') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    sqlx::query_as(
        "SELECT status, version::float8 AS version, expires_on, owner_ref, created_by \
           FROM quote WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

fn version_of(row: &QuoteRow) -> i64 {
    row.version
        .filter(|v| v.is_finite())
        .map_or(1, |v| v.round() as i64)
}

/// Makes the guest link for a sent quote the caller may change.
pub async fn create_guest_link(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    req: &GuestLinkRequest,
) -> Result<GuestLink, AppError> {
    ctx.require("quote", "update")?;
    // Read as the caller: a quote they may not see has no link.
    attome_records::entity_crud::read_record(state, ctx, "quote", id).await?;
    let row = quote_row(state, id).await?.ok_or(AppError::NotFound)?;
    if row.status.as_deref() != Some("sent") {
        return Err(AppError::Conflict("only a sent quote has a guest link"));
    }
    let now = Utc::now();
    let expires_at = link_expiry(now, req.expires_in_days, row.expires_on);
    if expires_at <= now {
        return Err(AppError::Conflict("the quote has expired"));
    }
    let token = signed_link::sign(
        &secret(state)?,
        LINK_DOMAIN,
        &subject(id, version_of(&row)),
        expires_at.timestamp(),
    )
    .ok_or_else(|| AppError::internal("quote link could not be signed"))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "quote",
            id,
            attome_audit::AuditOperation::Update,
            "quote.guest_link_created",
            ctx.user_id,
        )
        .comment(format!("expires {}", expires_at.to_rfc3339())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(GuestLink {
        url: format!(
            "{}/quote/{token}",
            state.base.config.frontend_url().trim_end_matches('/')
        ),
        expires_at,
    })
}

/// The quote a token names, if the token is genuine and current: same
/// version, not expired.
async fn quote_for(state: &EngineState, token: &str) -> Result<(Uuid, QuoteRow), AppError> {
    let (id, version) =
        signed_link::verify(&secret(state)?, LINK_DOMAIN, token, Utc::now().timestamp())
            .and_then(|s| parse_subject(&s))
            .ok_or(AppError::NotFound)?;
    let row = quote_row(state, id).await?.ok_or(AppError::NotFound)?;
    if version_of(&row) != version {
        // Superseded by a new version: the link ends with the old terms.
        return Err(AppError::NotFound);
    }
    Ok((id, row))
}

/// The customer's view of the quote a token names.
pub async fn view(state: &EngineState, token: &str) -> Result<QuoteView, AppError> {
    let (id, _) = quote_for(state, token).await?;
    #[derive(sqlx::FromRow)]
    struct Head {
        quote_number: Option<String>,
        name: Option<String>,
        currency: Option<String>,
        valid_from: Option<DateTime<Utc>>,
        expires_on: Option<DateTime<Utc>>,
        payment_terms: Option<String>,
        terms: Option<String>,
        subtotal: Option<String>,
        discount_total: Option<String>,
        vat_estimate: Option<String>,
        grand_total: Option<String>,
        status: Option<String>,
        accepted_by_name: Option<String>,
        decided_at: Option<DateTime<Utc>>,
    }
    let head: Head = sqlx::query_as(
        "SELECT quote_number, name, currency, valid_from, expires_on, payment_terms, terms, \
                subtotal::text AS subtotal, discount_total::text AS discount_total, \
                vat_estimate::text AS vat_estimate, grand_total::text AS grand_total, \
                status, accepted_by_name, decided_at \
           FROM quote WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let lines: Vec<QuoteLineView> = sqlx::query_as(
        "SELECT p.name AS product, ql.quantity::text AS quantity, ql.unit_price::text AS unit_price, \
                ql.discount_amount::text AS discount_amount, ql.tax_amount::text AS tax_amount, \
                ql.line_total::text AS line_total \
           FROM quote_line ql LEFT JOIN product p ON p.id = ql.product_ref \
          WHERE ql.quote_ref = $1 AND ql.is_active IS NOT FALSE \
          ORDER BY ql.created_at, ql.id LIMIT 500",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(QuoteView {
        quote_number: head.quote_number,
        name: head.name,
        currency: head.currency,
        valid_from: head.valid_from,
        expires_on: head.expires_on,
        payment_terms: head.payment_terms,
        terms: head.terms,
        subtotal: head.subtotal,
        discount_total: head.discount_total,
        vat_estimate: head.vat_estimate,
        grand_total: head.grand_total,
        status: head.status.unwrap_or_else(|| "sent".to_owned()),
        accepted_by_name: head.accepted_by_name,
        decided_at: head.decided_at,
        lines,
    })
}

async fn version_now(state: &EngineState, id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar("SELECT row_version FROM quote WHERE id = $1")
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Records the customer's decision on the quote a token names.
pub async fn decide(
    state: &EngineState,
    token: &str,
    decision: &QuoteDecision,
) -> Result<QuoteView, AppError> {
    let (status, name, note) = validate(decision)?;
    let (id, row) = quote_for(state, token).await?;
    if row.status.as_deref() != Some("sent") {
        return Err(AppError::Conflict("this quote has already been decided"));
    }
    if row.expires_on.is_some_and(|e| e < Utc::now()) {
        return Err(AppError::Conflict("this quote has expired"));
    }
    let owner = row
        .owner_ref
        .or(row.created_by)
        .ok_or_else(|| AppError::Conflict("the quote has no owner to record the decision"))?;
    let ctx = state.base.security.resolve(owner).await?;
    let now = Utc::now();
    let mut details = json!({ "accepted_by_name": name, "decided_at": now.to_rfc3339() });
    if let Some(note) = &note {
        details["decision_note"] = Value::String(note.clone());
    }
    // The decision first, while the quote is still open; then the status,
    // after which the pack's rule locks both.
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        owner,
        "quote",
        id,
        version_now(state, id).await?,
        details,
    )
    .await?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        owner,
        "quote",
        id,
        version_now(state, id).await?,
        json!({ "status": status }),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "quote",
            id,
            attome_audit::AuditOperation::Update,
            if status == "accepted" {
                "quote.accepted_online"
            } else {
                "quote.rejected_online"
            },
            owner,
        )
        .comment(format!("by {name}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(quote = %id, status, "quote: decided online");
    view(state, token).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn quote_accept_binds_the_link_to_the_version() {
        let id = Uuid::from_u128(7);
        assert_eq!(parse_subject(&subject(id, 3)), Some((id, 3)));
        assert_eq!(parse_subject("nope"), None);
        assert_eq!(parse_subject(&format!("{id}:x")), None);
    }

    #[test]
    fn quote_accept_link_expiry() {
        let now = at("2026-11-01T00:00:00Z");
        assert_eq!(link_expiry(now, None, None), at("2026-12-01T00:00:00Z"));
        assert_eq!(link_expiry(now, Some(500), None), now + Duration::days(90));
        assert_eq!(link_expiry(now, Some(0), None), now + Duration::days(1));
        assert_eq!(
            link_expiry(now, None, Some(at("2026-11-10T00:00:00Z"))),
            at("2026-11-10T00:00:00Z"),
            "never past the quote's own expiry"
        );
        assert_eq!(
            link_expiry(now, None, Some(at("2026-10-01T00:00:00Z"))),
            now
        );
    }

    #[test]
    fn quote_accept_validates_the_decision() {
        let d = |decision: &str, name: &str| QuoteDecision {
            decision: decision.into(),
            name: name.into(),
            note: Some("  ".into()),
        };
        let (status, name, note) = validate(&d("accept", " Fahad Al-Harbi ")).unwrap();
        assert_eq!(
            (status, name.as_str(), note),
            ("accepted", "Fahad Al-Harbi", None)
        );
        assert_eq!(validate(&d("reject", "Fahad")).unwrap().0, "rejected");
        assert!(validate(&d("maybe", "Fahad")).is_err());
        assert!(validate(&d("accept", "")).is_err());
    }
}
