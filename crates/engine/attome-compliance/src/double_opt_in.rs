//! E27-T3: double opt-in by country and consent expiry.
//!
//! **Double opt-in.** A grant captured from a public form for a contact,
//! lead or account (`POST /api/v1/consents/capture` naming the subject)
//! reaches the consent ledger at once where the subject's country does not
//! require confirmation, and only once confirmed where it does: the person
//! gets an email with a link (`GET /api/v1/consents/confirm?token=`), valid
//! [`CONFIRM_DAYS`] days, whose token is stored only as its SHA-256. Which
//! countries require it is `compliance.double_opt_in_countries` (ISO codes);
//! a form that names no country uses the deployment's `core.country`.
//!
//! **Expiry.** With `compliance.consent_expiry_days` above 0, a grant older
//! than that is withdrawn by the daily retention sweep ([`expire_grants`]),
//! as a consent event with source `expiry`, so it must be given again.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::consent::ConsentChange;

/// How long a confirmation link works.
pub const CONFIRM_DAYS: i64 = 7;
/// Most grants one expiry pass withdraws.
pub const EXPIRY_BATCH: i64 = 1000;

/// Whether a subject in `country` must confirm by email. Pure.
pub fn requires_confirmation(country: Option<&str>, countries: &[String]) -> bool {
    let Some(country) = country.map(str::trim).filter(|c| !c.is_empty()) else {
        return false;
    };
    countries
        .iter()
        .any(|c| c.trim().eq_ignore_ascii_case(country))
}

/// Whether a grant given at `granted_at` has expired at `now`. Pure.
pub fn expired(granted_at: DateTime<Utc>, now: DateTime<Utc>, expiry_days: i64) -> bool {
    expiry_days > 0 && now - granted_at >= chrono::Duration::days(expiry_days)
}

/// A token's stored form. Pure.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A fresh confirmation token: 64 hex characters of randomness.
pub fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The deployment's double opt-in countries and consent expiry, and its own
/// country.
pub struct Rules {
    pub countries: Vec<String>,
    pub expiry_days: i64,
    pub deployment_country: Option<String>,
}

/// The rules as the settings stand.
pub fn rules(state: &EngineState) -> Rules {
    let settings = state.settings.load();
    let registry = attome_core::setting_registry();
    let value = |key: &str| registry.get(key).map(|d| settings.resolve(d, None, None).0);
    Rules {
        countries: value("compliance.double_opt_in_countries")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| c.as_str().map(str::to_owned))
            .collect(),
        expiry_days: value("compliance.consent_expiry_days")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        deployment_country: value("core.country")
            .and_then(|v| v.as_str().map(str::to_owned))
            .filter(|c| !c.is_empty()),
    }
}

/// A captured grant for a known subject, to put in the ledger.
#[derive(Debug, Clone)]
pub struct CapturedGrant {
    pub subject_entity: String,
    pub subject_id: Uuid,
    pub purpose_key: String,
    pub channel: String,
    pub email: Option<String>,
    pub country: Option<String>,
}

/// What became of a captured grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOutcome {
    /// In the ledger now.
    Recorded,
    /// Waiting for the person to confirm by email.
    AwaitingConfirmation,
    /// Confirmation is required and there is no address to ask at.
    NotRecorded,
}

/// Puts a captured grant in the ledger, or asks for confirmation first, in
/// the capture's transaction.
pub async fn capture_grant(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    grant: &CapturedGrant,
) -> Result<CaptureOutcome, AppError> {
    let rules = rules(state);
    let country = grant
        .country
        .clone()
        .or_else(|| rules.deployment_country.clone());
    if !requires_confirmation(country.as_deref(), &rules.countries) {
        crate::consent::record(
            tx,
            &ConsentChange {
                subject_entity: grant.subject_entity.clone(),
                subject_id: grant.subject_id,
                purpose_key: grant.purpose_key.clone(),
                channel: grant.channel.clone(),
                grant: true,
                source: "form".to_owned(),
                proof: serde_json::json!({ "single_opt_in": true, "country": country }),
                occurred_at: Utc::now(),
                recorded_by: None,
            },
        )
        .await?;
        return Ok(CaptureOutcome::Recorded);
    }
    let Some(email) = grant.email.as_deref().filter(|e| e.contains('@')) else {
        return Ok(CaptureOutcome::NotRecorded);
    };
    let token = new_token();
    sqlx::query(
        "INSERT INTO consent_confirmation \
             (token_hash, subject_entity, subject_id, purpose_key, channel, email, country, \
              expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(days => $8))",
    )
    .bind(token_hash(&token))
    .bind(&grant.subject_entity)
    .bind(grant.subject_id)
    .bind(&grant.purpose_key)
    .bind(&grant.channel)
    .bind(email)
    .bind(&country)
    .bind(i32::try_from(CONFIRM_DAYS).unwrap_or(7))
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let link = format!(
        "{}/api/v1/consents/confirm?token={token}",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: email.to_owned(),
            subject: "Please confirm your subscription".to_owned(),
            text_body: format!(
                "Please confirm that you want to hear from us by opening this link within {CONFIRM_DAYS} days:\n\n{link}\n\n\
                 يرجى تأكيد رغبتك في تلقي رسائلنا بفتح هذا الرابط خلال {CONFIRM_DAYS} أيام:\n\n{link}\n"
            ),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
        })),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(CaptureOutcome::AwaitingConfirmation)
}

/// `?token=`, or the confirm form's field.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct ConfirmQuery {
    pub token: String,
}

/// The page the emailed link opens: a button that confirms. Opening the
/// link changes nothing, so a mail scanner that fetches links cannot
/// confirm for the person. Pure.
pub fn confirm_page(token: &str) -> String {
    let token = attome_html::escape_html(token);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>Confirm</title></head><body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <form method=\"post\" action=\"/api/v1/consents/confirm\">\
         <input type=\"hidden\" name=\"token\" value=\"{token}\">\
         <p>Confirm that you want to hear from us.</p>\
         <p dir=\"rtl\" lang=\"ar\">أكّد رغبتك في تلقي رسائلنا.</p>\
         <button type=\"submit\">Confirm / تأكيد</button></form></body></html>"
    )
}

/// The confirmation page (E27-T3).
///
/// An HTML page with one button; the button's POST confirms. Opening the
/// link alone changes nothing.
#[utoipa::path(
    get,
    path = "/api/v1/consents/confirm",
    tag = "compliance",
    params(ConfirmQuery),
    responses(
        (status = 200, description = "A page with a confirm button", content_type = "text/html"),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn confirm_get(Query(query): Query<ConfirmQuery>) -> axum::response::Html<String> {
    axum::response::Html(confirm_page(query.token.trim()))
}

/// Confirms a subscription (E27-T3).
///
/// The grant reaches the consent ledger with the confirmation as its proof.
/// A link used before, expired or unknown answers 404.
#[utoipa::path(
    post,
    path = "/api/v1/consents/confirm",
    tag = "compliance",
    request_body(content = ConfirmQuery, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Grant)])))),
    responses(
        (status = 200, description = "Confirmed", content_type = "text/html"),
        (status = 404, description = "The link is not valid", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn confirm_post(
    State(state): State<EngineState>,
    axum::Form(form): axum::Form<ConfirmQuery>,
) -> Result<axum::response::Html<&'static str>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Uuid, String, Uuid, String, String, Option<String>)> = sqlx::query_as(
        "UPDATE consent_confirmation SET confirmed_at = NOW() \
          WHERE token_hash = $1 AND confirmed_at IS NULL AND expires_at > NOW() \
          RETURNING id, subject_entity, subject_id, purpose_key, channel, country",
    )
    .bind(token_hash(form.token.trim()))
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (confirmation, subject_entity, subject_id, purpose_key, channel, country) =
        row.ok_or(AppError::NotFound)?;
    crate::consent::record(
        &mut tx,
        &ConsentChange {
            subject_entity: subject_entity.clone(),
            subject_id,
            purpose_key,
            channel,
            grant: true,
            source: "double_opt_in".to_owned(),
            proof: serde_json::json!({ "confirmation": confirmation, "country": country }),
            occurred_at: Utc::now(),
            recorded_by: None,
        },
    )
    .await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Grant,
            Uuid::nil(),
            &subject_entity,
            Some(subject_id),
        )
        .named("consent.confirmed"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(axum::response::Html(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Confirmed</title></head>\
         <body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <p>Thank you. You are subscribed.</p><p dir=\"rtl\" lang=\"ar\">شكرًا لك. تم تأكيد اشتراكك.</p>\
         </body></html>",
    ))
}

/// Withdraws grants older than `compliance.consent_expiry_days` (when set):
/// each becomes a withdrawal event with source `expiry`. Returns how many.
pub async fn expire_grants(state: &EngineState) -> Result<u64, AppError> {
    let days = rules(state).expiry_days;
    if days <= 0 {
        return Ok(0);
    }
    let due: Vec<(String, Uuid, String, String)> = sqlx::query_as(
        "SELECT subject_entity, subject_id, purpose_key, channel FROM consent_current \
          WHERE status = 'granted' AND updated_at <= NOW() - make_interval(days => $1) \
          LIMIT $2",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .bind(EXPIRY_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if due.is_empty() {
        return Ok(0);
    }
    let now = Utc::now();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for (subject_entity, subject_id, purpose_key, channel) in &due {
        crate::consent::record(
            &mut tx,
            &ConsentChange {
                subject_entity: subject_entity.clone(),
                subject_id: *subject_id,
                purpose_key: purpose_key.clone(),
                channel: channel.clone(),
                grant: false,
                source: "expiry".to_owned(),
                proof: serde_json::json!({ "expiry_days": days }),
                occurred_at: now,
                recorded_by: None,
            },
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(u64::try_from(due.len()).unwrap_or(u64::MAX))
}

/// The public confirmation route, bypass-listed like the consent capture.
pub fn public_routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/consents/confirm",
        get(confirm_get).post(confirm_post),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(confirm_get, confirm_post))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod double_opt_in {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn double_opt_in_follows_the_country_list() {
        let countries = vec!["DE".to_owned(), "at".to_owned()];
        assert!(requires_confirmation(Some("de"), &countries));
        assert!(requires_confirmation(Some("AT"), &countries));
        assert!(!requires_confirmation(Some("SA"), &countries));
        assert!(!requires_confirmation(None, &countries));
        assert!(!requires_confirmation(Some("DE"), &[]));
    }

    #[test]
    fn double_opt_in_grants_expire_after_the_set_days_only() {
        let given = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or_default();
        let later = given + chrono::Duration::days(365);
        assert!(expired(given, later, 365));
        assert!(!expired(given, later - chrono::Duration::seconds(1), 365));
        assert!(!expired(given, later, 0), "0 means grants never expire");
    }

    #[test]
    fn double_opt_in_link_only_shows_a_button() {
        let page = confirm_page("abc\"><script>");
        assert!(page.contains("method=\"post\""));
        assert!(!page.contains("<script>"), "the token is escaped");
    }

    #[test]
    fn double_opt_in_tokens_are_kept_only_as_hashes() {
        let token = new_token();
        assert_eq!(token.len(), 64);
        assert_ne!(token, new_token());
        assert_eq!(token_hash(&token).len(), 64);
        assert_ne!(token_hash(&token), token);
    }
}
