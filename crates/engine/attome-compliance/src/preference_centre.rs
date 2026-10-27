//! E26-T1: the public preference page behind a signed link.
//!
//! Staff create a link for one contact (or lead, or account): a token
//! signed with the active token-signing key under its own domain, naming
//! the subject and lasting [`LINK_DAYS`] days, so it needs no storage and
//! opens nothing else. Whoever holds the link reads the subject's consent
//! for every consent-based purpose (`audit_consent_purpose` with lawful
//! basis `consent`) on every channel, and changes it; each change is an E27
//! consent event (`consent::record`) with the link as its proof, written in
//! one transaction with its audit event.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::consent::{CHANNELS, ConsentChange};

/// The domain preference links are signed under.
pub const DOMAIN: &str = "attome-consent-preferences";
/// How long a preference link works.
pub const LINK_DAYS: i64 = 180;
/// The subjects a preference link may name.
pub const SUBJECTS: &[&str] = &["contact", "lead", "account"];
/// Most changes one save carries.
pub const MAX_CHANGES: usize = 100;

/// The signed subject: `{entity}:{id}`. Pure.
pub fn subject_claim(entity: &str, id: Uuid) -> String {
    format!("{entity}:{id}")
}

/// The subject a verified claim names, if it is one a link may name. Pure.
pub fn parse_claim(claim: &str) -> Option<(String, Uuid)> {
    let (entity, id) = claim.split_once(':')?;
    if !SUBJECTS.contains(&entity) {
        return None;
    }
    Some((entity.to_owned(), Uuid::parse_str(id).ok()?))
}

/// The subject a token names, if it is valid now. Pure but for the clock.
pub fn verify_token(secret: &str, token: &str, now: DateTime<Utc>) -> Option<(String, Uuid)> {
    attome_auth::signed_link::verify(secret, DOMAIN, token, now.timestamp())
        .and_then(|claim| parse_claim(&claim))
}

fn signing_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// `POST /api/v1/consents/preference-links`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreferenceLinkBody {
    /// `contact`, `lead` or `account`.
    pub subject_entity: String,
    pub subject_id: Uuid,
}

/// A preference link.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreferenceLink {
    /// The token for `GET/POST /api/v1/consents/preferences?token=`.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Creates a preference link for one subject (E26-T1).
///
/// Whoever holds it can read and change that subject's marketing consent
/// for 180 days. Put it in the footer of what is sent to them.
#[utoipa::path(
    post,
    path = "/api/v1/consents/preference-links",
    tag = "compliance",
    request_body = PreferenceLinkBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The link's token", body = PreferenceLink),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "The subject is not a contact, lead or account", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_link(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Json(body): Json<PreferenceLinkBody>,
) -> Result<Json<PreferenceLink>, AppError> {
    if !SUBJECTS.contains(&body.subject_entity.as_str()) {
        return Err(AppError::Validation(
            "subject_entity is contact, lead or account".into(),
        ));
    }
    let expires_at = Utc::now() + chrono::Duration::days(LINK_DAYS);
    let token = attome_auth::signed_link::sign(
        &signing_secret(&state)?,
        DOMAIN,
        &subject_claim(&body.subject_entity, body.subject_id),
        expires_at.timestamp(),
    )
    .ok_or_else(|| AppError::internal("the preference link could not be signed"))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            &body.subject_entity,
            Some(body.subject_id),
        )
        .named("consent.preference_link"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(PreferenceLink { token, expires_at }))
}

/// `?token=`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PreferenceQuery {
    /// The signed token from the link.
    pub token: String,
}

/// One channel's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChannelState {
    pub channel: String,
    /// `true` granted, `false` withdrawn, `null` never asked.
    pub granted: Option<bool>,
}

/// One purpose and its channels.
#[derive(Debug, Serialize, ToSchema)]
pub struct PurposePreferences {
    pub key: String,
    pub description: Option<String>,
    pub channels: Vec<ChannelState>,
}

/// The subject's preferences.
#[derive(Debug, Serialize, ToSchema)]
pub struct Preferences {
    pub purposes: Vec<PurposePreferences>,
}

/// Each channel's state from the subject's current rows. Pure.
pub fn channel_states(rows: &[(String, bool)]) -> Vec<ChannelState> {
    CHANNELS
        .iter()
        .map(|channel| ChannelState {
            channel: (*channel).to_owned(),
            granted: rows.iter().find(|(c, _)| c == channel).map(|(_, g)| *g),
        })
        .collect()
}

async fn subject_from(state: &EngineState, token: &str) -> Result<(String, Uuid), AppError> {
    verify_token(&signing_secret(state)?, token, Utc::now()).ok_or(AppError::NotFound)
}

async fn consent_purposes(
    db: &attome_db::DbPool,
) -> Result<Vec<(String, Option<String>)>, AppError> {
    sqlx::query_as(
        "SELECT key, description FROM audit_consent_purpose \
          WHERE (is_active IS NULL OR is_active = true) AND lawful_basis = 'consent' \
          ORDER BY key",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// A subject's marketing preferences, read through their link (E26-T1).
///
/// Every consent-based purpose with each channel's state. An invalid or
/// expired link answers 404, like a link that never existed.
#[utoipa::path(
    get,
    path = "/api/v1/consents/preferences",
    tag = "compliance",
    params(PreferenceQuery),
    responses(
        (status = 200, description = "The subject's preferences", body = Preferences),
        (status = 404, description = "The link is not valid", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn read_preferences(
    State(state): State<EngineState>,
    Query(query): Query<PreferenceQuery>,
) -> Result<Json<Preferences>, AppError> {
    let (entity, id) = subject_from(&state, &query.token).await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT purpose_key, channel, status FROM consent_current \
          WHERE subject_entity = $1 AND subject_id = $2",
    )
    .bind(&entity)
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let purposes = consent_purposes(&state.base.db)
        .await?
        .into_iter()
        .map(|(key, description)| {
            let mine: Vec<(String, bool)> = rows
                .iter()
                .filter(|(p, _, _)| *p == key)
                .map(|(_, channel, status)| (channel.clone(), status == "granted"))
                .collect();
            PurposePreferences {
                channels: channel_states(&mine),
                key,
                description,
            }
        })
        .collect();
    Ok(Json(Preferences { purposes }))
}

/// One change.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PreferenceChange {
    pub purpose_key: String,
    pub channel: String,
    pub grant: bool,
}

/// `POST /api/v1/consents/preferences`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SavePreferences {
    pub token: String,
    pub changes: Vec<PreferenceChange>,
}

/// The changes, checked against the channels and purposes. Pure.
pub fn check_changes(changes: &[PreferenceChange], purposes: &[String]) -> Result<(), AppError> {
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(AppError::Validation(format!(
            "a save holds 1 to {MAX_CHANGES} changes"
        )));
    }
    for change in changes {
        if !CHANNELS.contains(&change.channel.as_str()) {
            return Err(AppError::Validation(format!(
                "unknown channel {:?}",
                change.channel
            )));
        }
        if !purposes.contains(&change.purpose_key) {
            return Err(AppError::Validation(format!(
                "unknown purpose {:?}",
                change.purpose_key
            )));
        }
    }
    Ok(())
}

/// Saves a subject's preferences through their link (E26-T1).
///
/// Each change is recorded as a consent grant or withdrawal with the link
/// as its proof. An invalid or expired link answers 404.
#[utoipa::path(
    post,
    path = "/api/v1/consents/preferences",
    tag = "compliance",
    request_body = SavePreferences,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Grant)])))),
    responses(
        (status = 200, description = "The subject's preferences after the save", body = Preferences),
        (status = 404, description = "The link is not valid", body = ErrorResponse),
        (status = 422, description = "No changes, too many, or an unknown purpose or channel", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn save_preferences(
    State(state): State<EngineState>,
    Json(body): Json<SavePreferences>,
) -> Result<Json<Preferences>, AppError> {
    let (entity, id) = subject_from(&state, &body.token).await?;
    let purposes: Vec<String> = consent_purposes(&state.base.db)
        .await?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    check_changes(&body.changes, &purposes)?;
    let now = Utc::now();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for change in &body.changes {
        crate::consent::record(
            &mut tx,
            &ConsentChange {
                subject_entity: entity.clone(),
                subject_id: id,
                purpose_key: change.purpose_key.clone(),
                channel: change.channel.clone(),
                grant: change.grant,
                source: "preference_centre".to_owned(),
                proof: serde_json::json!({ "via": "signed_link" }),
                occurred_at: now,
                recorded_by: None,
            },
        )
        .await?;
    }
    // No signed-in actor: the link is the authority (`Uuid::nil()`, as the
    // public consent capture uses).
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Grant,
            Uuid::nil(),
            &entity,
            Some(id),
        )
        .named("consent.preferences_saved")
        .comment(format!("{} change(s)", body.changes.len())),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    read_preferences(State(state), Query(PreferenceQuery { token: body.token })).await
}

/// The authenticated route.
pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/consents/preference-links", post(create_link))
}

/// The public routes, bypass-listed like the consent capture.
pub fn public_routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/consents/preferences",
        get(read_preferences).post(save_preferences),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(create_link, read_preferences, save_preferences))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_centre_links_name_one_subject_until_they_expire() {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let token = attome_auth::signed_link::sign(
            "secret",
            DOMAIN,
            &subject_claim("contact", id),
            (now + chrono::Duration::days(1)).timestamp(),
        )
        .unwrap_or_default();
        assert_eq!(
            verify_token("secret", &token, now),
            Some(("contact".to_owned(), id))
        );
        assert_eq!(verify_token("other", &token, now), None);
        assert_eq!(
            verify_token("secret", &token, now + chrono::Duration::days(2)),
            None
        );
        assert_eq!(
            parse_claim(&subject_claim("user_account", id)),
            None,
            "only contacts, leads and accounts"
        );
    }

    #[test]
    fn preference_centre_shows_every_channel() {
        let states = channel_states(&[("email".to_owned(), true), ("sms".to_owned(), false)]);
        assert_eq!(states.len(), CHANNELS.len());
        assert_eq!(
            states
                .iter()
                .find(|s| s.channel == "email")
                .and_then(|s| s.granted),
            Some(true)
        );
        assert_eq!(
            states
                .iter()
                .find(|s| s.channel == "sms")
                .and_then(|s| s.granted),
            Some(false)
        );
        assert_eq!(
            states
                .iter()
                .find(|s| s.channel == "whatsapp")
                .and_then(|s| s.granted),
            None
        );
    }

    #[test]
    fn preference_centre_refuses_unknown_purposes_and_channels() {
        let purposes = vec!["newsletter".to_owned()];
        let change = |purpose: &str, channel: &str| PreferenceChange {
            purpose_key: purpose.into(),
            channel: channel.into(),
            grant: true,
        };
        assert!(check_changes(&[change("newsletter", "email")], &purposes).is_ok());
        assert!(check_changes(&[change("offers", "email")], &purposes).is_err());
        assert!(check_changes(&[change("newsletter", "fax")], &purposes).is_err());
        assert!(check_changes(&[], &purposes).is_err());
    }
}
