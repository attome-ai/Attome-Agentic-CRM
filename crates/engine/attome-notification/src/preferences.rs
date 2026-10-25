//! Per-user notification preferences (basic-units plan U5, ruling B-R5,
//! D-602).
//!
//! A user mutes a channel for a category: a notification template key, or a
//! platform event name from [`EVENT_CATEGORIES`]. Stored in the
//! migration-owned `notification_preference` (migration 0497).
//!
//! The rules, all enforced in the dispatch engine rather than in any UI:
//! - **Mute only.** A preference removes channels from what the request or
//!   template resolved (`dispatch::create_dispatch_in_tx`); it never adds one.
//!   Organization/global dispatches apply it per user when their in-app rows
//!   are materialized (`recipient::fan_out_notification`).
//! - **Never security.** A template marked `is_mandatory` ignores every
//!   preference, and account-security mail (`attome_email::templates`: password
//!   reset, verification, MFA, invitation) never goes through a dispatch at
//!   all, so there is nothing for a preference to remove.
//! - **Own rows only.** The self-service routes read and write the caller's
//!   own rows, keyed by the session's user; no request field names a user.
//!   There is no admin default per category in v1 (plan §7 Q8).
//! - **Audited.** A change writes a `Configuration`/`Update` security event in
//!   the same transaction (D-542).

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Every channel a preference may name — the channels the dispatch engine
/// knows (`dispatch::send_channel`). Mirrors migration 0497's CHECK.
pub const CHANNELS: &[&str] = &["in_app", "email", "sms", "push", "chat"];

/// Platform event names a dispatch can be categorized under without a
/// template (`dispatch::create_dispatch_in_tx`'s `category`).
pub const EVENT_CATEGORIES: &[&str] = &[
    crate::reminders::REMINDER_CATEGORY,
    crate::follows::FOLLOW_CATEGORY,
];

/// Upper bound on the rows one PUT may write.
const MAX_ITEMS_PER_PUT: usize = 200;
/// Upper bound on the template categories one GET lists.
const MAX_TEMPLATE_CATEGORIES: i64 = 500;
const MAX_CATEGORY_LEN: usize = 100;

/// The channels `user_id` muted for `category`. Read inside the dispatch's own
/// transaction, so the decision is atomic with the dispatch insert.
pub(crate) async fn muted_channels(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    category: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT channel FROM notification_preference \
         WHERE user_ref = $1 AND category = $2 AND enabled = FALSE AND is_deleted = FALSE",
    )
    .bind(user_id)
    .bind(category)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)
}

/// One stored preference.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct NotificationPreference {
    pub category: String,
    pub channel: String,
    pub enabled: bool,
    /// Send it back on the next PUT of this (category, channel).
    pub row_version: i64,
}

/// The caller's preferences: what can be muted, and what is.
///
/// A settings document rather than a `PaginatedResponse`: it is bounded by
/// categories × channels and read whole by the one screen that edits it,
/// the same shape as `GET /api/v1/settings/me`.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationPreferences {
    /// Categories the caller may mute: active, non-mandatory template keys
    /// plus platform event names. Mandatory templates are not listed.
    pub categories: Vec<String>,
    /// Channels a preference may name.
    pub channels: Vec<String>,
    /// The caller's stored rows. A (category, channel) with no row is enabled.
    pub items: Vec<NotificationPreference>,
}

/// One (category, channel) the caller sets.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NotificationPreferenceWrite {
    pub category: String,
    pub channel: String,
    pub enabled: bool,
    /// The stored row's `row_version`; omit (or 0) for a (category, channel)
    /// that has no row yet. A mismatch is a 409.
    #[serde(default)]
    pub row_version: Option<i64>,
}

/// `PUT /api/v1/me/notification-preferences`. Rows not named are unchanged.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutNotificationPreferences {
    pub items: Vec<NotificationPreferenceWrite>,
}

async fn known_categories(db: &attome_db::DbPool) -> Result<Vec<String>, AppError> {
    let mut categories: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT template_key FROM notification_template \
         WHERE is_active = TRUE AND is_mandatory IS NOT TRUE AND template_key IS NOT NULL \
         ORDER BY template_key LIMIT $1",
    )
    .bind(MAX_TEMPLATE_CATEGORIES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for event in EVENT_CATEGORIES {
        if !categories.iter().any(|c| c == event) {
            categories.push((*event).to_owned());
        }
    }
    Ok(categories)
}

/// The caller's preferences document.
pub async fn read_for_user(
    db: &attome_db::DbPool,
    user_id: Uuid,
) -> Result<NotificationPreferences, AppError> {
    let items: Vec<NotificationPreference> = sqlx::query_as(
        "SELECT category, channel, enabled, row_version FROM notification_preference \
         WHERE user_ref = $1 AND is_deleted = FALSE ORDER BY category, channel",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(NotificationPreferences {
        categories: known_categories(db).await?,
        channels: CHANNELS.iter().map(|c| (*c).to_owned()).collect(),
        items,
    })
}

fn validate_shape(body: &PutNotificationPreferences) -> Result<(), AppError> {
    if body.items.is_empty() || body.items.len() > MAX_ITEMS_PER_PUT {
        return Err(AppError::Validation(format!(
            "items must hold between 1 and {MAX_ITEMS_PER_PUT} preferences"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for item in &body.items {
        if !CHANNELS.contains(&item.channel.as_str()) {
            return Err(AppError::Validation(format!(
                "unknown channel '{}'; expected one of {}",
                item.channel,
                CHANNELS.join(", ")
            )));
        }
        let category = item.category.as_str();
        let well_formed = !category.is_empty()
            && category.len() <= MAX_CATEGORY_LEN
            && category
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
        if !well_formed {
            return Err(AppError::Validation(format!(
                "category must be 1-{MAX_CATEGORY_LEN} characters of letters, digits, '_', '-', '.' or ':'"
            )));
        }
        if !seen.insert((category, item.channel.as_str())) {
            return Err(AppError::Validation(format!(
                "({category}, {}) appears more than once",
                item.channel
            )));
        }
    }
    Ok(())
}

/// Applies `body` to the caller's own rows in one transaction, with the
/// security event, and returns the updated document. Optimistic concurrency
/// per row: an existing row must be named with its current `row_version`,
/// and a new one with none (or 0); anything else is `VersionConflict`.
pub async fn write_for_user(
    state: &EngineState,
    user_id: Uuid,
    body: PutNotificationPreferences,
) -> Result<NotificationPreferences, AppError> {
    validate_shape(&body)?;

    // A category must be one the caller can see in the GET: an active,
    // non-mandatory template key or a platform event name. A mandatory
    // template cannot be muted (B-R5), and saying so beats silently
    // storing a row the engine would ignore.
    let known = known_categories(&state.base.db).await?;
    if let Some(unknown) = body.items.iter().find(|i| !known.contains(&i.category)) {
        return Err(AppError::Validation(format!(
            "'{}' is not a notification category that can be muted",
            unknown.category
        )));
    }

    let summary = body
        .items
        .iter()
        .map(|i| {
            format!(
                "{}:{}={}",
                i.category,
                i.channel,
                if i.enabled { "on" } else { "off" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let summary: String = summary.chars().take(1000).collect();

    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        user_id,
        "notification_preference",
        None,
    )
    .named("notification_preferences_updated")
    .comment(summary);
    let mut stx = SecurityTx::begin(state, event).await?;

    for item in &body.items {
        let existing: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT id, row_version FROM notification_preference \
             WHERE user_ref = $1 AND category = $2 AND channel = $3 FOR UPDATE",
        )
        .bind(user_id)
        .bind(&item.category)
        .bind(&item.channel)
        .fetch_optional(&mut *stx)
        .await
        .map_err(AppError::internal)?;

        match existing {
            Some((id, row_version)) => {
                if item.row_version != Some(row_version) {
                    return Err(AppError::VersionConflict);
                }
                let updated = sqlx::query(
                    "UPDATE notification_preference \
                     SET enabled = $2, is_deleted = FALSE, updated_at = NOW(), \
                         row_version = row_version + 1 \
                     WHERE id = $1 AND row_version = $3",
                )
                .bind(id)
                .bind(item.enabled)
                .bind(row_version)
                .execute(&mut *stx)
                .await
                .map_err(AppError::internal)?;
                if updated.rows_affected() != 1 {
                    return Err(AppError::VersionConflict);
                }
            }
            None => {
                if item.row_version.is_some_and(|v| v != 0) {
                    return Err(AppError::VersionConflict);
                }
                // A concurrent first write of the same key loses here rather
                // than overwriting the winner blindly.
                let inserted: Option<Uuid> = sqlx::query_scalar(
                    "INSERT INTO notification_preference (user_ref, category, channel, enabled) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (user_ref, category, channel) DO NOTHING RETURNING id",
                )
                .bind(user_id)
                .bind(&item.category)
                .bind(&item.channel)
                .bind(item.enabled)
                .fetch_optional(&mut *stx)
                .await
                .map_err(AppError::internal)?;
                if inserted.is_none() {
                    return Err(AppError::VersionConflict);
                }
            }
        }
    }
    stx.commit().await?;

    read_for_user(&state.base.db, user_id).await
}

// ── Self-service routes ──────────────────────────────────────────────────────

/// My notification preferences
///
/// The caller's own notification preferences (U5). Always the session's own
/// user; there is no way to name another user.
#[utoipa::path(
    get,
    path = "/api/v1/me/notification-preferences",
    tag = "notification",
    responses(
        (status = 200, description = "Success", body = NotificationPreferences),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_my_preferences(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<NotificationPreferences>, AppError> {
    Ok(Json(read_for_user(&state.base.db, ctx.user_id).await?))
}

/// Set my notification preferences
///
/// Sets the caller's own preferences (U5, B-R5). Mute-only, never for a
/// mandatory template; audited as a configuration change (D-542).
#[utoipa::path(
    put,
    path = "/api/v1/me/notification-preferences",
    tag = "notification",
    request_body = PutNotificationPreferences,
    responses(
        (status = 200, description = "Success", body = NotificationPreferences),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 409, description = "A row_version is stale", body = ErrorResponse),
        (status = 422, description = "Unknown channel or category, a mandatory category, or a malformed body", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn put_my_preferences(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<PutNotificationPreferences>,
) -> Result<Json<NotificationPreferences>, AppError> {
    Ok(Json(write_for_user(&state, ctx.user_id, body).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/me/notification-preferences",
        get(get_my_preferences).put(put_my_preferences),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_my_preferences, put_my_preferences))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write(category: &str, channel: &str) -> NotificationPreferenceWrite {
        NotificationPreferenceWrite {
            category: category.into(),
            channel: channel.into(),
            enabled: false,
            row_version: None,
        }
    }

    #[test]
    fn an_empty_put_is_refused() {
        let err = validate_shape(&PutNotificationPreferences { items: vec![] }).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn an_unknown_channel_is_refused() {
        let body = PutNotificationPreferences {
            items: vec![write("reminder", "carrier_pigeon")],
        };
        assert!(matches!(
            validate_shape(&body).unwrap_err(),
            AppError::Validation(_)
        ));
    }

    #[test]
    fn a_malformed_category_is_refused() {
        for bad in ["", "has space", "semi;colon", &"x".repeat(101)] {
            let body = PutNotificationPreferences {
                items: vec![write(bad, "email")],
            };
            assert!(
                matches!(validate_shape(&body).unwrap_err(), AppError::Validation(_)),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_repeated_key_is_refused() {
        let body = PutNotificationPreferences {
            items: vec![write("reminder", "email"), write("reminder", "email")],
        };
        assert!(matches!(
            validate_shape(&body).unwrap_err(),
            AppError::Validation(_)
        ));
    }

    #[test]
    fn a_well_formed_put_passes_the_shape_check() {
        let body = PutNotificationPreferences {
            items: vec![write("reminder", "email"), write("sla.warning", "in_app")],
        };
        validate_shape(&body).expect("well formed");
    }

    #[test]
    fn a_body_naming_a_user_is_refused_at_parse_time() {
        let parsed: Result<PutNotificationPreferences, _> = serde_json::from_value(json!({
            "items": [{"category": "reminder", "channel": "email", "enabled": false,
                       "user_ref": Uuid::now_v7()}]
        }));
        assert!(parsed.is_err(), "no field may name another user");
    }
}
