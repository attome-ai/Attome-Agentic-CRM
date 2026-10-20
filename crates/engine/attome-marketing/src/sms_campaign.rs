//! E16-T1: SMS campaigns — one message to a marketing list's people who
//! consented to SMS for the campaign's purpose, with a cost estimate first
//! and quiet hours in each recipient's own time.
//!
//! - `POST /api/v1/marketing/lists/{id}/sms/estimate` answers how many
//!   people can be reached, the message's encoding and segments, and the
//!   cost at `marketing.sms_price_per_segment` (nothing is sent).
//! - `POST /api/v1/marketing/lists/{id}/sms/send` fixes the recipients in
//!   `sms_campaign_recipient` and starts the send. When the caller passes
//!   `expected_cost`, a send whose estimate has grown past it is refused, so
//!   nobody pays for more than they saw.
//! - The `sms_campaign` job ([`sweep`]) sends pending recipients in
//!   batches through the configured SMS provider (J4-T1), holding anyone
//!   whose local time is inside `marketing.sms_quiet_hours` until the next
//!   run after their morning, and closes a send when nobody is left.
//!
//! Recipients are the list's people as the sender may see them, with a
//! phone (`mobile`, else `phone`) and a current `granted` consent for the
//! purpose on `sms` or `any`. Consent is read again just before each
//! message, so a withdrawal between start and send is honoured.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::quote_ident;
use attome_integration::connector::adapters::sms::{country_of, e164, segments};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{DateTime, NaiveTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// Most people one campaign sends to.
pub const MAX_RECIPIENTS: usize = 50_000;
/// Messages one sweep sends per campaign.
pub const BATCH: i64 = 200;

/// `marketing_list.update`: starting a send changes what the list does.
#[derive(Debug)]
pub struct ListUpdate;

impl PrivilegeKey for ListUpdate {
    const KEY: &'static str = "marketing_list.update";
}

/// A quiet window in local time; it may cross midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietHours {
    pub start: NaiveTime,
    pub end: NaiveTime,
}

impl QuietHours {
    /// Whether `local` falls inside the window. Pure.
    pub fn holds(&self, local: NaiveTime) -> bool {
        if self.start == self.end {
            false
        } else if self.start < self.end {
            local >= self.start && local < self.end
        } else {
            local >= self.start || local < self.end
        }
    }
}

/// The quiet hours for `country` from the setting's value: the country's
/// own entry, else `*`, else none. Pure.
pub fn quiet_hours_for(setting: &Value, country: Option<&str>) -> Option<QuietHours> {
    let entry = country
        .and_then(|c| setting.get(c))
        .or_else(|| setting.get("*"))?;
    let time = |k: &str| {
        entry
            .get(k)
            .and_then(Value::as_str)
            .and_then(|t| NaiveTime::parse_from_str(t, "%H:%M").ok())
    };
    Some(QuietHours {
        start: time("start")?,
        end: time("end")?,
    })
}

/// The time zone a country's numbers are reached in, for the countries the
/// SMS adapter knows; others use `fallback`. Pure.
pub fn country_zone(country: Option<&str>, fallback: chrono_tz::Tz) -> chrono_tz::Tz {
    use chrono_tz::{Africa, America, Asia, Europe};
    match country {
        Some("SA") => Asia::Riyadh,
        Some("AE") => Asia::Dubai,
        Some("KW") => Asia::Kuwait,
        Some("QA") => Asia::Qatar,
        Some("BH") => Asia::Bahrain,
        Some("OM") => Asia::Muscat,
        Some("JO") => Asia::Amman,
        Some("LB") => Asia::Beirut,
        Some("IQ") => Asia::Baghdad,
        Some("YE") => Asia::Aden,
        Some("EG") => Africa::Cairo,
        Some("MA") => Africa::Casablanca,
        Some("DZ") => Africa::Algiers,
        Some("TN") => Africa::Tunis,
        Some("LY") => Africa::Tripoli,
        Some("SD") => Africa::Khartoum,
        Some("GB") => Europe::London,
        Some("DE") => Europe::Berlin,
        Some("FR") => Europe::Paris,
        Some("TR") => Europe::Istanbul,
        Some("IN") => Asia::Kolkata,
        Some("PK") => Asia::Karachi,
        Some("US") => America::New_York,
        _ => fallback,
    }
}

/// Whether a message to `phone` must wait at `now`. Pure.
pub fn held(phone: &str, now: DateTime<Utc>, setting: &Value, fallback: chrono_tz::Tz) -> bool {
    let country = country_of(phone);
    let Some(quiet) = quiet_hours_for(setting, country) else {
        return false;
    };
    let local = now.with_timezone(&country_zone(country, fallback));
    quiet.holds(NaiveTime::from_hms_opt(local.hour(), local.minute(), 0).unwrap_or_default())
}

/// The estimate shown before sending.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SmsEstimate {
    /// People with a phone and SMS consent for the purpose.
    pub recipients: i64,
    /// `gsm7` or `ucs2` (Arabic text is UCS-2).
    pub encoding: String,
    /// Segments one message takes.
    pub segments_each: u32,
    pub total_segments: i64,
    /// `total_segments` at `marketing.sms_price_per_segment`; absent when no
    /// price is set.
    pub cost: Option<f64>,
}

/// The estimate for `body` to `recipients` people at `price`. Pure.
pub fn estimate(body: &str, recipients: i64, price: f64) -> SmsEstimate {
    let (encoding, each) = segments(body.trim());
    let total = recipients * i64::from(each);
    SmsEstimate {
        recipients,
        encoding: encoding.as_str().to_owned(),
        segments_each: each,
        total_segments: total,
        cost: (price > 0.0).then(|| (total as f64 * price * 100.0).round() / 100.0),
    }
}

fn setting(state: &EngineState, key: &str) -> Value {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(key)
        .map(|d| store.resolve(d, None, None).0)
        .unwrap_or(Value::Null)
}

fn deployment_zone(state: &EngineState) -> chrono_tz::Tz {
    state
        .base
        .config
        .app
        .time_zone
        .as_deref()
        .and_then(|z| z.parse().ok())
        .unwrap_or(chrono_tz::UTC)
}

/// The people of `list` the caller may see who can be texted for
/// `purpose`: `(entity, id, phone)`, at most [`MAX_RECIPIENTS`].
async fn recipients(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    purpose: &str,
) -> Result<(String, Vec<(Uuid, String)>), AppError> {
    let target: String = sqlx::query_scalar(
        "SELECT COALESCE(target_entity, 'contact') FROM marketing_list \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let phone_column = {
        let entities = state.entities.load();
        let meta = entities.get(&target);
        ["mobile", "phone"]
            .into_iter()
            .find(|c| meta.is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == *c)))
    };
    let Some(phone_column) = phone_column else {
        return Ok((target, Vec::new()));
    };
    let people: Vec<Uuid> = crate::segment::evaluate(state, ctx, list, Vec::new())
        .await?
        .into_iter()
        .collect();
    if people.is_empty() {
        return Ok((target, Vec::new()));
    }
    let sql = format!(
        "SELECT t.id, t.{} FROM {} t \
          WHERE t.id = ANY($1) AND COALESCE(trim(t.{}), '') <> '' \
            AND EXISTS (SELECT 1 FROM consent_current c \
                 WHERE c.subject_entity = $3 AND c.subject_id = t.id AND c.purpose_key = $2 \
                   AND c.channel IN ('sms', 'any') AND c.status = 'granted') \
          ORDER BY t.id LIMIT $4",
        quote_ident(phone_column),
        quote_ident(&target),
        quote_ident(phone_column),
    );
    let rows: Vec<(Uuid, String)> = sqlx::query_as(&sql)
        .bind(&people)
        .bind(purpose)
        .bind(&target)
        .bind(MAX_RECIPIENTS as i64)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let rows = rows
        .into_iter()
        .filter_map(|(id, raw)| e164(&raw).map(|p| (id, p)))
        .collect();
    Ok((target, rows))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SmsCampaignBody {
    /// The message (at most 670 characters).
    pub body: String,
    /// The consent purpose the message is sent under.
    pub purpose_key: String,
    /// `send` only: the cost the sender agreed to; a larger estimate is
    /// refused.
    #[serde(default)]
    pub expected_cost: Option<f64>,
}

fn check_body(body: &SmsCampaignBody) -> Result<(), AppError> {
    let text = body.body.trim();
    if text.is_empty() {
        return Err(AppError::Validation("body is required".into()));
    }
    if text.chars().count() > attome_integration::sms::MAX_BODY_CHARS {
        return Err(AppError::Validation(format!(
            "body is longer than {} characters",
            attome_integration::sms::MAX_BODY_CHARS
        )));
    }
    if body.purpose_key.trim().is_empty() {
        return Err(AppError::Validation("purpose_key is required".into()));
    }
    Ok(())
}

fn price(state: &EngineState) -> f64 {
    setting(state, "marketing.sms_price_per_segment")
        .as_f64()
        .unwrap_or(0.0)
}

/// The estimate for sending `body` to the list.
pub async fn estimate_for(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    body: &SmsCampaignBody,
) -> Result<SmsEstimate, AppError> {
    check_body(body)?;
    let (_, people) = recipients(state, ctx, list, body.purpose_key.trim()).await?;
    Ok(estimate(&body.body, people.len() as i64, price(state)))
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SmsCampaignStarted {
    pub send_id: Uuid,
    pub estimate: SmsEstimate,
}

/// Fixes the recipients and starts a send.
pub async fn start(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    body: &SmsCampaignBody,
) -> Result<SmsCampaignStarted, AppError> {
    check_body(body)?;
    let purpose = body.purpose_key.trim();
    let (target, people) = recipients(state, ctx, list, purpose).await?;
    let estimate = estimate(&body.body, people.len() as i64, price(state));
    if let (Some(expected), Some(cost)) = (body.expected_cost, estimate.cost)
        && cost > expected + 0.005
    {
        return Err(AppError::Conflict(
            "the estimate has grown past the expected cost; estimate again",
        ));
    }
    if people.is_empty() {
        return Err(AppError::Validation(
            "nobody on the list can be texted for this purpose".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let send_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sms_campaign_send \
           (list_id, body, purpose_key, segments_each, estimated_cost, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(list)
    .bind(body.body.trim())
    .bind(purpose)
    .bind(i32::try_from(estimate.segments_each).unwrap_or(i32::MAX))
    .bind(estimate.cost)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = people.iter().map(|(id, _)| *id).collect();
    let phones: Vec<String> = people.iter().map(|(_, p)| p.clone()).collect();
    sqlx::query(
        "INSERT INTO sms_campaign_recipient (send_id, subject_entity, subject_id, phone) \
         SELECT $1, $2, u.id, u.phone FROM unnest($3::uuid[], $4::text[]) AS u(id, phone) \
         ON CONFLICT DO NOTHING",
    )
    .bind(send_id)
    .bind(&target)
    .bind(&ids)
    .bind(&phones)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "marketing_list",
            list,
            AuditOperation::Create,
            "sms_campaign.start",
            ctx.user_id,
        )
        .comment(format!(
            "SMS campaign {send_id}: {} recipients, {} segments",
            estimate.recipients, estimate.total_segments
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(SmsCampaignStarted { send_id, estimate })
}

/// One run of the `sms_campaign` job: each open send's pending recipients
/// outside their quiet hours, up to [`BATCH`] per send. Returns the
/// messages handed to the provider.
pub async fn sweep(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db;
    let sends: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, body, purpose_key FROM sms_campaign_send WHERE status = 'sending' \
          ORDER BY created_at LIMIT 20",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let quiet = setting(state, "marketing.sms_quiet_hours");
    let zone = deployment_zone(state);
    let now = Utc::now();
    let mut sent = 0;
    for (send_id, body, purpose) in sends {
        // Recipients whose consent still stands, held ones last.
        let pending: Vec<(String, Uuid, String, bool)> = sqlx::query_as(
            "SELECT r.subject_entity, r.subject_id, r.phone, \
                    EXISTS (SELECT 1 FROM consent_current c \
                      WHERE c.subject_entity = r.subject_entity AND c.subject_id = r.subject_id \
                        AND c.purpose_key = $2 AND c.channel IN ('sms', 'any') \
                        AND c.status = 'granted') \
               FROM sms_campaign_recipient r \
              WHERE r.send_id = $1 AND r.status = 'pending' \
              ORDER BY r.subject_id LIMIT $3",
        )
        .bind(send_id)
        .bind(&purpose)
        .bind(BATCH * 5)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if pending.is_empty() {
            sqlx::query(
                "UPDATE sms_campaign_send SET status = 'done', finished_at = now() \
                  WHERE id = $1 AND status = 'sending'",
            )
            .bind(send_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            continue;
        }
        let mut this_batch = 0;
        for (_, subject, phone, consent) in pending {
            if this_batch >= BATCH {
                break;
            }
            let outcome: (&str, Option<Uuid>) = if !consent {
                ("skipped", None)
            } else if held(&phone, now, &quiet, zone) {
                continue;
            } else {
                this_batch += 1;
                match attome_integration::sms::send(state, &phone, &body, None).await {
                    Ok(attome_integration::sms::Sent::Accepted(delivery)) => {
                        sent += 1;
                        ("sent", Some(delivery))
                    }
                    Ok(attome_integration::sms::Sent::Skipped) => ("skipped", None),
                    Err(error) => {
                        tracing::warn!(%send_id, %error, "sms campaign: message not sent");
                        ("failed", None)
                    }
                }
            };
            sqlx::query(
                "UPDATE sms_campaign_recipient SET status = $3, delivery_id = $4, attempted_at = now() \
                  WHERE send_id = $1 AND subject_id = $2 AND status = 'pending'",
            )
            .bind(send_id)
            .bind(subject)
            .bind(outcome.0)
            .bind(outcome.1)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(sent)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/sms/estimate",
    operation_id = "estimate_sms_campaign",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    request_body = SmsCampaignBody,
    responses(
        (status = 200, description = "Who can be reached and what it costs", body = SmsEstimate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
        (status = 422, description = "No body or purpose, or the body is too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "estimates an SMS campaign; sends and writes nothing",
    )))),
)]
/// Estimate an SMS campaign to a list.
///
/// How many of the list's people can be texted for the purpose, the
/// message's encoding and segments, and the cost at the configured price.
pub(crate) async fn post_sms_estimate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<crate::segment_insight::ListRead>>,
    Path(list): Path<Uuid>,
    Json(body): Json<SmsCampaignBody>,
) -> Result<Json<SmsEstimate>, AppError> {
    estimate_for(&state, &ctx, list, &body).await.map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/sms/send",
    operation_id = "start_sms_campaign",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    request_body = SmsCampaignBody,
    responses(
        (status = 200, description = "The send has started", body = SmsCampaignStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
        (status = 409, description = "The estimate grew past expected_cost", body = ErrorResponse),
        (status = 422, description = "No body or purpose, or nobody to text", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
/// Start an SMS campaign to a list.
///
/// Fixes the consenting recipients and starts sending in the background,
/// holding each message until the recipient's quiet hours end.
pub(crate) async fn post_sms_send(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<SmsCampaignBody>,
) -> Result<Json<SmsCampaignStarted>, AppError> {
    start(&state, &ctx, list, &body).await.map(Json)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sms_estimate, post_sms_send),
    components(schemas(SmsCampaignBody, SmsEstimate, SmsCampaignStarted))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod sms_campaign {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn hhmm(t: &str) -> NaiveTime {
        NaiveTime::parse_from_str(t, "%H:%M").unwrap()
    }

    #[test]
    fn quiet_hours_cross_midnight() {
        let night = QuietHours {
            start: hhmm("21:00"),
            end: hhmm("08:00"),
        };
        assert!(night.holds(hhmm("23:30")));
        assert!(night.holds(hhmm("07:59")));
        assert!(!night.holds(hhmm("08:00")));
        assert!(!night.holds(hhmm("12:00")));
        let lunch = QuietHours {
            start: hhmm("13:00"),
            end: hhmm("14:00"),
        };
        assert!(lunch.holds(hhmm("13:30")));
        assert!(!lunch.holds(hhmm("20:00")));
    }

    #[test]
    fn each_country_waits_for_its_own_morning() {
        let setting = json!({
            "*": {"start": "21:00", "end": "08:00"},
            "SA": {"start": "22:00", "end": "09:00"}
        });
        // 04:30 UTC: 07:30 in Riyadh (quiet until 09:00), 08:30 in Dubai.
        let now = Utc.with_ymd_and_hms(2026, 10, 20, 4, 30, 0).unwrap();
        assert!(held("+966501234567", now, &setting, chrono_tz::UTC));
        assert!(!held("+971501234567", now, &setting, chrono_tz::UTC));
        assert!(!held("+966501234567", now, &Value::Null, chrono_tz::UTC));
    }

    #[test]
    fn the_estimate_counts_segments_and_cost() {
        let english = estimate("Sale ends tonight", 1000, 0.05);
        assert_eq!(english.encoding, "gsm7");
        assert_eq!(english.segments_each, 1);
        assert_eq!(english.total_segments, 1000);
        assert_eq!(english.cost, Some(50.0));
        // Arabic is UCS-2: 70 characters a part, 67 once split.
        let arabic = estimate(&"عرض".repeat(30), 10, 0.0);
        assert_eq!(arabic.encoding, "ucs2");
        assert_eq!(arabic.segments_each, 2);
        assert_eq!(arabic.total_segments, 20);
        assert_eq!(arabic.cost, None);
    }
}
