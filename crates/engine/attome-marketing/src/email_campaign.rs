//! E3-T1: email campaigns — one designed email to a marketing list's people
//! who consented to email for the campaign's purpose, sent in the
//! background on the bulk stream.
//!
//! - `POST /api/v1/marketing/lists/{id}/email/send` renders the design once
//!   (E2-T2) and keeps that snapshot with the send (`email_campaign_send`,
//!   migration 0269), fixes the recipients (`email_campaign_recipient`),
//!   each with a random unsubscribe token, and starts the send.
//! - The `email_campaign` job ([`sweep`]) works through at most 1,000
//!   pending recipients per send each run: consent is read again just
//!   before each message (a withdrawal since the start is honoured); a
//!   person who already had [`DEFAULT_WEEKLY_CAP`] marketing messages in the
//!   last seven days, email and SMS together, is `capped` (the
//!   `marketing.weekly_message_cap` setting changes the number when it is
//!   registered); the snapshot is personalised with the person's own fields
//!   and `{{ unsubscribe_url }}`, and queued as bulk mail with
//!   `List-Unsubscribe` and one-click `List-Unsubscribe-Post` (RFC 8058).
//! - `GET /api/v1/marketing/unsubscribe/{token}` shows a page with one
//!   button; `POST` to the same address (the button, or a mail client's
//!   one-click request) suppresses the address for bulk mail. Public: the
//!   unguessable token is the credential, and an unknown token answers the
//!   same page, so nothing is learned from it.

use std::collections::HashMap;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::quote_ident;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::email_render::{EmailDesign, RenderedEmail};
use crate::sms_campaign::ListUpdate;

/// Most people one campaign sends to.
pub const MAX_RECIPIENTS: usize = 50_000;
/// Messages one sweep queues per campaign.
pub const BATCH: i64 = 1_000;
/// Marketing messages one person gets in seven days, across channels.
pub const DEFAULT_WEEKLY_CAP: i64 = 3;
/// The setting that changes the cap, when registered.
pub const CAP_SETTING: &str = "marketing.weekly_message_cap";

/// A campaign to start.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EmailCampaignBody {
    /// The subject line (at most 200 characters).
    pub subject: String,
    /// The email designer's JSON (E2-T1): blocks, direction, width, colour.
    #[schema(value_type = Object)]
    pub design: Value,
    /// The consent purpose the email is sent under.
    pub purpose_key: String,
    /// `en` (default) or `ar`: how values are formatted.
    #[serde(default)]
    pub locale: Option<String>,
    /// E4-T1: more versions to test against this one (which is `A`), up to
    /// four; with any, the campaign is an A/B test.
    #[serde(default)]
    pub variants: Vec<crate::email_ab::EmailVariantBody>,
    /// E4-T1: how the test picks its winner; defaults when absent.
    #[serde(default)]
    pub ab_test: Option<crate::email_ab::AbTestBody>,
}

/// A campaign started.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EmailCampaignStarted {
    pub send_id: Uuid,
    /// People who will be emailed, before caps and later withdrawals.
    pub recipients: i64,
}

fn check_subject(subject: &str) -> Result<(), AppError> {
    let subject = subject.trim();
    if subject.is_empty() || subject.chars().count() > 200 {
        return Err(AppError::Validation(
            "subject is 1 to 200 characters".into(),
        ));
    }
    Ok(())
}

fn check_body(body: &EmailCampaignBody) -> Result<String, AppError> {
    check_subject(&body.subject)?;
    for variant in &body.variants {
        check_subject(&variant.subject)?;
    }
    if body.variants.len() + 1 > crate::email_ab::MAX_VARIANTS {
        return Err(AppError::Validation(format!(
            "an A/B test has at most {} variants",
            crate::email_ab::MAX_VARIANTS
        )));
    }
    if body.variants.is_empty() && body.ab_test.is_some() {
        return Err(AppError::Validation(
            "an A/B test needs at least one more variant".into(),
        ));
    }
    if body.purpose_key.trim().is_empty() {
        return Err(AppError::Validation("purpose_key is required".into()));
    }
    match body.locale.as_deref().unwrap_or("en") {
        "en" | "ar" => Ok(body.locale.clone().unwrap_or_else(|| "en".into())),
        _ => Err(AppError::Validation("locale is en or ar".into())),
    }
}

/// Whether a person who already had `sent_this_week` marketing messages
/// is over `cap`. Pure.
pub fn over_cap(sent_this_week: i64, cap: i64) -> bool {
    sent_this_week >= cap
}

/// A record's fields as rule types and values, plus `extra` text fields,
/// for personalising one email. Pure.
pub fn record_context(
    row: &Map<String, Value>,
    extra: &[(&str, String)],
) -> (attome_rules::Schema, attome_rules::Context) {
    use attome_rules::{Type, Value as R};
    let mut schema = attome_rules::Schema::new();
    let mut ctx = attome_rules::Context::new(Utc::now());
    for (name, value) in row {
        let (ty, v) = match value {
            Value::Bool(b) => (Type::Bool, R::Bool(*b)),
            Value::Number(n) => match n.as_f64().filter(|f| f.is_finite()) {
                Some(f) => (Type::Number, R::Number(f)),
                None => (Type::Null, R::Null),
            },
            Value::String(s) => (Type::Text, R::Text(s.clone())),
            _ => (Type::Null, R::Null),
        };
        schema = schema.with_field(name.clone(), ty);
        ctx = ctx.with_field(name.clone(), v);
    }
    for (name, value) in extra {
        schema = schema.with_field(*name, Type::Text);
        ctx = ctx.with_field(*name, R::Text(value.clone()));
    }
    (schema, ctx)
}

/// The people of `list` the caller may see who can be emailed for
/// `purpose`: `(entity, [(id, email)])`, at most [`MAX_RECIPIENTS`].
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
    let has_email = state
        .entities
        .load()
        .get(&target)
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "email"));
    if !has_email {
        return Ok((target, Vec::new()));
    }
    let people: Vec<Uuid> = crate::segment::evaluate(state, ctx, list, Vec::new())
        .await?
        .into_iter()
        .collect();
    if people.is_empty() {
        return Ok((target, Vec::new()));
    }
    let sql = format!(
        "SELECT t.id, trim(t.email) FROM {} t \
          WHERE t.id = ANY($1) AND position('@' IN COALESCE(t.email, '')) > 1 \
            AND EXISTS (SELECT 1 FROM consent_current c \
                 WHERE c.subject_entity = $3 AND c.subject_id = t.id AND c.purpose_key = $2 \
                   AND c.channel IN ('email', 'any') AND c.status = 'granted') \
          ORDER BY t.id LIMIT $4",
        quote_ident(&target),
    );
    let rows: Vec<(Uuid, String)> = sqlx::query_as(&sql)
        .bind(&people)
        .bind(purpose)
        .bind(&target)
        .bind(MAX_RECIPIENTS as i64)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok((target, rows))
}

/// Renders the design, fixes the recipients and starts the send.
pub async fn start(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    body: &EmailCampaignBody,
) -> Result<EmailCampaignStarted, AppError> {
    let locale = check_body(body)?;
    let purpose = body.purpose_key.trim();
    let design: EmailDesign = serde_json::from_value(body.design.clone())
        .map_err(|e| AppError::Validation(format!("design: {e}")))?;
    let rendered = crate::email_render::render(&design)
        .map_err(|e| AppError::Validation(format!("design: {e}")))?;
    // E4-T1: every version as (name, subject, rendered), `A` first.
    let mut versions = vec![(
        crate::email_ab::variant_name(0),
        body.subject.trim().to_owned(),
        rendered.clone(),
    )];
    for (i, variant) in body.variants.iter().enumerate() {
        let design: EmailDesign = serde_json::from_value(variant.design.clone())
            .map_err(|e| AppError::Validation(format!("variants[{i}].design: {e}")))?;
        let rendered = crate::email_render::render(&design)
            .map_err(|e| AppError::Validation(format!("variants[{i}].design: {e}")))?;
        versions.push((
            crate::email_ab::variant_name(i + 1),
            variant.subject.trim().to_owned(),
            rendered,
        ));
    }
    let ab = if body.variants.is_empty() {
        None
    } else {
        if !attome_notification::tracking::enabled(state) {
            return Err(AppError::Validation(
                "an A/B test counts opens and clicks: turn on email tracking \
                 (email.tracking.enabled) first"
                    .into(),
            ));
        }
        Some(crate::email_ab::settings(body.ab_test.as_ref())?)
    };
    let (target, people) = recipients(state, ctx, list, purpose).await?;
    if people.is_empty() {
        return Err(AppError::Validation(
            "nobody on the list can be emailed for this purpose".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let send_id: Uuid = sqlx::query_scalar(
        "INSERT INTO email_campaign_send \
           (list_id, subject, html_body, text_body, purpose_key, locale, created_by, \
            ab_metric, ab_window_minutes, ab_fallback) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(list)
    .bind(body.subject.trim())
    .bind(&rendered.html)
    .bind(&rendered.text)
    .bind(purpose)
    .bind(&locale)
    .bind(ctx.user_id)
    .bind(ab.as_ref().map(|a| a.metric))
    .bind(ab.as_ref().map(|a| a.window_minutes as i32))
    .bind(ab.as_ref().map(|a| a.fallback))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The recipients in a random order: their random tokens.
    let mut people: Vec<(Uuid, String, String)> = people
        .into_iter()
        .map(|(id, email)| {
            let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            (id, email, token)
        })
        .collect();
    let mut variant_of: Vec<Option<String>> = vec![None; people.len()];
    let mut status_of: Vec<&str> = vec!["pending"; people.len()];
    let mut tracked_of: Vec<bool> = vec![false; people.len()];
    if let Some(ab) = &ab {
        people.sort_by(|a, b| a.2.cmp(&b.2));
        let base = state.base.config.frontend_url();
        for (name, subject, version) in &versions {
            let (html, links) = crate::email_ab::track_body(&version.html, &base);
            sqlx::query(
                "INSERT INTO email_campaign_variant \
                   (send_id, name, subject, html_body, text_body, tracked_html, links) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(send_id)
            .bind(name)
            .bind(subject)
            .bind(&version.html)
            .bind(&version.text)
            .bind(&html)
            .bind(serde_json::json!(links))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        let picks = crate::email_ab::assign(people.len(), versions.len(), ab.per_variant as usize);
        for (i, pick) in picks.into_iter().enumerate() {
            match pick {
                Some(v) => {
                    variant_of[i] = Some(versions[v].0.clone());
                    tracked_of[i] = true;
                }
                None => status_of[i] = "held",
            }
        }
    }
    let ids: Vec<Uuid> = people.iter().map(|(id, _, _)| *id).collect();
    let emails: Vec<String> = people.iter().map(|(_, e, _)| e.clone()).collect();
    let tokens: Vec<String> = people.iter().map(|(_, _, t)| t.clone()).collect();
    sqlx::query(
        "INSERT INTO email_campaign_recipient \
           (send_id, subject_entity, subject_id, email, unsubscribe_token, variant, status, \
            tracked) \
         SELECT $1, $2, u.id, u.email, u.token, u.variant, u.status, u.tracked \
           FROM unnest($3::uuid[], $4::text[], $5::text[], $6::text[], $7::text[], \
                       $8::boolean[]) \
                AS u(id, email, token, variant, status, tracked) \
         ON CONFLICT DO NOTHING",
    )
    .bind(send_id)
    .bind(&target)
    .bind(&ids)
    .bind(&emails)
    .bind(&tokens)
    .bind(&variant_of)
    .bind(&status_of)
    .bind(&tracked_of)
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
            "email_campaign.start",
            ctx.user_id,
        )
        .comment(format!(
            "email campaign {send_id}: {} recipients{}",
            people.len(),
            if versions.len() > 1 {
                format!(", A/B test of {} variants", versions.len())
            } else {
                String::new()
            }
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(EmailCampaignStarted {
        send_id,
        recipients: people.len() as i64,
    })
}

fn weekly_cap(state: &EngineState) -> i64 {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(CAP_SETTING)
        .map(|d| store.resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .filter(|cap| *cap > 0)
        .unwrap_or(DEFAULT_WEEKLY_CAP)
}

/// A send the sweep works on: id, subject, bodies, purpose, locale, and
/// its A/B test (metric, window, fallback, decided, started).
type SendRow = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i32>,
    Option<String>,
    bool,
    chrono::DateTime<Utc>,
);

/// A pending recipient: entity, id, email, token, variant, tracked, consent.
type PendingRow = (String, Uuid, String, String, Option<String>, bool, bool);

/// A test's version: subject, untracked and tracked bodies.
type Version = (String, RenderedEmail, RenderedEmail);

/// One run of the `email_campaign` job; answers the messages queued.
pub async fn sweep(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db;
    let sends: Vec<SendRow> = sqlx::query_as(
        "SELECT id, subject, html_body, text_body, purpose_key, locale, \
                ab_metric, ab_window_minutes, ab_fallback, ab_decided_at IS NOT NULL, created_at \
           FROM email_campaign_send \
          WHERE status = 'sending' ORDER BY created_at LIMIT 10",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let cap = weekly_cap(state);
    let base = state.base.config.frontend_url();
    let base = base.trim_end_matches('/');
    let mut queued = 0;
    for (
        send_id,
        subject,
        html,
        text,
        purpose,
        locale,
        ab_metric,
        ab_window,
        ab_fallback,
        ab_decided,
        started_at,
    ) in sends
    {
        // E4-T1: an A/B test's versions, by name.
        let versions: HashMap<String, Version> = if ab_metric.is_some() {
            sqlx::query_as::<_, (String, String, String, String, String)>(
                "SELECT name, subject, html_body, text_body, tracked_html \
                   FROM email_campaign_variant WHERE send_id = $1",
            )
            .bind(send_id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .map(|(name, subject, html, text, tracked_html)| {
                let tracked = RenderedEmail {
                    html: tracked_html,
                    text: text.clone(),
                };
                (name, (subject, RenderedEmail { html, text }, tracked))
            })
            .collect()
        } else {
            HashMap::new()
        };
        let pending: Vec<PendingRow> = sqlx::query_as(
            "SELECT r.subject_entity, r.subject_id, r.email, r.unsubscribe_token, r.variant, \
                    r.tracked, \
                    EXISTS (SELECT 1 FROM consent_current c \
                      WHERE c.subject_entity = r.subject_entity AND c.subject_id = r.subject_id \
                        AND c.purpose_key = $2 AND c.channel IN ('email', 'any') \
                        AND c.status = 'granted') \
               FROM email_campaign_recipient r \
              WHERE r.send_id = $1 AND r.status = 'pending' \
              ORDER BY r.subject_id LIMIT $3",
        )
        .bind(send_id)
        .bind(&purpose)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if pending.is_empty() {
            // E4-T1: a test with recipients held for the winner is done only
            // once they have been released and sent.
            if let Some(metric) = ab_metric.as_deref()
                && !ab_decided
            {
                crate::email_ab::decide(
                    state,
                    send_id,
                    started_at,
                    metric,
                    ab_window.unwrap_or(crate::email_ab::DEFAULT_WINDOW_MINUTES as i32),
                    ab_fallback.as_deref().unwrap_or("leader"),
                )
                .await?;
                continue;
            }
            sqlx::query(
                "UPDATE email_campaign_send SET status = 'done', finished_at = now() \
                  WHERE id = $1 AND status = 'sending'",
            )
            .bind(send_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            continue;
        }
        // The people's own fields, one query per entity in this batch.
        let mut rows: HashMap<Uuid, Map<String, Value>> = HashMap::new();
        let mut by_entity: HashMap<&str, Vec<Uuid>> = HashMap::new();
        for (entity, id, ..) in &pending {
            by_entity.entry(entity.as_str()).or_default().push(*id);
        }
        for (entity, ids) in by_entity {
            let found: Vec<Value> = sqlx::query_scalar(&format!(
                "SELECT row_to_json(t) FROM {} t WHERE t.id = ANY($1)",
                quote_ident(entity)
            ))
            .bind(&ids)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            for row in found {
                if let Value::Object(map) = row
                    && let Some(id) = map
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|s| Uuid::parse_str(s).ok())
                {
                    rows.insert(id, map);
                }
            }
        }
        let snapshot = RenderedEmail { html, text };
        for (entity, subject_id, email, token, variant, tracked, consent) in pending {
            // E4-T1: a test recipient gets the tracked copy, unless they
            // withdrew tracking; then they are not counted.
            let tracked = tracked
                && consent
                && !attome_notification::tracking::opted_out(
                    &mut *db.acquire().await.map_err(AppError::internal)?,
                    &entity,
                    subject_id,
                )
                .await?;
            let (subject, snapshot) = match variant.as_deref().and_then(|v| versions.get(v)) {
                Some((subject, plain, with_tracking)) => {
                    (subject, if tracked { with_tracking } else { plain })
                }
                None => (&subject, &snapshot),
            };
            let status = if !consent {
                "skipped"
            } else {
                let this_week: i64 = sqlx::query_scalar(
                    "SELECT (SELECT COUNT(*) FROM email_campaign_recipient \
                              WHERE subject_entity = $1 AND subject_id = $2 AND status = 'sent' \
                                AND attempted_at > now() - interval '7 days') \
                          + (SELECT COUNT(*) FROM sms_campaign_recipient \
                              WHERE subject_entity = $1 AND subject_id = $2 AND status = 'sent' \
                                AND attempted_at > now() - interval '7 days')",
                )
                .bind(&entity)
                .bind(subject_id)
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
                if over_cap(this_week, cap) {
                    "capped"
                } else {
                    let url = format!("{base}/api/v1/marketing/unsubscribe/{token}");
                    let (schema, values) = record_context(
                        rows.get(&subject_id).unwrap_or(&Map::new()),
                        &[
                            ("unsubscribe_url", url.clone()),
                            ("tracking_token", token.clone()),
                        ],
                    );
                    match crate::email_render::personalise(snapshot, &schema, values, &locale) {
                        Ok(mail) => {
                            let job = attome_core::jobs::EngineJob::SendEmail(Box::new(
                                attome_email::EmailMessage {
                                    to: email.clone(),
                                    subject: subject.clone(),
                                    text_body: mail.text,
                                    html_body: Some(mail.html),
                                    delivery_id: None,
                                    from_override: None,
                                    message_id: None,
                                    in_reply_to: None,
                                    references: None,
                                    communication_id: None,
                                    attachments: Vec::new(),
                                    stream: attome_email::EmailStream::Bulk,
                                    list_unsubscribe: Some(url),
                                },
                            ));
                            let mut tx = attome_db::tx::begin(db).await?;
                            attome_jobs::enqueue_in_tx(&mut tx, job)
                                .await
                                .map_err(AppError::internal)?;
                            sqlx::query(
                                "UPDATE email_campaign_recipient SET status = 'sent', attempted_at = now(), \
                                        tracked = $3 \
                                  WHERE send_id = $1 AND subject_id = $2 AND status = 'pending'",
                            )
                            .bind(send_id)
                            .bind(subject_id)
                            .bind(tracked)
                            .execute(&mut *tx)
                            .await
                            .map_err(AppError::internal)?;
                            attome_db::tx::commit(tx).await?;
                            queued += 1;
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(%send_id, %error, "email campaign: message not personalised");
                            "failed"
                        }
                    }
                }
            };
            sqlx::query(
                "UPDATE email_campaign_recipient SET status = $3, attempted_at = now() \
                  WHERE send_id = $1 AND subject_id = $2 AND status = 'pending'",
            )
            .bind(send_id)
            .bind(subject_id)
            .bind(status)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(queued)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/email/send",
    operation_id = "start_email_campaign",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    request_body = EmailCampaignBody,
    responses(
        (status = 200, description = "The send has started", body = EmailCampaignStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
        (status = 422, description = "No subject or purpose, a design that does not render, or nobody to email", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
/// Start an email campaign to a list.
///
/// Renders the design once, fixes the consenting recipients and starts
/// sending on the bulk stream in the background, at most three marketing
/// messages per person per week.
pub(crate) async fn post_email_send(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<EmailCampaignBody>,
) -> Result<Json<EmailCampaignStarted>, AppError> {
    start(&state, &ctx, list, &body).await.map(Json)
}

/// The unsubscribe page, in English and Arabic; `done` says it worked.
pub fn unsubscribe_page(done: bool) -> String {
    let (en, ar, form) = if done {
        (
            "You will not get these emails again.",
            "لن تصلك هذه الرسائل مرة أخرى.",
            String::new(),
        )
    } else {
        (
            "Stop getting these emails?",
            "هل تريد إيقاف هذه الرسائل؟",
            "<form method=\"post\"><button type=\"submit\" name=\"List-Unsubscribe\" value=\"One-Click\">Unsubscribe · إلغاء الاشتراك</button></form>".to_owned(),
        )
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width\"><title>Unsubscribe</title></head>\
         <body><p>{en}</p><p dir=\"rtl\" lang=\"ar\">{ar}</p>{form}</body></html>"
    )
}

fn html(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/unsubscribe/{token}",
    operation_id = "show_email_unsubscribe",
    tag = "marketing",
    params(("token" = String, Path, description = "The token from the email's unsubscribe link")),
    responses(
        (status = 200, description = "A page with one unsubscribe button", content_type = "text/html", body = String),
    ),
)]
/// Unsubscribe page
///
/// The page an email's unsubscribe link opens: one button that confirms.
/// Public; opening it changes nothing (link scanners open links).
pub(crate) async fn get_unsubscribe(Path(_token): Path<String>) -> Response {
    html(unsubscribe_page(false))
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/unsubscribe/{token}",
    operation_id = "email_unsubscribe",
    tag = "marketing",
    params(("token" = String, Path, description = "The token from the email's unsubscribe link")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Unsubscribed (the same page for any token)", content_type = "text/html", body = String),
    ),
)]
/// Unsubscribe from marketing email
///
/// The page's button, or a mail client's one-click request (RFC 8058):
/// the address stops getting bulk mail. Public; the token is the
/// credential, and an unknown one answers the same page.
pub(crate) async fn post_unsubscribe(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let token = token.trim();
    if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        let found: Option<(String, Uuid)> = sqlx::query_as(
            "SELECT email, send_id FROM email_campaign_recipient WHERE unsubscribe_token = $1",
        )
        .bind(token)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if let Some((email, send_id)) = found {
            let event = attome_email::feedback::Feedback {
                email,
                kind: attome_email::feedback::FeedbackKind::Unsubscribe,
                detail: Some(format!("email campaign {send_id}")),
            };
            attome_email::feedback::apply(&state.base.db, &[event])
                .await
                .map_err(AppError::internal)?;
            attome_audit::write_business_event(
                &state,
                "email_campaign_send",
                send_id,
                AuditOperation::Create,
                "email_campaign.unsubscribe",
                Uuid::nil(),
                None,
                None,
                "a recipient unsubscribed from bulk mail".to_owned(),
            )
            .await;
        }
    }
    Ok(html(unsubscribe_page(true)))
}

/// The public unsubscribe routes, mounted outside the authenticated set.
pub fn public_routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/marketing/unsubscribe/{token}",
            get(get_unsubscribe).post(post_unsubscribe),
        )
        // E4-T1: an A/B-tested email's open pixel and tracked links.
        .route(
            "/api/v1/marketing/o/{token}",
            get(crate::email_ab::get_open),
        )
        .route(
            "/api/v1/marketing/c/{token}/{n}",
            get(crate::email_ab::get_click),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_email_send,
        get_unsubscribe,
        post_unsubscribe,
        crate::email_ab::get_open,
        crate::email_ab::get_click
    ),
    components(schemas(
        EmailCampaignBody,
        EmailCampaignStarted,
        crate::email_ab::EmailVariantBody,
        crate::email_ab::AbTestBody
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn three_messages_a_week_is_the_cap() {
        assert!(!over_cap(2, DEFAULT_WEEKLY_CAP));
        assert!(over_cap(3, DEFAULT_WEEKLY_CAP));
        assert!(over_cap(4, 3));
    }

    #[test]
    fn each_email_is_personalised_with_the_recipients_fields_and_link() {
        let design: EmailDesign = serde_json::from_value(json!({
            "blocks": [
                { "type": "heading", "text": "Hello {{ first_name }}", "level": 1 },
                { "type": "text", "text": "Not for you? {{ unsubscribe_url }}" }
            ]
        }))
        .unwrap();
        let snapshot = crate::email_render::render(&design).unwrap();
        let row =
            json!({ "id": "x", "first_name": "Sara", "score": 7, "vip": true, "notes": null });
        let (schema, ctx) = record_context(
            row.as_object().unwrap(),
            &[(
                "unsubscribe_url",
                "https://crm.example/api/v1/marketing/unsubscribe/ab".into(),
            )],
        );
        let mail = crate::email_render::personalise(&snapshot, &schema, ctx, "en").unwrap();
        assert!(mail.text.contains("Hello Sara"));
        assert!(
            mail.text
                .contains("https://crm.example/api/v1/marketing/unsubscribe/ab")
        );
    }

    #[test]
    fn the_unsubscribe_page_confirms_with_a_post_button() {
        let ask = unsubscribe_page(false);
        assert!(ask.contains("method=\"post\""));
        assert!(ask.contains("dir=\"rtl\""));
        assert!(!unsubscribe_page(true).contains("<form"));
    }

    #[test]
    fn a_campaign_needs_a_subject_purpose_and_known_locale() {
        let body = |subject: &str, purpose: &str, locale: Option<&str>| EmailCampaignBody {
            subject: subject.into(),
            design: json!({ "blocks": [] }),
            purpose_key: purpose.into(),
            locale: locale.map(str::to_owned),
            variants: Vec::new(),
            ab_test: None,
        };
        assert_eq!(
            check_body(&body("Offer", "promotions", None)).unwrap(),
            "en"
        );
        assert_eq!(
            check_body(&body("عرض", "promotions", Some("ar"))).unwrap(),
            "ar"
        );
        assert!(check_body(&body(" ", "promotions", None)).is_err());
        assert!(check_body(&body("Offer", "", None)).is_err());
        assert!(check_body(&body("Offer", "promotions", Some("fr"))).is_err());
    }
}
