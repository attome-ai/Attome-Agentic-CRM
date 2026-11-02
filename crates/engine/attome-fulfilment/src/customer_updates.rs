//! F6-T15: telling the customer where their order is.
//!
//! **Messages.** With the setting [`UPDATES_SETTING`] on, the order's
//! updates contact (`order.updates_contact_ref`, fulfilment pack changeset
//! 0009) is told at each step: a shipment leaving (`picked_up` or
//! `in_transit`), going out for delivery, delivered, and the order running
//! late (a `late` fulfilment exception, F6-T14). [`drain`] reads those
//! events from the change feed (consumer [`CONSUMER`]) every minute. A
//! message goes only with the contact's active consent to the
//! [`PURPOSE`] purpose, through the notification template for the step
//! (`fulfilment.shipped`, `fulfilment.out_for_delivery`,
//! `fulfilment.delivered`, `fulfilment.delayed`) in the contact's language,
//! on the template's channels: `email` (queued in the same transaction as
//! the decision, unless the address is suppressed) and `sms` (sent after
//! the commit). WhatsApp is not used: its templates need provider approval
//! first.
//!
//! Each subject and step is decided once (`fulfilment_customer_update`,
//! migration 0371), sent or not, so a replayed event never messages twice
//! and a step without consent is not sent later.
//!
//! **Where is my order.** [`portal_order`] answers an order's lines, their
//! shipments and tracking numbers only when the order belongs to the portal
//! user's account (the route derives the account from the portal session,
//! never from the request).

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeEvent};
use attome_core::erasure_hook::{ErasureFuture, ErasureHook};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::order_view::{OrderFulfilment, order_fulfilment};

/// The setting that turns the messages on (off by default).
pub const UPDATES_SETTING: &str = "fulfilment.customer_updates";
/// The setting that opens the portal route (off by default).
pub const PORTAL_SETTING: &str = "fulfilment.portal";
/// The consent purpose a message needs.
pub const PURPOSE: &str = "order_updates";
/// The change-feed consumer.
pub const CONSUMER: &str = "attome-fulfilment/customer_updates";
/// The job that drains it.
pub const JOB: &str = "fulfilment_customer_updates";
/// Events read per batch, and batches per run.
const BATCH: i64 = 200;
const MAX_BATCHES: usize = 10;

/// A step the customer hears about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Shipped,
    OutForDelivery,
    Delivered,
    Delayed,
}

impl Step {
    /// The stored step and the template key's suffix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shipped => "shipped",
            Self::OutForDelivery => "out_for_delivery",
            Self::Delivered => "delivered",
            Self::Delayed => "delayed",
        }
    }

    /// The notification template's key.
    pub fn template_key(self) -> String {
        format!("fulfilment.{}", self.as_str())
    }
}

/// The step a shipment status starts, if any. Pure.
pub fn step_for_status(status: &str) -> Option<Step> {
    match status {
        "picked_up" | "in_transit" => Some(Step::Shipped),
        "out_for_delivery" => Some(Step::OutForDelivery),
        "delivered" => Some(Step::Delivered),
        _ => None,
    }
}

/// The step a change-feed event starts, with its subject (the shipment, or
/// for a late exception the exception). Pure.
pub fn step_of(event: &ChangeEvent) -> Option<(Step, Uuid)> {
    if event.entity_logicalname == "shipment" {
        let status = event
            .event_name
            .as_deref()?
            .strip_prefix("fulfilment.shipment.")?;
        return step_for_status(status).map(|s| (s, event.record_id));
    }
    if event.entity_logicalname == "fulfilment_exception"
        && event.event_name.is_none()
        && event.operation == "create"
    {
        return Some((Step::Delayed, event.record_id));
    }
    None
}

/// `template` with each `{{name}}` replaced by its value; unknown names are
/// left as they are. Pure.
pub fn render(template: &str, values: &Map<String, Value>) -> String {
    let mut out = template.to_owned();
    for (name, value) in values {
        let text = match value {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        out = out.replace(&format!("{{{{{name}}}}}"), &text);
    }
    out
}

/// The template locales to try for a contact's preferred language. Pure.
pub fn locales_for(preferred_language: Option<&str>) -> &'static [&'static str] {
    match preferred_language.map(|l| l.trim().to_ascii_lowercase()) {
        Some(l) if l.starts_with("ar") => &["ar-SA", "ar", "en"],
        _ => &["en"],
    }
}

fn setting_on(state: &EngineState, key: &str) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(key) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

/// Whether portal users may see their orders.
pub fn portal_on(state: &EngineState) -> bool {
    setting_on(state, PORTAL_SETTING)
}

/// Reads the new events and tells customers; how many messages were queued
/// or sent. The cursor moves on whether or not messages are on, so turning
/// them on never replays old events.
pub async fn drain(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let on = setting_on(state, UPDATES_SETTING);
    let mut sent = 0;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        if on {
            for (step, subject) in events.iter().filter_map(step_of) {
                match notify(state, step, subject).await {
                    Ok(true) => sent += 1,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%subject, step = step.as_str(), %error, "customer update not sent");
                    }
                }
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(sent)
}

/// What a message is about.
struct Context {
    contact: Option<Uuid>,
    values: Map<String, Value>,
}

/// The order behind a step's subject, its updates contact and the values a
/// template may use. `None` when the subject is not one this step names.
async fn context(
    state: &EngineState,
    step: Step,
    subject: Uuid,
) -> Result<Option<Context>, AppError> {
    let db = &state.base.db;
    // An order without the pack's updates_contact_ref reads as no contact.
    type Row = (Option<String>, Option<String>, Option<String>, Option<Uuid>);
    let row: Option<Row> = if step == Step::Delayed {
        sqlx::query_as(
            "SELECT COALESCE(NULLIF(to_jsonb(o) ->> 'order_number', ''), o.name), NULL::text, NULL::text, \
                    (to_jsonb(o) ->> 'updates_contact_ref')::uuid \
               FROM fulfilment_exception e \
               JOIN fulfilment_order f ON f.id = e.fulfilment_order_ref \
               JOIN \"order\" o ON o.id = f.order_ref \
              WHERE e.id = $1 AND e.kind::text = 'late'",
        )
        .bind(subject)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else {
        sqlx::query_as(
            "SELECT COALESCE(NULLIF(to_jsonb(o) ->> 'order_number', ''), o.name), s.carrier::text, \
                    s.tracking_number, \
                    (to_jsonb(o) ->> 'updates_contact_ref')::uuid \
               FROM shipment s \
               JOIN fulfilment_order f ON f.id = s.fulfilment_order_ref \
               JOIN \"order\" o ON o.id = f.order_ref \
              WHERE s.id = $1",
        )
        .bind(subject)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    };
    let Some((number, carrier, tracking, contact)) = row else {
        return Ok(None);
    };
    let mut values = Map::new();
    values.insert(
        "order_number".into(),
        number.map_or(Value::Null, Value::String),
    );
    values.insert("carrier".into(), carrier.map_or(Value::Null, Value::String));
    values.insert(
        "tracking_number".into(),
        tracking.map_or(Value::Null, Value::String),
    );
    Ok(Some(Context { contact, values }))
}

/// Records the decision for a subject and step; false when it was decided
/// already.
async fn decide(
    db: &attome_db::DbPool,
    subject: Uuid,
    step: Step,
    contact: Option<Uuid>,
    status: &str,
) -> Result<bool, AppError> {
    let claimed = sqlx::query(
        "INSERT INTO fulfilment_customer_update (subject_id, step, contact_id, status) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (subject_id, step) DO NOTHING",
    )
    .bind(subject)
    .bind(step.as_str())
    .bind(contact)
    .bind(status)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(claimed.rows_affected() == 1)
}

/// Tells the order's updates contact about `step` of `subject`; true when
/// a message was queued or sent.
pub async fn notify(state: &EngineState, step: Step, subject: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let Some(Context { contact, values }) = context(state, step, subject).await? else {
        return Ok(false);
    };
    let Some(contact) = contact else {
        decide(db, subject, step, None, "no_contact").await?;
        return Ok(false);
    };
    if !attome_notification::consent_gate::has_active_consent(
        db,
        "contact",
        &contact.to_string(),
        PURPOSE,
    )
    .await?
    {
        decide(db, subject, step, Some(contact), "no_consent").await?;
        return Ok(false);
    }
    let person: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT to_jsonb(c) ->> 'email', \
                COALESCE(NULLIF(to_jsonb(c) ->> 'mobile_phone', ''), to_jsonb(c) ->> 'phone'), \
                to_jsonb(c) ->> 'preferred_language' \
           FROM contact c WHERE c.id = $1 AND (c.is_active IS NULL OR c.is_active = true)",
    )
    .bind(contact)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((email, phone, language)) = person else {
        decide(db, subject, step, Some(contact), "no_contact").await?;
        return Ok(false);
    };
    let mut template: Option<(Option<String>, String, Option<String>)> = None;
    for locale in locales_for(language.as_deref()) {
        template = sqlx::query_as(
            "SELECT subject, body_text, default_channels FROM notification_template \
              WHERE template_key = $1 AND locale = $2 AND is_active IS NOT FALSE \
              ORDER BY created_at DESC LIMIT 1",
        )
        .bind(step.template_key())
        .bind(locale)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if template.is_some() {
            break;
        }
    }
    let Some((subject_line, body, channels)) = template else {
        decide(db, subject, step, Some(contact), "no_template").await?;
        return Ok(false);
    };
    let channels = channels.unwrap_or_else(|| "email".into());
    let wants = |c: &str| channels.split([',', ' ']).any(|x| x.trim() == c);
    let text = render(&body, &values);
    let subject_text = render(subject_line.as_deref().unwrap_or(""), &values);

    let email = email
        .map(|e| e.trim().to_owned())
        .filter(|e| wants("email") && e.contains('@'));
    let mut tx = attome_db::tx::begin(db).await?;
    let claimed = sqlx::query(
        "INSERT INTO fulfilment_customer_update (subject_id, step, contact_id, status, channels) \
         VALUES ($1, $2, $3, 'queued', $4) ON CONFLICT (subject_id, step) DO NOTHING",
    )
    .bind(subject)
    .bind(step.as_str())
    .bind(contact)
    .bind(&channels)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(false);
    }
    let mut queued = false;
    if let Some(to) = email
        && !attome_notification::dispatch::is_email_suppressed(&mut *tx, &to).await?
    {
        let job = attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to,
            subject: subject_text,
            text_body: text.clone(),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
            stream: attome_email::EmailStream::Transactional,
            list_unsubscribe: None,
        }));
        attome_jobs::enqueue_in_tx(&mut tx, job)
            .await
            .map_err(AppError::internal)?;
        queued = true;
    }
    attome_db::tx::commit(tx).await?;

    // A text goes after the decision is committed: no I/O inside it.
    if wants("sms")
        && let Some(phone) = phone.filter(|p| !p.trim().is_empty())
    {
        match attome_integration::sms::send(state, phone.trim(), &text, None).await {
            Ok(attome_integration::sms::Sent::Accepted(_)) => queued = true,
            Ok(attome_integration::sms::Sent::Skipped) => {}
            Err(error) => tracing::warn!(%subject, %error, "customer update: text not sent"),
        }
    }
    let status = if queued { "sent" } else { "failed" };
    sqlx::query(
        "UPDATE fulfilment_customer_update SET status = $3 WHERE subject_id = $1 AND step = $2",
    )
    .bind(subject)
    .bind(step.as_str())
    .bind(status)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(queued)
}

/// The order's lines and shipments when `order` belongs to `account`;
/// `None` otherwise, so the caller answers 404 for anyone else's order.
pub async fn portal_order(
    state: &EngineState,
    account: Uuid,
    order: Uuid,
) -> Result<Option<OrderFulfilment>, AppError> {
    let mine: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM \"order\" WHERE id = $1 AND account_ref = $2 \
                          AND (is_active IS NULL OR is_active = true))",
    )
    .bind(order)
    .bind(account)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !mine {
        return Ok(None);
    }
    Ok(Some(order_fulfilment(state, order).await?))
}

/// An erased contact's update decisions go with them.
#[derive(Debug)]
pub struct CustomerUpdateErasure;

impl ErasureHook for CustomerUpdateErasure {
    fn name(&self) -> &'static str {
        "fulfilment_customer_updates"
    }

    fn erase<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        entity: &'a str,
        record_id: Uuid,
    ) -> ErasureFuture<'a> {
        Box::pin(async move {
            if entity != "contact" {
                return Ok(0);
            }
            let installed: bool =
                sqlx::query_scalar("SELECT to_regclass('fulfilment_customer_update') IS NOT NULL")
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
            if !installed {
                return Ok(0);
            }
            Ok(
                sqlx::query("DELETE FROM fulfilment_customer_update WHERE contact_id = $1")
                    .bind(record_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn statuses_map_to_steps() {
        assert_eq!(step_for_status("in_transit"), Some(Step::Shipped));
        assert_eq!(step_for_status("picked_up"), Some(Step::Shipped));
        assert_eq!(
            step_for_status("out_for_delivery"),
            Some(Step::OutForDelivery)
        );
        assert_eq!(step_for_status("delivered"), Some(Step::Delivered));
        assert_eq!(step_for_status("booked"), None);
        assert_eq!(step_for_status("failed_attempt"), None);
        assert_eq!(Step::Delayed.template_key(), "fulfilment.delayed");
    }

    #[test]
    fn templates_render_their_values() {
        let values = json!({"order_number": "SO-17", "tracking_number": "AWB9", "carrier": null});
        let values = values.as_object().unwrap();
        assert_eq!(
            render(
                "Order {{order_number}}: {{tracking_number}} {{carrier}}{{other}}",
                values
            ),
            "Order SO-17: AWB9 {{other}}"
        );
    }

    #[test]
    fn arabic_speakers_get_arabic_first() {
        assert_eq!(locales_for(Some("ar")), &["ar-SA", "ar", "en"]);
        assert_eq!(locales_for(Some("en")), &["en"]);
        assert_eq!(locales_for(None), &["en"]);
    }
}
