//! Collections actions (roadmap AI5-T3), on the follow-up ledger items the
//! collections detector writes (`followup_collections`, reasons
//! `invoice_due`, `invoice_overdue`, `renewal_due`).
//!
//! - `collections.send_reminder` (Consequential): the rule's template, in the
//!   customer's language, sent through the compose writer
//!   (`attome_notification::communication::write_communication`), the one
//!   `followup.send_message` uses; the item then moves to `sent`. Every value
//!   in the message — invoice number, amount, currency, dates, names — is
//!   filled from the records, never from model text; the action takes no
//!   free text at all. An agent's call waits for a person's approval; the
//!   daily collections run sends directly only for an active rule within its
//!   reminders (AI5-T5, [`send_reminder`]).
//! - `collections.record_promise` (Reversible): an `ai_payment_promise` row
//!   for the invoice, written through the record engine with
//!   `source = agent` and the customer's own words as its note.
//!
//! Both act only on an item the caller owns, apply an agent session's write
//! caps, and record an `agent_task` outcome tied to the session.
//!
//! Only the `email` channel is sent today: the compose writer sends email
//! and internal messages, so a rule on `whatsapp` or `sms` is refused with a
//! validation error rather than sent some other way.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SEND_REMINDER: &str = "collections.send_reminder";
pub const RECORD_PROMISE: &str = "collections.record_promise";

/// The outcome kind both actions record.
pub const OUTCOME_KIND: &str = "agent_task";
/// Per-minute cap on either action inside one agent session.
pub const PER_MINUTE_CAP: i32 = 10;
/// Per-day cap on promises one agent session records.
pub const PROMISES_PER_DAY: i64 = 50;
/// The longest note a promise keeps.
pub const MAX_NOTE_CHARS: usize = 2_000;

const SEND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "item_id": { "type": "string", "format": "uuid", "description": "The collections follow-up item." }
  },
  "required": ["item_id"],
  "additionalProperties": false
}"#;

const PROMISE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "item_id": { "type": "string", "format": "uuid", "description": "The collections follow-up item for the invoice." },
    "promised_amount": { "type": "number", "exclusiveMinimum": 0, "description": "The amount the customer promised; omit when they named none." },
    "promised_date": { "type": "string", "format": "date", "description": "The date the customer promised to pay by (YYYY-MM-DD)." },
    "note": { "type": "string", "maxLength": 2000, "description": "The customer's own words." }
  },
  "required": ["item_id", "promised_date", "note"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            SEND_REMINDER,
            "Send the collections reminder for a follow-up item: the rule's template in the \
             customer's language, with every amount and date taken from the invoice or \
             subscription. A person approves it first.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(SEND_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
        ActionDescriptor::new(
            RECORD_PROMISE,
            "Record a customer's promise to pay an invoice (amount, date and their own \
             words) so reminders stop while it is open.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(PROMISE_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(SendReminder), Box::new(RecordPromise)]
}

/// A collections item with its rule.
#[derive(Debug, Clone)]
pub struct CollectionsItem {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub owner: Uuid,
    pub reason: String,
    pub status: String,
    pub rule_active: bool,
    pub channel: String,
    pub template_en: Option<String>,
    pub template_ar: Option<String>,
    pub max_reminders: Option<i64>,
}

type ItemRow = (
    Uuid,
    String,
    Uuid,
    Uuid,
    String,
    String,
    Option<bool>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<f64>,
);

/// The collections reasons.
pub fn is_collections_reason(reason: &str) -> bool {
    matches!(reason, "invoice_due" | "invoice_overdue" | "renewal_due")
}

/// One collections item the caller owns, still open to act on.
pub async fn load_item(
    state: &EngineState,
    ctx: &ActionContext,
    id: Uuid,
) -> Result<CollectionsItem, AppError> {
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT i.rule_ref, i.entity_logical_name, i.record_id, i.owner_user_id, i.reason, \
                i.status, r.is_active, r.channel::text, r.template_text_en, r.template_text_ar, \
                r.max_reminders::float8 \
           FROM ai_followup_item i JOIN ai_collection_rule r ON r.id = i.rule_ref \
          WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((
        rule_id,
        entity,
        record_id,
        owner,
        reason,
        status,
        active,
        channel,
        template_en,
        template_ar,
        max,
    )) = row
    else {
        return Err(AppError::NotFound);
    };
    if owner != ctx.security.user_id && !ctx.security.is_admin {
        return Err(AppError::NotFound);
    }
    if !is_collections_reason(&reason) {
        return Err(AppError::Validation("not a collections item".into()));
    }
    if !matches!(status.as_str(), "open" | "reminded" | "drafted") {
        return Err(AppError::Conflict("the follow-up is already closed"));
    }
    Ok(CollectionsItem {
        id,
        rule_id,
        entity,
        record_id,
        owner,
        reason,
        status,
        rule_active: active.unwrap_or(true),
        channel: channel.unwrap_or_else(|| "email".to_owned()),
        template_en,
        template_ar,
        max_reminders: max.filter(|m| *m > 0.0).map(|m| m as i64),
    })
}

/// A record's value as message text: text as it is, a number in its own
/// digits, a date or time as its date. Pure.
pub fn value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => {
            let looks_like_time = s.len() > 10 && s.as_bytes().get(10) == Some(&b'T');
            if looks_like_time {
                s[..10].to_owned()
            } else {
                s.clone()
            }
        }
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// The message's values, from the invoice or subscription and the customer.
/// Pure.
pub fn template_values(
    reason: &str,
    record: &Map<String, Value>,
    customer_name: &str,
) -> BTreeMap<&'static str, String> {
    let mut values = BTreeMap::new();
    values.insert("customer_name", customer_name.to_owned());
    values.insert("currency", value_text(record.get("currency")));
    if reason == "renewal_due" {
        values.insert("subscription_name", value_text(record.get("name")));
        values.insert("end_date", value_text(record.get("end_date")));
    } else {
        values.insert("invoice_number", value_text(record.get("invoice_number")));
        let amount = ["open_total", "grand_total", "amount"]
            .iter()
            .map(|k| value_text(record.get(*k)))
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        values.insert("amount", amount);
        values.insert("due_date", value_text(record.get("due_date")));
    }
    values
}

/// Replaces each `{name}` in `template` with its value; a name with no
/// value becomes empty. Pure.
pub fn render(template: &str, values: &BTreeMap<&'static str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close)
                if after[..close]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                let name = &after[..close];
                if let Some(value) = values.get(name) {
                    out.push_str(value);
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The built-in subject and body for a reason in a language, used when the
/// rule has no template of its own. Pure.
pub fn default_template(reason: &str, language: &str) -> (&'static str, &'static str) {
    match (reason, language) {
        ("renewal_due", "ar") => (
            "تجديد {subscription_name}",
            "مرحباً {customer_name}،\nينتهي اشتراك {subscription_name} في {end_date}. نتطلع إلى تجديده معكم.",
        ),
        ("renewal_due", _) => (
            "Renewal of {subscription_name}",
            "Hello {customer_name},\nYour subscription {subscription_name} ends on {end_date}. We look forward to renewing it with you.",
        ),
        ("invoice_overdue", "ar") => (
            "الفاتورة {invoice_number} متأخرة",
            "مرحباً {customer_name}،\nالفاتورة {invoice_number} بمبلغ {amount} {currency} كانت مستحقة في {due_date} ولم تُسدَّد بعد.",
        ),
        ("invoice_overdue", _) => (
            "Invoice {invoice_number} is overdue",
            "Hello {customer_name},\nInvoice {invoice_number} for {amount} {currency} was due on {due_date} and is still open.",
        ),
        (_, "ar") => (
            "الفاتورة {invoice_number} مستحقة قريباً",
            "مرحباً {customer_name}،\nالفاتورة {invoice_number} بمبلغ {amount} {currency} مستحقة في {due_date}.",
        ),
        _ => (
            "Invoice {invoice_number} is coming due",
            "Hello {customer_name},\nInvoice {invoice_number} for {amount} {currency} is due on {due_date}.",
        ),
    }
}

/// `ar` or `en` from a language value, else the fallback. Pure.
pub fn language_of(value: Option<&str>, fallback: &str) -> String {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v.starts_with("ar") => "ar".to_owned(),
        Some(v) if v.starts_with("en") => "en".to_owned(),
        _ => fallback.to_owned(),
    }
}

/// The deployment's own language (`core.locale` with no user), `ar` or `en`.
fn deployment_language(state: &EngineState) -> String {
    let locale = attome_core::setting_registry()
        .get("core.locale")
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "en-US".to_owned());
    language_of(Some(&locale), "en")
}

/// Who a reminder goes to.
struct Customer {
    name: String,
    email: Option<String>,
    language: Option<String>,
    do_not_email: bool,
}

/// The customer of an invoice or subscription: its contact, else the first
/// contact of its account, as the caller may read them.
async fn customer(
    state: &EngineState,
    ctx: &ActionContext,
    record: &Map<String, Value>,
) -> Result<Option<Customer>, AppError> {
    let id_of = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
    };
    let mut contact = id_of("contact_ref");
    let has_contacts = state.entities.load().get("contact").is_some();
    if contact.is_none()
        && has_contacts
        && let Some(account) = id_of("account_ref")
    {
        contact = sqlx::query_scalar(
            "SELECT id FROM contact WHERE account_ref = $1 \
               AND (is_active IS NULL OR is_active = true) ORDER BY created_at LIMIT 1",
        )
        .bind(account)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    let Some(contact) = contact else {
        return Ok(None);
    };
    let row = match attome_records::entity_crud::read_record_bulk(
        state,
        &ctx.security,
        "contact",
        contact,
    )
    .await
    {
        Ok(row) => row,
        Err(AppError::NotFound | AppError::Forbidden) => return Ok(None),
        Err(error) => return Err(error),
    };
    let data = row.data();
    let text = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    Ok(Some(Customer {
        name: text("full_name").unwrap_or_default(),
        email: text("email"),
        language: text("preferred_language"),
        do_not_email: data.get("do_not_email").and_then(Value::as_bool) == Some(true),
    }))
}

/// Applies an agent session's write caps.
async fn session_caps(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
    per_day: i64,
) -> Result<(), AppError> {
    if let Some(session) = ctx.agent_session_id {
        crate::write_guard::enforce_write_caps(state, session, action_id, per_day, PER_MINUTE_CAP)
            .await?;
    }
    Ok(())
}

/// Records the action in the outcome ledger; a failure is logged.
async fn record_outcome(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
    item: &CollectionsItem,
    expected: Value,
) {
    let proposal = crate::outcome::OutcomeProposal {
        kind: OUTCOME_KIND,
        entity_logicalname: Some(&item.entity),
        regarding_entity: Some("ai_followup_item"),
        regarding_id: Some(item.id),
        model_id: None,
        prompt_version: None,
        rule_ref: Some("ai.collections"),
        proposed_by: Some(ctx.security.user_id),
        organization_ref: None,
        expected_value: Some(expected),
    };
    if let Err(error) = crate::outcome::record_proposed(
        &state.base.db,
        Uuid::now_v7(),
        action_id,
        &proposal,
        ctx.agent_session_id,
    )
    .await
    {
        tracing::warn!(item = %item.id, %error, "collections outcome not recorded");
    }
}

/// Sends a collections item's reminder: the body of
/// `collections.send_reminder`, also called by the daily collections run for
/// an active rule within its reminders.
pub async fn send_reminder(
    state: &EngineState,
    ctx: &ActionContext,
    item_id: Uuid,
) -> Result<Value, AppError> {
    let item = load_item(state, ctx, item_id).await?;
    if item.channel != "email" {
        return Err(AppError::Validation(format!(
            "collections reminders are sent by email; this rule's channel is {}",
            item.channel
        )));
    }
    // A message about a record is an update of the record, as on the
    // compose route.
    ctx.security.require(&item.entity, "update")?;
    let entity_id = state
        .entities
        .load()
        .get(&item.entity)
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        &ctx.security,
        entity_id,
        &item.entity,
        item.record_id,
        RecordAction::Update,
    )
    .await?;
    let record = attome_records::entity_crud::read_record_bulk(
        state,
        &ctx.security,
        &item.entity,
        item.record_id,
    )
    .await?;
    let record = record
        .data()
        .as_object()
        .cloned()
        .ok_or(AppError::NotFound)?;
    let customer = customer(state, ctx, &record)
        .await?
        .ok_or_else(|| AppError::Validation("the customer has no contact to remind".into()))?;
    if customer.do_not_email {
        return Err(AppError::Validation(
            "the customer asked not to be emailed".into(),
        ));
    }
    let email = customer
        .email
        .clone()
        .ok_or_else(|| AppError::Validation("the customer's contact has no email".into()))?;
    let fallback = deployment_language(state);
    let language = language_of(
        customer
            .language
            .as_deref()
            .or_else(|| record.get("language").and_then(Value::as_str)),
        &fallback,
    );
    let values = template_values(&item.reason, &record, &customer.name);
    let (default_subject, default_body) = default_template(&item.reason, &language);
    let own = if language == "ar" {
        item.template_ar.as_deref()
    } else {
        item.template_en.as_deref()
    }
    .map(str::trim)
    .filter(|t| !t.is_empty());
    let subject = render(default_subject, &values);
    let body = render(own.unwrap_or(default_body), &values);

    let (to, recipients) =
        attome_notification::communication::validate_recipients("email", &[email], &[])?;
    session_caps(
        state,
        ctx,
        SEND_REMINDER,
        item.max_reminders.unwrap_or(i64::MAX),
    )
    .await?;
    let sent = attome_notification::communication::write_communication(
        state,
        &ctx.security,
        ctx.security.user_id,
        &item.entity,
        item.record_id,
        "email",
        "outbound",
        &to,
        &recipients,
        &subject,
        &body,
        None,
        None,
        None,
        None,
    )
    .await?;
    // The message is durable; an item closed meanwhile is only not marked.
    let marked = sqlx::query(
        "UPDATE ai_followup_item SET status = 'sent', updated_at = now(), \
             row_version = row_version + 1, \
             agent_session_ref = COALESCE($2, agent_session_ref) \
          WHERE id = $1 AND status IN ('open', 'reminded', 'drafted')",
    )
    .bind(item_id)
    .bind(ctx.agent_session_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if marked == 0 {
        tracing::info!(item = %item_id, "collections item closed before it was marked sent");
    }
    record_outcome(
        state,
        ctx,
        SEND_REMINDER,
        &item,
        json!({ "reason": item.reason, "language": language }),
    )
    .await;
    Ok(json!({
        "item_id": item_id,
        "status": "sent",
        "communication_id": sent.id,
        "language": language,
        "previous_status": item.status,
    }))
}

struct SendReminder;

impl Action for SendReminder {
    fn id(&self) -> ActionId {
        ActionId(SEND_REMINDER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let item_id = uuid_arg(args, "item_id")?;
            Ok(ActionResult::plain(
                send_reminder(state, ctx, item_id).await?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({ "action": SEND_REMINDER, "item_id": args["item_id"] }))
    }
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

/// A promise's checked values. Pure.
pub fn promise_values(args: &Value) -> Result<(Option<f64>, chrono::NaiveDate, String), AppError> {
    let amount = match args.get("promised_amount") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_f64()
                .filter(|a| a.is_finite() && *a > 0.0)
                .ok_or_else(|| AppError::Validation("promised_amount must be above 0".into()))?,
        ),
    };
    let date = args["promised_date"]
        .as_str()
        .and_then(|s| chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok())
        .ok_or_else(|| AppError::Validation("promised_date must be a date (YYYY-MM-DD)".into()))?;
    let note: String = args["note"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("note must hold the customer's words".into()))?
        .chars()
        .take(MAX_NOTE_CHARS)
        .collect();
    Ok((amount, date, note))
}

/// Records a promise to pay on a collections item's invoice, `pending`
/// review: the body of `collections.record_promise`, also called by the
/// promise reader (AI5-T4) for a promise found in a customer's reply.
pub async fn record_promise(
    state: &EngineState,
    ctx: &ActionContext,
    item_id: Uuid,
    amount: Option<f64>,
    date: chrono::NaiveDate,
    note: &str,
) -> Result<Value, AppError> {
    let item = load_item(state, ctx, item_id).await?;
    if item.reason == "renewal_due" {
        return Err(AppError::Validation(
            "a payment promise is for an invoice".into(),
        ));
    }
    // The invoice must be one the caller may read.
    let invoice = attome_records::entity_crud::read_record_bulk(
        state,
        &ctx.security,
        &item.entity,
        item.record_id,
    )
    .await?;
    let data = invoice.data();
    let customer = [("contact", "contact_ref"), ("account", "account_ref")]
        .into_iter()
        .find_map(|(entity, key)| {
            data.get(key)
                .and_then(Value::as_str)
                .map(|id| (entity, id.to_owned()))
        });
    session_caps(state, ctx, RECORD_PROMISE, PROMISES_PER_DAY).await?;
    let note: String = note.trim().chars().take(MAX_NOTE_CHARS).collect();
    let body = json!({
        "invoice_entity": item.entity,
        "invoice_id": item.record_id.to_string(),
        "invoice_number": data.get("invoice_number").cloned().unwrap_or(Value::Null),
        "customer_entity": customer.as_ref().map(|(entity, _)| *entity),
        "customer_id": customer.as_ref().map(|(_, id)| id.clone()),
        "promised_amount": amount,
        "promised_date": date.to_string(),
        "source": "agent",
        "status": "open",
        // AI5-T6: a person confirms or rejects what an agent recorded.
        "review_status": "pending",
        "note": note,
    });
    let (promise_id, _) = attome_records::entity_crud::create_record_for(
        state,
        &ctx.security,
        ctx.security.user_id,
        "ai_payment_promise",
        body,
    )
    .await?;
    record_outcome(
        state,
        ctx,
        RECORD_PROMISE,
        &item,
        json!({ "promise_id": promise_id, "promised_date": date.to_string() }),
    )
    .await;
    Ok(json!({
        "promise_id": promise_id,
        "item_id": item_id,
        "promised_date": date.to_string(),
        "status": "open",
    }))
}

struct RecordPromise;

impl Action for RecordPromise {
    fn id(&self) -> ActionId {
        ActionId(RECORD_PROMISE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let item_id = uuid_arg(args, "item_id")?;
            let (amount, date, note) = promise_values(args)?;
            Ok(ActionResult::plain(
                record_promise(state, ctx, item_id, amount, date, &note).await?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({
            "action": RECORD_PROMISE,
            "item_id": args["item_id"],
            "promised_amount": args["promised_amount"],
            "promised_date": args["promised_date"],
            "note": args["note"],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == id)
            .expect("described")
    }

    #[test]
    fn send_reminder_is_consequential() {
        let d = descriptor(SEND_REMINDER);
        assert_eq!(d.risk, RiskTier::Consequential);
        assert_eq!(d.outcome_kind, Some(OUTCOME_KIND));
    }

    #[test]
    fn record_promise_is_reversible() {
        let d = descriptor(RECORD_PROMISE);
        assert_eq!(d.risk, RiskTier::Reversible);
        assert_eq!(d.effect, Effect::Write);
    }

    #[test]
    fn amounts_and_dates_come_from_the_invoice() {
        let invoice: Map<String, Value> = serde_json::from_value(json!({
            "invoice_number": "INV-0042", "open_total": "1250.50", "grand_total": "2000",
            "currency": "SAR", "due_date": "2027-03-04T00:00:00Z",
        }))
        .expect("a map");
        let values = template_values("invoice_overdue", &invoice, "Huda");
        let (subject, body) = default_template("invoice_overdue", "en");
        assert_eq!(render(subject, &values), "Invoice INV-0042 is overdue");
        assert_eq!(
            render(body, &values),
            "Hello Huda,\nInvoice INV-0042 for 1250.50 SAR was due on 2027-03-04 and is still open."
        );
        let (_, ar) = default_template("invoice_due", "ar");
        assert!(render(ar, &values).contains("INV-0042 بمبلغ 1250.50 SAR"));
    }

    #[test]
    fn a_template_only_fills_known_names() {
        let mut values = BTreeMap::new();
        values.insert("amount", "10".to_owned());
        assert_eq!(
            render("Pay {amount} {unknown} {not a name} {", &values),
            "Pay 10  {not a name} {"
        );
    }

    #[test]
    fn a_promise_needs_a_date_and_the_customers_words() {
        let ok = promise_values(&json!({
            "item_id": Uuid::nil(), "promised_amount": 500, "promised_date": "2027-04-01",
            "note": " سأدفع يوم الخميس ",
        }))
        .expect("valid");
        assert_eq!(ok.0, Some(500.0));
        assert_eq!(ok.1.to_string(), "2027-04-01");
        assert_eq!(ok.2, "سأدفع يوم الخميس");
        assert!(promise_values(&json!({ "promised_date": "next week", "note": "x" })).is_err());
        assert!(promise_values(&json!({ "promised_date": "2027-04-01", "note": " " })).is_err());
        assert!(
            promise_values(
                &json!({ "promised_amount": -1, "promised_date": "2027-04-01", "note": "x" })
            )
            .is_err()
        );
    }

    #[test]
    fn the_language_follows_the_customer() {
        assert_eq!(language_of(Some("ar"), "en"), "ar");
        assert_eq!(language_of(Some("ar_en"), "en"), "ar");
        assert_eq!(language_of(None, "ar"), "ar");
        assert_eq!(language_of(Some("fr"), "en"), "en");
    }
}
