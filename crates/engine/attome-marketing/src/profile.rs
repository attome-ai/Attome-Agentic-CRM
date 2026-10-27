//! E23-T2: sending profile events in batches, and a contact's traits rolled
//! up from them.
//!
//! - `POST /api/v1/marketing/profile-events` takes up to [`MAX_BATCH`] events from a
//!   signed-in caller or an API key holding `contact.update`, at most
//!   [`BATCHES_PER_MINUTE`] batches a minute per caller (Redis sliding
//!   window). Each event names a contact the caller may read, or an
//!   anonymous id; its time defaults to now and must fall within the last
//!   [`MAX_AGE_DAYS`] days (or [`MAX_AHEAD_MINUTES`] ahead), where the
//!   monthly partitions exist. Valid events are written in one statement
//!   ([`crate::profile_events::TABLE`]); the others come back with their
//!   index and reason.
//! - `GET /api/v1/marketing/contacts/{id}/traits` computes the contact's
//!   traits from its events on the contact index: when it was last seen,
//!   visits, purchases and their total. Traits are computed when read, never
//!   stored, so nothing goes stale; they reach back as far as events are
//!   kept (`marketing.profile_event_retention_months`).

use std::collections::HashSet;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Most events one batch carries.
pub const MAX_BATCH: usize = 500;
/// Batches one caller may send a minute.
pub const BATCHES_PER_MINUTE: i32 = 60;
/// How far back an event's time may be.
pub const MAX_AGE_DAYS: i64 = 7;
/// How far ahead an event's time may be (clock skew).
pub const MAX_AHEAD_MINUTES: i64 = 5;
/// Most bytes of one event's properties, as JSON.
pub const MAX_PROPERTIES_BYTES: usize = 8 * 1024;
/// Event kinds that count as a visit.
pub const VISIT_KINDS: [&str; 3] = ["visit", "page_view", "session_start"];
/// The event kind that counts as a purchase; its `amount` property adds up.
pub const PURCHASE_KIND: &str = "purchase";

/// One event sent.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct IncomingEvent {
    #[serde(default)]
    pub contact_id: Option<Uuid>,
    /// A visitor not yet known as a contact.
    #[serde(default)]
    pub anonymous_id: Option<String>,
    /// What happened (1 to 100 characters), such as `page_view` or `purchase`.
    pub kind: String,
    /// When; now when absent.
    #[serde(default)]
    pub at: Option<DateTime<Utc>>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub properties: Option<Value>,
}

/// A batch of events.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EventBatch {
    pub events: Vec<IncomingEvent>,
}

/// An event left out, by its place in the batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RejectedEvent {
    pub index: usize,
    pub reason: String,
}

/// What a batch did.
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = MarketingProfileBatchResult)]
pub struct BatchResult {
    pub accepted: usize,
    pub rejected: Vec<RejectedEvent>,
}

/// An event ready to write.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidEvent {
    pub contact_id: Option<Uuid>,
    pub anonymous_id: Option<String>,
    pub kind: String,
    pub at: DateTime<Utc>,
    pub properties: Value,
}

/// Checks one event at `now`, without the database. Pure.
pub fn validate(event: &IncomingEvent, now: DateTime<Utc>) -> Result<ValidEvent, String> {
    let anonymous = event
        .anonymous_id
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    if event.contact_id.is_none() && anonymous.is_none() {
        return Err("needs a contact_id or an anonymous_id".into());
    }
    if anonymous.is_some_and(|a| a.len() > 200) {
        return Err("anonymous_id is at most 200 characters".into());
    }
    let kind = event.kind.trim();
    if kind.is_empty() || kind.len() > 100 {
        return Err("kind is 1 to 100 characters".into());
    }
    let at = event.at.unwrap_or(now);
    if at < now - Duration::days(MAX_AGE_DAYS) || at > now + Duration::minutes(MAX_AHEAD_MINUTES) {
        return Err(format!(
            "at is within the last {MAX_AGE_DAYS} days and not in the future"
        ));
    }
    let properties = event.properties.clone().unwrap_or_else(|| json!({}));
    if !properties.is_object() {
        return Err("properties is an object".into());
    }
    if properties.to_string().len() > MAX_PROPERTIES_BYTES {
        return Err(format!(
            "properties is at most {MAX_PROPERTIES_BYTES} bytes"
        ));
    }
    Ok(ValidEvent {
        contact_id: event.contact_id,
        anonymous_id: anonymous.map(str::to_owned),
        kind: kind.to_owned(),
        at,
        properties,
    })
}

/// The contacts among `ids` the caller may read.
async fn readable_contacts(
    state: &EngineState,
    ctx: &SecurityContext,
    ids: &[Uuid],
) -> Result<HashSet<Uuid>, AppError> {
    let mut out = HashSet::new();
    for id in ids {
        if attome_records::entity_crud::referenced_record_visible(state, ctx, "contact", *id)
            .await?
        {
            out.insert(*id);
        }
    }
    Ok(out)
}

/// Checks and writes a batch.
pub async fn ingest(
    state: &EngineState,
    ctx: &SecurityContext,
    batch: &EventBatch,
    now: DateTime<Utc>,
) -> Result<BatchResult, AppError> {
    ctx.require("contact", "update")?;
    if batch.events.is_empty() || batch.events.len() > MAX_BATCH {
        return Err(AppError::Validation(format!(
            "a batch has 1 to {MAX_BATCH} events"
        )));
    }
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &format!("marketing:rl:events:user:{}", ctx.user_id),
        BATCHES_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    let mut rejected = Vec::new();
    let mut valid: Vec<(usize, ValidEvent)> = Vec::new();
    for (index, event) in batch.events.iter().enumerate() {
        match validate(event, now) {
            Ok(v) => valid.push((index, v)),
            Err(reason) => rejected.push(RejectedEvent { index, reason }),
        }
    }
    let mut named: Vec<Uuid> = valid.iter().filter_map(|(_, v)| v.contact_id).collect();
    named.sort();
    named.dedup();
    let readable = readable_contacts(state, ctx, &named).await?;
    valid.retain(|(index, v)| match v.contact_id {
        Some(contact) if !readable.contains(&contact) => {
            rejected.push(RejectedEvent {
                index: *index,
                reason: "no such contact".into(),
            });
            false
        }
        _ => true,
    });
    rejected.sort_by_key(|r| r.index);

    if !valid.is_empty() {
        let contacts: Vec<Option<Uuid>> = valid.iter().map(|(_, v)| v.contact_id).collect();
        let anonymous: Vec<Option<String>> =
            valid.iter().map(|(_, v)| v.anonymous_id.clone()).collect();
        let kinds: Vec<String> = valid.iter().map(|(_, v)| v.kind.clone()).collect();
        let times: Vec<DateTime<Utc>> = valid.iter().map(|(_, v)| v.at).collect();
        let properties: Vec<Value> = valid.iter().map(|(_, v)| v.properties.clone()).collect();
        sqlx::query(
            "INSERT INTO profile_event (contact_id, anonymous_id, kind, at, properties) \
             SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::timestamptz[], $5::jsonb[])",
        )
        .bind(&contacts)
        .bind(&anonymous)
        .bind(&kinds)
        .bind(&times)
        .bind(&properties)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(BatchResult {
        accepted: valid.len(),
        rejected,
    })
}

/// A contact's traits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, ToSchema)]
pub struct ContactTraits {
    pub contact_id: Uuid,
    /// The latest event of any kind.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Events of a visit kind.
    pub visits: i64,
    pub purchases: i64,
    /// The sum of purchase events' numeric `amount`.
    pub total_purchases: f64,
    /// All events kept for the contact.
    pub events: i64,
}

/// Rolls a contact's events up into its traits.
pub async fn traits(
    state: &EngineState,
    ctx: &SecurityContext,
    contact: Uuid,
) -> Result<ContactTraits, AppError> {
    if !attome_records::entity_crud::referenced_record_visible(state, ctx, "contact", contact)
        .await?
    {
        return Err(AppError::NotFound);
    }
    let visit_kinds: Vec<&str> = VISIT_KINDS.to_vec();
    let (last_seen_at, visits, purchases, total, events): (
        Option<DateTime<Utc>>,
        i64,
        i64,
        Option<f64>,
        i64,
    ) = sqlx::query_as(
        "SELECT max(at), \
                count(*) FILTER (WHERE kind = ANY($2)), \
                count(*) FILTER (WHERE kind = $3), \
                sum(CASE WHEN properties->>'amount' ~ '^-?[0-9]+(\\.[0-9]+)?$' \
                         THEN (properties->>'amount')::float8 END) FILTER (WHERE kind = $3), \
                count(*) \
           FROM profile_event WHERE contact_id = $1",
    )
    .bind(contact)
    .bind(&visit_kinds)
    .bind(PURCHASE_KIND)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(ContactTraits {
        contact_id: contact,
        last_seen_at,
        visits,
        purchases,
        total_purchases: total.unwrap_or(0.0),
        events,
    })
}

// ── Routes ───────────────────────────────────────────────────────────────────

/// `contact.update`: sending events about contacts.
#[derive(Debug)]
pub struct ContactUpdate;

impl PrivilegeKey for ContactUpdate {
    const KEY: &'static str = "contact.update";
}

/// `contact.read`: reading a contact's traits.
#[derive(Debug)]
pub struct ContactRead;

impl PrivilegeKey for ContactRead {
    const KEY: &'static str = "contact.read";
}

/// Send profile events
///
/// Up to 500 events per batch, 60 batches a minute per caller. Each names
/// a contact or an anonymous id; events that fail a check come back with
/// their index and reason, and the rest are kept.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/profile-events",
    operation_id = "ingest_profile_events",
    tag = "marketing",
    request_body = EventBatch,
    responses(
        (status = 200, description = "Kept and left-out events", body = BatchResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contact.update", body = ErrorResponse),
        (status = 422, description = "An empty batch, or more than 500 events", body = ErrorResponse),
        (status = 429, description = "Too many batches this minute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
async fn post_events(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ContactUpdate>>,
    Json(batch): Json<EventBatch>,
) -> Result<Json<BatchResult>, AppError> {
    ingest(&state, &ctx, &batch, Utc::now()).await.map(Json)
}

/// A contact's traits
///
/// Last seen, visits, purchases and their total, rolled up from the
/// contact's profile events when read.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/contacts/{id}/traits",
    operation_id = "contact_traits",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The contact")),
    responses(
        (status = 200, description = "The contact's traits", body = ContactTraits),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contact.read", body = ErrorResponse),
        (status = 404, description = "No such contact, or not readable", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_traits(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ContactRead>>,
    Path(contact): Path<Uuid>,
) -> Result<Json<ContactTraits>, AppError> {
    traits(&state, &ctx, contact).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/profile-events", post(post_events))
        .route("/api/v1/marketing/contacts/{id}/traits", get(get_traits))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_events, get_traits),
    components(schemas(EventBatch, IncomingEvent, BatchResult, RejectedEvent, ContactTraits))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn event(contact: Option<Uuid>, anonymous: Option<&str>, kind: &str) -> IncomingEvent {
        IncomingEvent {
            contact_id: contact,
            anonymous_id: anonymous.map(str::to_owned),
            kind: kind.to_owned(),
            at: None,
            properties: None,
        }
    }

    #[test]
    fn profile_event_needs_a_subject_and_a_kind() {
        let now = Utc::now();
        assert!(validate(&event(Some(Uuid::now_v7()), None, "page_view"), now).is_ok());
        assert!(validate(&event(None, Some(" v-1 "), "visit"), now).is_ok());
        assert!(validate(&event(None, Some("  "), "visit"), now).is_err());
        assert!(validate(&event(Some(Uuid::now_v7()), None, " "), now).is_err());
    }

    #[test]
    fn profile_event_time_stays_in_the_window() {
        let now = Utc::now();
        let mut e = event(Some(Uuid::now_v7()), None, "purchase");
        e.at = Some(now - Duration::days(MAX_AGE_DAYS + 1));
        assert!(validate(&e, now).is_err());
        e.at = Some(now + Duration::hours(1));
        assert!(validate(&e, now).is_err());
        e.at = Some(now - Duration::days(1));
        assert_eq!(validate(&e, now).map(|v| v.at), Ok(now - Duration::days(1)));
    }

    #[test]
    fn profile_event_properties_are_a_small_object() {
        let now = Utc::now();
        let mut e = event(Some(Uuid::now_v7()), None, "purchase");
        e.properties = Some(json!([1, 2]));
        assert!(validate(&e, now).is_err());
        e.properties = Some(json!({ "note": "x".repeat(MAX_PROPERTIES_BYTES) }));
        assert!(validate(&e, now).is_err());
        e.properties = Some(json!({ "amount": 120.5 }));
        assert!(validate(&e, now).is_ok());
    }
}
