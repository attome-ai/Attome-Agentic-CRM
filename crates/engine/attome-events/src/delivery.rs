//! Webhook delivery (M62 plan §3 "Webhook delivery job") — signs, SSRF-
//! guards, sends, and records the outcome of one `event_delivery`
//! row.
//!
//! **Retry/backoff.** A retriable failure returns `Err`, which
//! `server::jobs::handle_platform_job`'s wrapper turns into T2-12's existing
//! platform-wide exponential backoff (`attome_jobs::apply_retry_backoff` — 10s
//! doubling to a 900s cap) before apalis reclaims the job — the same
//! mechanism every other `EngineJob` variant already gets, not a
//! bespoke second backoff curve. `event_subscription.max_attempts`
//! layers a **per-subscription** circuit breaker on top of that shared
//! curve: this handler increments `event_delivery.attempts` on
//! every call (1:1 with apalis's own `Attempt` counter, since one call here
//! is one apalis attempt) and marks the delivery `dead_letter` — returning
//! `Ok(())`, so apalis stops retrying — once `attempts >= max_attempts`,
//! rather than always running to apalis's own global ceiling (25). The
//! admin API clamps an accepted `max_attempts` to `1..=25`
//! (`admin::MAX_ATTEMPTS_CEILING`) so this circuit breaker always fires at
//! or before apalis's own — `retry_class` selects which default a creation
//! request that omits `max_attempts` gets (`standard` = 8, `extended` =
//! 20), the two ends of that same clamped range.
//!
//! **Breaker (AB6-T5).** Each subscription's target host has its own
//! breaker ([`endpoint`]). While it is open, a delivery is not attempted and
//! not counted: [`defer_if_open`] queues the same delivery again for when the
//! breaker may let a call through, and the job ends. A 429, a 5xx, a timeout
//! or a refused connection counts against the breaker; any other answer is
//! the target's own and does not. There is no retry loop here: retries stay
//! M13's job backoff and `max_attempts`.
//!
//! **SSRF.** `target_url` is screened by `ssrf_guard::validate_url` at
//! subscription save time (`admin.rs`) and unconditionally again here,
//! immediately before every send — DNS can change between the two. A
//! send-time rejection is treated as permanent, not transient: it goes
//! straight to `dead_letter` rather than consuming the subscription's retry
//! budget on a target that will keep failing the same way.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::crypto;
use crate::telemetry::{self, DeadLetterReason as Why};

/// AB6-T5: webhook targets' breakers, one per subscription and host.
static ENDPOINTS: std::sync::LazyLock<attome_outbound::EndpointServices> =
    std::sync::LazyLock::new(|| {
        attome_outbound::EndpointServices::new(
            "webhook",
            attome_outbound::Policy {
                timeout: std::time::Duration::from_secs(15),
                ..attome_outbound::Policy::default()
            },
            1_000,
        )
    });

/// The endpoint key of a subscription's target: the subscription and the
/// target's host and port.
pub fn endpoint_key(subscription: Uuid, url: &reqwest::Url) -> String {
    format!(
        "{subscription}:{}:{}",
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default()
    )
}

/// The breaker-holding service of a subscription's target.
pub fn endpoint(
    subscription: Uuid,
    url: &reqwest::Url,
) -> std::sync::Arc<attome_outbound::Service> {
    ENDPOINTS.get(&endpoint_key(subscription, url))
}

/// When `service`'s breaker is open: queues delivery `delivery_id` again for
/// when it may let a call through, and answers `true`, so the caller ends
/// without attempting or counting anything. `false` when it may be tried now.
pub async fn defer_if_open(
    db: &DbPool,
    delivery_id: Uuid,
    service: &attome_outbound::Service,
) -> Result<bool, AppError> {
    let Err(retry_after) = service.breaker.allow() else {
        return Ok(false);
    };
    let wait =
        chrono::Duration::from_std(retry_after).unwrap_or_else(|_| chrono::Duration::seconds(30));
    attome_jobs::enqueue_at_on_pool(
        db,
        attome_core::jobs::EngineJob::EventsDeliverWebhook { delivery_id },
        Utc::now() + wait,
    )
    .await
    .map_err(AppError::internal)?;
    tracing::info!(
        %delivery_id,
        retry_after_secs = retry_after.as_secs(),
        "events delivery: the target's breaker is open; queued again without an attempt"
    );
    Ok(true)
}

/// M13-T3: how long an ordered delivery waits before it looks again.
const ORDERED_RECHECK_SECS: i64 = 10;

/// M13-T3: whether an earlier delivery of the same record to the same
/// subscription is still open (pending, being sent, or failed and retrying).
/// Delivery ids are UUIDv7, so `id <` is "matched earlier".
async fn earlier_open(db: &DbPool, delivery: &DeliveryRow) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM event_delivery \
                         WHERE subscription_ref = $1 AND event_record_id = $2 AND id < $3 \
                           AND status IN ('pending', 'delivering', 'failed'))",
    )
    .bind(delivery.subscription_ref)
    .bind(delivery.event_record_id)
    .bind(delivery.id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// M13-T3: after a failed attempt, pauses the subscription when its
/// endpoint keeps failing. Observational for this delivery: an error here is
/// logged, never the delivery's outcome.
async fn pause_if_failing(state: &EngineState, delivery: &DeliveryRow, owner_ref: Uuid) {
    if let Err(error) = crate::auto_pause::check(state, delivery.subscription_ref, owner_ref).await
    {
        tracing::warn!(
            subscription_id = %delivery.subscription_ref,
            %error,
            "events delivery: the auto-pause check failed"
        );
    }
}

/// Whether an HTTP answer says the target is unwell (rather than refusing
/// this one request).
fn unwell(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Standard: 8 attempts before dead-lettering (roughly a day of T2-12's
/// backoff curve). Extended: 20 (close to apalis's own 25-attempt ceiling)
/// for a subscription an operator explicitly wants to keep retrying through
/// a longer outage. Both are only the *default* a creation request gets when
/// it omits `max_attempts` — `admin.rs` lets a caller pick any value in
/// `1..=25` regardless of `retry_class`.
pub fn default_max_attempts(retry_class: &str) -> i32 {
    match retry_class {
        "extended" => 20,
        _ => 8,
    }
}

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: Uuid,
    subscription_ref: Uuid,
    event_id: Uuid,
    event_entity_logicalname: String,
    event_record_id: Uuid,
    event_operation: String,
    status: String,
    created_at: chrono::DateTime<Utc>,
    event_name: Option<String>,
    changed_attributes: Option<Vec<String>>,
    changes_before: Option<Value>,
    changes_after: Option<Value>,
}

#[derive(sqlx::FromRow)]
struct SubscriptionRow {
    kind: String,
    is_active: bool,
    is_deleted: bool,
    target_url: Option<String>,
    webhook_secret_encrypted: Option<String>,
    max_attempts: i32,
    owner_ref: Uuid,
    payload_shape: String,
    target_auth_header: Option<String>,
    target_auth_value_encrypted: Option<String>,
    ordered: bool,
    external_system: Option<String>,
}

/// Delivers (or terminally fails) one `event_delivery` row.
/// Idempotent at the top: a row already in a terminal state (`delivered`/
/// `dead_letter`) is a no-op — safe for apalis to re-claim/retry this
/// handler for reasons unrelated to the delivery outcome itself (a worker
/// restart mid-flight, `enqueue_dedup` losing its race in a way that still
/// let two rows through, etc).
pub async fn deliver(state: &EngineState, delivery_id: Uuid) -> Result<(), AppError> {
    let Some(delivery) = load_delivery(&state.base.db, delivery_id).await? else {
        tracing::warn!(%delivery_id, "events delivery: row no longer exists, nothing to do");
        return Ok(());
    };
    if delivery.status == "delivered" || delivery.status == "dead_letter" {
        return Ok(());
    }

    let Some(sub) = load_subscription(&state.base.db, delivery.subscription_ref).await? else {
        dead_letter(
            &state.base.db,
            delivery.id,
            telemetry::KIND_UNKNOWN,
            Why::SubscriptionGone,
            "subscription no longer exists",
        )
        .await?;
        return Ok(());
    };
    let kind = telemetry::kind_label(&sub.kind);
    if sub.is_deleted || !sub.is_active {
        dead_letter(
            &state.base.db,
            delivery.id,
            kind,
            Why::SubscriptionInactive,
            "subscription is no longer active",
        )
        .await?;
        return Ok(());
    }
    let (Some(target_url), Some(secret_encrypted)) = (
        sub.target_url.as_deref(),
        sub.webhook_secret_encrypted.as_deref(),
    ) else {
        dead_letter(
            &state.base.db,
            delivery.id,
            kind,
            Why::NoTarget,
            "subscription has no webhook target",
        )
        .await?;
        return Ok(());
    };

    let url = match reqwest::Url::parse(target_url) {
        Ok(u) => u,
        Err(_) => {
            dead_letter(
                &state.base.db,
                delivery.id,
                kind,
                Why::BadUrl,
                "target url no longer parses",
            )
            .await?;
            return Ok(());
        }
    };

    // AB6-T5: an open breaker defers the delivery before it is counted.
    let breaker = endpoint(delivery.subscription_ref, &url);
    if defer_if_open(&state.base.db, delivery.id, &breaker).await? {
        return Ok(());
    }
    // M13-T3: an ordered subscription sends one record's events one at a
    // time: this waits while an earlier one of the same record is open.
    if sub.ordered && earlier_open(&state.base.db, &delivery).await? {
        attome_jobs::enqueue_at_on_pool(
            &state.base.db,
            attome_core::jobs::EngineJob::EventsDeliverWebhook {
                delivery_id: delivery.id,
            },
            Utc::now() + chrono::Duration::seconds(ORDERED_RECHECK_SECS),
        )
        .await
        .map_err(AppError::internal)?;
        return Ok(());
    }

    // Every call here is one apalis attempt — see this module's doc comment
    // for why that keeps this counter and apalis's own `Attempt` in lockstep.
    let attempts = mark_attempt(&state.base.db, delivery.id).await?;
    if attempts > sub.max_attempts {
        dead_letter(
            &state.base.db,
            delivery.id,
            kind,
            Why::AttemptsExhausted,
            "attempts exhausted (subscription max_attempts)",
        )
        .await?;
        return Ok(());
    }

    if attome_server::ssrf_guard::validate_url(&url).await.is_err() {
        dead_letter(
            &state.base.db,
            delivery.id,
            kind,
            Why::SsrfRejected,
            "target rejected by SSRF guard at send time",
        )
        .await?;
        return Ok(());
    }

    let ring = state.base.secrets.load().webhook_signing_key.clone();
    let secret =
        crypto::decrypt_webhook_secret(&ring, delivery.subscription_ref, secret_encrypted)?;

    // M19 gap list: `kind = 'audit'` deliveries carry the raw audit header
    // (`build_audit_body`), not an owner-scoped entity-record projection —
    // `event_entity_logicalname` is `audit_dispatch::create_delivery_row`'s
    // sentinel `"audit_header"` for this source. Every `kind = 'audit'`
    // subscription can only have been created via `POST
    // /api/v1/admin/events/subscriptions` (`Authorized<Admin>`), and this
    // codebase's established convention is that an admin-only surface skips
    // per-owner scoping by design, not by gap (security-model skill: "…
    // require system.admin on every route including reads — a scope
    // choice, not a gap") — the same posture `attome_audit::admin::search`/
    // `export` already take over this exact ledger. `owner_ref` still
    // gates ordinary `kind = 'webhook'` deliveries below exactly as before
    // (M62 plan §5 "a subscription must never be a permission bypass") —
    // this branch does not weaken that for any entity-change subscription.
    let body_bytes = if sub.kind == "audit" {
        let body = build_audit_body(&state.base.db, &delivery).await?;
        serde_json::to_vec(&body).map_err(AppError::internal)?
    } else {
        // M62 plan §5 "Security": the payload's `data` is scoped to
        // whatever the subscription owner may currently read, never a
        // permission bypass.
        let owner_ctx = state.base.security.resolve(sub.owner_ref).await?;
        let read_pool = state.base.read_pool(sub.owner_ref).await;
        let shape = crate::payload::PayloadShape::from_stored(&sub.payload_shape);
        let mut body = build_body(read_pool, &owner_ctx, &delivery, shape).await?;
        // L1-T7: a golden-record change names the subscriber's own id for it.
        if delivery.event_name.as_deref() == Some(crate::master::GOLDEN_CHANGED) {
            body["master"] = crate::master::block(
                &state.base.db,
                &delivery.event_entity_logicalname,
                delivery.event_record_id,
                sub.external_system.as_deref(),
            )
            .await?;
        }
        serde_json::to_vec(&body).map_err(AppError::internal)?
    };

    let now = Utc::now();
    let timestamp_ms = now.timestamp_millis().to_string();
    let signature = crypto::sign_header(&secret, &timestamp_ms, &body_bytes)?;
    // M13-T2: the Standard Webhooks trio, keyed on the event id (also the
    // Idempotency-Key), so every retry of one event carries the same id.
    let standard_id = delivery.event_id.to_string();
    let standard_timestamp = now.timestamp().to_string();
    let standard_signature =
        crypto::sign_standard(&secret, &standard_id, &standard_timestamp, &body_bytes)?;
    let target_auth = match (&sub.target_auth_header, &sub.target_auth_value_encrypted) {
        (Some(name), Some(encrypted)) => Some((
            name.clone(),
            crypto::decrypt_target_auth(&ring, delivery.subscription_ref, encrypted)?,
        )),
        _ => None,
    };

    let client = attome_server::ssrf_guard::GuardedClient::new(15).map_err(AppError::internal)?;
    let Ok(request) = client.post(url) else {
        dead_letter(
            &state.base.db,
            delivery.id,
            kind,
            Why::SsrfRejected,
            "target rejected by SSRF guard at send time",
        )
        .await?;
        return Ok(());
    };
    let attempt_started = std::time::Instant::now();
    let request = request
        .header(crypto::SIGNATURE_HEADER, signature)
        .header(crypto::STANDARD_ID_HEADER, &standard_id)
        .header(crypto::STANDARD_TIMESTAMP_HEADER, standard_timestamp)
        .header(crypto::STANDARD_SIGNATURE_HEADER, standard_signature)
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", delivery.event_id.to_string());
    let request = match target_auth {
        Some((name, value)) => request.header(name, value),
        None => request,
    };
    let send_result = request.body(body_bytes).send().await;
    telemetry::attempt(kind, attempt_started.elapsed().as_secs_f64());
    breaker.breaker.record(match &send_result {
        Ok(resp) => !unwell(resp.status()),
        Err(_) => false,
    });

    match send_result {
        Ok(resp) if resp.status().is_success() => {
            let status_code = resp.status().as_u16() as i32;
            mark_delivered(&state.base.db, delivery.id, status_code).await?;
            // End to end: the dispatcher recorded the match at `created_at`.
            let waited = (Utc::now() - delivery.created_at).num_milliseconds().max(0);
            telemetry::delivered(kind, waited as f64 / 1000.0);
            Ok(())
        }
        Ok(resp) => {
            let status_code = resp.status().as_u16() as i32;
            let masked = format!("webhook target returned HTTP {status_code}");
            mark_failed(&state.base.db, delivery.id, Some(status_code), &masked).await?;
            pause_if_failing(state, &delivery, sub.owner_ref).await;
            if attempts < sub.max_attempts {
                telemetry::delivery_outcome(kind, telemetry::OUTCOME_FAILED);
            }
            if attempts >= sub.max_attempts {
                dead_letter(
                    &state.base.db,
                    delivery.id,
                    kind,
                    Why::AttemptsExhausted,
                    "attempts exhausted",
                )
                .await?;
                Ok(())
            } else {
                Err(AppError::internal(masked))
            }
        }
        Err(e) => {
            // Never log/persist the raw reqwest error — it can echo the
            // request URL including any query-string credentials an admin
            // mistakenly embedded (guidelines §6/§11).
            let masked = if e.is_timeout() {
                "webhook delivery timed out".to_string()
            } else if e.is_connect() {
                "webhook delivery could not connect".to_string()
            } else {
                "webhook delivery failed".to_string()
            };
            mark_failed(&state.base.db, delivery.id, None, &masked).await?;
            pause_if_failing(state, &delivery, sub.owner_ref).await;
            if attempts < sub.max_attempts {
                telemetry::delivery_outcome(kind, telemetry::OUTCOME_FAILED);
            }
            if attempts >= sub.max_attempts {
                dead_letter(
                    &state.base.db,
                    delivery.id,
                    kind,
                    Why::AttemptsExhausted,
                    "attempts exhausted",
                )
                .await?;
                Ok(())
            } else {
                Err(AppError::internal(masked))
            }
        }
    }
}

/// S2-T12: the body of every outbound webhook delivery, published as the
/// `WebhookPayload` schema under the document's `webhooks.entityChanged`.
/// An audit-stream subscription sends the same shape with `entity`
/// `audit_header` and the audit event as `data`.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct WebhookPayload {
    /// The event's id; also the `Idempotency-Key` header, the same on every
    /// retry of one event.
    pub event_id: Uuid,
    /// The changed record's entity logical name.
    pub entity: String,
    pub record_id: Uuid,
    /// `create`, `update`, `delete`, and the other entity change operations.
    pub operation: String,
    /// When the change was matched to the subscription.
    pub occurred_at: chrono::DateTime<Utc>,
    /// M13-T1: the named business event (`sla.breached`, `record.merged`),
    /// or `null` for an ordinary entity change.
    pub event_name: Option<String>,
    /// M13-T1: the attributes the write changed that the owner may read, on
    /// `changes` and `full` shapes; `null` on `id`, when the owner cannot
    /// read the record, or when the source did not record them.
    pub changed_attributes: Option<Vec<String>>,
    /// M13-T1, `changes` shape only: `{attribute: {old, new}}` for each
    /// changed attribute the owner may read; a sensitive value is
    /// `{"ref": true}`.
    #[schema(value_type = Option<Object>)]
    pub changes: Option<Value>,
    /// The record as the subscription's owner may read it now, or `null`
    /// when they cannot read it or it is gone. `full` shape only.
    #[schema(value_type = Option<Object>)]
    pub data: Option<Value>,
}

impl WebhookPayload {
    fn into_value(self) -> Result<Value, AppError> {
        serde_json::to_value(self).map_err(AppError::internal)
    }
}

async fn build_body(
    db: &DbPool,
    owner_ctx: &SecurityContext,
    delivery: &DeliveryRow,
    shape: crate::payload::PayloadShape,
) -> Result<Value, AppError> {
    use crate::payload::PayloadShape;
    let data = if shape == PayloadShape::Full {
        crate::payload::owner_scoped_record_data(
            db,
            owner_ctx,
            &delivery.event_entity_logicalname,
            delivery.event_record_id,
        )
        .await?
    } else {
        None
    };
    // The owner may not see which attributes changed on an entity it cannot
    // read, so the names are dropped with the values in that case.
    let (changed_attributes, changes) = match (shape, &delivery.changed_attributes) {
        (PayloadShape::Id, _) | (_, None) => (None, None),
        // Only the names of attributes the owner sees in `data`.
        (PayloadShape::Full, Some(names)) => (
            data.as_ref().and_then(Value::as_object).map(|row| {
                names
                    .iter()
                    .filter(|n| row.contains_key(n.as_str()))
                    .cloned()
                    .collect()
            }),
            None,
        ),
        (PayloadShape::Changes, Some(names)) => {
            let changes = crate::payload::owner_scoped_changes(
                db,
                owner_ctx,
                &delivery.event_entity_logicalname,
                names,
                delivery.changes_before.as_ref(),
                delivery.changes_after.as_ref(),
            )
            .await?;
            let visible = changes
                .as_ref()
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect());
            (visible, changes)
        }
    };
    WebhookPayload {
        event_id: delivery.event_id,
        entity: delivery.event_entity_logicalname.clone(),
        record_id: delivery.event_record_id,
        operation: delivery.event_operation.clone(),
        // The source outbox row (entity_change_event) may already
        // be pruned by the time this fires — the delivery row's own
        // created_at (when the dispatcher recorded the match) is the closest
        // durable timestamp available.
        occurred_at: delivery.created_at,
        event_name: delivery.event_name.clone(),
        changed_attributes,
        changes,
        data,
    }
    .into_value()
}

async fn load_delivery(db: &DbPool, delivery_id: Uuid) -> Result<Option<DeliveryRow>, AppError> {
    sqlx::query_as(
        "SELECT id, subscription_ref, event_id, event_entity_logicalname, event_record_id, \
                event_operation, status, created_at, event_name, changed_attributes, \
                changes_before, changes_after \
         FROM event_delivery WHERE id = $1",
    )
    .bind(delivery_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn load_subscription(
    db: &DbPool,
    subscription_id: Uuid,
) -> Result<Option<SubscriptionRow>, AppError> {
    sqlx::query_as(
        "SELECT kind, is_active, is_deleted, target_url, webhook_secret_encrypted, \
                max_attempts, owner_ref, payload_shape, target_auth_header, \
                target_auth_value_encrypted, ordered, external_system \
         FROM event_subscription WHERE id = $1",
    )
    .bind(subscription_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// M19 gap list — the `kind = 'audit'` payload builder. Reads
/// `audit_header` directly by id (`delivery.event_record_id`, which
/// `audit_dispatch::create_delivery_row` set to the header's own id) rather
/// than through `payload::owner_scoped_record_data` — see this function's
/// call site for why no owner-scoping applies here. `Ok(None)` `data` if
/// the header row is gone (partition archived/pruned since the event was
/// dispatched) — the delivery still carries `event_id`/`occurred_at` from
/// its own row regardless, same "still send the envelope, `data` can be
/// absent" shape `payload::owner_scoped_record_data`'s doc comment
/// describes for the entity case.
#[derive(sqlx::FromRow)]
struct AuditHeaderPayloadRow {
    id: Uuid,
    created_at: chrono::DateTime<Utc>,
    organization_ref: Uuid,
    category: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    operation: i32,
    user_id: Uuid,
    user_name: String,
    user_email: String,
    changed_on: chrono::DateTime<Utc>,
    correlation_id: Option<Uuid>,
    batch_id: Option<Uuid>,
    event_name: Option<String>,
    event_hash: String,
    prev_hash: Option<String>,
    signing_key_id: Option<String>,
}

async fn build_audit_body(db: &DbPool, delivery: &DeliveryRow) -> Result<Value, AppError> {
    let row: Option<AuditHeaderPayloadRow> = sqlx::query_as(
        "SELECT id, created_at, organization_ref, category, entity_name, record_id, \
                operation, user_id, user_name, user_email, changed_on, correlation_id, \
                batch_id, event_name, event_hash, prev_hash, signing_key_id \
         FROM audit_header WHERE id = $1 AND is_active = true",
    )
    .bind(delivery.event_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let data = row.map(|r| {
        json!({
            "id": r.id,
            "created_at": r.created_at,
            "organization_ref": r.organization_ref,
            "category": r.category,
            "entity_name": r.entity_name,
            "record_id": r.record_id,
            "operation": r.operation,
            "user_id": r.user_id,
            "user_name": r.user_name,
            "user_email": r.user_email,
            "changed_on": r.changed_on,
            "correlation_id": r.correlation_id,
            "batch_id": r.batch_id,
            "event_name": r.event_name,
            "event_hash": r.event_hash,
            "prev_hash": r.prev_hash,
            "signing_key_id": r.signing_key_id,
        })
    });

    WebhookPayload {
        event_id: delivery.event_id,
        entity: "audit_header".to_owned(),
        record_id: delivery.event_record_id,
        operation: delivery.event_operation.clone(),
        occurred_at: delivery.created_at,
        event_name: None,
        changed_attributes: None,
        changes: None,
        data,
    }
    .into_value()
}

async fn mark_attempt(db: &DbPool, delivery_id: Uuid) -> Result<i32, AppError> {
    sqlx::query_scalar(
        "UPDATE event_delivery \
            SET attempts = attempts + 1, status = 'delivering', \
                last_attempted_at = NOW(), updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 \
          RETURNING attempts",
    )
    .bind(delivery_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

async fn mark_delivered(
    db: &DbPool,
    delivery_id: Uuid,
    response_status: i32,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE event_delivery \
            SET status = 'delivered', response_status = $2, delivered_at = NOW(), \
                last_error = NULL, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(response_status)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_failed(
    db: &DbPool,
    delivery_id: Uuid,
    response_status: Option<i32>,
    masked_error: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE event_delivery \
            SET status = 'failed', response_status = $2, last_error = $3, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(response_status)
    .bind(masked_error)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn dead_letter(
    db: &DbPool,
    delivery_id: Uuid,
    kind: &'static str,
    why: Why,
    masked_reason: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE event_delivery \
            SET status = 'dead_letter', last_error = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(masked_reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    telemetry::dead_lettered(kind, why);
    tracing::warn!(%delivery_id, reason = masked_reason, "events delivery: dead-lettered");
    Ok(())
}
