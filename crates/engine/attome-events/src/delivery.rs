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
        let body = build_body(read_pool, &owner_ctx, &delivery).await?;
        serde_json::to_vec(&body).map_err(AppError::internal)?
    };

    let timestamp_ms = Utc::now().timestamp_millis().to_string();
    let signature = crypto::sign_header(&secret, &timestamp_ms, &body_bytes)?;

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
    let send_result = request
        .header(crypto::SIGNATURE_HEADER, signature)
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", delivery.event_id.to_string())
        .body(body_bytes)
        .send()
        .await;
    telemetry::attempt(kind, attempt_started.elapsed().as_secs_f64());

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

async fn build_body(
    db: &DbPool,
    owner_ctx: &SecurityContext,
    delivery: &DeliveryRow,
) -> Result<Value, AppError> {
    let data = crate::payload::owner_scoped_record_data(
        db,
        owner_ctx,
        &delivery.event_entity_logicalname,
        delivery.event_record_id,
    )
    .await?;
    Ok(json!({
        "event_id": delivery.event_id,
        "entity": delivery.event_entity_logicalname,
        "record_id": delivery.event_record_id,
        "operation": delivery.event_operation,
        // The source outbox row (entity_change_event) may already
        // be pruned by the time this fires — the delivery row's own
        // created_at (when the dispatcher recorded the match) is the closest
        // durable timestamp available.
        "occurred_at": delivery.created_at,
        "data": data,
    }))
}

async fn load_delivery(db: &DbPool, delivery_id: Uuid) -> Result<Option<DeliveryRow>, AppError> {
    sqlx::query_as(
        "SELECT id, subscription_ref, event_id, event_entity_logicalname, event_record_id, \
                event_operation, status, created_at \
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
                max_attempts, owner_ref \
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

    Ok(json!({
        "event_id": delivery.event_id,
        "entity": "audit_header",
        "record_id": delivery.event_record_id,
        "operation": delivery.event_operation,
        "occurred_at": delivery.created_at,
        "data": data,
    }))
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
