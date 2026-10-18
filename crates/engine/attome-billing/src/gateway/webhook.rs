//! Payment gateway webhooks (roadmap F5-T7):
//! `POST /api/v1/billing/gateways/{system}/webhook`.
//!
//! The caller is the gateway, with no session: the route is bypass-listed by
//! an exact segment-shape match
//! (`attome_server::middleware::bypass::is_billing_gateway_webhook_path`: one
//! `{system}` segment, then `webhook`, nothing after) and authenticates the
//! call itself, through the adapter's [`super::PaymentGateway::verify_webhook`]
//! with the secret in the system's credential (`webhook_secret`). It is still
//! behind the body limit, the pre-authentication rate limit and the billing
//! module's license gate, and adds a per-address limit of its own.
//!
//! The handler applies nothing: it stores each verified event once in
//! `billing_gateway_event` (unique per system and event key, so a
//! redelivered event is a no-op) and enqueues the
//! `BillingGatewayEventApply` job in the same transaction. The job
//! ([`apply_events`]) applies each unapplied event to its payment through
//! the payment service in one transaction with the event's `applied_at`, so
//! an event changes its payment once; a failure is stored on the event and
//! retried until [`MAX_ATTEMPTS`].

use attome_core::EngineState;
use attome_types::AppError;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{GatewayError, GatewayEvent, GatewayHttp, gateway_for};

/// The apply job's dedup key: one queued run at a time.
pub const APPLY_DEDUP_KEY: &str = "billing-gateway-event-apply";

/// How many times an event is tried before it waits for a person.
pub const MAX_ATTEMPTS: i32 = 10;

/// Events applied per job run.
const BATCH: i64 = 200;

/// Calls one address may make in a minute.
const RATE_LIMIT_PER_MINUTE: i32 = 600;

/// The largest webhook body read.
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookAccepted {
    /// Events the call carried.
    pub events: usize,
    /// Of those, new ones (the rest were delivered before).
    pub new: usize,
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/gateways/{system}/webhook",
    tag = "billing",
    params(("system" = Uuid, Path, description = "The payment_gateway integration system")),
    request_body(content = String, description = "The gateway's notification, as it sends it", content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "Verified and stored; applied by a job", body = WebhookAccepted),
        (status = 401, description = "The signature or secret does not verify", body = attome_types::ErrorResponse),
        (status = 404, description = "No such gateway, or billing is not licensed", body = attome_types::ErrorResponse),
        (status = 413, description = "The body is too large", body = attome_types::ErrorResponse),
        (status = 422, description = "A verified notification that does not read", body = attome_types::ErrorResponse),
        (status = 429, description = "Too many calls from this address", body = attome_types::ErrorResponse),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("BillingGatewayEventApply -> payment::service::apply_gateway_status_in_tx"),
        "unauthenticated gateway callback; the applied payment change is audited by the job",
    )))),
)]
pub(crate) async fn post_webhook(
    State(state): State<EngineState>,
    Path(system_id): Path<Uuid>,
    request: Request,
) -> Result<axum::response::Response, AppError> {
    let ip = attome_server::middleware::client_ip::client_ip(&request, &state.base.config)
        .map_or_else(
            || "unknown".to_owned(),
            |ip| attome_server::middleware::client_ip::rate_limit_subject(ip, 64),
        );
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &format!("attome-billing:rl:gateway-webhook:{ip}"),
        RATE_LIMIT_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
    };

    let system = super::system(&state, system_id).await?;
    let adapter = gateway_for(&system.adapter, GatewayHttp::new(&system.base_url)?)
        .ok_or(AppError::NotFound)?;
    let credential = super::credential(&state, &system).await?;
    let Some(secret) = super::webhook_secret(&credential) else {
        tracing::warn!(%system_id, "billing: a gateway webhook arrived but the gateway has no webhook_secret");
        return Err(AppError::Unauthorized);
    };
    let events = match adapter.verify_webhook(&headers, &body, &secret) {
        Ok(events) => events,
        Err(GatewayError::BadSignature) => {
            metrics::counter!("security_rejection_total", "reason" => "billing_gateway_webhook_signature")
                .increment(1);
            tracing::info!(%system_id, "billing: gateway webhook rejected: bad signature");
            return Err(AppError::Unauthorized);
        }
        Err(e) => return Err(e.into()),
    };
    let new = store_events(&state, system_id, &events).await?;
    Ok(axum::Json(WebhookAccepted {
        events: events.len(),
        new,
    })
    .into_response())
}

/// Stores the events once each and, when any is new, enqueues the apply job
/// in the same transaction.
pub async fn store_events(
    state: &EngineState,
    system_id: Uuid,
    events: &[GatewayEvent],
) -> Result<usize, AppError> {
    if events.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut new = 0;
    for event in events {
        let payload = serde_json::to_value(event).map_err(AppError::internal)?;
        let inserted = sqlx::query(
            "INSERT INTO billing_gateway_event (id, gateway_system_id, event_key, payload) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (gateway_system_id, event_key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(system_id)
        .bind(&event.event_id)
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        new += usize::try_from(inserted).unwrap_or(0);
    }
    if new > 0 {
        attome_jobs::enqueue_in_tx_dedup(
            &mut tx,
            attome_core::jobs::EngineJob::BillingGatewayEventApply,
            APPLY_DEDUP_KEY,
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(new)
}

type EventRow = (Uuid, Uuid, serde_json::Value);

/// Applies unapplied gateway events, each in its own transaction with its
/// `applied_at`; returns how many changed a payment. A failure is stored on
/// the event (and its attempt counted) for a later run.
pub async fn apply_events(state: &EngineState) -> Result<usize, AppError> {
    let mut changed = 0;
    let mut principals: std::collections::HashMap<Uuid, Uuid> = std::collections::HashMap::new();
    // Each event is tried at most once a run: a failing one waits for the
    // next run instead of spending its attempts here.
    let mut tried: Vec<Uuid> = Vec::new();
    for _ in 0..BATCH {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let row: Option<EventRow> = sqlx::query_as(
            "SELECT id, gateway_system_id, payload FROM billing_gateway_event \
             WHERE applied_at IS NULL AND attempts < $1 AND id <> ALL($2) \
             ORDER BY received_at, id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .bind(MAX_ATTEMPTS)
        .bind(&tried)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let Some((event_id, system_id, payload)) = row else {
            return Ok(changed);
        };
        tried.push(event_id);
        let actor = match principals.get(&system_id) {
            Some(actor) => *actor,
            None => {
                let actor = principal(state, system_id).await?;
                principals.insert(system_id, actor);
                actor
            }
        };
        let applied = match serde_json::from_value::<GatewayEvent>(payload) {
            Ok(event) => {
                // A savepoint, so a refused event still records its error in
                // this transaction.
                let mut inner = sqlx::Acquire::begin(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                match crate::payment::service::apply_gateway_status_in_tx(
                    &mut inner,
                    state,
                    system_id,
                    &event.gateway_reference,
                    &event.status,
                    actor,
                )
                .await
                {
                    Ok(did) => {
                        attome_db::tx::commit(inner).await?;
                        Ok(did)
                    }
                    Err(e) => {
                        inner.rollback().await.map_err(AppError::internal)?;
                        Err(e)
                    }
                }
            }
            Err(e) => Err(AppError::Validation(format!(
                "the stored event does not read: {e}"
            ))),
        };
        match applied {
            Ok(did) => {
                sqlx::query(
                    "UPDATE billing_gateway_event SET applied_at = now(), error = NULL, \
                         attempts = attempts + 1 WHERE id = $1",
                )
                .bind(event_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                changed += usize::from(did);
            }
            Err(e) => {
                let message: String = e.to_string().chars().take(500).collect();
                tracing::warn!(%event_id, %system_id, error = %message, "billing: a gateway event did not apply");
                sqlx::query(
                    "UPDATE billing_gateway_event SET error = $2, attempts = attempts + 1 \
                     WHERE id = $1",
                )
                .bind(event_id)
                .bind(&message)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
        }
        attome_db::tx::commit(tx).await?;
    }
    Ok(changed)
}

/// The user a gateway system acts as (its service principal), for the
/// payment's audit trail; the nil id when the system has none.
async fn principal(state: &EngineState, system_id: Uuid) -> Result<Uuid, AppError> {
    let principal: Option<Option<String>> = sqlx::query_scalar(
        "SELECT service_principal_ref::text FROM integration_system WHERE id = $1",
    )
    .bind(system_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(principal
        .flatten()
        .and_then(|p| Uuid::parse_str(p.trim()).ok())
        .unwrap_or_else(Uuid::nil))
}

/// This module's routes, for the OpenAPI document.
#[derive(Debug, utoipa::OpenApi)]
#[openapi(paths(post_webhook), components(schemas(WebhookAccepted)))]
pub struct ApiDocFragment;
