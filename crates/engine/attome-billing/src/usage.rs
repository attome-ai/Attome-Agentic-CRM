//! Metered usage ingest (roadmap F3-T7): `POST /api/v1/billing/usage` takes
//! up to [`MAX_BATCH`] usage records per call. Each record carries the
//! sender's idempotency key; a key already stored for the same subscription
//! line and time is ignored and counted as a duplicate, so a sender can
//! safely retry a whole batch. Accepted records also add to the daily total
//! per line and metric that rating reads.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most records one call may send.
pub const MAX_BATCH: usize = 1000;

/// `subscription_usage.write`: may send usage for any subscription line.
#[derive(Debug)]
pub struct UsageWrite;

impl PrivilegeKey for UsageWrite {
    const KEY: &'static str = "subscription_usage.write";
}

/// One usage record as the sender reports it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UsageIn {
    pub subscription_line_id: Uuid,
    /// What was used, such as `api_calls` or `storage_gb_hours`.
    pub metric: String,
    pub quantity: f64,
    pub occurred_at: DateTime<Utc>,
    /// The sender's key for this record; repeating it is harmless.
    pub idempotency_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UsageBatch {
    pub records: Vec<UsageIn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct IngestResult {
    pub accepted: u64,
    /// Records whose idempotency key was already stored.
    pub duplicates: u64,
}

/// Refuses an empty or oversized batch and records that cannot be rated.
pub fn validate_batch(records: &[UsageIn]) -> Result<(), String> {
    if records.is_empty() {
        return Err("send at least one usage record".into());
    }
    if records.len() > MAX_BATCH {
        return Err(format!("send at most {MAX_BATCH} usage records per call"));
    }
    for (i, r) in records.iter().enumerate() {
        if r.metric.trim().is_empty() || r.metric.len() > 100 {
            return Err(format!("record {i}: metric must be 1 to 100 characters"));
        }
        if r.idempotency_key.trim().is_empty() || r.idempotency_key.len() > 200 {
            return Err(format!(
                "record {i}: idempotency_key must be 1 to 200 characters"
            ));
        }
        if !r.quantity.is_finite() || r.quantity < 0.0 {
            return Err(format!(
                "record {i}: quantity must be a non-negative number"
            ));
        }
    }
    Ok(())
}

/// Stores `records` in `tx`: each new one, and its share of the daily total;
/// a repeated key is skipped. The caller has validated the batch.
pub async fn insert_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    records: &[UsageIn],
) -> Result<IngestResult, AppError> {
    let mut result = IngestResult {
        accepted: 0,
        duplicates: 0,
    };
    for r in records {
        let inserted = sqlx::query(
            "INSERT INTO billing_usage_record \
                 (id, subscription_line_id, metric, quantity, occurred_at, idempotency_key) \
             VALUES ($1, $2, $3, $4::float8::numeric, $5, $6) \
             ON CONFLICT (subscription_line_id, idempotency_key, occurred_at) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(r.subscription_line_id)
        .bind(r.metric.trim())
        .bind(r.quantity)
        .bind(r.occurred_at)
        .bind(r.idempotency_key.trim())
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.code().as_deref() == Some("23514"))
            {
                AppError::Validation(
                    "occurred_at is outside the months usage is accepted for".into(),
                )
            } else {
                AppError::internal(e)
            }
        })?
        .rows_affected();
        if inserted == 0 {
            result.duplicates += 1;
            continue;
        }
        result.accepted += 1;
        sqlx::query(
            "INSERT INTO billing_usage_daily (subscription_line_id, metric, day, quantity) \
             VALUES ($1, $2, ($3 AT TIME ZONE 'UTC')::date, $4::float8::numeric) \
             ON CONFLICT (subscription_line_id, metric, day) \
             DO UPDATE SET quantity = billing_usage_daily.quantity + EXCLUDED.quantity",
        )
        .bind(r.subscription_line_id)
        .bind(r.metric.trim())
        .bind(r.occurred_at)
        .bind(r.quantity)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(result)
}

/// Validates and stores one batch for `actor`, with a business event that
/// names how many records were accepted and how many were duplicates.
pub async fn ingest(
    state: &EngineState,
    actor: Uuid,
    records: Vec<UsageIn>,
) -> Result<IngestResult, AppError> {
    validate_batch(&records).map_err(AppError::Validation)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = insert_batch(&mut tx, &records).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "billing_usage_record",
            Uuid::now_v7(),
            AuditOperation::Create,
            "billing.usage_ingested",
            actor,
        )
        .comment(format!(
            "{} usage records accepted, {} duplicates ignored",
            result.accepted, result.duplicates
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/usage",
    tag = "billing",
    request_body = UsageBatch,
    responses(
        (status = 200, description = "Stored; repeated idempotency keys counted as duplicates", body = IngestResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks subscription_usage.write", body = ErrorResponse),
        (status = 422, description = "Empty batch, more than 1000 records, or an invalid record", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_usage(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<UsageWrite>>,
    Json(body): Json<UsageBatch>,
) -> Result<Json<IngestResult>, AppError> {
    Ok(Json(ingest(&state, ctx.user_id, body.records).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_usage),
    components(schemas(UsageIn, UsageBatch, IngestResult))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: &str) -> UsageIn {
        UsageIn {
            subscription_line_id: Uuid::from_u128(1),
            metric: "api_calls".into(),
            quantity: 3.0,
            occurred_at: Utc::now(),
            idempotency_key: key.into(),
        }
    }

    #[test]
    fn over_1000_records_is_rejected() {
        let batch: Vec<UsageIn> = (0..=MAX_BATCH).map(|i| record(&i.to_string())).collect();
        assert!(validate_batch(&batch).is_err());
        assert!(validate_batch(&batch[..MAX_BATCH]).is_ok());
        assert!(validate_batch(&[]).is_err());
    }

    #[test]
    fn bad_records_are_rejected() {
        let mut negative = record("a");
        negative.quantity = -1.0;
        assert!(validate_batch(&[negative]).is_err());
        let mut nan = record("b");
        nan.quantity = f64::NAN;
        assert!(validate_batch(&[nan]).is_err());
        assert!(validate_batch(&[record("  ")]).is_err());
    }
}
