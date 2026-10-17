//! Invoice requests and recurring schedules (roadmap F4-T9).
//!
//! Other features (a won order, a subscription charge, a project milestone)
//! do not write invoices; they ask for one.
//!
//! - `POST /api/v1/billing/invoice-requests` stores a request once per
//!   `(source_kind, idempotency_key)`: a repeat answers the stored request
//!   (and puts a failed one back in the queue), so a caller may retry
//!   freely.
//! - The `BillingRequestSweep` job (every five minutes, one at a time by its
//!   dedup key) turns pending requests into draft invoices, created as the
//!   person who asked through the generic record path. An account with
//!   `billing_group_invoices` gets one draft per currency and request date;
//!   otherwise each request is its own draft. A crash half way is safe to
//!   rerun: the draft is found again by its `idempotency_key`
//!   (`request:{first request id}`) and each line by its `source_ref`
//!   (`{request id}:{line index}`), so nothing is created twice. A request
//!   that cannot be turned into a draft (its requester is gone, a line is
//!   refused) is marked `failed` with the reason and skipped.
//! - The `BillingScheduleRun` job (daily) copies each enabled
//!   `invoice_schedule` whose `next_run` has come into a draft, as the
//!   schedule's creator, keyed `schedule:{id}:{next_run}` so a period never
//!   gives two drafts, then moves `next_run` on by one period. A schedule
//!   behind by several periods catches up one period per run.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{Months, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Requests taken per sweep batch.
const BATCH: i64 = 200;

/// Schedules taken per run.
const SCHEDULE_BATCH: i64 = 500;

/// One line of an invoice request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestLine {
    pub description: String,
    #[schema(value_type = f64)]
    pub quantity: serde_json::Number,
    #[schema(value_type = f64)]
    pub unit_price: serde_json::Number,
    /// `standard` (default), `reduced`, `zero_rated`, `exempt` or
    /// `out_of_scope`.
    pub vat_category: Option<String>,
    pub product_ref: Option<Uuid>,
    pub period_from: Option<NaiveDate>,
    pub period_to: Option<NaiveDate>,
}

/// An invoice another feature asks for.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct InvoiceRequest {
    /// What asked: `order`, `subscription`, `milestone`, …
    pub source_kind: String,
    /// The asking record's id or key.
    pub source_ref: String,
    /// Unique per `source_kind`; a repeat with the same key is the same
    /// request.
    pub idempotency_key: String,
    pub account_ref: Uuid,
    /// ISO 4217, three letters.
    pub currency: String,
    /// The day the charge belongs to (default today); grouped accounts get
    /// one invoice per currency and day.
    pub request_date: Option<NaiveDate>,
    pub lines: Vec<RequestLine>,
}

/// The stored request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RequestAccepted {
    pub request_id: Uuid,
    /// `pending`, `invoiced` or `failed`.
    pub status: String,
    pub invoice_id: Option<Uuid>,
    /// False when this was a repeat of a stored request.
    pub created: bool,
}

fn validate(req: &InvoiceRequest) -> Result<(), AppError> {
    for (name, value) in [
        ("source_kind", &req.source_kind),
        ("source_ref", &req.source_ref),
        ("idempotency_key", &req.idempotency_key),
    ] {
        if value.trim().is_empty() || value.len() > 200 {
            return Err(AppError::Validation(format!(
                "{name} is required (at most 200 characters)"
            )));
        }
    }
    if req.currency.len() != 3 || !req.currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(AppError::Validation(
            "currency is a three-letter ISO code".into(),
        ));
    }
    if req.lines.is_empty() || req.lines.len() > 500 {
        return Err(AppError::Validation(
            "a request has between 1 and 500 lines".into(),
        ));
    }
    for (i, line) in req.lines.iter().enumerate() {
        let qty: Decimal = line.quantity.to_string().parse().unwrap_or(Decimal::ZERO);
        let price: Option<Decimal> = line.unit_price.to_string().parse().ok();
        if line.description.trim().is_empty()
            || qty.is_zero()
            || price.is_none_or(|p| p < Decimal::ZERO)
        {
            return Err(AppError::Validation(format!(
                "line {i}: a description, a quantity other than zero and a price of zero or more"
            )));
        }
    }
    Ok(())
}

type StoredRow = (Uuid, String, Option<Uuid>);

/// Stores a request once per `(source_kind, idempotency_key)`.
pub async fn submit_request(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &InvoiceRequest,
) -> Result<RequestAccepted, AppError> {
    validate(req)?;
    let db = &state.base.db;
    let account: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account WHERE id = $1 \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(req.account_ref)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !account {
        return Err(AppError::Validation("account_ref names no account".into()));
    }
    let lines = serde_json::to_value(&req.lines).map_err(AppError::internal)?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO billing_invoice_request \
             (id, source_kind, source_ref, idempotency_key, account_ref, currency, \
              request_date, lines, requested_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (source_kind, idempotency_key) DO NOTHING \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(req.source_kind.trim())
    .bind(req.source_ref.trim())
    .bind(req.idempotency_key.trim())
    .bind(req.account_ref)
    .bind(&req.currency)
    .bind(req.request_date.unwrap_or_else(|| Utc::now().date_naive()))
    .bind(lines)
    .bind(ctx.user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = inserted {
        return Ok(RequestAccepted {
            request_id: id,
            status: "pending".into(),
            invoice_id: None,
            created: true,
        });
    }
    // A repeat: a failed request goes back in the queue; any other answers
    // as stored.
    let (id, status, invoice): StoredRow = sqlx::query_as(
        "UPDATE billing_invoice_request \
         SET status = CASE WHEN status = 'failed' THEN 'pending' ELSE status END, \
             error = CASE WHEN status = 'failed' THEN NULL ELSE error END \
         WHERE source_kind = $1 AND idempotency_key = $2 \
         RETURNING id, status, invoice_ref",
    )
    .bind(req.source_kind.trim())
    .bind(req.idempotency_key.trim())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(RequestAccepted {
        request_id: id,
        status,
        invoice_id: invoice,
        created: false,
    })
}

type PendingRow = (Uuid, Uuid, String, NaiveDate, Value, Option<Uuid>);

struct Pending {
    id: Uuid,
    account: Uuid,
    currency: String,
    date: NaiveDate,
    lines: Value,
    requested_by: Option<Uuid>,
}

/// Turns pending requests into draft invoices; returns the drafts made.
pub async fn process_pending(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let mut made = 0;
    let mut after: Option<Uuid> = None;
    loop {
        let rows: Vec<PendingRow> = sqlx::query_as(
            "SELECT id, account_ref, currency, request_date, lines, requested_by \
             FROM billing_invoice_request \
             WHERE status = 'pending' AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else {
            break;
        };
        after = Some(last.0);
        let pending: Vec<Pending> = rows
            .into_iter()
            .map(
                |(id, account, currency, date, lines, requested_by)| Pending {
                    id,
                    account,
                    currency,
                    date,
                    lines,
                    requested_by,
                },
            )
            .collect();
        let accounts: Vec<Uuid> = pending.iter().map(|p| p.account).collect();
        let grouped: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM account WHERE id = ANY($1) AND billing_group_invoices = true",
        )
        .bind(&accounts)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        // One draft per group: (account, currency, date) for grouping
        // accounts, the request itself otherwise. Requests keep id order.
        let mut groups: BTreeMap<(Uuid, String, NaiveDate, Option<Uuid>), Vec<&Pending>> =
            BTreeMap::new();
        for p in &pending {
            let alone = (!grouped.contains(&p.account)).then_some(p.id);
            groups
                .entry((p.account, p.currency.clone(), p.date, alone))
                .or_default()
                .push(p);
        }
        for members in groups.into_values() {
            match invoice_group(state, &members).await {
                Ok(invoice) => {
                    made += 1;
                    let ids: Vec<Uuid> = members.iter().map(|m| m.id).collect();
                    sqlx::query(
                        "UPDATE billing_invoice_request \
                         SET status = 'invoiced', invoice_ref = $2, error = NULL \
                         WHERE id = ANY($1) AND status = 'pending'",
                    )
                    .bind(&ids)
                    .bind(invoice)
                    .execute(db)
                    .await
                    .map_err(AppError::internal)?;
                }
                Err(e) => {
                    let ids: Vec<Uuid> = members.iter().map(|m| m.id).collect();
                    tracing::warn!(requests = ?ids, error = %e, "billing requests: a group could not be invoiced");
                    sqlx::query(
                        "UPDATE billing_invoice_request SET status = 'failed', error = $2 \
                         WHERE id = ANY($1) AND status = 'pending'",
                    )
                    .bind(&ids)
                    .bind(e.to_string())
                    .execute(db)
                    .await
                    .map_err(AppError::internal)?;
                }
            }
        }
    }
    Ok(made)
}

/// The draft of one group of requests (found again on a rerun).
async fn invoice_group(state: &EngineState, members: &[&Pending]) -> Result<Uuid, AppError> {
    let first = members
        .first()
        .ok_or_else(|| AppError::internal("an empty request group"))?;
    let requester = first
        .requested_by
        .ok_or_else(|| AppError::Validation("the request has no requester".into()))?;
    let ctx = state.base.security.resolve_strict(requester).await?;
    ctx.require("invoice", "create")?;
    ctx.require("invoice_line", "create")?;
    let key = format!("request:{}", first.id);
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM invoice WHERE idempotency_key = $1 \
           AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(&key)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let invoice = match existing {
        Some(id) => id,
        None => {
            let body = json!({
                "kind": "invoice",
                "status": "draft",
                "account_ref": first.account,
                "currency": first.currency,
                "supply_date": first.date,
                "idempotency_key": key,
            });
            attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                ctx.user_id,
                "invoice",
                body,
            )
            .await?
            .0
        }
    };
    let have: Vec<String> = sqlx::query_scalar(
        "SELECT source_ref FROM invoice_line \
         WHERE invoice_ref = $1 AND source_kind = 'request' AND source_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for member in members {
        let lines: Vec<RequestLine> = serde_json::from_value(member.lines.clone())
            .map_err(|e| AppError::Validation(format!("the stored lines no longer read: {e}")))?;
        for (i, line) in lines.iter().enumerate() {
            let source = format!("{}:{i}", member.id);
            if have.contains(&source) {
                continue;
            }
            let mut body = Map::new();
            body.insert("invoice_ref".into(), json!(invoice));
            body.insert("description".into(), json!(line.description.trim()));
            body.insert("quantity".into(), Value::Number(line.quantity.clone()));
            body.insert("unit_price".into(), Value::Number(line.unit_price.clone()));
            body.insert(
                "vat_category".into(),
                json!(line.vat_category.as_deref().unwrap_or("standard")),
            );
            body.insert("source_kind".into(), json!("request"));
            body.insert("source_ref".into(), json!(source));
            for (field, value) in [
                ("product_ref", line.product_ref.map(|p| json!(p))),
                ("period_from", line.period_from.map(|d| json!(d))),
                ("period_to", line.period_to.map(|d| json!(d))),
            ] {
                if let Some(value) = value {
                    body.insert(field.into(), value);
                }
            }
            attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                ctx.user_id,
                "invoice_line",
                Value::Object(body),
            )
            .await?;
        }
    }
    crate::invoice::recompute_draft(state, &ctx, invoice).await?;
    Ok(invoice)
}

/// The next run after `from` for a schedule's frequency.
pub fn next_run(from: NaiveDate, frequency: Option<&str>) -> Option<NaiveDate> {
    let months = match frequency.unwrap_or("monthly") {
        "quarterly" => 3,
        "yearly" => 12,
        _ => 1,
    };
    from.checked_add_months(Months::new(months))
}

type ScheduleRow = (Uuid, Uuid, Option<String>, NaiveDate, Option<Uuid>, i64);

/// Copies each due schedule's template into a draft; returns the drafts
/// made. One schedule failing is logged and the others still run.
pub async fn run_schedules(state: &EngineState) -> Result<u64, AppError> {
    let today = Utc::now().date_naive();
    let rows: Vec<ScheduleRow> = sqlx::query_as(
        "SELECT id, template_invoice_ref, frequency, next_run::date, created_by, row_version \
         FROM invoice_schedule \
         WHERE (is_active IS NULL OR is_active = true) AND COALESCE(is_enabled, true) \
           AND template_invoice_ref IS NOT NULL AND next_run::date <= $1 \
         ORDER BY next_run, id LIMIT $2",
    )
    .bind(today)
    .bind(SCHEDULE_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut made = 0;
    for (id, template, frequency, due, creator, version) in rows {
        match run_one(
            state,
            id,
            template,
            frequency.as_deref(),
            due,
            creator,
            version,
        )
        .await
        {
            Ok(true) => made += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(schedule = %id, error = %e, "billing schedules: a schedule could not run");
            }
        }
    }
    Ok(made)
}

async fn run_one(
    state: &EngineState,
    schedule: Uuid,
    template: Uuid,
    frequency: Option<&str>,
    due: NaiveDate,
    creator: Option<Uuid>,
    version: i64,
) -> Result<bool, AppError> {
    let creator =
        creator.ok_or_else(|| AppError::Validation("the schedule has no creator".into()))?;
    let ctx = state.base.security.resolve_strict(creator).await?;
    ctx.require("invoice_schedule", "update")?;
    let key = format!("schedule:{schedule}:{due}");
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM invoice WHERE idempotency_key = $1 \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&key)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let made = if existing {
        false
    } else {
        let mut extra = Map::new();
        extra.insert("kind".into(), json!("invoice"));
        extra.insert("idempotency_key".into(), json!(key));
        extra.insert("supply_date".into(), json!(due));
        crate::deposit::copy_as_draft(state, &ctx, template, extra).await?;
        true
    };
    let next = next_run(due, frequency)
        .ok_or_else(|| AppError::Validation("the next run is out of range".into()))?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        ctx.user_id,
        "invoice_schedule",
        schedule,
        version,
        json!({ "next_run": next }),
    )
    .await?;
    Ok(made)
}

/// The caller may ask for invoices: `billing.issue`, held by billing staff
/// and by the service accounts of features that bill.
#[utoipa::path(
    post,
    path = "/api/v1/billing/invoice-requests",
    tag = "billing",
    request_body = InvoiceRequest,
    responses(
        (status = 200, description = "The stored request (a repeat answers the first)", body = RequestAccepted),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not ask for invoices", body = attome_types::ErrorResponse),
        (status = 422, description = "A missing key, an unknown account, a bad currency or line", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_request(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<crate::issue::BillingIssue>,
    >,
    axum::Json(body): axum::Json<InvoiceRequest>,
) -> Result<axum::Json<RequestAccepted>, AppError> {
    Ok(axum::Json(submit_request(&state, &ctx, &body).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_request),
    components(schemas(RequestLine, InvoiceRequest, RequestAccepted))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_move_on_by_their_period() {
        let jan31 = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        assert_eq!(
            next_run(jan31, Some("monthly")),
            NaiveDate::from_ymd_opt(2026, 2, 28)
        );
        assert_eq!(
            next_run(jan31, Some("quarterly")),
            NaiveDate::from_ymd_opt(2026, 4, 30)
        );
        assert_eq!(
            next_run(jan31, Some("yearly")),
            NaiveDate::from_ymd_opt(2027, 1, 31)
        );
        assert_eq!(next_run(jan31, None), NaiveDate::from_ymd_opt(2026, 2, 28));
    }

    fn request(lines: Vec<RequestLine>) -> InvoiceRequest {
        InvoiceRequest {
            source_kind: "order".into(),
            source_ref: "SO-1".into(),
            idempotency_key: "SO-1".into(),
            account_ref: Uuid::now_v7(),
            currency: "SAR".into(),
            request_date: None,
            lines,
        }
    }

    fn line(qty: i64, price: i64) -> RequestLine {
        RequestLine {
            description: "Item".into(),
            quantity: qty.into(),
            unit_price: price.into(),
            vat_category: None,
            product_ref: None,
            period_from: None,
            period_to: None,
        }
    }

    #[test]
    fn a_request_is_checked_before_it_is_stored() {
        assert!(validate(&request(vec![line(1, 10)])).is_ok());
        assert!(validate(&request(vec![])).is_err());
        assert!(validate(&request(vec![line(0, 10)])).is_err());
        assert!(validate(&request(vec![line(1, -1)])).is_err());
        let mut bad = request(vec![line(1, 10)]);
        bad.currency = "sar".into();
        assert!(validate(&bad).is_err());
        let mut bad = request(vec![line(1, 10)]);
        bad.idempotency_key = " ".into();
        assert!(validate(&bad).is_err());
    }
}
