//! I11-T2: what an inspected return line's disposition does.
//!
//! `POST /api/v1/service/returns/{id}/dispositions` acts on every line of
//! a received or inspected return (field-service pack 0002) whose
//! inspection is done and whose disposition is set, once per line:
//!
//! - **refund**: a draft credit note (billing, F4) for the line's quantity
//!   on the invoice line it names (`invoice_line_ref`, pack 0008), with the
//!   reason `Return {reference}, line {id}`;
//! - **restock**: a `return` stock movement (I6) of the line's quantity into
//!   the return's `restock_location`, referenced `return_line:{id}`;
//! - **replace**: a draft replacement order (sales, D10) for the account
//!   with the line's product and quantity at no charge, named
//!   `Replacement for {reference}, line {id}`;
//! - **repair**, **scrap**, **return_to_vendor**: recorded only.
//!
//! **Once per line.** Each line is worked under its own advisory lock
//! (`attome-service/return-disposition:{line}`) and its row lock, and
//! keeps what it made in `disposition_reference` (`credit_note:{id}`,
//! `stock_movement:{id}`, `order:{id}` or `recorded`) with `disposed_on`.
//! A line that already has one is answered as done. A restock writes its
//! movement and the reference in one transaction. A credit note or order
//! is made through the record engine as the caller (record rules, audit);
//! after a crash between that and the reference, the next run finds the
//! note by its reason (or the order by its name) and records it instead of
//! making a second.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The currency of a replacement order whose original order names none.
const DEFAULT_CURRENCY: &str = "SAR";
/// Lines one call works, at most.
const MAX_LINES: i64 = 500;

/// `return_request.update`: who may run dispositions.
#[derive(Debug)]
pub struct ReturnUpdate;

impl PrivilegeKey for ReturnUpdate {
    const KEY: &'static str = "return_request.update";
}

/// What a disposition does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Refund,
    Restock,
    Replace,
    /// Repair, scrap or return to vendor: recorded, nothing made.
    Record,
}

impl Disposition {
    /// The disposition of a `disposition` value. Pure.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "refund" => Some(Self::Refund),
            "restock" => Some(Self::Restock),
            "replace" => Some(Self::Replace),
            "repair" | "scrap" | "return_to_vendor" => Some(Self::Record),
            _ => None,
        }
    }
}

/// Whether a line is ready for its disposition: one is set and the
/// inspection is done. Pure.
pub fn line_ready(disposition: Option<&str>, inspection: Option<&str>) -> bool {
    disposition.is_some_and(|d| !d.is_empty())
        && inspection.is_some_and(|i| !i.is_empty() && i != "pending")
}

/// Whether the return may be acted on. Pure.
pub fn return_ready(status: Option<&str>) -> bool {
    matches!(status, Some("received" | "inspected"))
}

/// The credit note reason that finds a line's note again. Pure.
pub fn refund_reason(reference: &str, line: Uuid) -> String {
    format!("Return {reference}, line {line}")
}

/// The name that finds a line's replacement order again. Pure.
pub fn replacement_name(reference: &str, line: Uuid) -> String {
    format!("Replacement for {reference}, line {line}")
}

/// The advisory lock key of one line. Pure.
pub fn lock_key(line: Uuid) -> String {
    format!("attome-service/return-disposition:{line}")
}

/// One line's result.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DispositionOutcome {
    pub line_id: Uuid,
    pub disposition: Option<String>,
    /// `done` (acted now), `already_done`, `not_ready`, `busy` (another
    /// call holds the line) or `failed`.
    pub status: String,
    /// What the line made: `credit_note:{id}`, `stock_movement:{id}`,
    /// `order:{id}` or `recorded`.
    pub reference: Option<String>,
    pub error: Option<String>,
}

/// Every line's result.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DispositionRun {
    pub return_id: Uuid,
    pub lines: Vec<DispositionOutcome>,
}

/// `(reference, account, order, status, restock location)`.
type ReturnRow = (
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// `(id, product, quantity, disposition, inspection, reference, invoice line)`.
type LineRow = (
    Uuid,
    Option<Uuid>,
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

struct ReturnHead {
    id: Uuid,
    reference: String,
    account: Option<Uuid>,
    order: Option<Uuid>,
    restock_location: Option<String>,
}

/// Runs every ready line's disposition as `ctx`.
pub async fn run(
    state: &EngineState,
    ctx: &SecurityContext,
    return_id: Uuid,
) -> Result<DispositionRun, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'return_line' \
            AND column_name = 'disposition_reference')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Err(AppError::NotFound);
    }
    // The caller must see the return.
    attome_records::entity_crud::read_record(state, ctx, "return_request", return_id).await?;
    let head: Option<ReturnRow> = sqlx::query_as(
        "SELECT reference, account_ref, order_ref, status::text, restock_location \
           FROM return_request WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((reference, account, order, status, restock_location)) = head else {
        return Err(AppError::NotFound);
    };
    if !return_ready(status.as_deref()) {
        return Err(AppError::Conflict(
            "a return is acted on once it is received or inspected",
        ));
    }
    let head = ReturnHead {
        id: return_id,
        reference: reference.unwrap_or_else(|| return_id.to_string()),
        account,
        order,
        restock_location,
    };
    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT id, product_ref, quantity::float8, disposition::text, inspection_result::text, \
                disposition_reference, invoice_line_ref \
           FROM return_line \
          WHERE return_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $2",
    )
    .bind(return_id)
    .bind(MAX_LINES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let (id, _, _, disposition, inspection, done, _) = &line;
        let outcome =
            |status: &str, reference: Option<String>, error: Option<String>| DispositionOutcome {
                line_id: *id,
                disposition: disposition.clone(),
                status: status.to_owned(),
                reference,
                error,
            };
        if done.is_some() {
            out.push(outcome("already_done", done.clone(), None));
            continue;
        }
        if !line_ready(disposition.as_deref(), inspection.as_deref()) {
            out.push(outcome("not_ready", None, None));
            continue;
        }
        out.push(match act(state, ctx, &head, &line).await {
            Ok(Acted::Now(reference)) => outcome("done", Some(reference), None),
            Ok(Acted::Before(reference)) => outcome("already_done", Some(reference), None),
            Ok(Acted::Busy) => outcome("busy", None, None),
            Err(AppError::Validation(message)) => outcome("failed", None, Some(message)),
            Err(AppError::Conflict(message)) => outcome("failed", None, Some(message.to_owned())),
            Err(AppError::Forbidden) => outcome(
                "failed",
                None,
                Some("you may not make what this disposition needs".to_owned()),
            ),
            Err(error) => return Err(error),
        });
    }
    Ok(DispositionRun {
        return_id,
        lines: out,
    })
}

enum Acted {
    Now(String),
    Before(String),
    Busy,
}

async fn act(
    state: &EngineState,
    ctx: &SecurityContext,
    head: &ReturnHead,
    line: &LineRow,
) -> Result<Acted, AppError> {
    let (id, product, quantity, disposition, _, _, invoice_line) = line;
    let id = *id;
    let disposition = disposition
        .as_deref()
        .and_then(Disposition::parse)
        .ok_or_else(|| AppError::Validation(format!("line {id}: an unknown disposition")))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(id))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(Acted::Busy);
    }
    let current: Option<String> = sqlx::query_scalar(
        "SELECT disposition_reference FROM return_line WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(done) = current {
        return Ok(Acted::Before(done));
    }
    let quantity = quantity.filter(|q| q.is_finite() && *q > 0.0);
    let reference = match disposition {
        Disposition::Record => "recorded".to_owned(),
        Disposition::Restock => {
            let (Some(product), Some(quantity)) = (*product, quantity) else {
                return Err(AppError::Validation(format!(
                    "line {id}: a restock needs a product and a quantity"
                )));
            };
            let Some(location) = head
                .restock_location
                .as_deref()
                .filter(|l| !l.trim().is_empty())
            else {
                return Err(AppError::Validation(
                    "restock_location: name where returned stock goes".into(),
                ));
            };
            ctx.require("stock_movement", "create")?;
            let moved = crate::inventory::record_in_tx(
                &mut tx,
                &crate::inventory::NewMovement {
                    product_id: product,
                    location_code: location.to_owned(),
                    kind: "return".to_owned(),
                    quantity,
                    reference: Some(format!("return_line:{id}")),
                    serial_id: None,
                    lot_id: None,
                },
                Some(ctx.user_id),
                false,
            )
            .await?;
            format!("stock_movement:{}", moved.movement_id)
        }
        Disposition::Refund => {
            let (Some(invoice_line), Some(quantity)) = (*invoice_line, quantity) else {
                return Err(AppError::Validation(format!(
                    "line {id}: a refund needs the invoice line it credits and a quantity"
                )));
            };
            format!(
                "credit_note:{}",
                refund(state, ctx, head, id, invoice_line, quantity).await?
            )
        }
        Disposition::Replace => {
            let (Some(product), Some(quantity)) = (*product, quantity) else {
                return Err(AppError::Validation(format!(
                    "line {id}: a replacement needs a product and a quantity"
                )));
            };
            format!(
                "order:{}",
                replace(state, ctx, head, id, product, quantity).await?
            )
        }
    };
    sqlx::query(
        "UPDATE return_line SET disposition_reference = $2, disposed_on = CURRENT_DATE, \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND disposition_reference IS NULL",
    )
    .bind(id)
    .bind(&reference)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "return_line",
            id,
            attome_audit::AuditOperation::Update,
            "return.disposition_done",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Acted::Now(reference))
}

/// The line's credit note, found by its reason or made.
async fn refund(
    state: &EngineState,
    ctx: &SecurityContext,
    head: &ReturnHead,
    line: Uuid,
    invoice_line: Uuid,
    quantity: f64,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    let invoice: Option<Uuid> = sqlx::query_scalar(
        "SELECT invoice_ref FROM invoice_line \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_line)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let Some(invoice) = invoice else {
        return Err(AppError::Validation(format!(
            "line {line}: its invoice line is not found"
        )));
    };
    let reason = refund_reason(&head.reference, line);
    let earlier: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM invoice WHERE kind::text = 'credit_note' AND original_invoice_ref = $1 \
            AND reason = $2 AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(invoice)
    .bind(&reason)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(note) = earlier {
        return Ok(note);
    }
    let quantity = Decimal::from_f64_retain(quantity)
        .map(|q| q.round_dp(4))
        .ok_or_else(|| AppError::Validation(format!("line {line}: a quantity")))?;
    let created = attome_billing::notes::create_credit_note(
        state,
        ctx,
        invoice,
        &[(invoice_line, quantity)],
        &reason,
    )
    .await?;
    Ok(created.note_id)
}

/// The line's replacement order, found by its name or made.
async fn replace(
    state: &EngineState,
    ctx: &SecurityContext,
    head: &ReturnHead,
    line: Uuid,
    product: Uuid,
    quantity: f64,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    let Some(account) = head.account else {
        return Err(AppError::Validation(
            "account_ref: a replacement order needs the return's account".into(),
        ));
    };
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('\"order\"') IS NOT NULL AND to_regclass('order_line') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::Validation(
            "a replacement needs the sales orders (install the sales pack)".into(),
        ));
    }
    let name = replacement_name(&head.reference, line);
    let earlier: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM \"order\" WHERE name = $1 AND account_ref = $2 \
            AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(&name)
    .bind(account)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(order) = earlier {
        return Ok(order);
    }
    ctx.require("order", "create")?;
    ctx.require("order_line", "create")?;
    let currency: Option<String> = match head.order {
        Some(order) => sqlx::query_scalar("SELECT currency FROM \"order\" WHERE id = $1")
            .bind(order)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten(),
        None => None,
    };
    let (order, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "order",
        json!({
            "name": name,
            "account_ref": account,
            "currency": currency
                .map(|c| c.trim().to_ascii_uppercase())
                .filter(|c| c.len() == 3)
                .unwrap_or_else(|| DEFAULT_CURRENCY.to_owned()),
            "ordered_on": chrono::Utc::now().date_naive().to_string(),
            "status": "draft",
        }),
    )
    .await?;
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "order_line",
        json!({
            "order_ref": order,
            "product_ref": product,
            "quantity": quantity,
            "unit_price": 0,
            "line_total": 0,
        }),
    )
    .await?;
    tracing::info!(return_id = %head.id, %line, %order, "return: replacement order made");
    Ok(order)
}

#[utoipa::path(
    post,
    path = "/api/v1/service/returns/{id}/dispositions",
    operation_id = "post_return_dispositions",
    tag = "service",
    params(("id" = Uuid, Path, description = "The return request")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Each line's result", body = DispositionRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks return_request.update", body = ErrorResponse),
        (status = 404, description = "No such return, or returns are not installed", body = ErrorResponse),
        (status = 409, description = "The return is not received or inspected yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Runs the disposition of every inspected return line.
///
/// A refund makes a draft credit note on the line's invoice line, a
/// restock a return stock movement into the return's restock location,
/// and a replace a draft replacement order; repair, scrap and return to
/// vendor are recorded. Each line acts once: a repeat answers
/// `already_done` with what the line made.
async fn post_dispositions(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReturnUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DispositionRun>, AppError> {
    Ok(Json(run(&state, &ctx, id).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/service/returns/{id}/dispositions",
        post(post_dispositions),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_dispositions),
    components(schemas(DispositionOutcome, DispositionRun))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod return_disposition {
    use super::*;

    #[test]
    fn each_disposition_has_one_action() {
        assert_eq!(Disposition::parse("refund"), Some(Disposition::Refund));
        assert_eq!(Disposition::parse("restock"), Some(Disposition::Restock));
        assert_eq!(Disposition::parse("replace"), Some(Disposition::Replace));
        for recorded in ["repair", "scrap", "return_to_vendor"] {
            assert_eq!(Disposition::parse(recorded), Some(Disposition::Record));
        }
        assert_eq!(Disposition::parse("give_away"), None);
    }

    #[test]
    fn only_inspected_lines_of_a_received_return_are_acted_on() {
        assert!(line_ready(Some("refund"), Some("as_described")));
        assert!(!line_ready(Some("refund"), Some("pending")));
        assert!(!line_ready(Some("refund"), None));
        assert!(!line_ready(None, Some("as_described")));
        assert!(return_ready(Some("received")));
        assert!(return_ready(Some("inspected")));
        assert!(!return_ready(Some("requested")));
        assert!(!return_ready(Some("rejected")));
        assert!(!return_ready(None));
    }

    #[test]
    fn a_refund_finds_its_credit_note_again_by_a_fixed_reason() {
        let line = Uuid::from_u128(7);
        assert_eq!(refund_reason("RMA-1", line), refund_reason("RMA-1", line));
        assert_ne!(
            refund_reason("RMA-1", line),
            refund_reason("RMA-1", Uuid::from_u128(8)),
            "each line has its own note"
        );
        assert_eq!(
            replacement_name("RMA-1", line),
            format!("Replacement for RMA-1, line {line}")
        );
    }

    #[test]
    fn each_line_has_its_own_lock() {
        let a = lock_key(Uuid::from_u128(1));
        assert!(a.starts_with("attome-service/return-disposition:"));
        assert_ne!(a, lock_key(Uuid::from_u128(2)));
    }
}
