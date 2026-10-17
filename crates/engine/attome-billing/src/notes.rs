//! Credit notes, debit notes and cancellation (roadmap F4-T7).
//!
//! An issued invoice never changes; every correction is a new document that
//! points at it (`original_invoice_ref`) and says why (`reason`).
//!
//! - A credit note copies chosen lines of the original with a negative
//!   quantity (and the line discount scaled to the credited part), each
//!   copy recording the line it credits (`source_kind = 'credit_of'`,
//!   `source_ref` = the original line). A line is never credited beyond its
//!   quantity less what earlier credit notes (drafts included) took: `422`
//!   naming the line. Issuing a credit note checks the same sum again under
//!   the credit-note series lock, counting issued notes only, so two drafts
//!   racing past the first check cannot both be issued.
//! - A debit note adds new positive lines (a charge the original missed).
//! - Cancelling is a full credit of whatever is still uncredited, issued at
//!   once through [`crate::issue::issue`] (so the issue approval threshold
//!   applies to it as to any document).
//!
//! Notes are created as drafts through the generic record path, so field
//! rules, audit and change events apply; their totals come from the tax
//! engine through [`crate::invoice::recompute_draft`].

use std::str::FromStr;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Statuses of an invoice that has been issued (and so may be corrected).
const ISSUED_STATUSES: [&str; 4] = ["issued", "sent", "paid", "overdue"];

/// One original line to credit, and how much of it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreditLine {
    pub line_id: Uuid,
    /// A positive quantity, at most what is still uncredited on the line.
    #[schema(value_type = f64)]
    pub quantity: serde_json::Number,
}

/// A new line on a debit note.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DebitLine {
    pub description: String,
    #[schema(value_type = f64)]
    pub quantity: serde_json::Number,
    #[schema(value_type = f64)]
    pub unit_price: serde_json::Number,
    /// `standard` (default), `reduced`, `zero_rated`, `exempt` or
    /// `out_of_scope`.
    pub vat_category: Option<String>,
    pub product_ref: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreditNoteRequest {
    pub lines: Vec<CreditLine>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DebitNoteRequest {
    pub lines: Vec<DebitLine>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CancelRequest {
    pub reason: String,
}

/// The note created (a draft), or, for a cancellation, how its issue went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct NoteCreated {
    pub note_id: Uuid,
    pub original_id: Uuid,
    pub kind: String,
    /// `draft`, `issued` or `pending_approval`.
    pub status: String,
    pub invoice_number: Option<String>,
    pub approval_id: Option<Uuid>,
}

fn decimal(n: &serde_json::Number) -> Result<Decimal, AppError> {
    Decimal::from_str(&n.to_string())
        .or_else(|_| Decimal::from_scientific(&n.to_string()))
        .map_err(|_| AppError::Validation(format!("{n} is not a decimal amount")))
}

fn opt_decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// A decimal as the JSON number the record write path expects.
fn number(value: Decimal) -> Value {
    use rust_decimal::prelude::ToPrimitive;
    value
        .to_f64()
        .and_then(serde_json::Number::from_f64)
        .map_or(Value::Null, Value::Number)
}

fn reason_of(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("a note needs a reason".into()));
    }
    Ok(reason.to_owned())
}

type OriginalRow = (
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

struct Original {
    account: Option<Uuid>,
    contact: Option<Uuid>,
    currency: Option<String>,
    billing_address: Option<String>,
    buyer_vat_number: Option<String>,
    language: Option<String>,
}

/// Reads an issued invoice that may be corrected.
async fn original(state: &EngineState, id: Uuid) -> Result<Original, AppError> {
    let row: Option<OriginalRow> = sqlx::query_as(
        "SELECT status, kind, account_ref, contact_ref, currency, billing_address, \
                buyer_vat_number, language \
         FROM invoice WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, kind, account, contact, currency, address, vat, language)) = row else {
        return Err(AppError::NotFound);
    };
    if !ISSUED_STATUSES.contains(&status.as_deref().unwrap_or("draft")) {
        return Err(AppError::Conflict("only an issued invoice is corrected"));
    }
    if matches!(kind.as_deref(), Some("credit_note" | "pro_forma")) {
        return Err(AppError::Conflict(
            "a credit note or pro forma invoice is not corrected by a note",
        ));
    }
    Ok(Original {
        account,
        contact,
        currency,
        billing_address: address,
        buyer_vat_number: vat,
        language,
    })
}

/// Creates the note's draft header through the generic record path.
async fn create_note(
    state: &EngineState,
    ctx: &SecurityContext,
    original_id: Uuid,
    head: &Original,
    kind: &str,
    reason: &str,
) -> Result<Uuid, AppError> {
    ctx.require("invoice", "create")?;
    ctx.require("invoice_line", "create")?;
    let mut body = Map::new();
    body.insert("kind".into(), json!(kind));
    body.insert("status".into(), json!("draft"));
    body.insert("original_invoice_ref".into(), json!(original_id));
    body.insert("reason".into(), json!(reason));
    body.insert("payment_terms_days".into(), json!(0));
    for (field, value) in [
        ("account_ref", head.account.map(|a| json!(a))),
        ("contact_ref", head.contact.map(|c| json!(c))),
        ("currency", head.currency.clone().map(Value::String)),
        (
            "billing_address",
            head.billing_address.clone().map(Value::String),
        ),
        (
            "buyer_vat_number",
            head.buyer_vat_number.clone().map(Value::String),
        ),
        ("language", head.language.clone().map(Value::String)),
    ] {
        if let Some(value) = value {
            body.insert(field.into(), value);
        }
    }
    let (id, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "invoice",
        Value::Object(body),
    )
    .await?;
    Ok(id)
}

async fn create_line(
    state: &EngineState,
    ctx: &SecurityContext,
    body: Map<String, Value>,
) -> Result<(), AppError> {
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "invoice_line",
        Value::Object(body),
    )
    .await?;
    Ok(())
}

type LineRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

struct OriginalLine {
    id: Uuid,
    description: Option<String>,
    product: Option<Uuid>,
    unit: Option<String>,
    quantity: Decimal,
    unit_price: Decimal,
    discount: Decimal,
    category: Option<String>,
    /// What earlier credit notes (drafts included, void excluded) took.
    credited: Decimal,
}

async fn original_lines(state: &EngineState, id: Uuid) -> Result<Vec<OriginalLine>, AppError> {
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT id, description, product_ref, unit, quantity::text, unit_price::text, \
                discount::text, vat_category \
         FROM invoice_line \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let credited: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT l.source_ref, SUM(-l.quantity)::text \
         FROM invoice_line l JOIN invoice n ON n.id = l.invoice_ref \
         WHERE n.original_invoice_ref = $1 AND n.kind = 'credit_note' \
           AND COALESCE(n.status, 'draft') <> 'void' \
           AND (n.is_active IS NULL OR n.is_active = true) \
           AND (l.is_active IS NULL OR l.is_active = true) \
           AND l.source_kind = 'credit_of' AND l.source_ref IS NOT NULL \
         GROUP BY l.source_ref",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(line, description, product, unit, qty, price, discount, category)| {
                let taken = credited
                    .iter()
                    .find(|(source, _)| *source == line.to_string())
                    .map(|(_, sum)| opt_decimal(sum.as_deref()))
                    .unwrap_or(Decimal::ZERO);
                OriginalLine {
                    id: line,
                    description,
                    product,
                    unit,
                    quantity: opt_decimal(qty.as_deref()),
                    unit_price: opt_decimal(price.as_deref()),
                    discount: opt_decimal(discount.as_deref()),
                    category,
                    credited: taken,
                }
            },
        )
        .collect())
}

/// The credit copy of `line` for `quantity` of it.
fn credit_copy(line: &OriginalLine, quantity: Decimal) -> Map<String, Value> {
    let share = if line.quantity.is_zero() {
        Decimal::ZERO
    } else {
        line.discount * quantity / line.quantity
    };
    let mut body = Map::new();
    body.insert(
        "description".into(),
        json!(line.description.clone().unwrap_or_default()),
    );
    body.insert("quantity".into(), number(-quantity));
    body.insert("unit_price".into(), number(line.unit_price));
    body.insert("discount".into(), number(-share.round_dp(6)));
    body.insert(
        "vat_category".into(),
        json!(line.category.clone().unwrap_or_else(|| "standard".into())),
    );
    body.insert("source_kind".into(), json!("credit_of"));
    body.insert("source_ref".into(), json!(line.id.to_string()));
    if let Some(product) = line.product {
        body.insert("product_ref".into(), json!(product));
    }
    if let Some(unit) = &line.unit {
        body.insert("unit".into(), json!(unit));
    }
    body
}

/// Checks each requested credit against what is left on its line.
fn plan_credit(
    lines: &[OriginalLine],
    requested: &[(Uuid, Decimal)],
) -> Result<Vec<(usize, Decimal)>, AppError> {
    if requested.is_empty() {
        return Err(AppError::Validation(
            "a credit note credits at least one line".into(),
        ));
    }
    let mut plan = Vec::with_capacity(requested.len());
    for (line_id, quantity) in requested {
        let Some(index) = lines.iter().position(|l| l.id == *line_id) else {
            return Err(AppError::Validation(format!(
                "line {line_id} is not on the original invoice"
            )));
        };
        if *quantity <= Decimal::ZERO {
            return Err(AppError::Validation(format!(
                "line {line_id}: credit a positive quantity"
            )));
        }
        let left = lines[index].quantity - lines[index].credited;
        let asked: Decimal = requested
            .iter()
            .filter(|(id, _)| id == line_id)
            .map(|(_, q)| *q)
            .sum();
        if asked > left {
            return Err(AppError::Validation(format!(
                "line {line_id}: {asked} is more than the {left} still uncredited"
            )));
        }
        plan.push((index, *quantity));
    }
    Ok(plan)
}

/// Creates a draft credit note for chosen lines of an issued invoice.
pub async fn create_credit_note(
    state: &EngineState,
    ctx: &SecurityContext,
    original_id: Uuid,
    lines: &[(Uuid, Decimal)],
    reason: &str,
) -> Result<NoteCreated, AppError> {
    let reason = reason_of(reason)?;
    let head = original(state, original_id).await?;
    let originals = original_lines(state, original_id).await?;
    let plan = plan_credit(&originals, lines)?;
    let note = create_note(state, ctx, original_id, &head, "credit_note", &reason).await?;
    for (index, quantity) in plan {
        let mut body = credit_copy(&originals[index], quantity);
        body.insert("invoice_ref".into(), json!(note));
        create_line(state, ctx, body).await?;
    }
    crate::invoice::recompute_draft(state, ctx, note).await?;
    Ok(NoteCreated {
        note_id: note,
        original_id,
        kind: "credit_note".into(),
        status: "draft".into(),
        invoice_number: None,
        approval_id: None,
    })
}

/// Creates a draft debit note with new charges against an issued invoice.
pub async fn create_debit_note(
    state: &EngineState,
    ctx: &SecurityContext,
    original_id: Uuid,
    lines: &[DebitLine],
    reason: &str,
) -> Result<NoteCreated, AppError> {
    let reason = reason_of(reason)?;
    if lines.is_empty() {
        return Err(AppError::Validation(
            "a debit note has at least one line".into(),
        ));
    }
    let mut bodies = Vec::with_capacity(lines.len());
    for line in lines {
        let quantity = decimal(&line.quantity)?;
        let price = decimal(&line.unit_price)?;
        if quantity <= Decimal::ZERO || price < Decimal::ZERO {
            return Err(AppError::Validation(
                "a debit note line has a positive quantity and price".into(),
            ));
        }
        if line.description.trim().is_empty() {
            return Err(AppError::Validation(
                "a debit note line needs a description".into(),
            ));
        }
        let mut body = Map::new();
        body.insert("description".into(), json!(line.description.trim()));
        body.insert("quantity".into(), number(quantity));
        body.insert("unit_price".into(), number(price));
        body.insert(
            "vat_category".into(),
            json!(line.vat_category.as_deref().unwrap_or("standard")),
        );
        if let Some(product) = line.product_ref {
            body.insert("product_ref".into(), json!(product));
        }
        bodies.push(body);
    }
    let head = original(state, original_id).await?;
    let note = create_note(state, ctx, original_id, &head, "debit_note", &reason).await?;
    for mut body in bodies {
        body.insert("invoice_ref".into(), json!(note));
        create_line(state, ctx, body).await?;
    }
    crate::invoice::recompute_draft(state, ctx, note).await?;
    Ok(NoteCreated {
        note_id: note,
        original_id,
        kind: "debit_note".into(),
        status: "draft".into(),
        invoice_number: None,
        approval_id: None,
    })
}

/// Cancels an issued invoice: a credit note for everything still
/// uncredited, issued at once.
pub async fn cancel(
    state: &EngineState,
    ctx: &SecurityContext,
    original_id: Uuid,
    reason: &str,
) -> Result<NoteCreated, AppError> {
    let reason = reason_of(reason)?;
    original(state, original_id).await?;
    let remaining: Vec<(Uuid, Decimal)> = original_lines(state, original_id)
        .await?
        .iter()
        .map(|l| (l.id, l.quantity - l.credited))
        .filter(|(_, left)| *left > Decimal::ZERO)
        .collect();
    if remaining.is_empty() {
        return Err(AppError::Conflict("the invoice is already fully credited"));
    }
    let draft = create_credit_note(state, ctx, original_id, &remaining, &reason).await?;
    let issued = crate::issue::issue(state, ctx, draft.note_id).await?;
    Ok(NoteCreated {
        status: issued.status,
        invoice_number: issued.invoice_number,
        approval_id: issued.approval_id,
        ..draft
    })
}

/// Under the credit-note series lock: refuses issuing `note` when, with the
/// credit notes already issued, it would credit a line beyond its quantity.
pub(crate) async fn check_issued_credit(
    tx: &mut attome_db::Tx<'_>,
    note: Uuid,
) -> Result<(), AppError> {
    let over: Option<String> = sqlx::query_scalar(
        "SELECT this.source_ref \
         FROM invoice_line this \
         JOIN invoice_line orig ON orig.id::text = this.source_ref \
         WHERE this.invoice_ref = $1 AND this.source_kind = 'credit_of' \
           AND (this.is_active IS NULL OR this.is_active = true) \
           AND orig.quantity + this.quantity + COALESCE(( \
                 SELECT SUM(l.quantity) FROM invoice_line l \
                 JOIN invoice n ON n.id = l.invoice_ref \
                 WHERE l.source_kind = 'credit_of' AND l.source_ref = this.source_ref \
                   AND n.id <> $1 AND n.kind = 'credit_note' \
                   AND COALESCE(n.status, 'draft') NOT IN ('draft', 'void') \
                   AND (l.is_active IS NULL OR l.is_active = true) \
                   AND (n.is_active IS NULL OR n.is_active = true)), 0) < 0 \
         LIMIT 1",
    )
    .bind(note)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    match over {
        Some(line) => Err(AppError::Validation(format!(
            "line {line} would be credited beyond its quantity by issued credit notes"
        ))),
        None => Ok(()),
    }
}

/// `billing.credit`: may create credit and debit notes and cancel invoices.
#[derive(Debug)]
pub struct BillingCredit;

impl attome_server::authz::PrivilegeKey for BillingCredit {
    const KEY: &'static str = "billing.credit";
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/credit-notes",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The issued invoice to credit")),
    request_body = CreditNoteRequest,
    responses(
        (status = 200, description = "The draft credit note", body = NoteCreated),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not credit invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "The invoice is not issued, or is itself a credit note", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason, an unknown line, or more than is left on a line", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_credit_note(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<BillingCredit>>,
    axum::extract::Path(original_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<CreditNoteRequest>,
) -> Result<axum::Json<NoteCreated>, AppError> {
    let lines = body
        .lines
        .iter()
        .map(|l| Ok((l.line_id, decimal(&l.quantity)?)))
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(axum::Json(
        create_credit_note(&state, &ctx, original_id, &lines, &body.reason).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/debit-notes",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The issued invoice the charge belongs to")),
    request_body = DebitNoteRequest,
    responses(
        (status = 200, description = "The draft debit note", body = NoteCreated),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not raise notes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "The invoice is not issued, or is a credit note", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason, no lines, or a line without a positive quantity", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_debit_note(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<BillingCredit>>,
    axum::extract::Path(original_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<DebitNoteRequest>,
) -> Result<axum::Json<NoteCreated>, AppError> {
    Ok(axum::Json(
        create_debit_note(&state, &ctx, original_id, &body.lines, &body.reason).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/cancel",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The issued invoice to cancel")),
    request_body = CancelRequest,
    responses(
        (status = 200, description = "The full credit note, issued or waiting for an approval", body = NoteCreated),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not cancel invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "Not issued, already fully credited, or the series is being issued", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_cancel(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<BillingCredit>>,
    axum::extract::Path(original_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<CancelRequest>,
) -> Result<axum::Json<NoteCreated>, AppError> {
    Ok(axum::Json(
        cancel(&state, &ctx, original_id, &body.reason).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_credit_note, post_debit_note, post_cancel),
    components(schemas(
        CreditLine,
        DebitLine,
        CreditNoteRequest,
        DebitNoteRequest,
        CancelRequest,
        NoteCreated
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn line(quantity: i64, credited: i64) -> OriginalLine {
        OriginalLine {
            id: Uuid::now_v7(),
            description: None,
            product: None,
            unit: None,
            quantity: Decimal::from(quantity),
            unit_price: Decimal::from(10),
            discount: Decimal::from(4),
            category: None,
            credited: Decimal::from(credited),
        }
    }

    #[test]
    fn a_line_is_never_credited_beyond_what_is_left() {
        let lines = vec![line(5, 2)];
        let id = lines[0].id;
        assert!(plan_credit(&lines, &[(id, Decimal::from(3))]).is_ok());
        assert!(plan_credit(&lines, &[(id, Decimal::from(4))]).is_err());
        // The same line twice counts both.
        assert!(plan_credit(&lines, &[(id, Decimal::from(2)), (id, Decimal::from(2))]).is_err());
        assert!(plan_credit(&lines, &[(Uuid::now_v7(), Decimal::ONE)]).is_err());
        assert!(plan_credit(&lines, &[(id, Decimal::ZERO)]).is_err());
        assert!(plan_credit(&lines, &[]).is_err());
    }

    #[test]
    fn a_credit_copy_negates_quantity_and_its_share_of_the_discount() {
        let original = line(4, 0);
        let copy = credit_copy(&original, Decimal::from(2));
        assert_eq!(copy["quantity"], json!(-2.0));
        assert_eq!(copy["discount"], json!(-2.0));
        assert_eq!(copy["source_kind"], json!("credit_of"));
        assert_eq!(copy["source_ref"], json!(original.id.to_string()));
    }

    #[test]
    fn a_note_needs_a_reason() {
        assert!(reason_of("  ").is_err());
        assert_eq!(reason_of(" wrong price ").unwrap(), "wrong price");
    }
}
