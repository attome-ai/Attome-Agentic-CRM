//! Deposits and pro forma invoices (roadmap F4-T8).
//!
//! - A deposit invoice is issued like any invoice (its own `DEP` series).
//!   Applying it to a final draft adds one negative line per VAT category
//!   of the deposit (`Deposit DEP-2026-000001`, the deposit's net in that
//!   category), recording the deposit (`source_kind = 'deposit'`,
//!   `source_ref` = the deposit's id). A deposit is applied once: a second
//!   application, on any invoice that is not void, is refused with `409`,
//!   and issuing re-checks it under a per-deposit lock
//!   (`attome-billing/deposit:{id}`) so two finals racing past the first
//!   check cannot both be issued with it.
//! - A pro forma invoice never takes a tax number (issuing answers `409`).
//!   Converting copies it and its lines into a new draft invoice, which is
//!   then priced and issued as usual; the pro forma stays as it was.

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

const ISSUED_STATUSES: [&str; 4] = ["issued", "sent", "paid", "overdue"];

fn decimal(text: Option<&str>) -> Decimal {
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

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ApplyDepositRequest {
    pub deposit_invoice_id: Uuid,
}

/// The final invoice after a deposit was deducted.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DepositApplied {
    pub invoice_id: Uuid,
    pub deposit_invoice_id: Uuid,
    /// Lines added, one per VAT category of the deposit.
    pub lines: usize,
    pub grand_total: String,
}

/// The new draft a pro forma invoice became.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ProFormaConverted {
    pub pro_forma_id: Uuid,
    pub invoice_id: Uuid,
    pub lines: usize,
}

type HeadRow = (
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

async fn head(state: &EngineState, id: Uuid) -> Result<HeadRow, AppError> {
    sqlx::query_as(
        "SELECT status, kind, account_ref, currency, invoice_number FROM invoice \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Whether `deposit` is already deducted on an invoice other than
/// `except` that is not void.
async fn applied_elsewhere<'e, E>(db: E, deposit: Uuid, except: Uuid) -> Result<bool, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM invoice_line l JOIN invoice i ON i.id = l.invoice_ref \
         WHERE l.source_kind = 'deposit' AND l.source_ref = $1 AND i.id <> $2 \
           AND COALESCE(i.status, 'draft') <> 'void' \
           AND (l.is_active IS NULL OR l.is_active = true) \
           AND (i.is_active IS NULL OR i.is_active = true))",
    )
    .bind(deposit.to_string())
    .bind(except)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Deducts an issued deposit invoice from a final draft.
pub async fn apply_deposit(
    state: &EngineState,
    ctx: &SecurityContext,
    final_id: Uuid,
    deposit_id: Uuid,
) -> Result<DepositApplied, AppError> {
    ctx.require("invoice_line", "create")?;
    let (status, kind, account, currency, _) = head(state, final_id).await?;
    if status.as_deref().unwrap_or("draft") != "draft" {
        return Err(AppError::Conflict(
            "a deposit is deducted on a draft invoice",
        ));
    }
    if kind.as_deref().unwrap_or("invoice") != "invoice" {
        return Err(AppError::Conflict(
            "a deposit is deducted on a final invoice",
        ));
    }
    let (d_status, d_kind, d_account, d_currency, d_number) = head(state, deposit_id).await?;
    if d_kind.as_deref() != Some("deposit") {
        return Err(AppError::Validation("that invoice is not a deposit".into()));
    }
    if !ISSUED_STATUSES.contains(&d_status.as_deref().unwrap_or("draft")) {
        return Err(AppError::Conflict("only an issued deposit is deducted"));
    }
    if d_account != account || d_currency != currency {
        return Err(AppError::Validation(
            "the deposit belongs to another account or currency".into(),
        ));
    }
    let on_this: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM invoice_line WHERE invoice_ref = $1 \
           AND source_kind = 'deposit' AND source_ref = $2 \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(final_id)
    .bind(deposit_id.to_string())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if on_this || applied_elsewhere(&state.base.db, deposit_id, final_id).await? {
        return Err(AppError::Conflict("the deposit is already deducted"));
    }
    // The deposit's net per VAT category (net = total less VAT).
    let nets: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT vat_category, SUM(COALESCE(line_total, 0) - COALESCE(vat_amount, 0))::text \
         FROM invoice_line \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) \
         GROUP BY vat_category ORDER BY vat_category",
    )
    .bind(deposit_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let label = format!("Deposit {}", d_number.unwrap_or_default());
    let mut added = 0;
    for (category, net) in nets {
        let net = decimal(net.as_deref());
        if net.is_zero() {
            continue;
        }
        let mut body = Map::new();
        body.insert("invoice_ref".into(), json!(final_id));
        body.insert("description".into(), json!(label.trim()));
        body.insert("quantity".into(), json!(-1));
        body.insert("unit_price".into(), number(net));
        body.insert(
            "vat_category".into(),
            json!(category.unwrap_or_else(|| "standard".into())),
        );
        body.insert("source_kind".into(), json!("deposit"));
        body.insert("source_ref".into(), json!(deposit_id.to_string()));
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "invoice_line",
            Value::Object(body),
        )
        .await?;
        added += 1;
    }
    let totals = crate::invoice::recompute_draft(state, ctx, final_id).await?;
    Ok(DepositApplied {
        invoice_id: final_id,
        deposit_invoice_id: deposit_id,
        lines: added,
        grand_total: totals.grand_total,
    })
}

/// Under the issue transaction: takes each deducted deposit's lock and
/// refuses issuing when another live invoice already carries it.
pub(crate) async fn check_deposits(
    tx: &mut attome_db::Tx<'_>,
    invoice: Uuid,
) -> Result<(), AppError> {
    let deposits: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT source_ref FROM invoice_line \
         WHERE invoice_ref = $1 AND source_kind = 'deposit' AND source_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY source_ref",
    )
    .bind(invoice)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for deposit in deposits {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-billing/deposit:{deposit}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict(
                "another invoice with this deposit is being issued; try again",
            ));
        }
        let used: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM invoice_line l JOIN invoice i ON i.id = l.invoice_ref \
             WHERE l.source_kind = 'deposit' AND l.source_ref = $1 AND i.id <> $2 \
               AND COALESCE(i.status, 'draft') NOT IN ('draft', 'void') \
               AND (l.is_active IS NULL OR l.is_active = true) \
               AND (i.is_active IS NULL OR i.is_active = true))",
        )
        .bind(&deposit)
        .bind(invoice)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if used {
            return Err(AppError::Conflict(
                "a deposit on this invoice is already deducted on an issued invoice",
            ));
        }
    }
    Ok(())
}

type ProFormaRow = (
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

type CopyLineRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Copies a pro forma invoice into a new draft invoice.
pub async fn convert_pro_forma(
    state: &EngineState,
    ctx: &SecurityContext,
    pro_forma_id: Uuid,
) -> Result<ProFormaConverted, AppError> {
    let kind: Option<Option<String>> = sqlx::query_scalar(
        "SELECT kind FROM invoice WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(pro_forma_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match kind {
        None => return Err(AppError::NotFound),
        Some(kind) if kind.as_deref() != Some("pro_forma") => {
            return Err(AppError::Conflict("only a pro forma invoice is converted"));
        }
        Some(_) => {}
    }
    let mut extra = Map::new();
    extra.insert("kind".into(), json!("invoice"));
    let (invoice, lines) = copy_as_draft(state, ctx, pro_forma_id, extra).await?;
    Ok(ProFormaConverted {
        pro_forma_id,
        invoice_id: invoice,
        lines,
    })
}

/// Copies an invoice's buyer, terms and lines into a new draft (as `ctx`,
/// through the generic record path), with `extra` fields set on the new
/// header, and prices it. Returns the draft and its line count.
pub(crate) async fn copy_as_draft(
    state: &EngineState,
    ctx: &SecurityContext,
    source_id: Uuid,
    extra: Map<String, Value>,
) -> Result<(Uuid, usize), AppError> {
    ctx.require("invoice", "create")?;
    ctx.require("invoice_line", "create")?;
    let row: Option<ProFormaRow> = sqlx::query_as(
        "SELECT kind, currency, account_ref, contact_ref, billing_address, buyer_vat_number,                 language, payment_terms_days::text, supply_date::text          FROM invoice WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(source_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((kind, currency, account, contact, address, vat, language, terms, supply)) = row
    else {
        return Err(AppError::NotFound);
    };
    let mut body = Map::new();
    body.insert(
        "kind".into(),
        json!(kind.unwrap_or_else(|| "invoice".into())),
    );
    body.insert("status".into(), json!("draft"));
    for (field, value) in [
        ("currency", currency.map(Value::String)),
        ("account_ref", account.map(|a| json!(a))),
        ("contact_ref", contact.map(|c| json!(c))),
        ("billing_address", address.map(Value::String)),
        ("buyer_vat_number", vat.map(Value::String)),
        ("language", language.map(Value::String)),
        ("supply_date", supply.map(Value::String)),
        (
            "payment_terms_days",
            terms.map(|t| number(decimal(Some(&t)))),
        ),
    ] {
        if let Some(value) = value {
            body.insert(field.into(), value);
        }
    }
    body.extend(extra);
    let (invoice, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "invoice",
        Value::Object(body),
    )
    .await?;
    let lines: Vec<CopyLineRow> = sqlx::query_as(
        "SELECT description, product_ref, unit, quantity::text, unit_price::text,                 discount::text, vat_category          FROM invoice_line          WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true)          ORDER BY id",
    )
    .bind(source_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let count = lines.len();
    for (description, product, unit, qty, price, discount, category) in lines {
        let mut body = Map::new();
        body.insert("invoice_ref".into(), json!(invoice));
        body.insert("description".into(), json!(description.unwrap_or_default()));
        body.insert("quantity".into(), number(decimal(qty.as_deref())));
        body.insert("unit_price".into(), number(decimal(price.as_deref())));
        body.insert("discount".into(), number(decimal(discount.as_deref())));
        body.insert(
            "vat_category".into(),
            json!(category.unwrap_or_else(|| "standard".into())),
        );
        if let Some(product) = product {
            body.insert("product_ref".into(), json!(product));
        }
        if let Some(unit) = unit {
            body.insert("unit".into(), json!(unit));
        }
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "invoice_line",
            Value::Object(body),
        )
        .await?;
    }
    if count > 0 {
        crate::invoice::recompute_draft(state, ctx, invoice).await?;
    }
    Ok((invoice, count))
}

/// `invoice.create`: may create invoices.
#[derive(Debug)]
pub struct InvoiceCreate;

impl attome_server::authz::PrivilegeKey for InvoiceCreate {
    const KEY: &'static str = "invoice.create";
}

/// Apply a deposit to a final invoice
///
/// Adds one negative line per VAT category of an issued deposit invoice to a draft final invoice. A
/// deposit applies once; a second application is 409. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/apply-deposit",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The final draft invoice")),
    request_body = ApplyDepositRequest,
    responses(
        (status = 200, description = "The deposit is deducted and the draft repriced", body = DepositApplied),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not update invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice or deposit", body = attome_types::ErrorResponse),
        (status = 409, description = "Not a final draft, the deposit is not issued, or it is already deducted", body = attome_types::ErrorResponse),
        (status = 422, description = "Not a deposit, or another account or currency", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_apply_deposit(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<crate::invoice::InvoiceUpdate>,
    >,
    axum::extract::Path(final_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ApplyDepositRequest>,
) -> Result<axum::Json<DepositApplied>, AppError> {
    Ok(axum::Json(
        apply_deposit(&state, &ctx, final_id, body.deposit_invoice_id).await?,
    ))
}

/// Convert a pro forma invoice
///
/// Copies a pro forma invoice and its lines into a new draft invoice, which is then priced and issued
/// as usual; the pro forma stays as it was. Needs the invoice create privilege. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/convert-pro-forma",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The pro forma invoice")),
    responses(
        (status = 200, description = "The new draft invoice", body = ProFormaConverted),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not create invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "Not a pro forma invoice", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_convert_pro_forma(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<InvoiceCreate>>,
    axum::extract::Path(pro_forma_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<ProFormaConverted>, AppError> {
    Ok(axum::Json(
        convert_pro_forma(&state, &ctx, pro_forma_id).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_apply_deposit, post_convert_pro_forma),
    components(schemas(ApplyDepositRequest, DepositApplied, ProFormaConverted))
)]
pub(crate) struct ApiDocFragment;
