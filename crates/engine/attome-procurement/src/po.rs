//! W3-T2: requisition to purchase order, with budget commitment and
//! delegation-of-authority approvals.
//!
//! - **Submit** (`POST /api/v1/procurement/requisitions/{id}/submit`): the
//!   requisition's amount (its `estimated_total`, else the sum of its lines)
//!   is checked against its `budget_line_ref` ([`crate::budget::check`],
//!   under the line's `overspend`, block by default), the delegation of
//!   authority table (`procurement_doa_rule`, procurement pack 0002) picks
//!   the approvers by amount, category and the budget line's cost centre
//!   ([`pick_rule`]), and an approval with that plan opens
//!   ([`ACTION_REQUISITION_APPROVE`]). The requisition becomes `submitted`.
//! - **Approved**: the requisition becomes `approved` and its amount is
//!   **committed** on the budget line, in one transaction guarded on
//!   `submitted`, so a replay commits nothing twice.
//! - **Order** (`.../order`): an approved requisition makes a draft purchase
//!   order with its lines for its vendor (not one on hold); the commitment
//!   moves to the order and the requisition becomes `ordered`.
//! - **Cancel** (a requisition, `.../cancel`, or an order,
//!   `POST /api/v1/procurement/purchase-orders/{id}/cancel`): the commitment
//!   is **released** with the status change.
//! - **Change order** (`.../change`): a new total within the rule's
//!   `change_tolerance_pct` (10% when unset) of the approved total applies at
//!   once, moving the commitment by the difference; above it a re-approval
//!   opens ([`ACTION_PO_CHANGE`]) and the change applies once approved.
//!
//! Each step that moves money takes the record's advisory lock
//! (`attome-procurement/requisition:{id}` or `.../order:{id}`) and a row
//! lock, and checks the status it starts from, so retries are safe.

use std::str::FromStr;

use attome_approval::{ApprovalPlan, ApprovalStep, OnTimeout, StepExtras, StepMode};
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::budget::{BudgetCheck, BudgetLine, OverspendPolicy};

/// The approval a submitted requisition opens.
pub const ACTION_REQUISITION_APPROVE: &str = "procurement.requisition_approve";
/// The re-approval a change order above tolerance opens.
pub const ACTION_PO_CHANGE: &str = "procurement.po_change";
/// The tolerance when a rule names none, in percent.
pub const DEFAULT_TOLERANCE_PCT: i64 = 10;
/// The manager-of-requester approver token.
const MANAGER: &str = "position:manager_of_requester";
const REQUISITION: &str = "purchase_requisition";
const ORDER: &str = "purchase_order";

/// `purchase_requisition.update`: who submits, orders or cancels.
#[derive(Debug)]
pub struct RequisitionUpdate;

impl PrivilegeKey for RequisitionUpdate {
    const KEY: &'static str = "purchase_requisition.update";
}

/// `purchase_order.update`: who changes or cancels an order.
#[derive(Debug)]
pub struct OrderUpdate;

impl PrivilegeKey for OrderUpdate {
    const KEY: &'static str = "purchase_order.update";
}

/// One delegation-of-authority row.
#[derive(Debug, Clone, PartialEq)]
pub struct DoaRule {
    pub id: Uuid,
    pub min_amount: Option<Decimal>,
    pub max_amount: Option<Decimal>,
    pub category: Option<String>,
    pub cost_center: Option<Uuid>,
    pub approver: Option<Uuid>,
    pub second_approver: Option<Uuid>,
    pub manager_first: bool,
    pub tolerance_pct: Option<Decimal>,
    pub priority: i64,
}

impl DoaRule {
    fn matches(&self, amount: Decimal, category: Option<&str>, cost_center: Option<Uuid>) -> bool {
        self.min_amount.is_none_or(|m| amount >= m)
            && self.max_amount.is_none_or(|m| amount <= m)
            && self.category.as_deref().is_none_or(|c| {
                category.is_some_and(|have| have.trim().eq_ignore_ascii_case(c.trim()))
            })
            && self.cost_center.is_none_or(|c| cost_center == Some(c))
    }

    fn specificity(&self) -> u8 {
        u8::from(self.category.is_some()) + u8::from(self.cost_center.is_some())
    }
}

/// The rule that applies: among the rules that match, the most specific
/// (category and cost centre named), then the highest priority, then the
/// narrowest amount band. Pure.
pub fn pick_rule<'a>(
    rules: &'a [DoaRule],
    amount: Decimal,
    category: Option<&str>,
    cost_center: Option<Uuid>,
) -> Option<&'a DoaRule> {
    rules
        .iter()
        .filter(|r| r.matches(amount, category, cost_center))
        .max_by(|a, b| {
            a.specificity()
                .cmp(&b.specificity())
                .then(a.priority.cmp(&b.priority))
                .then_with(|| {
                    // A lower ceiling is narrower; no ceiling is the widest.
                    let ceil = |r: &DoaRule| r.max_amount.unwrap_or(Decimal::MAX);
                    ceil(b).cmp(&ceil(a))
                })
                .then(b.id.cmp(&a.id))
        })
}

fn step(approvers: Vec<String>) -> ApprovalStep {
    ApprovalStep {
        mode: StepMode::Any,
        threshold: None,
        approvers,
        sla_minutes: None,
        on_timeout: OnTimeout::Escalate,
        extras: StepExtras::default(),
    }
}

/// The approval plan a rule asks for: the requester's manager first when
/// the rule says so, then its approver, then its second approver. `None`
/// when the rule names nobody. Pure.
pub fn plan_for(rule: &DoaRule) -> Option<ApprovalPlan> {
    let mut steps = Vec::new();
    if rule.manager_first {
        steps.push(step(vec![MANAGER.to_owned()]));
    }
    for user in [rule.approver, rule.second_approver].into_iter().flatten() {
        steps.push(step(vec![format!("user:{user}")]));
    }
    (!steps.is_empty()).then_some(ApprovalPlan { steps })
}

/// Whether a change order needs approval again: it raises the total above
/// the approved total by more than `tolerance_pct`. A decrease never does.
/// Pure.
pub fn change_needs_approval(
    approved_total: Decimal,
    new_total: Decimal,
    tolerance_pct: Option<Decimal>,
) -> bool {
    let tolerance = tolerance_pct
        .filter(|t| *t >= Decimal::ZERO)
        .unwrap_or(Decimal::from(DEFAULT_TOLERANCE_PCT));
    new_total > approved_total + approved_total * tolerance / Decimal::from(100)
}

/// A budget line's overspend setting (`warn` or `block`, block when unset).
/// Pure.
pub fn overspend_policy(value: Option<&str>) -> OverspendPolicy {
    match value {
        Some("warn") => OverspendPolicy::Warn,
        _ => OverspendPolicy::Block,
    }
}

fn dec(value: Option<String>) -> Option<Decimal> {
    value.and_then(|v| Decimal::from_str(v.trim()).ok())
}

/// A decimal as a JSON number for the record engine.
fn number(d: Decimal) -> Value {
    d.to_string()
        .parse::<f64>()
        .ok()
        .and_then(serde_json::Number::from_f64)
        .map_or(Value::Null, Value::Number)
}

/// A numeric column read as text, as a JSON number (null when empty).
fn number_text(v: Option<String>) -> Value {
    dec(v).map_or(Value::Null, number)
}

fn lock_key(kind: &str, id: Uuid) -> String {
    format!("attome-procurement/{kind}:{id}")
}

async fn lock(tx: &mut attome_db::Tx<'_>, key: &str) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "this record is being changed by someone else",
        ))
    }
}

async fn installed(db: &attome_db::DbPool) -> Result<(), AppError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('procurement_doa_rule') IS NOT NULL \
            AND to_regclass('budget_line') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if ready {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// What a submit, order, cancel or change did.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProcurementStep {
    pub id: Uuid,
    pub status: String,
    /// The approval opened, when one was.
    pub approval_id: Option<Uuid>,
    /// The purchase order made by an order step.
    pub order_id: Option<Uuid>,
    /// The amount committed on the budget line after the step.
    pub committed: Option<String>,
    /// Set when the budget is over and the line only warns.
    pub budget_warning: Option<String>,
}

/// `(budget line id, amount, committed, actual, overspend, cost centre)`.
type BudgetRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

async fn budget_row(
    db: &attome_db::DbPool,
    line: Option<Uuid>,
) -> Result<Option<BudgetRow>, AppError> {
    let Some(line) = line else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT id, amount::text, committed::text, actual::text, overspend::text, cost_center_ref \
           FROM budget_line WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(line)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn rules(db: &attome_db::DbPool) -> Result<Vec<DoaRule>, AppError> {
    type Row = (
        Uuid,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<bool>,
        Option<String>,
        Option<f64>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, min_amount::text, max_amount::text, category, cost_center_ref, approver_ref, \
                second_approver_ref, manager_first, change_tolerance_pct::text, priority::float8 \
           FROM procurement_doa_rule WHERE (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, min, max, category, cost_center, approver, second, manager, tol, priority)| {
                DoaRule {
                    id,
                    min_amount: dec(min),
                    max_amount: dec(max),
                    category: category.filter(|c| !c.trim().is_empty()),
                    cost_center,
                    approver,
                    second_approver: second,
                    manager_first: manager.unwrap_or(false),
                    tolerance_pct: dec(tol),
                    priority: priority.unwrap_or(0.0) as i64,
                }
            },
        )
        .collect())
}

/// `(status, budget line, category, estimated total, vendor, currency,
/// committed)`.
type RequisitionRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// Reads the requisition; `row_lock` also takes its row lock (never when
/// the record engine updates the same row in this call: it would wait on
/// this transaction). `FOR NO KEY UPDATE` leaves the foreign-key checks of
/// new child rows unblocked.
async fn requisition_row(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
    row_lock: bool,
) -> Result<RequisitionRow, AppError> {
    let sql = if row_lock {
        "SELECT status::text, budget_line_ref, category, estimated_total::text, \
                suggested_vendor_ref, currency::text, committed_amount::text \
           FROM purchase_requisition \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR NO KEY UPDATE"
    } else {
        "SELECT status::text, budget_line_ref, category, estimated_total::text, \
                suggested_vendor_ref, currency::text, committed_amount::text \
           FROM purchase_requisition \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

async fn requisition_amount(
    db: &attome_db::DbPool,
    id: Uuid,
    estimated: Option<Decimal>,
) -> Result<Decimal, AppError> {
    if let Some(e) = estimated.filter(|e| *e > Decimal::ZERO) {
        return Ok(e);
    }
    let sum: Option<String> = sqlx::query_scalar(
        "SELECT SUM(COALESCE(line_total, quantity * unit_price, 0))::text \
           FROM purchase_requisition_line \
          WHERE requisition_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    dec(sum)
        .filter(|s| *s > Decimal::ZERO)
        .ok_or_else(|| AppError::Validation("a requisition needs an amount or lines".into()))
}

fn checked(row: &BudgetRow, amount: Decimal) -> BudgetCheck {
    let line = BudgetLine {
        amount: dec(row.1.clone()).unwrap_or_default(),
        commitments: dec(row.2.clone()).unwrap_or_default(),
        actuals: dec(row.3.clone()).unwrap_or_default(),
    };
    crate::budget::check(&line, amount, overspend_policy(row.4.as_deref()))
}

/// Moves the budget line's commitment by `delta` (negative releases).
async fn commit_budget(
    tx: &mut attome_db::Tx<'_>,
    line: Option<Uuid>,
    delta: Decimal,
) -> Result<Option<String>, AppError> {
    let Some(line) = line else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "UPDATE budget_line SET committed = COALESCE(committed, 0) + $2::numeric, \
             available = COALESCE(amount, 0) - (COALESCE(committed, 0) + $2::numeric) \
                         - COALESCE(actual, 0), \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 RETURNING committed::text",
    )
    .bind(line)
    .bind(delta.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

async fn business_event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    entity: &str,
    id: Uuid,
    what: &str,
    user: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity,
            id,
            attome_audit::AuditOperation::Update,
            what,
            user,
        ),
    )
    .await
    .map(|_| ())
}

/// A pending approval of this action on this record, if one is open.
async fn pending_approval(
    db: &attome_db::DbPool,
    action: &str,
    entity: &str,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM approval_request \
          WHERE action_type = $1 AND regarding_entity = $2 AND regarding_id = $3 \
            AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(action)
    .bind(entity)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Submits a draft requisition for approval.
pub async fn submit_requisition(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<ProcurementStep, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    let record = attome_records::entity_crud::read_record(state, ctx, REQUISITION, id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    lock(&mut tx, &lock_key("requisition", id)).await?;
    let (status, budget_line, category, estimated, _, _, _) =
        requisition_row(&mut tx, id, false).await?;
    if status.as_deref() == Some("submitted") {
        return Ok(ProcurementStep {
            id,
            status: "submitted".into(),
            approval_id: pending_approval(db, ACTION_REQUISITION_APPROVE, REQUISITION, id).await?,
            order_id: None,
            committed: None,
            budget_warning: None,
        });
    }
    if status.as_deref().is_some_and(|s| s != "draft") {
        return Err(AppError::Conflict("only a draft requisition is submitted"));
    }
    let amount = requisition_amount(db, id, dec(estimated)).await?;
    let budget = budget_row(db, budget_line).await?;
    let mut warning = None;
    if let Some(row) = &budget {
        match checked(row, amount) {
            BudgetCheck::Blocked { over_by } => {
                return Err(AppError::Validation(format!(
                    "budget_line_ref: this goes over the budget by {over_by}"
                )));
            }
            BudgetCheck::Warn { over_by } => {
                warning = Some(format!("over the budget by {over_by}"));
            }
            BudgetCheck::Within { .. } => {}
        }
    }
    let cost_center = budget.as_ref().and_then(|b| b.5);
    let rules = rules(db).await?;
    let rule = pick_rule(&rules, amount, category.as_deref(), cost_center).ok_or_else(|| {
        AppError::Validation(format!(
            "no delegation of authority rule covers {amount} for this category and cost centre"
        ))
    })?;
    let plan = plan_for(rule)
        .ok_or_else(|| AppError::Validation("the matching rule names no approver".into()))?;
    let approval = match pending_approval(db, ACTION_REQUISITION_APPROVE, REQUISITION, id).await? {
        // A submit that crashed after opening it: reuse it.
        Some(existing) => existing,
        None => {
            attome_audit::approval::gate_with_plan_regarding(
                state,
                ACTION_REQUISITION_APPROVE,
                json!({ "requisition_id": id, "amount": amount.to_string() }),
                ctx.user_id,
                plan,
                Some((REQUISITION, id)),
            )
            .await?
            .id
        }
    };
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        REQUISITION,
        id,
        record.row_version(),
        json!({ "status": "submitted", "approval_ref": approval.to_string() }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "submitted".into(),
        approval_id: Some(approval),
        order_id: None,
        committed: None,
        budget_warning: warning,
    })
}

/// The approval payload of a requisition.
#[derive(Debug, Clone, Deserialize)]
pub struct RequisitionApproval {
    pub requisition_id: Uuid,
    pub amount: String,
}

/// The approved requisition: approved and committed, once.
pub async fn do_requisition_approved(
    state: &EngineState,
    payload: &RequisitionApproval,
    approver: Uuid,
) -> Result<ProcurementStep, AppError> {
    let id = payload.requisition_id;
    let amount = Decimal::from_str(payload.amount.trim())
        .map_err(|_| AppError::internal("approval amount is not a number"))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, &lock_key("requisition", id)).await?;
    let line: Option<Option<Uuid>> = sqlx::query_scalar(
        "UPDATE purchase_requisition SET status = 'approved', committed_amount = $2::numeric, \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'submitted' RETURNING budget_line_ref",
    )
    .bind(id)
    .bind(amount.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(line) = line else {
        // Approved before, or cancelled meanwhile: nothing to commit.
        return Ok(ProcurementStep {
            id,
            status: "unchanged".into(),
            approval_id: None,
            order_id: None,
            committed: None,
            budget_warning: None,
        });
    };
    let committed = commit_budget(&mut tx, line, amount).await?;
    business_event(
        &mut tx,
        state,
        REQUISITION,
        id,
        "procurement.requisition_approved",
        approver,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "approved".into(),
        approval_id: None,
        order_id: None,
        committed,
        budget_warning: None,
    })
}

/// What to order.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct OrderBody {
    /// The vendor; the requisition's suggested vendor when absent.
    pub vendor_id: Option<Uuid>,
}

/// Turns an approved requisition into a draft purchase order.
pub async fn order_requisition(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: &OrderBody,
) -> Result<ProcurementStep, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    attome_records::entity_crud::read_record(state, ctx, REQUISITION, id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    lock(&mut tx, &lock_key("requisition", id)).await?;
    let (status, budget_line, _, estimated, suggested, currency, committed) =
        requisition_row(&mut tx, id, true).await?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM purchase_order WHERE requisition_ref = $1 \
            AND (is_active IS NULL OR is_active = true) ORDER BY created_at LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if status.as_deref() == Some("ordered") {
        return Ok(ProcurementStep {
            id,
            status: "ordered".into(),
            approval_id: None,
            order_id: existing,
            committed: None,
            budget_warning: None,
        });
    }
    if status.as_deref() != Some("approved") {
        return Err(AppError::Conflict(
            "only an approved requisition is ordered",
        ));
    }
    let vendor = body
        .vendor_id
        .or(suggested)
        .ok_or_else(|| AppError::Validation("vendor_id: name the vendor".into()))?;
    let held: Option<Option<bool>> = sqlx::query_scalar(
        "SELECT (to_jsonb(v)->>'on_hold')::boolean FROM vendor v \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(vendor)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    match held {
        None => return Err(AppError::Validation("vendor_id: no such vendor".into())),
        Some(Some(true)) => {
            return Err(AppError::Validation(
                "vendor_id: the vendor is on hold and takes no new orders".into(),
            ));
        }
        Some(_) => {}
    }
    ctx.require(ORDER, "create")?;
    ctx.require("purchase_order_line", "create")?;
    let amount = requisition_amount(db, id, dec(estimated)).await?;
    let committed = dec(committed).unwrap_or(amount);
    let order = match existing {
        // Made before a crash, not yet marked ordered: keep it.
        Some(order) => order,
        None => {
            let (order, _) = attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                ORDER,
                json!({
                    "vendor_ref": vendor,
                    "requisition_ref": id,
                    "buyer": ctx.user_id,
                    "order_date": chrono::Utc::now().date_naive().to_string(),
                    "currency": currency,
                    "net_total": number(amount),
                    "grand_total": number(amount),
                    "budget_line_ref": budget_line,
                    "committed_amount": number(committed),
                    "approved_total": number(amount),
                    "status": "draft",
                }),
            )
            .await?;
            type Line = (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            );
            let lines: Vec<Line> = sqlx::query_as(
                "SELECT item, sku, quantity::text, unit, unit_price::text, vat_rate::text, \
                        line_total::text \
                   FROM purchase_requisition_line \
                  WHERE requisition_ref = $1 AND (is_active IS NULL OR is_active = true) \
                  ORDER BY created_at, id",
            )
            .bind(id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            for (item, sku, quantity, unit, price, vat, total) in lines {
                attome_records::entity_crud::create_record_for(
                    state,
                    ctx,
                    ctx.user_id,
                    "purchase_order_line",
                    json!({
                        "order_ref": order,
                        "item": item,
                        "sku": sku,
                        "quantity": number_text(quantity),
                        "unit": unit,
                        "unit_price": number_text(price),
                        "vat_rate": number_text(vat),
                        "line_total": number_text(total),
                    }),
                )
                .await?;
            }
            order
        }
    };
    // The commitment moves from the requisition to the order.
    sqlx::query(
        "UPDATE purchase_requisition SET status = 'ordered', committed_amount = 0, \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'approved'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    business_event(
        &mut tx,
        state,
        REQUISITION,
        id,
        "procurement.requisition_ordered",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "ordered".into(),
        approval_id: None,
        order_id: Some(order),
        committed: Some(committed.to_string()),
        budget_warning: None,
    })
}

/// Cancels a requisition, releasing what it committed.
pub async fn cancel_requisition(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<ProcurementStep, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    attome_records::entity_crud::read_record(state, ctx, REQUISITION, id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    lock(&mut tx, &lock_key("requisition", id)).await?;
    let (status, budget_line, _, _, _, _, committed) = requisition_row(&mut tx, id, true).await?;
    match status.as_deref() {
        Some("cancelled") => {
            return Ok(ProcurementStep {
                id,
                status: "cancelled".into(),
                approval_id: None,
                order_id: None,
                committed: None,
                budget_warning: None,
            });
        }
        Some("draft" | "submitted" | "approved") | None => {}
        Some(_) => {
            return Err(AppError::Conflict(
                "an ordered requisition is cancelled through its purchase order",
            ));
        }
    }
    let release = dec(committed).unwrap_or_default();
    sqlx::query(
        "UPDATE purchase_requisition SET status = 'cancelled', committed_amount = 0, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let after = if release > Decimal::ZERO {
        commit_budget(&mut tx, budget_line, -release).await?
    } else {
        None
    };
    business_event(
        &mut tx,
        state,
        REQUISITION,
        id,
        "procurement.requisition_cancelled",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "cancelled".into(),
        approval_id: None,
        order_id: None,
        committed: after,
        budget_warning: None,
    })
}

/// `(status, budget line, committed, approved total, requisition)`.
type OrderRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

async fn order_row(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<OrderRow, AppError> {
    sqlx::query_as(
        "SELECT status::text, budget_line_ref, committed_amount::text, approved_total::text, \
                requisition_ref \
           FROM purchase_order WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
          FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Cancels a draft or issued order, releasing its commitment.
pub async fn cancel_order(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<ProcurementStep, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    attome_records::entity_crud::read_record(state, ctx, ORDER, id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    lock(&mut tx, &lock_key("order", id)).await?;
    let (status, budget_line, committed, _, _) = order_row(&mut tx, id).await?;
    match status.as_deref() {
        Some("cancelled") => {
            return Ok(ProcurementStep {
                id,
                status: "cancelled".into(),
                approval_id: None,
                order_id: Some(id),
                committed: None,
                budget_warning: None,
            });
        }
        Some("draft" | "issued") | None => {}
        Some(_) => return Err(AppError::Conflict("a received order is not cancelled")),
    }
    let release = dec(committed).unwrap_or_default();
    sqlx::query(
        "UPDATE purchase_order SET status = 'cancelled', committed_amount = 0, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let after = if release > Decimal::ZERO {
        commit_budget(&mut tx, budget_line, -release).await?
    } else {
        None
    };
    business_event(
        &mut tx,
        state,
        ORDER,
        id,
        "procurement.order_cancelled",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "cancelled".into(),
        approval_id: None,
        order_id: Some(id),
        committed: after,
        budget_warning: None,
    })
}

/// A change order.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangeBody {
    /// The order's new total, as a decimal string.
    pub new_total: String,
}

/// The re-approval payload of a change order.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangeApproval {
    pub order_id: Uuid,
    pub new_total: String,
}

async fn apply_change(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
    budget_line: Option<Uuid>,
    committed: Decimal,
    new_total: Decimal,
    approved: bool,
) -> Result<Option<String>, AppError> {
    sqlx::query(
        "UPDATE purchase_order SET grand_total = $2::numeric, committed_amount = $2::numeric, \
             approved_total = CASE WHEN $3 THEN $2::numeric ELSE approved_total END, \
             pending_total = NULL, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(new_total.to_string())
    .bind(approved)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    commit_budget(tx, budget_line, new_total - committed).await
}

/// Changes an order's total, re-approving above tolerance.
pub async fn change_order(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: &ChangeBody,
) -> Result<ProcurementStep, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    let new_total = Decimal::from_str(body.new_total.trim())
        .ok()
        .filter(|t| *t >= Decimal::ZERO)
        .ok_or_else(|| AppError::Validation("new_total: a number of zero or more".into()))?;
    attome_records::entity_crud::read_record(state, ctx, ORDER, id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    lock(&mut tx, &lock_key("order", id)).await?;
    let (status, budget_line, committed, approved_total, requisition) =
        order_row(&mut tx, id).await?;
    if !matches!(status.as_deref(), Some("draft" | "issued") | None) {
        return Err(AppError::Conflict(
            "only a draft or issued order is changed",
        ));
    }
    let committed = dec(committed).unwrap_or_default();
    let approved_total = dec(approved_total).unwrap_or(committed);
    let category: Option<String> = match requisition {
        Some(r) => sqlx::query_scalar("SELECT category FROM purchase_requisition WHERE id = $1")
            .bind(r)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .flatten(),
        None => None,
    };
    let budget = budget_row(db, budget_line).await?;
    let rules = rules(db).await?;
    let rule = pick_rule(
        &rules,
        new_total,
        category.as_deref(),
        budget.as_ref().and_then(|b| b.5),
    );
    if !change_needs_approval(
        approved_total,
        new_total,
        rule.and_then(|r| r.tolerance_pct),
    ) {
        let after = apply_change(&mut tx, id, budget_line, committed, new_total, false).await?;
        business_event(
            &mut tx,
            state,
            ORDER,
            id,
            "procurement.order_changed",
            ctx.user_id,
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        return Ok(ProcurementStep {
            id,
            status: "changed".into(),
            approval_id: None,
            order_id: Some(id),
            committed: after,
            budget_warning: None,
        });
    }
    if let Some(row) = &budget
        && let BudgetCheck::Blocked { over_by } = checked(row, new_total - committed)
    {
        return Err(AppError::Validation(format!(
            "new_total: this goes over the budget by {over_by}"
        )));
    }
    let plan = rule.and_then(plan_for).ok_or_else(|| {
        AppError::Validation(format!(
            "no delegation of authority rule covers {new_total} for this order"
        ))
    })?;
    let approval = attome_audit::approval::gate_with_plan_regarding(
        state,
        ACTION_PO_CHANGE,
        json!({ "order_id": id, "new_total": new_total.to_string() }),
        ctx.user_id,
        plan,
        Some((ORDER, id)),
    )
    .await?;
    sqlx::query(
        "UPDATE purchase_order SET pending_total = $2::numeric, change_approval_ref = $3, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(new_total.to_string())
    .bind(approval.id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "pending_approval".into(),
        approval_id: Some(approval.id),
        order_id: Some(id),
        committed: Some(committed.to_string()),
        budget_warning: None,
    })
}

/// `(status, pending total, budget line, committed)`.
type PendingChange = (Option<String>, Option<String>, Option<Uuid>, Option<String>);

/// The approved change order: applied once, if the order still waits for
/// exactly this change.
pub async fn do_po_change_approved(
    state: &EngineState,
    payload: &ChangeApproval,
    approver: Uuid,
) -> Result<ProcurementStep, AppError> {
    let id = payload.order_id;
    let new_total = Decimal::from_str(payload.new_total.trim())
        .map_err(|_| AppError::internal("approval total is not a number"))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, &lock_key("order", id)).await?;
    let pending: Option<PendingChange> = sqlx::query_as(
        "SELECT status::text, pending_total::text, budget_line_ref, committed_amount::text \
               FROM purchase_order WHERE id = $1 FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((status, pending_total, budget_line, committed)) = pending else {
        return Err(AppError::NotFound);
    };
    if dec(pending_total) != Some(new_total)
        || !matches!(status.as_deref(), Some("draft" | "issued"))
    {
        return Ok(ProcurementStep {
            id,
            status: "unchanged".into(),
            approval_id: None,
            order_id: Some(id),
            committed,
            budget_warning: None,
        });
    }
    let committed = dec(committed).unwrap_or_default();
    let after = apply_change(&mut tx, id, budget_line, committed, new_total, true).await?;
    business_event(
        &mut tx,
        state,
        ORDER,
        id,
        "procurement.order_change_approved",
        approver,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ProcurementStep {
        id,
        status: "changed".into(),
        approval_id: None,
        order_id: Some(id),
        committed: after,
        budget_warning: None,
    })
}

/// The approved-action payloads as JSON results, for the approval
/// dispatcher in `attome-api`.
pub async fn dispatch_approved(
    state: &EngineState,
    action_type: &str,
    payload: &Value,
    approver: Uuid,
) -> Result<Value, AppError> {
    let step = match action_type {
        ACTION_REQUISITION_APPROVE => {
            let p: RequisitionApproval =
                serde_json::from_value(payload.clone()).map_err(AppError::internal)?;
            do_requisition_approved(state, &p, approver).await?
        }
        ACTION_PO_CHANGE => {
            let p: ChangeApproval =
                serde_json::from_value(payload.clone()).map_err(AppError::internal)?;
            do_po_change_approved(state, &p, approver).await?
        }
        _ => return Err(AppError::internal("not a procurement approval")),
    };
    serde_json::to_value(&step).map_err(AppError::internal)
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/requisitions/{id}/submit",
    operation_id = "post_requisition_submit",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The record")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the step did", body = ProcurementStep),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or procurement budgets are not installed", body = ErrorResponse),
        (status = 409, description = "Not in a status this step starts from, or being changed", body = ErrorResponse),
        (status = 422, description = "Over budget, no rule or vendor, or a bad amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Submits a requisition for approval.
///
/// The budget line is checked and the delegation of authority table picks the approvers by amount, category and cost centre.
async fn post_submit(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RequisitionUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProcurementStep>, AppError> {
    Ok(Json(submit_requisition(&state, &ctx, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/requisitions/{id}/order",
    operation_id = "post_requisition_order",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The record")),
    request_body = OrderBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the step did", body = ProcurementStep),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or procurement budgets are not installed", body = ErrorResponse),
        (status = 409, description = "Not in a status this step starts from, or being changed", body = ErrorResponse),
        (status = 422, description = "Over budget, no rule or vendor, or a bad amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Turns an approved requisition into a draft purchase order.
///
/// The order copies the lines, the vendor must not be on hold, and the budget commitment moves to the order.
async fn post_order(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RequisitionUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<OrderBody>,
) -> Result<Json<ProcurementStep>, AppError> {
    Ok(Json(order_requisition(&state, &ctx, id, &body).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/requisitions/{id}/cancel",
    operation_id = "post_requisition_cancel",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The record")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the step did", body = ProcurementStep),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or procurement budgets are not installed", body = ErrorResponse),
        (status = 409, description = "Not in a status this step starts from, or being changed", body = ErrorResponse),
        (status = 422, description = "Over budget, no rule or vendor, or a bad amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Cancels a requisition.
///
/// What an approved requisition committed on its budget line is released with the status change.
async fn post_cancel_requisition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RequisitionUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProcurementStep>, AppError> {
    Ok(Json(cancel_requisition(&state, &ctx, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/purchase-orders/{id}/cancel",
    operation_id = "post_purchase_order_cancel",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The record")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the step did", body = ProcurementStep),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or procurement budgets are not installed", body = ErrorResponse),
        (status = 409, description = "Not in a status this step starts from, or being changed", body = ErrorResponse),
        (status = 422, description = "Over budget, no rule or vendor, or a bad amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Cancels a purchase order.
///
/// A draft or issued order releases its budget commitment with the status change.
async fn post_cancel_order(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OrderUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProcurementStep>, AppError> {
    Ok(Json(cancel_order(&state, &ctx, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/purchase-orders/{id}/change",
    operation_id = "post_purchase_order_change",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The record")),
    request_body = ChangeBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the step did", body = ProcurementStep),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or procurement budgets are not installed", body = ErrorResponse),
        (status = 409, description = "Not in a status this step starts from, or being changed", body = ErrorResponse),
        (status = 422, description = "Over budget, no rule or vendor, or a bad amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Changes a purchase order total.
///
/// Within the rule tolerance the change applies at once; above it a re-approval opens and the change applies once approved.
async fn post_change_order(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OrderUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ChangeBody>,
) -> Result<Json<ProcurementStep>, AppError> {
    Ok(Json(change_order(&state, &ctx, id, &body).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/procurement/requisitions/{id}/submit",
            post(post_submit),
        )
        .route(
            "/api/v1/procurement/requisitions/{id}/order",
            post(post_order),
        )
        .route(
            "/api/v1/procurement/requisitions/{id}/cancel",
            post(post_cancel_requisition),
        )
        .route(
            "/api/v1/procurement/purchase-orders/{id}/cancel",
            post(post_cancel_order),
        )
        .route(
            "/api/v1/procurement/purchase-orders/{id}/change",
            post(post_change_order),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_submit,
        post_order,
        post_cancel_requisition,
        post_cancel_order,
        post_change_order
    ),
    components(schemas(ProcurementStep, OrderBody, ChangeBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod po_flow {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).expect("a number")
    }

    fn rule(n: u128) -> DoaRule {
        DoaRule {
            id: Uuid::from_u128(n),
            min_amount: None,
            max_amount: None,
            category: None,
            cost_center: None,
            approver: Some(Uuid::from_u128(1000 + n)),
            second_approver: None,
            manager_first: false,
            tolerance_pct: None,
            priority: 0,
        }
    }

    #[test]
    fn the_amount_band_picks_the_approver() {
        let mut small = rule(1);
        small.max_amount = Some(d("10000"));
        let mut large = rule(2);
        large.min_amount = Some(d("10000.01"));
        let rules = [small, large];
        assert_eq!(
            pick_rule(&rules, d("500"), None, None).map(|r| r.id.as_u128()),
            Some(1)
        );
        assert_eq!(
            pick_rule(&rules, d("10000"), None, None).map(|r| r.id.as_u128()),
            Some(1)
        );
        assert_eq!(
            pick_rule(&rules, d("25000"), None, None).map(|r| r.id.as_u128()),
            Some(2)
        );
    }

    #[test]
    fn category_and_cost_centre_rules_beat_general_ones() {
        let cc = Uuid::from_u128(77);
        let general = rule(1);
        let mut it = rule(2);
        it.category = Some("IT".into());
        let mut it_cc = rule(3);
        it_cc.category = Some("it".into());
        it_cc.cost_center = Some(cc);
        let rules = [general, it, it_cc];
        let pick = |cat: Option<&str>, c: Option<Uuid>| {
            pick_rule(&rules, d("100"), cat, c).map(|r| r.id.as_u128())
        };
        assert_eq!(pick(Some("IT"), Some(cc)), Some(3));
        assert_eq!(pick(Some("IT"), None), Some(2));
        assert_eq!(pick(Some("Facilities"), Some(cc)), Some(1));
        assert_eq!(pick(None, None), Some(1));
    }

    #[test]
    fn priority_and_the_narrower_band_break_ties() {
        let mut wide = rule(1);
        wide.max_amount = None;
        let mut narrow = rule(2);
        narrow.max_amount = Some(d("5000"));
        assert_eq!(
            pick_rule(&[wide.clone(), narrow.clone()], d("100"), None, None)
                .map(|r| r.id.as_u128()),
            Some(2)
        );
        wide.priority = 5;
        assert_eq!(
            pick_rule(&[wide, narrow], d("100"), None, None).map(|r| r.id.as_u128()),
            Some(1)
        );
        assert!(pick_rule(&[], d("1"), None, None).is_none());
    }

    #[test]
    fn the_plan_runs_manager_then_approvers() {
        let mut r = rule(1);
        r.manager_first = true;
        r.second_approver = Some(Uuid::from_u128(9));
        let plan = plan_for(&r).expect("a plan");
        let tokens: Vec<&str> = plan.steps.iter().map(|s| s.approvers[0].as_str()).collect();
        assert_eq!(tokens[0], MANAGER);
        assert_eq!(tokens[1], format!("user:{}", Uuid::from_u128(1001)));
        assert_eq!(tokens[2], format!("user:{}", Uuid::from_u128(9)));
        assert!(plan.validate().is_ok());
        let mut nobody = rule(2);
        nobody.approver = None;
        assert!(plan_for(&nobody).is_none());
    }

    #[test]
    fn change_orders_reapprove_only_above_tolerance() {
        assert!(
            !change_needs_approval(d("1000"), d("1100"), None),
            "10% is within"
        );
        assert!(change_needs_approval(d("1000"), d("1100.01"), None));
        assert!(
            !change_needs_approval(d("1000"), d("500"), None),
            "a decrease"
        );
        assert!(change_needs_approval(d("1000"), d("1001"), Some(d("0"))));
        assert!(!change_needs_approval(d("1000"), d("1250"), Some(d("25"))));
    }

    #[test]
    fn budget_lines_block_unless_set_to_warn() {
        assert_eq!(overspend_policy(Some("warn")), OverspendPolicy::Warn);
        assert_eq!(overspend_policy(Some("block")), OverspendPolicy::Block);
        assert_eq!(overspend_policy(None), OverspendPolicy::Block);
    }
}
