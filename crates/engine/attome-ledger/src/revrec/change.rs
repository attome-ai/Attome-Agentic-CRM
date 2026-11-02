//! F11-T6: contract changes (an F3 amendment, a D10 change order, an F4
//! credit note), previewed before they touch a schedule (V2-D1588 (4)).
//!
//! **Treatment, by IFRS 15.** [`treatment_for`] decides it from two facts
//! about the change: goods added that are distinct and priced at their
//! standalone price make a **separate contract** (the existing schedules
//! stay as they are; the added goods come in through their own source,
//! F11-T3); otherwise, when the goods still to deliver are distinct from
//! those delivered, the change is **prospective** (the new total less what
//! is already recognised is spread over the planned lines); otherwise a
//! **cumulative catch-up** (the planned lines are rescaled to the new total
//! and the difference the change makes to what should have been recognised
//! to date lands in the first open line). A revenue accountant may name the
//! treatment instead; the preview records that it was overridden.
//!
//! **Preview, then apply.** `POST /api/v1/ledger/revrec/changes` computes the
//! new amounts of every planned line of the obligations named and stores
//! them (`revenue_contract_change`, migration 0373) as `previewed`; nothing
//! else changes. `POST .../changes/{id}/apply` writes them, only to lines
//! still `planned` with the amount the preview saw (else 409, preview
//! again), never to a recognised or locked line, sets each obligation's
//! allocated amount, and marks the change `applied`; `.../discard` marks it
//! `discarded`. All three need `revenue_contract.update` and revenue
//! recognition on, and are audited.

use std::str::FromStr;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::contract::{BASIC_FLAG, RevenueContractUpdate};

/// How a change is accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Treatment {
    SeparateContract,
    Prospective,
    CumulativeCatchUp,
}

impl Treatment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeparateContract => "separate_contract",
            Self::Prospective => "prospective",
            Self::CumulativeCatchUp => "cumulative_catch_up",
        }
    }
}

/// The IFRS 15 treatment of a change. Pure.
pub fn treatment_for(
    adds_distinct_at_standalone_price: bool,
    remaining_distinct: bool,
) -> Treatment {
    if adds_distinct_at_standalone_price {
        Treatment::SeparateContract
    } else if remaining_distinct {
        Treatment::Prospective
    } else {
        Treatment::CumulativeCatchUp
    }
}

/// A planned schedule line as a change sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedLine {
    pub id: Uuid,
    pub period: String,
    pub amount: Decimal,
}

/// An obligation's schedule before a change.
#[derive(Debug, Clone, PartialEq)]
pub struct ObligationSchedule {
    /// Recognised or locked: never changed.
    pub recognised: Decimal,
    /// Planned, in period order.
    pub planned: Vec<PlannedLine>,
}

impl ObligationSchedule {
    fn total(&self) -> Decimal {
        self.recognised + self.planned.iter().map(|l| l.amount).sum::<Decimal>()
    }
}

fn cents(v: Decimal) -> Decimal {
    v.round_dp(2)
}

/// Spreads `amount` over `lines` in proportion to their amounts (evenly
/// when they are all zero), to the cent; the last takes the remainder.
/// Pure.
fn spread(lines: &[PlannedLine], amount: Decimal) -> Vec<Decimal> {
    if lines.is_empty() {
        return Vec::new();
    }
    let weight: Decimal = lines.iter().map(|l| l.amount).sum();
    let mut out: Vec<Decimal> = lines
        .iter()
        .map(|l| {
            if weight.is_zero() {
                cents(amount / Decimal::from(lines.len()))
            } else {
                cents(amount * l.amount / weight)
            }
        })
        .collect();
    let given: Decimal = out.iter().sum();
    if let Some(last) = out.last_mut() {
        *last += amount - given;
    }
    out
}

/// Prospective: what is not yet recognised of `new_total` over the planned
/// lines. Pure.
pub fn prospective(schedule: &ObligationSchedule, new_total: Decimal) -> Vec<Decimal> {
    spread(&schedule.planned, new_total - schedule.recognised)
}

/// Cumulative catch-up: the planned lines rescaled to `new_total`, and the
/// difference the new total makes to what should have been recognised to
/// date added to the first planned line. The lines and what is recognised
/// sum to `new_total`. Pure.
pub fn catch_up(schedule: &ObligationSchedule, new_total: Decimal) -> Vec<Decimal> {
    let old_total = schedule.total();
    if old_total.is_zero() || schedule.planned.is_empty() {
        return prospective(schedule, new_total);
    }
    let ratio = new_total / old_total;
    let mut out = spread(
        &schedule.planned,
        cents(schedule.planned.iter().map(|l| l.amount).sum::<Decimal>() * ratio),
    );
    let catch = cents(schedule.recognised * ratio) - schedule.recognised;
    if let Some(first) = out.first_mut() {
        *first += catch;
    }
    let total: Decimal = schedule.recognised + out.iter().sum::<Decimal>();
    if let Some(last) = out.last_mut() {
        *last += new_total - total;
    }
    out
}

/// One obligation's new total.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ObligationChange {
    pub obligation_id: Uuid,
    /// The obligation's whole allocated amount after the change, a decimal.
    #[schema(value_type = f64)]
    pub new_total: serde_json::Number,
}

/// A change to preview.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ChangeRequest {
    pub contract_id: Uuid,
    /// `amendment` (F3), `change_order` (D10) or `credit_note` (F4).
    pub change_kind: String,
    /// The record the change came from, if any.
    pub source_ref: Option<String>,
    /// Goods added that are distinct and priced at their standalone price.
    #[serde(default)]
    pub adds_distinct_at_standalone_price: bool,
    /// The goods still to deliver are distinct from those delivered.
    #[serde(default)]
    pub remaining_distinct: bool,
    /// A revenue accountant's own choice, replacing the rule's.
    pub treatment: Option<Treatment>,
    #[serde(default)]
    pub obligations: Vec<ObligationChange>,
}

/// A planned line's change.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LineChange {
    pub line_id: Uuid,
    pub fiscal_period: String,
    /// Decimals in text.
    pub from: String,
    pub to: String,
}

/// An obligation's change.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ObligationPreview {
    pub obligation_id: Uuid,
    pub recognised: String,
    pub old_total: String,
    pub new_total: String,
    pub lines: Vec<LineChange>,
}

/// A stored preview.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChangePreview {
    pub change_id: Uuid,
    pub contract_id: Uuid,
    pub change_kind: String,
    pub treatment: Treatment,
    /// The treatment was named by the caller rather than the rule.
    pub overridden: bool,
    /// `previewed`, `applied` or `discarded`.
    pub status: String,
    pub obligations: Vec<ObligationPreview>,
}

const KINDS: [&str; 3] = ["amendment", "change_order", "credit_note"];
const MAX_OBLIGATIONS: usize = 200;

fn decimal(n: &serde_json::Number) -> Result<Decimal, AppError> {
    Decimal::from_str(&n.to_string())
        .map_err(|_| AppError::Validation("new_total: a decimal amount".into()))
}

fn text_decimal(v: Option<&str>) -> Decimal {
    v.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

type LineRow = (Uuid, Option<String>, Option<String>, Option<String>);

async fn schedule_of(
    state: &EngineState,
    contract: Uuid,
    obligation: Uuid,
) -> Result<ObligationSchedule, AppError> {
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT s.id, s.fiscal_period, s.amount_contract_ccy::text, s.status::text \
           FROM revenue_schedule_line s \
           JOIN performance_obligation o ON o.id = s.obligation_ref \
          WHERE s.obligation_ref = $1 AND o.revenue_contract_ref = $2 \
            AND (s.is_active IS NULL OR s.is_active = true) \
          ORDER BY s.fiscal_period, s.id",
    )
    .bind(obligation)
    .bind(contract)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut schedule = ObligationSchedule {
        recognised: Decimal::ZERO,
        planned: Vec::new(),
    };
    for (id, period, amount, status) in rows {
        let amount = text_decimal(amount.as_deref());
        if status.as_deref() == Some("planned") {
            schedule.planned.push(PlannedLine {
                id,
                period: period.unwrap_or_default(),
                amount,
            });
        } else {
            schedule.recognised += amount;
        }
    }
    Ok(schedule)
}

/// Computes and stores the preview of `req`.
pub async fn preview(
    state: &EngineState,
    actor: Uuid,
    req: &ChangeRequest,
) -> Result<ChangePreview, AppError> {
    if !KINDS.contains(&req.change_kind.as_str()) {
        return Err(AppError::Validation(format!(
            "change_kind: one of {}",
            KINDS.join(", ")
        )));
    }
    if req.obligations.len() > MAX_OBLIGATIONS {
        return Err(AppError::Validation(format!(
            "at most {MAX_OBLIGATIONS} obligations a change"
        )));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM revenue_contract WHERE id = $1 \
                          AND (is_active IS NULL OR is_active = true))",
    )
    .bind(req.contract_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let rule = treatment_for(
        req.adds_distinct_at_standalone_price,
        req.remaining_distinct,
    );
    let treatment = req.treatment.unwrap_or(rule);
    let mut obligations = Vec::with_capacity(req.obligations.len());
    if treatment != Treatment::SeparateContract {
        for change in &req.obligations {
            let new_total = decimal(&change.new_total)?;
            let schedule = schedule_of(state, req.contract_id, change.obligation_id).await?;
            if schedule.planned.is_empty() {
                return Err(AppError::Validation(format!(
                    "obligation {} has no planned line left to change",
                    change.obligation_id
                )));
            }
            let amounts = match treatment {
                Treatment::Prospective => prospective(&schedule, new_total),
                _ => catch_up(&schedule, new_total),
            };
            obligations.push(ObligationPreview {
                obligation_id: change.obligation_id,
                recognised: schedule.recognised.to_string(),
                old_total: schedule.total().to_string(),
                new_total: new_total.to_string(),
                lines: schedule
                    .planned
                    .iter()
                    .zip(amounts)
                    .map(|(line, to)| LineChange {
                        line_id: line.id,
                        fiscal_period: line.period.clone(),
                        from: line.amount.to_string(),
                        to: to.to_string(),
                    })
                    .collect(),
            });
        }
    }
    let preview = ChangePreview {
        change_id: Uuid::now_v7(),
        contract_id: req.contract_id,
        change_kind: req.change_kind.clone(),
        treatment,
        overridden: treatment != rule,
        status: "previewed".into(),
        obligations,
    };
    let json = serde_json::to_value(&preview).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO revenue_contract_change \
             (id, contract_id, change_kind, source_ref, treatment, overridden, preview, status, \
              created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'previewed', $8)",
    )
    .bind(preview.change_id)
    .bind(req.contract_id)
    .bind(&req.change_kind)
    .bind(req.source_ref.as_deref())
    .bind(treatment.as_str())
    .bind(preview.overridden)
    .bind(&json)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "revenue_contract",
            req.contract_id,
            AuditOperation::Create,
            "revrec.change_previewed",
            actor,
        )
        .comment(format!(
            "{} previewed as {}{}",
            req.change_kind,
            treatment.as_str(),
            if preview.overridden {
                " (overridden)"
            } else {
                ""
            }
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(preview)
}

/// Applies a previewed change; the lines it changed.
pub async fn apply(state: &EngineState, actor: Uuid, change: Uuid) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(String, Value)> = sqlx::query_as(
        "SELECT status, preview FROM revenue_contract_change WHERE id = $1 FOR UPDATE",
    )
    .bind(change)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (status, json) = row.ok_or(AppError::NotFound)?;
    if status != "previewed" {
        return Err(AppError::Conflict(
            "the change was applied or discarded already",
        ));
    }
    let preview: ChangePreview = serde_json::from_value(json).map_err(AppError::internal)?;
    let mut changed = 0;
    for obligation in &preview.obligations {
        for line in &obligation.lines {
            let to = text_decimal(Some(&line.to));
            let from = text_decimal(Some(&line.from));
            // Only a line still planned at the amount the preview saw: a
            // recognised or locked line is never touched.
            let done = sqlx::query(
                "UPDATE revenue_schedule_line \
                    SET amount_base_ccy = CASE WHEN amount_contract_ccy <> 0 \
                            THEN round(amount_base_ccy * $3::numeric / amount_contract_ccy, 2) \
                            ELSE amount_base_ccy END, \
                        amount_contract_ccy = $3::numeric, modified_at = now(), \
                        row_version = row_version + 1 \
                  WHERE id = $1 AND status::text = 'planned' AND amount_contract_ccy = $2::numeric \
                    AND (is_active IS NULL OR is_active = true)",
            )
            .bind(line.line_id)
            .bind(from.to_string())
            .bind(to.to_string())
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if done != 1 {
                return Err(AppError::Conflict(
                    "a schedule line changed since the preview; preview the change again",
                ));
            }
            changed += 1;
        }
        sqlx::query(
            "UPDATE performance_obligation SET allocated_amount = $2::numeric, \
                    modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(obligation.obligation_id)
        .bind(&obligation.new_total)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "UPDATE revenue_contract_change SET status = 'applied', decided_by = $2, decided_at = now() \
          WHERE id = $1",
    )
    .bind(change)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "revenue_contract",
            preview.contract_id,
            AuditOperation::Update,
            "revrec.change_applied",
            actor,
        )
        .comment(format!(
            "{} applied as {}: {changed} planned line(s)",
            preview.change_kind,
            preview.treatment.as_str()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(changed)
}

/// Discards a previewed change.
pub async fn discard(state: &EngineState, actor: Uuid, change: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let contract: Option<Uuid> = sqlx::query_scalar(
        "UPDATE revenue_contract_change SET status = 'discarded', decided_by = $2, \
                decided_at = now() \
          WHERE id = $1 AND status = 'previewed' RETURNING contract_id",
    )
    .bind(change)
    .bind(actor)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(contract) = contract else {
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM revenue_contract_change WHERE id = $1)",
        )
        .bind(change)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return Err(if known {
            AppError::Conflict("the change was applied or discarded already")
        } else {
            AppError::NotFound
        });
    };
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "revenue_contract",
            contract,
            AuditOperation::Update,
            "revrec.change_discarded",
            actor,
        )
        .comment(format!("change {change} discarded")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Preview a contract change
///
/// Computes how a contract change moves the planned schedule lines of the obligations named, by the
/// IFRS 15 treatment (or the one named), and stores it as a preview. Nothing else changes.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/changes",
    operation_id = "revrec_change_preview",
    tag = "ledger",
    request_body = ChangeRequest,
    responses(
        (status = 201, description = "The stored preview", body = ChangePreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revenue_contract.update", body = ErrorResponse),
        (status = 404, description = "No such contract, or revenue recognition is off", body = ErrorResponse),
        (status = 422, description = "Not a change kind, a bad amount, or an obligation with no planned line", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_preview(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RevenueContractUpdate>>,
    Json(body): Json<ChangeRequest>,
) -> Result<(StatusCode, Json<ChangePreview>), AppError> {
    if !state.feature_flags().is_on(BASIC_FLAG, &ctx).await {
        return Err(AppError::NotFound);
    }
    let preview = preview(&state, ctx.user_id, &body).await?;
    Ok((StatusCode::CREATED, Json(preview)))
}

/// What applying did.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangeApplied {
    pub change_id: Uuid,
    /// Planned lines changed.
    pub lines: u64,
}

/// Apply a previewed contract change
///
/// Writes a previewed change to the planned schedule lines it named, only while each is still
/// planned at the previewed amount; recognised and locked lines are never changed.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/changes/{id}/apply",
    operation_id = "revrec_change_apply",
    tag = "ledger",
    params(("id" = Uuid, Path, description = "The change")),
    responses(
        (status = 200, description = "Applied", body = ChangeApplied),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revenue_contract.update", body = ErrorResponse),
        (status = 404, description = "No such change, or revenue recognition is off", body = ErrorResponse),
        (status = 409, description = "Applied or discarded already, or a line changed since the preview", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_apply(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RevenueContractUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangeApplied>, AppError> {
    if !state.feature_flags().is_on(BASIC_FLAG, &ctx).await {
        return Err(AppError::NotFound);
    }
    let lines = apply(&state, ctx.user_id, id).await?;
    Ok(Json(ChangeApplied {
        change_id: id,
        lines,
    }))
}

/// Discard a previewed contract change
///
/// Marks a previewed change discarded; no schedule line changes.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/changes/{id}/discard",
    operation_id = "revrec_change_discard",
    tag = "ledger",
    params(("id" = Uuid, Path, description = "The change")),
    responses(
        (status = 204, description = "Discarded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revenue_contract.update", body = ErrorResponse),
        (status = 404, description = "No such change, or revenue recognition is off", body = ErrorResponse),
        (status = 409, description = "Applied or discarded already", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_discard(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RevenueContractUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if !state.feature_flags().is_on(BASIC_FLAG, &ctx).await {
        return Err(AppError::NotFound);
    }
    discard(&state, ctx.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ledger/revrec/changes", post(post_preview))
        .route("/api/v1/ledger/revrec/changes/{id}/apply", post(post_apply))
        .route(
            "/api/v1/ledger/revrec/changes/{id}/discard",
            post(post_discard),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_preview, post_apply, post_discard),
    components(schemas(
        ChangeRequest,
        ObligationChange,
        ChangePreview,
        ObligationPreview,
        LineChange,
        Treatment,
        ChangeApplied
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(v: &str) -> Decimal {
        Decimal::from_str(v).unwrap()
    }

    /// 1,200 over twelve periods, the first four recognised (one locked).
    fn schedule() -> ObligationSchedule {
        ObligationSchedule {
            recognised: d("400"),
            planned: (5..=12)
                .map(|m| PlannedLine {
                    id: Uuid::now_v7(),
                    period: format!("2027-{m:02}"),
                    amount: d("100"),
                })
                .collect(),
        }
    }

    #[test]
    fn the_rule_follows_ifrs_15() {
        assert_eq!(treatment_for(true, false), Treatment::SeparateContract);
        assert_eq!(treatment_for(false, true), Treatment::Prospective);
        assert_eq!(treatment_for(false, false), Treatment::CumulativeCatchUp);
    }

    #[test]
    fn prospective_spreads_over_remaining() {
        // The price rises to 1,600: the 1,200 not recognised spreads evenly.
        let amounts = prospective(&schedule(), d("1600"));
        assert_eq!(amounts.len(), 8);
        assert!(amounts.iter().all(|a| *a == d("150")));
    }

    #[test]
    fn catch_up_hits_first_open_period() {
        // 1,200 to 1,500: to date should be 500, so 100 more lands first.
        let amounts = catch_up(&schedule(), d("1500"));
        assert_eq!(amounts[0], d("225"));
        assert!(amounts[1..].iter().all(|a| *a == d("125")));
        assert_eq!(d("400") + amounts.iter().sum::<Decimal>(), d("1500"));
    }

    #[test]
    fn locked_periods_untouched() {
        // Only planned lines get amounts; what is recognised stays 400.
        let s = schedule();
        for amounts in [prospective(&s, d("900")), catch_up(&s, d("900"))] {
            assert_eq!(amounts.len(), s.planned.len());
            assert_eq!(s.recognised + amounts.iter().sum::<Decimal>(), d("900"));
        }
    }

    #[test]
    fn uneven_totals_keep_every_cent() {
        let s = schedule();
        let amounts = prospective(&s, d("1000.01"));
        assert_eq!(s.recognised + amounts.iter().sum::<Decimal>(), d("1000.01"));
    }
}
