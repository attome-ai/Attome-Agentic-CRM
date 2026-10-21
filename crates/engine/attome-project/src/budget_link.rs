//! V1-T2: a project's budget line and its proposed invoices.
//!
//! **Budget.** A project's budget is the finance pack's `budget_line` whose
//! `project_ref` is the project (W4-T1); with several, the one whose period
//! covers today, else the latest. `POST /api/v1/projects/{id}/spend-check`
//! answers whether a spend fits it through W4's check
//! ([`attome_procurement::budget::check`], under the line's `overspend`).
//!
//! **Invoices.** `POST /api/v1/projects/{id}/invoice-proposals` sends billing
//! (F4) an invoice request, which billing turns into a draft invoice for the
//! project's `account_ref` (finance pack 0003):
//!
//! - `milestone`: one accepted deliverable's `invoice_amount`, keyed
//!   `project_deliverable:{id}`;
//! - `time_and_materials`: the project's billable hours on approved
//!   timesheets up to `until` not yet proposed, one line per person at their
//!   billable rate (`project_resource_rate`, latest effective on or before
//!   `until`), keyed by the batch.
//!
//! **Once.** A deliverable or time entry is claimed by writing `pending`
//! (`pending:{batch}` for time) into its `invoice_request_ref` before billing
//! is asked, and the request id after; a retry finds the claim and asks
//! again with the same key, which billing answers with the stored request,
//! so nothing is proposed twice.

use std::collections::BTreeMap;
use std::str::FromStr;

use attome_core::EngineState;
use attome_procurement::budget::{BudgetCheck, BudgetLine, OverspendPolicy};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The currency when the project names none.
const DEFAULT_CURRENCY: &str = "SAR";
/// Most time entries one proposal takes.
const MAX_ENTRIES: i64 = 5_000;

/// `attome_project.update`: who checks spend and proposes invoices.
#[derive(Debug)]
pub struct ProjectUpdate;

impl PrivilegeKey for ProjectUpdate {
    const KEY: &'static str = "attome_project.update";
}

fn dec(v: Option<String>) -> Option<Decimal> {
    v.and_then(|s| Decimal::from_str(s.trim()).ok())
}

/// One person's billable time, as a line. Pure.
#[derive(Debug, Clone, PartialEq)]
pub struct TimeLine {
    pub user: Uuid,
    pub hours: Decimal,
    pub rate: Decimal,
}

/// Billable hours summed per person and priced at their rate; a person with
/// no rate is left out (and named by the caller). Pure.
pub fn time_lines(
    entries: &[(Uuid, Decimal)],
    rates: &BTreeMap<Uuid, Decimal>,
) -> (Vec<TimeLine>, Vec<Uuid>) {
    let mut hours: BTreeMap<Uuid, Decimal> = BTreeMap::new();
    for (user, h) in entries {
        if *h > Decimal::ZERO {
            *hours.entry(*user).or_default() += *h;
        }
    }
    let mut lines = Vec::new();
    let mut unrated = Vec::new();
    for (user, h) in hours {
        match rates.get(&user) {
            Some(rate) if *rate > Decimal::ZERO => lines.push(TimeLine {
                user,
                hours: h,
                rate: *rate,
            }),
            _ => unrated.push(user),
        }
    }
    (lines, unrated)
}

/// Whether a deliverable may be invoiced as a milestone. Pure.
pub fn milestone_ready(
    status: Option<&str>,
    amount: Option<Decimal>,
) -> Result<Decimal, &'static str> {
    if status != Some("accepted") {
        return Err("deliverable_id: only an accepted deliverable is invoiced");
    }
    amount
        .filter(|a| *a > Decimal::ZERO)
        .ok_or("deliverable_id: the deliverable has no invoice_amount")
}

fn number(d: Decimal) -> Result<serde_json::Number, AppError> {
    d.to_string()
        .parse::<f64>()
        .ok()
        .and_then(serde_json::Number::from_f64)
        .ok_or_else(|| AppError::Validation(format!("{d} is not a usable amount")))
}

/// `(id, amount, committed, actual, overspend)`.
type LineRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The spend check.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SpendCheck {
    pub budget_line_id: Uuid,
    /// `within`, `warn` or `blocked`.
    pub outcome: String,
    /// What is left after the spend (negative: over).
    pub available_after: String,
}

/// The spend to check.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SpendBody {
    /// A decimal string.
    pub amount: String,
}

/// Checks a spend against the project's budget line.
pub async fn check_spend(
    state: &EngineState,
    project: Uuid,
    amount: Decimal,
) -> Result<SpendCheck, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar("SELECT to_regclass('budget_line') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    let row: Option<LineRow> = sqlx::query_as(
        "SELECT id, amount::text, committed::text, actual::text, overspend::text FROM budget_line \
          WHERE project_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY (CURRENT_DATE BETWEEN COALESCE(period_start::date, '-infinity') \
                    AND COALESCE(period_end::date, 'infinity')) DESC, \
                   period_start DESC NULLS LAST, id LIMIT 1",
    )
    .bind(project)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((id, total, committed, actual, overspend)) = row else {
        return Err(AppError::Validation(
            "the project has no budget line (a budget line with this project_ref)".into(),
        ));
    };
    let line = BudgetLine {
        amount: dec(total).unwrap_or_default(),
        commitments: dec(committed).unwrap_or_default(),
        actuals: dec(actual).unwrap_or_default(),
    };
    let policy = if overspend.as_deref() == Some("warn") {
        OverspendPolicy::Warn
    } else {
        OverspendPolicy::Block
    };
    let outcome = attome_procurement::budget::check(&line, amount, policy);
    Ok(SpendCheck {
        budget_line_id: id,
        outcome: match outcome {
            BudgetCheck::Within { .. } => "within",
            BudgetCheck::Warn { .. } => "warn",
            BudgetCheck::Blocked { .. } => "blocked",
        }
        .into(),
        available_after: (line.available() - amount).to_string(),
    })
}

/// What to propose.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProposalBody {
    /// `milestone` or `time_and_materials`.
    pub kind: String,
    /// The accepted deliverable, for a milestone.
    pub deliverable_id: Option<Uuid>,
    /// The last day of time taken, for time and materials (today when
    /// absent).
    pub until: Option<NaiveDate>,
}

/// The proposal sent to billing.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Proposal {
    pub project_id: Uuid,
    pub request_id: Option<Uuid>,
    /// The time entries the proposal took.
    pub entries: usize,
    /// People with billable time but no billable rate, left out.
    pub unrated_users: Vec<Uuid>,
}

async fn project_head(
    state: &EngineState,
    project: Uuid,
) -> Result<(Uuid, String, String), AppError> {
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT to_jsonb(p)->>'account_ref', to_jsonb(p)->>'currency', name \
           FROM attome_project p WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((account, currency, name)) = row else {
        return Err(AppError::NotFound);
    };
    let account = account
        .and_then(|a| Uuid::parse_str(&a).ok())
        .ok_or_else(|| {
            AppError::Validation("account_ref: the project needs its customer account".into())
        })?;
    let currency = currency
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .unwrap_or_else(|| DEFAULT_CURRENCY.to_owned());
    Ok((
        account,
        currency,
        name.unwrap_or_else(|| project.to_string()),
    ))
}

async fn submit(
    state: &EngineState,
    ctx: &SecurityContext,
    project: Uuid,
    key: &str,
    lines: Vec<attome_billing::requests::RequestLine>,
) -> Result<Uuid, AppError> {
    let (account, currency, _) = project_head(state, project).await?;
    let accepted = attome_billing::requests::submit_request(
        state,
        ctx,
        &attome_billing::requests::InvoiceRequest {
            source_kind: "project".to_owned(),
            source_ref: project.to_string(),
            idempotency_key: key.to_owned(),
            account_ref: account,
            currency,
            request_date: Some(chrono::Utc::now().date_naive()),
            lines,
        },
    )
    .await?;
    Ok(accepted.request_id)
}

/// `(status, invoice amount, invoice request, name)`.
type DeliverableRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn propose_milestone(
    state: &EngineState,
    ctx: &SecurityContext,
    project: Uuid,
    deliverable: Uuid,
) -> Result<Proposal, AppError> {
    let db = &state.base.db;
    let (_, _, name) = project_head(state, project).await?;
    let row: Option<DeliverableRow> = sqlx::query_as(
        "SELECT status::text, invoice_amount::text, invoice_request_ref, name \
               FROM project_deliverable \
              WHERE id = $1 AND project_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deliverable)
    .bind(project)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, amount, claimed, title)) = row else {
        return Err(AppError::Validation(
            "deliverable_id: not a deliverable of this project".into(),
        ));
    };
    if let Some(done) = claimed.as_deref().and_then(|c| c.strip_prefix("request:")) {
        return Ok(Proposal {
            project_id: project,
            request_id: Uuid::parse_str(done).ok(),
            entries: 0,
            unrated_users: Vec::new(),
        });
    }
    let amount = milestone_ready(status.as_deref(), dec(amount))
        .map_err(|m| AppError::Validation(m.into()))?;
    // Claimed before billing is asked; a retry finds `pending` and asks
    // again with the same key.
    sqlx::query(
        "UPDATE project_deliverable SET invoice_request_ref = 'pending', modified_at = now(), \
             row_version = row_version + 1 \
          WHERE id = $1 AND (invoice_request_ref IS NULL OR invoice_request_ref = 'pending')",
    )
    .bind(deliverable)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    let request = submit(
        state,
        ctx,
        project,
        &format!("project_deliverable:{deliverable}"),
        vec![attome_billing::requests::RequestLine {
            description: format!(
                "{name}: {}",
                title.unwrap_or_else(|| "milestone".to_owned())
            ),
            quantity: serde_json::Number::from(1),
            unit_price: number(amount)?,
            vat_category: None,
            product_ref: None,
            period_from: None,
            period_to: None,
        }],
    )
    .await?;
    sqlx::query(
        "UPDATE project_deliverable SET invoice_request_ref = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(deliverable)
    .bind(format!("request:{request}"))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Proposal {
        project_id: project,
        request_id: Some(request),
        entries: 0,
        unrated_users: Vec::new(),
    })
}

async fn propose_time(
    state: &EngineState,
    ctx: &SecurityContext,
    project: Uuid,
    until: NaiveDate,
) -> Result<Proposal, AppError> {
    let db = &state.base.db;
    let (_, _, name) = project_head(state, project).await?;
    // An earlier batch claimed but not sent (a crash): finish it first.
    let pending: Option<String> = sqlx::query_scalar(
        "SELECT e.invoice_request_ref FROM project_time_entry e \
           JOIN project_work_item w ON w.id = e.work_item_id \
          WHERE w.project_id = $1 AND e.invoice_request_ref LIKE 'pending:%' LIMIT 1",
    )
    .bind(project)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let batch = match pending {
        Some(p) => p,
        None => {
            let batch = format!("pending:{}", Uuid::now_v7());
            sqlx::query(
                "UPDATE project_time_entry SET invoice_request_ref = $3, modified_at = now(), \
                     row_version = row_version + 1 \
                  WHERE id IN ( \
                    SELECT e.id FROM project_time_entry e \
                      JOIN project_work_item w ON w.id = e.work_item_id \
                      JOIN project_timesheet t ON t.id = e.timesheet_id \
                     WHERE w.project_id = $1 AND e.is_billable = true \
                       AND t.status = 'approved' AND e.entry_date::date <= $2 \
                       AND e.invoice_request_ref IS NULL \
                       AND (e.is_active IS NULL OR e.is_active = true) \
                     ORDER BY e.id LIMIT $4 FOR UPDATE OF e SKIP LOCKED)",
            )
            .bind(project)
            .bind(until)
            .bind(&batch)
            .bind(MAX_ENTRIES)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            batch
        }
    };
    let entries: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT user_id, hours::text FROM project_time_entry WHERE invoice_request_ref = $1",
    )
    .bind(&batch)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if entries.is_empty() {
        return Ok(Proposal {
            project_id: project,
            request_id: None,
            entries: 0,
            unrated_users: Vec::new(),
        });
    }
    let entries: Vec<(Uuid, Decimal)> = entries
        .into_iter()
        .filter_map(|(u, h)| dec(h).map(|h| (u, h)))
        .collect();
    let rate_rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT ON (user_id) user_id, billable_rate::text FROM project_resource_rate \
          WHERE project_id = $1 AND (effective_date IS NULL OR effective_date::date <= $2) \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY user_id, effective_date DESC NULLS LAST",
    )
    .bind(project)
    .bind(until)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rates: BTreeMap<Uuid, Decimal> = rate_rows
        .into_iter()
        .filter_map(|(u, r)| dec(r).map(|r| (u, r)))
        .collect();
    let (lines, unrated) = time_lines(&entries, &rates);
    if !unrated.is_empty() {
        // Their entries go back unclaimed, for a later proposal once rated.
        sqlx::query(
            "UPDATE project_time_entry SET invoice_request_ref = NULL \
              WHERE invoice_request_ref = $1 AND user_id = ANY($2)",
        )
        .bind(&batch)
        .bind(&unrated)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    if lines.is_empty() {
        return Ok(Proposal {
            project_id: project,
            request_id: None,
            entries: 0,
            unrated_users: unrated,
        });
    }
    let request_lines = lines
        .iter()
        .map(|l| {
            Ok(attome_billing::requests::RequestLine {
                description: format!("{name}: time and materials to {until}"),
                quantity: number(l.hours)?,
                unit_price: number(l.rate)?,
                vat_category: None,
                product_ref: None,
                period_from: None,
                period_to: Some(until),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let key = format!("project_tm:{}", batch.trim_start_matches("pending:"));
    let request = submit(state, ctx, project, &key, request_lines).await?;
    let taken = sqlx::query(
        "UPDATE project_time_entry SET invoice_request_ref = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE invoice_request_ref = $1",
    )
    .bind(&batch)
    .bind(format!("request:{request}"))
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(Proposal {
        project_id: project,
        request_id: Some(request),
        entries: usize::try_from(taken).unwrap_or(usize::MAX),
        unrated_users: unrated,
    })
}

/// Sends billing one invoice proposal for a project.
pub async fn propose(
    state: &EngineState,
    ctx: &SecurityContext,
    project: Uuid,
    body: &ProposalBody,
) -> Result<Proposal, AppError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'project_time_entry' \
            AND column_name = 'invoice_request_ref')",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    match body.kind.as_str() {
        "milestone" => {
            let deliverable = body.deliverable_id.ok_or_else(|| {
                AppError::Validation("deliverable_id: name the accepted deliverable".into())
            })?;
            propose_milestone(state, ctx, project, deliverable).await
        }
        "time_and_materials" => {
            let until = body
                .until
                .unwrap_or_else(|| chrono::Utc::now().date_naive());
            propose_time(state, ctx, project, until).await
        }
        _ => Err(AppError::Validation(
            "kind: milestone or time_and_materials".into(),
        )),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/projects/{id}/spend-check",
    operation_id = "post_project_spend_check",
    tag = "projects",
    params(("id" = Uuid, Path, description = "The project")),
    request_body = SpendBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "answers whether a spend fits the budget line; writes nothing",
    )))),
    responses(
        (status = 200, description = "Whether the spend fits the project's budget line", body = SpendCheck),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks attome_project.update", body = ErrorResponse),
        (status = 404, description = "No such project, or budgets are not installed", body = ErrorResponse),
        (status = 422, description = "No budget line, or not an amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Checks a spend against the project's budget line.
///
/// The line is the finance budget line linked to the project; the answer
/// says whether the spend fits, warns or is blocked by the line's setting.
async fn post_spend_check(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<SpendBody>,
) -> Result<Json<SpendCheck>, AppError> {
    attome_records::entity_crud::read_record(&state, &ctx, "attome_project", id).await?;
    let amount = Decimal::from_str(body.amount.trim())
        .map_err(|_| AppError::Validation("amount: a decimal number".into()))?;
    Ok(Json(check_spend(&state, id, amount).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/projects/{id}/invoice-proposals",
    operation_id = "post_project_invoice_proposal",
    tag = "projects",
    params(("id" = Uuid, Path, description = "The project")),
    request_body = ProposalBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The invoice request billing holds", body = Proposal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks attome_project.update", body = ErrorResponse),
        (status = 404, description = "No such project, or project invoicing is not installed", body = ErrorResponse),
        (status = 422, description = "No account, an unaccepted deliverable or an unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Proposes an invoice for a project.
///
/// A milestone invoices one accepted deliverable; time and materials
/// invoices the billable approved hours not yet proposed. Billing makes the
/// draft invoice; a repeat never proposes the same work twice.
async fn post_proposal(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProposalBody>,
) -> Result<Json<Proposal>, AppError> {
    attome_records::entity_crud::read_record(&state, &ctx, "attome_project", id).await?;
    let proposal = propose(&state, &ctx, id, &body).await?;
    if proposal.request_id.is_some() {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(&state),
            attome_audit::BusinessEvent::new(
                "attome_project",
                id,
                attome_audit::AuditOperation::Create,
                "project.invoice_proposed",
                ctx.user_id,
            ),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
    }
    Ok(Json(proposal))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/projects/{id}/spend-check", post(post_spend_check))
        .route(
            "/api/v1/projects/{id}/invoice-proposals",
            post(post_proposal),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_spend_check, post_proposal),
    components(schemas(SpendBody, SpendCheck, ProposalBody, Proposal))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod budget_link_tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).expect("a number")
    }

    #[test]
    fn time_is_summed_per_person_at_their_rate() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let entries = [
            (a, d("3")),
            (b, d("2.5")),
            (a, d("4.5")),
            (c, d("1")),
            (b, d("0")),
        ];
        let rates: BTreeMap<Uuid, Decimal> = [(a, d("200")), (b, d("150"))].into_iter().collect();
        let (lines, unrated) = time_lines(&entries, &rates);
        assert_eq!(
            lines,
            vec![
                TimeLine {
                    user: a,
                    hours: d("7.5"),
                    rate: d("200")
                },
                TimeLine {
                    user: b,
                    hours: d("2.5"),
                    rate: d("150")
                },
            ]
        );
        assert_eq!(unrated, vec![c], "no rate: left out and named");
    }

    #[test]
    fn only_an_accepted_deliverable_with_an_amount_is_a_milestone() {
        assert_eq!(
            milestone_ready(Some("accepted"), Some(d("5000"))),
            Ok(d("5000"))
        );
        assert!(milestone_ready(Some("submitted"), Some(d("5000"))).is_err());
        assert!(milestone_ready(Some("accepted"), None).is_err());
        assert!(milestone_ready(Some("accepted"), Some(d("0"))).is_err());
    }
}
