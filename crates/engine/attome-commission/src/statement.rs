//! Statement and estimator reads (roadmap F10-T6).
//!
//! A statement for a period is its statement lines, manual adjustments and
//! clawbacks (credits reversing an earlier credit), newest run first. Who
//! sees which rows is the record rules of the commission roles (F10-T13):
//! each source is filtered by the caller's read depth on its own entity, so
//! a seller sees their own rows, a manager their team's, and sales ops and
//! finance everything. Amounts are left out for a caller without the
//! amount field's grant.
//!
//! The estimate evaluates the caller's published plan for one of their own
//! open opportunities in the current open period, in memory, and writes
//! nothing.

use attome_core::EngineState;
use attome_security::{
    RecordAction, bind_rls_predicate, field_gate, resolve_entity_access_level, rls_predicate,
};
use attome_server::{
    authz::{Authorized, Privilege, PrivilegeKey},
    security::SecurityContext,
};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::rules::{Credit, evaluate};

/// `comp_statement_line.read`: may read commission statements.
#[derive(Debug)]
pub struct StatementRead;

impl PrivilegeKey for StatementRead {
    const KEY: &'static str = "comp_statement_line.read";
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MyStatementQuery {
    pub period_id: Uuid,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatementQuery {
    pub period_id: Uuid,
    /// Only this participant's rows.
    pub participant_id: Option<Uuid>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// One row of a statement.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CommissionStatementRow {
    pub id: Uuid,
    /// `line`, `adjustment` or `clawback`.
    pub kind: String,
    pub participant_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub component_id: Option<Uuid>,
    pub credit_id: Option<Uuid>,
    /// Absent when the caller may not see pay amounts.
    pub amount: Option<String>,
    /// A line's explanation steps; an adjustment's reason.
    pub explanation: Option<serde_json::Value>,
}

/// The three sources of a statement and the entity each reads.
const SOURCES: [(&str, &str); 3] = [
    (
        "comp_statement_line",
        "SELECT s.id, 'line' AS kind, s.participant_ref, s.run_ref, s.component_ref, \
                s.credit_ref, s.amount::text AS amount, s.explanation AS note, s.created_at \
         FROM comp_statement_line s JOIN comp_run r ON r.id = s.run_ref \
         WHERE r.period_ref = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    ),
    (
        "comp_adjustment",
        "SELECT s.id, 'adjustment', s.participant_ref, NULL::uuid, NULL::uuid, NULL::uuid, \
                s.amount::text, s.reason, s.created_at \
         FROM comp_adjustment s \
         WHERE s.period_ref = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    ),
    (
        "comp_credit",
        "SELECT s.id, 'clawback', s.participant_ref, NULL::uuid, NULL::uuid, s.id, \
                s.amount::text, NULL::text, s.created_at \
         FROM comp_credit s \
         WHERE s.period_ref = $1 AND s.reverses_credit_ref IS NOT NULL \
           AND (s.is_active IS NULL OR s.is_active = true)",
    ),
];

/// The caller's view of one source: its entity id, the record-rule
/// predicate (none for a global reader), and whether amounts show.
struct Scope {
    predicate: Option<attome_security::RlsPredicate>,
    amounts: bool,
}

async fn scope(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    first_placeholder: usize,
) -> Result<Option<Scope>, AppError> {
    let (entity_id, amount_attr, primary) = {
        let registry = state.entities.load();
        let Some(meta) = registry.get(entity) else {
            return Ok(None);
        };
        (
            meta.entity_id,
            meta.attrs
                .iter()
                .find(|a| a.logicalname == "amount")
                .cloned(),
            meta.primary_name_attribute.clone(),
        )
    };
    let level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity,
        RecordAction::Read,
    )
    .await?;
    let predicate = rls_predicate(
        ctx,
        entity_id,
        "s",
        level,
        RecordAction::Read.share_capability(),
        first_placeholder,
    );
    let amounts = amount_attr.is_some_and(|attr| {
        field_gate::readable(
            ctx,
            entity,
            &attr,
            primary.as_deref(),
            field_gate::Surface::Interactive,
        )
    });
    Ok(Some(Scope { predicate, amounts }))
}

type RawRow = (
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

async fn statement(
    state: &EngineState,
    ctx: &SecurityContext,
    period: Uuid,
    owner: Option<Uuid>,
    participant: Option<Uuid>,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<CommissionStatementRow>, AppError> {
    let window = page.window();
    // $1 period, $2 owner filter, $3 participant filter; each source's
    // record-rule binds follow.
    let mut next = 4;
    let mut parts = Vec::new();
    let mut scopes = Vec::new();
    for (entity, select) in SOURCES {
        let Some(scope) = scope(state, ctx, entity, next).await? else {
            continue;
        };
        let rls = scope.predicate.as_ref().map_or("", |p| p.sql.as_str());
        parts.push(format!(
            "{select} AND ($2::uuid IS NULL OR s.owner_ref = $2) \
             AND ($3::uuid IS NULL OR s.participant_ref = $3) {rls}"
        ));
        if scope.predicate.is_some() {
            next += attome_security::RLS_BIND_COUNT;
        }
        scopes.push((entity, scope));
    }
    if parts.is_empty() {
        return Ok(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        ));
    }
    let union = parts.join(" UNION ALL ");
    let count_sql = format!("SELECT COUNT(*) FROM ({union}) u");
    let rows_sql = format!(
        "SELECT row_to_json(u) FROM ({union}) u ORDER BY u.created_at DESC, u.id \
         LIMIT ${next} OFFSET ${}",
        next + 1
    );
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(period)
        .bind(owner)
        .bind(participant);
    let mut rows = sqlx::query_scalar::<_, serde_json::Value>(&rows_sql)
        .bind(period)
        .bind(owner)
        .bind(participant);
    for (_, scope) in &scopes {
        if let Some(p) = &scope.predicate {
            count = bind_rls_predicate(count, &p.binds);
            rows = bind_rls_predicate(rows, &p.binds);
        }
    }
    let total = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let rows = rows
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let amounts_for = |kind: &str| {
        let entity = match kind {
            "line" => "comp_statement_line",
            "adjustment" => "comp_adjustment",
            _ => "comp_credit",
        };
        scopes.iter().any(|(e, s)| *e == entity && s.amounts)
    };
    let items = rows
        .into_iter()
        .filter_map(|row| row_from_json(&row))
        .map(
            |(id, kind, participant, run, component, credit, amount, note)| {
                let explanation = note.map(|n| match kind.as_str() {
                    "line" => serde_json::from_str(&n).unwrap_or(serde_json::Value::String(n)),
                    _ => serde_json::Value::String(n),
                });
                CommissionStatementRow {
                    id,
                    amount: amount.filter(|_| amounts_for(&kind)),
                    kind,
                    participant_id: participant,
                    run_id: run,
                    component_id: component,
                    credit_id: credit,
                    explanation,
                }
            },
        )
        .collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

fn row_from_json(row: &serde_json::Value) -> Option<RawRow> {
    let uuid = |key: &str| row.get(key)?.as_str().and_then(|s| Uuid::parse_str(s).ok());
    let text = |key: &str| row.get(key)?.as_str().map(str::to_owned);
    Some((
        uuid("id")?,
        text("kind")?,
        uuid("participant_ref"),
        uuid("run_ref"),
        uuid("component_ref"),
        uuid("credit_ref"),
        text("amount"),
        text("note"),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/commission/statements/me",
    tag = "commission",
    params(MyStatementQuery),
    responses(
        (status = 200, description = "The caller's statement for the period", body = PaginatedResponse<CommissionStatementRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_statement_line.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_my_statement(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StatementRead>>,
    Query(q): Query<MyStatementQuery>,
) -> Result<Json<PaginatedResponse<CommissionStatementRow>>, AppError> {
    let page = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    };
    Ok(Json(
        statement(&state, &ctx, q.period_id, Some(ctx.user_id), None, &page).await?,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/commission/statements",
    tag = "commission",
    params(StatementQuery),
    responses(
        (status = 200, description = "The statements the caller may read for the period: a manager's team, or everyone for sales ops and finance", body = PaginatedResponse<CommissionStatementRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_statement_line.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_statements(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StatementRead>>,
    Query(q): Query<StatementQuery>,
) -> Result<Json<PaginatedResponse<CommissionStatementRow>>, AppError> {
    let page = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    };
    Ok(Json(
        statement(&state, &ctx, q.period_id, None, q.participant_id, &page).await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommissionEstimateBody {
    pub opportunity_id: Uuid,
}

/// What one opportunity would pay if it closed now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionEstimate {
    pub period_id: Uuid,
    pub participant_id: Uuid,
    /// The opportunity's own payout across the plan's components.
    #[schema(value_type = String)]
    pub payout: Decimal,
    /// How the period's total changes with it (more than `payout` when it
    /// lifts every credit into a higher retroactive band).
    #[schema(value_type = String)]
    pub period_change: Decimal,
}

/// The estimate, pure: the opportunity's own payout and the change in the
/// period total, given the period's credits and quota.
pub fn estimate_amounts(
    components: &[crate::rules::Component],
    credits: &[Credit],
    quota: Decimal,
    opportunity: Credit,
) -> (Decimal, Decimal) {
    let mut with = credits.to_vec();
    with.push(opportunity.clone());
    let total = |set: &[Credit]| -> Decimal {
        components
            .iter()
            .flat_map(|c| evaluate(c, set, quota))
            .map(|l| l.payout)
            .sum()
    };
    let own: Decimal = components
        .iter()
        .flat_map(|c| evaluate(c, &with, quota))
        .filter(|l| l.credit == opportunity.id)
        .map(|l| l.payout)
        .sum();
    (own, total(&with) - total(credits))
}

type ParticipantRow = (Uuid, Uuid);

#[utoipa::path(
    post,
    path = "/api/v1/commission/estimate",
    tag = "commission",
    request_body = CommissionEstimateBody,
    responses(
        (status = 200, description = "What the opportunity would pay in the current period", body = CommissionEstimate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_statement_line.read, or the opportunity is not theirs", body = ErrorResponse),
        (status = 404, description = "No such opportunity, no open period, or the caller is on no published plan", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "read-only estimate",
    )))),
)]
pub(crate) async fn post_estimate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StatementRead>>,
    Json(body): Json<CommissionEstimateBody>,
) -> Result<Json<CommissionEstimate>, AppError> {
    let db = &state.base.db;
    let opportunity: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT owner_ref, amount::text FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(body.opportunity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((owner, amount)) = opportunity else {
        return Err(AppError::NotFound);
    };
    if owner != Some(ctx.user_id) {
        return Err(AppError::Forbidden);
    }
    let today = Utc::now().date_naive();
    let period: Option<(Uuid, NaiveDate, NaiveDate)> = sqlx::query_as(
        "SELECT id, starts_on::date, ends_on::date FROM comp_period \
         WHERE (status IS NULL OR status = 'open') AND starts_on::date <= $1 \
           AND ends_on::date >= $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY starts_on DESC LIMIT 1",
    )
    .bind(today)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((period, starts, ends)) = period else {
        return Err(AppError::NotFound);
    };
    let participant: Option<ParticipantRow> = sqlx::query_as(
        "SELECT p.id, p.plan_version_ref FROM plan_participant p \
         JOIN comp_plan_version v ON v.id = p.plan_version_ref \
         WHERE p.user_ref = $1 AND v.published_at IS NOT NULL \
           AND (p.is_active IS NULL OR p.is_active = true) \
           AND (v.is_active IS NULL OR v.is_active = true) \
           AND (p.starts_on IS NULL OR p.starts_on::date <= $2) \
           AND (p.ends_on IS NULL OR p.ends_on::date >= $2) \
         ORDER BY v.published_at DESC, p.id LIMIT 1",
    )
    .bind(ctx.user_id)
    .bind(today)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((participant, version)) = participant else {
        return Err(AppError::NotFound);
    };
    let components = crate::run::components(&state, version)
        .await
        .map_err(AppError::Validation)?;
    let (credits, quota) =
        crate::run::inputs(db, participant, Some(ctx.user_id), period, starts, ends).await?;
    let opportunity = Credit {
        id: Uuid::now_v7(),
        deal: body.opportunity_id,
        amount: amount
            .as_deref()
            .and_then(|a| a.parse().ok())
            .unwrap_or(Decimal::ZERO),
        margin_pct: None,
    };
    let (payout, period_change) = estimate_amounts(&components, &credits, quota, opportunity);
    Ok(Json(CommissionEstimate {
        period_id: period,
        participant_id: participant,
        payout,
        period_change,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_my_statement, get_statements, post_estimate),
    components(schemas(CommissionStatementRow, CommissionEstimateBody, CommissionEstimate))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Band, Component, TierMode};

    fn component(mode: TierMode) -> Component {
        Component {
            id: Uuid::from_u128(1),
            bands: vec![
                Band {
                    from_pct: Decimal::ZERO,
                    to_pct: Some(Decimal::from(100)),
                    rate_pct: Decimal::from(5),
                },
                Band {
                    from_pct: Decimal::from(100),
                    to_pct: None,
                    rate_pct: Decimal::from(10),
                },
            ],
            mode,
            gate_pct: None,
            margin_floor_pct: None,
            cap_per_deal: None,
            cap_per_period: None,
            minor_units: 2,
        }
    }

    fn credit(id: u128, amount: i64) -> Credit {
        Credit {
            id: Uuid::from_u128(id),
            deal: Uuid::from_u128(id + 100),
            amount: Decimal::from(amount),
            margin_pct: None,
        }
    }

    #[test]
    fn an_estimate_below_the_next_band_changes_only_its_own_pay() {
        let components = [component(TierMode::Retroactive)];
        let (own, change) = estimate_amounts(
            &components,
            &[credit(1, 200)],
            Decimal::from(1000),
            credit(2, 100),
        );
        assert_eq!(own, Decimal::from(5));
        assert_eq!(change, own);
    }

    #[test]
    fn an_estimate_that_crosses_a_retroactive_band_lifts_the_period() {
        let components = [component(TierMode::Retroactive)];
        let (own, change) = estimate_amounts(
            &components,
            &[credit(1, 900)],
            Decimal::from(1000),
            credit(2, 200),
        );
        assert_eq!(own, Decimal::from(20));
        // 900 moves from 5% to 10%: +45, plus the new 20.
        assert_eq!(change, Decimal::from(65));
    }
}
