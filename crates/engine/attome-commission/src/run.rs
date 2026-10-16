//! The commission calculation run (roadmap F10-T5): one `comp_run` computes a
//! plan version's statements for one period. Participants are processed in
//! batches of [`BATCH`] in id order; each participant is one transaction
//! that replaces this run's earlier lines for them, writes a
//! `comp_statement_line` per computed credit and component, and one
//! `comp_payout`, then moves the run's `cursor` to that participant, so a
//! run stopped half way resumes where it left off.
//!
//! Lines and payouts are owned by the participant's user, so the owner-only
//! record rules of the commission roles (F10-T13) show each seller their own
//! and a manager their team's.
//!
//! A participant's quota is their `revenue` sales quota for the period (none
//! is zero: attainment is then 0 and band rules see it as such).

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rules::{Band, Component, Credit, TierMode, compile, evaluate};

/// Participants per batch.
pub const BATCH: i64 = 200;

/// `comp_run.create`: may start a calculation run.
#[derive(Debug)]
pub struct CompRunCreate;

impl PrivilegeKey for CompRunCreate {
    const KEY: &'static str = "comp_run.create";
}

fn dec(text: Option<&str>) -> Option<Decimal> {
    text.and_then(|t| t.trim().parse().ok())
}

/// Reads a rate table: `[{"from": 0, "to": 100, "rate": 5}, ...]`, `to`
/// absent or null for the open top band.
pub fn parse_rate_table(text: &str) -> Result<Vec<Band>, String> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(text).map_err(|e| format!("rate_table is not a JSON list: {e}"))?;
    rows.iter()
        .enumerate()
        .map(|(i, row)| {
            let num = |key: &str| -> Option<Decimal> {
                match row.get(key)? {
                    serde_json::Value::Number(n) => n.to_string().parse().ok(),
                    serde_json::Value::String(s) => s.parse().ok(),
                    _ => None,
                }
            };
            Ok(Band {
                from_pct: num("from").ok_or(format!("rate_table row {i} has no from"))?,
                to_pct: num("to"),
                rate_pct: num("rate").ok_or(format!("rate_table row {i} has no rate"))?,
            })
        })
        .collect()
}

type ComponentRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The plan version's components, compiled; why not when one fails.
pub(crate) async fn components(
    state: &EngineState,
    version: Uuid,
) -> Result<Vec<Component>, String> {
    let rows: Vec<ComponentRow> = sqlx::query_as(
        "SELECT id, rate_table, tier_mode, cap_per_deal::text, cap_per_period::text, \
                gate_attainment_percent::text, floor_margin_percent::text \
         FROM comp_component WHERE plan_version_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY id",
    )
    .bind(version)
    .fetch_all(&state.base.db)
    .await
    .map_err(|e| format!("reading the plan's components failed: {e}"))?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, table, mode, cap_deal, cap_period, gate, floor) in rows {
        let component = Component {
            id,
            bands: parse_rate_table(table.as_deref().unwrap_or("[]"))?,
            mode: if mode.as_deref() == Some("marginal") {
                TierMode::Marginal
            } else {
                TierMode::Retroactive
            },
            gate_pct: dec(gate.as_deref()),
            margin_floor_pct: dec(floor.as_deref()),
            cap_per_deal: dec(cap_deal.as_deref()),
            cap_per_period: dec(cap_period.as_deref()),
            minor_units: 2,
        };
        compile(&component).map_err(|e| format!("component {id} does not compile: {e:?}"))?;
        out.push(component);
    }
    Ok(out)
}

async fn set_status(state: &EngineState, run: Uuid, status: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE comp_run SET status = $2, \
             finished_at = CASE WHEN $2 IN ('done', 'failed') THEN now() ELSE finished_at END, \
             started_at = COALESCE(started_at, now()), modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(run)
    .bind(status)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

type RunRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    NaiveDate,
    NaiveDate,
);

/// Runs (or resumes) one calculation run; the number of participants
/// processed in this call.
pub async fn execute(state: &EngineState, run: Uuid) -> Result<u64, AppError> {
    let row: Option<RunRow> = sqlx::query_as(
        "SELECT r.period_ref, r.plan_version_ref, r.status, r.cursor, \
                p.starts_on::date, p.ends_on::date \
         FROM comp_run r JOIN comp_period p ON p.id = r.period_ref WHERE r.id = $1",
    )
    .bind(run)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((period, version, status, cursor, starts, ends)) = row else {
        return Ok(0);
    };
    if matches!(status.as_deref(), Some("done" | "failed")) {
        return Ok(0);
    }
    set_status(state, run, "running").await?;
    let components = match components(state, version).await {
        Ok(c) => c,
        Err(reason) => {
            tracing::warn!(%run, reason, "commission run: the plan does not compile");
            set_status(state, run, "failed").await?;
            return Ok(0);
        }
    };
    let mut after = cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok())
        .unwrap_or(Uuid::nil());
    let mut processed = 0;
    loop {
        let participants: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, user_ref FROM plan_participant \
             WHERE plan_version_ref = $1 AND id > $2 AND (is_active IS NULL OR is_active = true) \
             ORDER BY id LIMIT $3",
        )
        .bind(version)
        .bind(after)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = participants.last() else {
            break;
        };
        let full = participants.len() as i64 == BATCH;
        after = last.0;
        for (participant, user) in participants {
            pay_participant(
                state,
                run,
                period,
                participant,
                user,
                &components,
                starts,
                ends,
            )
            .await?;
            processed += 1;
        }
        if !full {
            break;
        }
    }
    set_status(state, run, "done").await?;
    Ok(processed)
}

#[expect(
    clippy::too_many_arguments,
    reason = "one participant's run context, passed straight through"
)]
async fn pay_participant(
    state: &EngineState,
    run: Uuid,
    period: Uuid,
    participant: Uuid,
    user: Option<Uuid>,
    components: &[Component],
    starts: NaiveDate,
    ends: NaiveDate,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let (credits, quota) = inputs(db, participant, user, period, starts, ends).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM comp_statement_line WHERE run_ref = $1 AND participant_ref = $2")
        .bind(run)
        .bind(participant)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM comp_payout WHERE run_ref = $1 AND participant_ref = $2")
        .bind(run)
        .bind(participant)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut total = Decimal::ZERO;
    for component in components {
        for line in evaluate(component, &credits, quota) {
            total += line.payout;
            let explanation: Vec<serde_json::Value> = line
                .steps
                .iter()
                .map(|s| {
                    let values: serde_json::Map<String, serde_json::Value> = s
                        .values
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String(v.clone())))
                        .collect();
                    serde_json::json!({ "key": s.key, "values": values })
                })
                .collect();
            sqlx::query(
                "INSERT INTO comp_statement_line \
                   (run_ref, participant_ref, component_ref, credit_ref, amount, explanation, \
                    owner_ref) \
                 VALUES ($1, $2, $3, $4, $5::numeric, $6, $7)",
            )
            .bind(run)
            .bind(participant)
            .bind(component.id)
            .bind(line.credit)
            .bind(line.payout.to_string())
            .bind(serde_json::Value::Array(explanation).to_string())
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }
    sqlx::query(
        "INSERT INTO comp_payout (run_ref, participant_ref, amount, status, owner_ref) \
         VALUES ($1, $2, $3::numeric, 'calculated', $4)",
    )
    .bind(run)
    .bind(participant)
    .bind(total.to_string())
    .bind(user)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("UPDATE comp_run SET cursor = $2 WHERE id = $1")
        .bind(run)
        .bind(participant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// A participant's credits in the period and their revenue quota for it.
pub(crate) async fn inputs(
    db: &attome_db::DbPool,
    participant: Uuid,
    user: Option<Uuid>,
    period: Uuid,
    starts: NaiveDate,
    ends: NaiveDate,
) -> Result<(Vec<Credit>, Decimal), AppError> {
    let credits: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, source_id, amount::text FROM comp_credit \
         WHERE participant_ref = $1 AND period_ref = $2 \
           AND (is_active IS NULL OR is_active = true) ORDER BY credited_on, id",
    )
    .bind(participant)
    .bind(period)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let credits: Vec<Credit> = credits
        .into_iter()
        .map(|(id, source, amount)| Credit {
            id,
            deal: source
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(id),
            amount: dec(amount.as_deref()).unwrap_or(Decimal::ZERO),
            margin_pct: None,
        })
        .collect();
    let quota: Decimal = match user {
        Some(user) => {
            let has_quota: bool =
                sqlx::query_scalar("SELECT to_regclass('sales_quota') IS NOT NULL")
                    .fetch_one(db)
                    .await
                    .map_err(AppError::internal)?;
            if has_quota {
                let text: Option<String> = sqlx::query_scalar(
                    "SELECT SUM(target)::text FROM sales_quota \
                     WHERE user_ref = $1 AND measure = 'revenue' \
                       AND period_start::date <= $3 AND period_end::date >= $2 \
                       AND (is_active IS NULL OR is_active = true)",
                )
                .bind(user)
                .bind(starts)
                .bind(ends)
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
                dec(text.as_deref()).unwrap_or(Decimal::ZERO)
            } else {
                Decimal::ZERO
            }
        }
        None => Decimal::ZERO,
    };
    Ok((credits, quota))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommissionRunBody {
    pub plan_version_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CommissionRunStarted {
    pub run_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/periods/{id}/runs",
    tag = "commission",
    params(("id" = Uuid, Path, description = "The commission period")),
    request_body = CommissionRunBody,
    responses(
        (status = 202, description = "The run is queued", body = CommissionRunStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_run.create", body = ErrorResponse),
        (status = 404, description = "No such period", body = ErrorResponse),
        (status = 409, description = "The period is approved or locked", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_run(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CompRunCreate>>,
    Path(period): Path<Uuid>,
    Json(body): Json<CommissionRunBody>,
) -> Result<(StatusCode, Json<CommissionRunStarted>), AppError> {
    let status: Option<Option<String>> = sqlx::query_scalar(
        "SELECT status FROM comp_period WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(period)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = status else {
        return Err(AppError::NotFound);
    };
    if matches!(status.as_deref(), Some("approved" | "locked")) {
        return Err(AppError::Conflict("the period is approved or locked"));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let run_id: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_run (period_ref, plan_version_ref, status, owner_ref) \
         VALUES ($1, $2, 'queued', $3) RETURNING id",
    )
    .bind(period)
    .bind(body.plan_version_id)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::CommissionRun { run_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "comp_run",
            run_id,
            attome_audit::AuditOperation::Create,
            "commission.run_started",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(CommissionRunStarted { run_id })))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_run),
    components(schemas(CommissionRunBody, CommissionRunStarted))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_tables_parse_numbers_and_open_bands() {
        let bands = parse_rate_table(
            r#"[{"from": 0, "to": 100, "rate": 5}, {"from": "100", "rate": 8.5}]"#,
        )
        .unwrap_or_default();
        assert_eq!(bands.len(), 2);
        assert_eq!(bands[0].to_pct, Some(Decimal::from(100)));
        assert_eq!(bands[1].to_pct, None);
        assert_eq!(bands[1].rate_pct, Decimal::new(85, 1));
        assert!(parse_rate_table("[{\"to\": 5}]").is_err());
        assert!(parse_rate_table("not json").is_err());
    }
}
