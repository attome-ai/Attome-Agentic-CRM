//! F11-T8 (V2-D1610 (1)): a close posted to an ERP's ledger instead of
//! Attome's.
//!
//! With [`TARGET_SETTING`] set to `connector:<integration system id>`,
//! posting an approved close (`close::post_close`) writes no journal entry
//! here: it locks the month's lines, marks the close posted, and queues
//! [`JOB`] in the same transaction. The job sends the close's balanced
//! entries (one per product: the `revrec_close` posting rule's debit and
//! credit account codes, the month's last day) to that system through the
//! REST connector, past the system's rate limit (`guard::outbound`), with
//! the `Idempotency-Key` `revrec-close:<close id>`, so a retried job is the
//! same request and the ERP takes it once. A refusal fails the job, which
//! retries. This is the one thing written back to an ERP; everything else
//! stays pull-only.

use std::str::FromStr;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// Where a close posts: `ledger` (the default) or `connector:<id>`.
pub const TARGET_SETTING: &str = "revrec.posting_target";
/// The job that sends a close to the ERP.
pub const JOB: &str = "revrec_erp_post";

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErpPostPayload {
    pub run_id: Uuid,
}

/// The integration system a target names; `None` for Attome's ledger.
/// Pure.
pub fn parse_target(value: &str) -> Option<Uuid> {
    value
        .trim()
        .strip_prefix("connector:")
        .and_then(|id| Uuid::parse_str(id.trim()).ok())
}

/// The ERP system this deployment posts closes to, if any.
pub fn target(state: &EngineState) -> Option<Uuid> {
    attome_core::setting_registry()
        .get(TARGET_SETTING)
        .and_then(|d| {
            state
                .settings
                .load()
                .resolve(d, None, None)
                .0
                .as_str()
                .map(str::to_owned)
        })
        .as_deref()
        .and_then(parse_target)
}

/// The key the ERP dedupes a close by. Pure.
pub fn idempotency_key(run: Uuid) -> String {
    format!("revrec-close:{run}")
}

/// The request a close sends: one balanced entry per product. Pure.
pub fn journal_event(
    run: Uuid,
    period: &str,
    date: NaiveDate,
    debit: &str,
    credit: &str,
    amounts: &[(String, Decimal)],
) -> Value {
    let entries: Vec<Value> = amounts
        .iter()
        .map(|(product, amount)| {
            json!({
                "reference": format!("revrec_close:{period}:{product}"),
                "date": date,
                "description": format!("Revenue recognised in {period}"),
                "lines": [
                    { "account": debit, "debit": amount.to_string(), "credit": "0" },
                    { "account": credit, "debit": "0", "credit": amount.to_string() },
                ],
            })
        })
        .collect();
    json!({
        "kind": "journal_entries",
        "close_id": run,
        "period": period,
        "entries": entries,
    })
}

/// The month's locked revenue by product, as the close posted it.
pub async fn amounts(
    state: &EngineState,
    period: &str,
) -> Result<Vec<(String, Decimal)>, AppError> {
    let rows: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT o.product_ref, sum(s.amount_contract_ccy)::text \
           FROM revenue_schedule_line s JOIN performance_obligation o ON o.id = s.obligation_ref \
          WHERE s.fiscal_period = $1 AND s.status::text = 'locked' \
            AND (s.is_active IS NULL OR s.is_active = true) \
          GROUP BY o.product_ref ORDER BY o.product_ref NULLS LAST",
    )
    .bind(period)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(product, amount)| {
            let amount = amount.and_then(|a| Decimal::from_str(&a).ok())?;
            (!amount.is_zero()).then(|| {
                (
                    product.map_or_else(|| "none".to_owned(), |p| p.to_string()),
                    amount,
                )
            })
        })
        .collect())
}

/// Sends close `run` to the ERP; whether the ERP took it.
pub async fn send(state: &EngineState, run: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let Some(system_id) = target(state) else {
        return Ok(false);
    };
    let period: String =
        sqlx::query_scalar("SELECT fiscal_period FROM revrec_close_run WHERE id = $1")
            .bind(run)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let (_, last) = super::close::month_bounds(&period)
        .ok_or_else(|| AppError::internal("bad close period"))?;
    let accounts: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT d.code, c.code FROM gl_posting_rule r \
           LEFT JOIN gl_account d ON d.id = r.debit_account_ref \
           LEFT JOIN gl_account c ON c.id = r.credit_account_ref \
          WHERE r.source_kind = $1 AND (r.is_active IS NULL OR r.is_active = true) \
          ORDER BY r.id LIMIT 1",
    )
    .bind(super::close::SOURCE_KIND)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (Some(debit), Some(credit)) = accounts.unwrap_or((None, None)) else {
        return Err(AppError::Validation(
            "no revrec_close posting rule names both accounts".into(),
        ));
    };
    let event = journal_event(
        run,
        &period,
        last,
        &debit,
        &credit,
        &amounts(state, &period).await?,
    );
    let system = attome_integration::system::load(db, system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ring = state.base.secrets.load().integration_credential_key.clone();
    let credential =
        attome_integration::credential::resolve(db, &ring, system.credential_ref.as_deref())
            .await?;
    let key = idempotency_key(run);
    let pushed = attome_types::request_scope::with_idempotency_key(Some(&key), async {
        attome_integration::guard::outbound(
            &state.base.redis_coordination,
            &system,
            attome_integration::connector::ConnectorKind::Rest,
        )
        .await?
        .push(&system, credential.as_ref(), &event)
        .await
    })
    .await?;
    if !pushed.ok {
        return Err(AppError::internal(format!(
            "the ERP refused the close: {}",
            pushed.detail.unwrap_or_default()
        )));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erp_target_and_entries() {
        let id = Uuid::from_u128(7);
        assert_eq!(parse_target(&format!("connector:{id}")), Some(id));
        assert_eq!(parse_target("ledger"), None);
        assert_eq!(parse_target("connector:nope"), None);
        assert_eq!(idempotency_key(id), format!("revrec-close:{id}"));
        let event = journal_event(
            id,
            "2027-01",
            NaiveDate::from_ymd_opt(2027, 1, 31).unwrap(),
            "2400",
            "4000",
            &[("p1".into(), Decimal::from(100))],
        );
        let entry = &event["entries"][0];
        assert_eq!(entry["lines"][0]["debit"], "100");
        assert_eq!(entry["lines"][1]["credit"], "100");
        assert_eq!(entry["reference"], "revrec_close:2027-01:p1");
    }
}
