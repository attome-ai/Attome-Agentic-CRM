//! W5-T1: the posting engine.
//!
//! **Entries.** A journal entry (`gl_entry`, ledger pack) and its lines
//! (`gl_entry_line`) are append-only: [`post_journal`] writes them once, in one
//! transaction, and nothing updates them; a correction is another entry.
//! An entry is refused (`422`) unless:
//!
//! - it has at least two lines, each a debit or a credit (not both, not
//!   zero), in exact decimals with at most four places;
//! - debits equal credits ([`check_lines`]);
//! - every account exists, is active and is postable (not a heading);
//! - its date falls in an **open** period (`gl_period`).
//!
//! **Once per source.** An entry made from a source document carries
//! `source_kind` and `source_ref`; posting the same source again answers the
//! entry already made, under the advisory lock
//! `attome-ledger/post:{source_kind}:{source_ref}`.
//!
//! **Posting rules.** A `gl_posting_rule` maps a source kind (an invoice, a
//! payment, a vendor bill, ...) to the account debited and the account
//! credited; [`post_from_rule`] turns a source document's amount into that
//! balanced entry ([`rule_lines`]). Billing, payments, procurement and
//! budgets call it as their own tasks wire them in.
//!
//! **Periods.** `POST /api/v1/ledger/periods/{id}/close` and `/reopen`
//! change a period's status with an audit event in the same transaction; a
//! closed period takes no entries.

use std::collections::HashSet;
use std::str::FromStr;

use attome_core::EngineState;
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

/// Most lines one entry has.
pub const MAX_LINES: usize = 500;
/// Most decimal places an amount has.
pub const MAX_SCALE: u32 = 4;

/// `gl_entry.create`: who posts.
#[derive(Debug)]
pub struct EntryCreate;

impl PrivilegeKey for EntryCreate {
    const KEY: &'static str = "gl_entry.create";
}

/// `gl_period.update`: who closes and reopens periods.
#[derive(Debug)]
pub struct PeriodUpdate;

impl PrivilegeKey for PeriodUpdate {
    const KEY: &'static str = "gl_period.update";
}

/// One line to post. Amounts are decimal strings.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct NewLine {
    pub account_id: Uuid,
    #[serde(default)]
    pub debit: Option<String>,
    #[serde(default)]
    pub credit: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// An entry to post.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewEntry {
    pub journal_id: Uuid,
    pub entry_date: NaiveDate,
    pub description: Option<String>,
    /// The source document's kind and id; posting the same pair again
    /// answers the entry already made.
    pub source_kind: Option<String>,
    pub source_ref: Option<String>,
    pub lines: Vec<NewLine>,
}

/// A checked line: `(account, debit, credit, memo)`.
pub type CheckedLine = (Uuid, Decimal, Decimal, Option<String>);

fn amount(raw: Option<&str>, at: usize, side: &str) -> Result<Decimal, String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(Decimal::ZERO);
    };
    let d = Decimal::from_str(raw).map_err(|_| format!("lines[{at}].{side}: not a number"))?;
    if d.is_sign_negative() {
        return Err(format!("lines[{at}].{side}: not negative"));
    }
    if d.scale() > MAX_SCALE {
        return Err(format!(
            "lines[{at}].{side}: at most {MAX_SCALE} decimal places"
        ));
    }
    Ok(d)
}

/// Checks an entry's lines: two or more, each one side only and not zero,
/// and debits equal to credits. Answers the lines in exact decimals. Pure.
pub fn check_lines(lines: &[NewLine]) -> Result<Vec<CheckedLine>, String> {
    if lines.len() < 2 {
        return Err("lines: an entry has at least two lines".into());
    }
    if lines.len() > MAX_LINES {
        return Err(format!("lines: at most {MAX_LINES}"));
    }
    let mut out = Vec::with_capacity(lines.len());
    let (mut debits, mut credits) = (Decimal::ZERO, Decimal::ZERO);
    for (i, line) in lines.iter().enumerate() {
        let debit = amount(line.debit.as_deref(), i, "debit")?;
        let credit = amount(line.credit.as_deref(), i, "credit")?;
        match (debit.is_zero(), credit.is_zero()) {
            (true, true) => return Err(format!("lines[{i}]: a debit or a credit")),
            (false, false) => return Err(format!("lines[{i}]: a debit or a credit, not both")),
            _ => {}
        }
        debits += debit;
        credits += credit;
        out.push((line.account_id, debit, credit, line.memo.clone()));
    }
    if debits != credits {
        return Err(format!(
            "lines: unbalanced, debits {debits} and credits {credits}"
        ));
    }
    Ok(out)
}

/// The two lines a posting rule makes of a source document's amount. Pure.
pub fn rule_lines(
    debit_account: Uuid,
    credit_account: Uuid,
    amount: Decimal,
    memo: &str,
) -> Vec<NewLine> {
    let a = amount.abs().round_dp(MAX_SCALE).to_string();
    // A negative amount (a credit note, a refund) posts the other way round.
    let (dr, cr) = if amount.is_sign_negative() {
        (credit_account, debit_account)
    } else {
        (debit_account, credit_account)
    };
    vec![
        NewLine {
            account_id: dr,
            debit: Some(a.clone()),
            credit: None,
            memo: Some(memo.to_owned()),
        },
        NewLine {
            account_id: cr,
            debit: None,
            credit: Some(a),
            memo: Some(memo.to_owned()),
        },
    ]
}

/// The posted entry.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Posted {
    pub entry_id: Uuid,
    pub period_id: Uuid,
    /// False when the source was posted before and this is that entry.
    pub created: bool,
    pub total: String,
}

/// Posts one balanced entry as `ctx`, or answers the entry its source
/// already made.
pub async fn post_journal(
    state: &EngineState,
    ctx: &SecurityContext,
    entry: &NewEntry,
) -> Result<Posted, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('gl_entry') IS NOT NULL AND to_regclass('gl_entry_line') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    let lines = check_lines(&entry.lines).map_err(AppError::Validation)?;
    let source = match (entry.source_kind.as_deref(), entry.source_ref.as_deref()) {
        (Some(k), Some(r)) if !k.trim().is_empty() && !r.trim().is_empty() => {
            Some((k.trim().to_owned(), r.trim().to_owned()))
        }
        (None, None) => None,
        _ => {
            return Err(AppError::Validation(
                "source_kind and source_ref go together".into(),
            ));
        }
    };

    let mut tx = attome_db::tx::begin(db).await?;
    if let Some((kind, reference)) = &source {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-ledger/post:{kind}:{reference}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict("this source is being posted"));
        }
        let earlier: Option<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
            "SELECT id, period_ref, total::text FROM gl_entry \
              WHERE source_kind = $1 AND source_ref = $2 \
                AND (is_active IS NULL OR is_active = true) LIMIT 1",
        )
        .bind(kind)
        .bind(reference)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if let Some((id, period, total)) = earlier {
            return Ok(Posted {
                entry_id: id,
                period_id: period.unwrap_or_default(),
                created: false,
                total: total.unwrap_or_default(),
            });
        }
    }
    let journal: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM gl_journal WHERE id = $1 \
            AND (is_active IS NULL OR is_active = true))",
    )
    .bind(entry.journal_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !journal {
        return Err(AppError::Validation("journal_id: no such journal".into()));
    }
    let period: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, status::text FROM gl_period \
          WHERE starts_on::date <= $1 AND ends_on::date >= $1 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY starts_on DESC LIMIT 1 FOR SHARE",
    )
    .bind(entry.entry_date)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((period, status)) = period else {
        return Err(AppError::Validation(format!(
            "entry_date: no period covers {}",
            entry.entry_date
        )));
    };
    if status.as_deref() != Some("open") {
        return Err(AppError::Validation(format!(
            "entry_date: the period holding {} is closed",
            entry.entry_date
        )));
    }
    let accounts: Vec<Uuid> = lines
        .iter()
        .map(|l| l.0)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let postable: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM gl_account WHERE id = ANY($1) AND COALESCE(is_postable, true) \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&accounts)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(bad) = accounts.iter().find(|a| !postable.contains(a)) {
        return Err(AppError::Validation(format!(
            "lines: account {bad} does not exist or takes no postings"
        )));
    }
    let total: Decimal = lines.iter().map(|l| l.1).sum();
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO gl_entry (id, journal_ref, period_ref, entry_date, description, source_kind, \
             source_ref, total, status, created_by, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, 'posted', $9, $9) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(entry.journal_id)
    .bind(period)
    .bind(entry.entry_date)
    .bind(entry.description.as_deref().map(str::trim))
    .bind(source.as_ref().map(|s| s.0.clone()))
    .bind(source.as_ref().map(|s| s.1.clone()))
    .bind(total.to_string())
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for (i, (account, debit, credit, memo)) in lines.iter().enumerate() {
        sqlx::query(
            "INSERT INTO gl_entry_line (id, entry_ref, line_no, account_ref, debit, credit, memo, \
                 created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, $5::numeric, $6::numeric, $7, $8, $8)",
        )
        .bind(Uuid::now_v7())
        .bind(entry_id)
        .bind(i64::try_from(i + 1).unwrap_or(i64::MAX))
        .bind(account)
        .bind(debit.to_string())
        .bind(credit.to_string())
        .bind(memo.as_deref())
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "gl_entry",
            entry_id,
            attome_audit::AuditOperation::Create,
            "ledger.entry_posted",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Posted {
        entry_id,
        period_id: period,
        created: true,
        total: total.to_string(),
    })
}

/// `(journal, debit account, credit account, description)`.
type RuleRow = (Option<Uuid>, Option<Uuid>, Option<Uuid>, Option<String>);

/// A source document to post through its rule.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SourcePosting {
    pub source_kind: String,
    pub source_ref: String,
    /// A decimal string; negative posts the rule the other way round.
    pub amount: String,
    pub entry_date: NaiveDate,
    pub description: Option<String>,
}

/// Posts a source document through the active rule for its kind.
pub async fn post_from_rule(
    state: &EngineState,
    ctx: &SecurityContext,
    source: &SourcePosting,
) -> Result<Posted, AppError> {
    let amount = Decimal::from_str(source.amount.trim())
        .ok()
        .filter(|a| !a.is_zero())
        .ok_or_else(|| AppError::Validation("amount: a number other than zero".into()))?;
    let rule: Option<RuleRow> = sqlx::query_as(
        "SELECT journal_ref, debit_account_ref, credit_account_ref, description \
           FROM gl_posting_rule WHERE source_kind = $1 \
            AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT 1",
    )
    .bind(source.source_kind.trim())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(journal), Some(debit), Some(credit), rule_text)) = rule else {
        return Err(AppError::Validation(format!(
            "source_kind: no complete posting rule for {}",
            source.source_kind.trim()
        )));
    };
    let memo =
        source.description.clone().or(rule_text).unwrap_or_else(|| {
            format!("{} {}", source.source_kind.trim(), source.source_ref.trim())
        });
    post_journal(
        state,
        ctx,
        &NewEntry {
            journal_id: journal,
            entry_date: source.entry_date,
            description: Some(memo.clone()),
            source_kind: Some(source.source_kind.clone()),
            source_ref: Some(source.source_ref.clone()),
            lines: rule_lines(debit, credit, amount, &memo),
        },
    )
    .await
}

/// A period's new status.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PeriodStatus {
    pub period_id: Uuid,
    pub status: String,
}

async fn set_period(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    to: &'static str,
) -> Result<PeriodStatus, AppError> {
    let from = if to == "closed" { "open" } else { "closed" };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let changed = sqlx::query(
        "UPDATE gl_period SET status = $2, modified_at = now(), modified_by = $4, \
             row_version = row_version + 1 \
          WHERE id = $1 AND status = $3 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .bind(to)
    .bind(from)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if changed == 0 {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM gl_period WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::Conflict("the period is not in a status this changes")
        } else {
            AppError::NotFound
        });
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "gl_period",
            id,
            attome_audit::AuditOperation::Update,
            if to == "closed" {
                "ledger.period_closed"
            } else {
                "ledger.period_reopened"
            },
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(PeriodStatus {
        period_id: id,
        status: to.to_owned(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/ledger/entries",
    operation_id = "post_ledger_entry",
    tag = "ledger",
    request_body = NewEntry,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Posted, or the entry its source made before", body = Posted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.create", body = ErrorResponse),
        (status = 404, description = "The ledger is not installed", body = ErrorResponse),
        (status = 409, description = "The same source is being posted", body = ErrorResponse),
        (status = 422, description = "Unbalanced, a closed or missing period, or an account that takes no postings", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Posts a journal entry.
///
/// Debits must equal credits, every account must take postings and the
/// date must fall in an open period; the entry is never changed afterwards.
async fn post_entry(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EntryCreate>>,
    Json(body): Json<NewEntry>,
) -> Result<Json<Posted>, AppError> {
    Ok(Json(post_journal(&state, &ctx, &body).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ledger/source-postings",
    operation_id = "post_ledger_source",
    tag = "ledger",
    request_body = SourcePosting,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Posted, or the entry its source made before", body = Posted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.create", body = ErrorResponse),
        (status = 404, description = "The ledger is not installed", body = ErrorResponse),
        (status = 409, description = "The same source is being posted", body = ErrorResponse),
        (status = 422, description = "No posting rule, a zero amount or a closed period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Posts a source document through its posting rule.
///
/// The rule for the source kind names the journal and the accounts
/// debited and credited; each source posts once.
async fn post_source(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EntryCreate>>,
    Json(body): Json<SourcePosting>,
) -> Result<Json<Posted>, AppError> {
    Ok(Json(post_from_rule(&state, &ctx, &body).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ledger/periods/{id}/close",
    operation_id = "post_ledger_period_close",
    tag = "ledger",
    params(("id" = Uuid, Path, description = "The period")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Closed", body = PeriodStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_period.update", body = ErrorResponse),
        (status = 404, description = "No such period", body = ErrorResponse),
        (status = 409, description = "The period is not open", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Closes a period.
///
/// A closed period takes no entries until it is reopened; both are audited.
async fn post_close(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PeriodUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PeriodStatus>, AppError> {
    Ok(Json(set_period(&state, &ctx, id, "closed").await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ledger/periods/{id}/reopen",
    operation_id = "post_ledger_period_reopen",
    tag = "ledger",
    params(("id" = Uuid, Path, description = "The period")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Reopened", body = PeriodStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_period.update", body = ErrorResponse),
        (status = 404, description = "No such period", body = ErrorResponse),
        (status = 409, description = "The period is not closed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Reopens a closed period.
///
/// The reopening is audited like the close, with who did it.
async fn post_reopen(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PeriodUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PeriodStatus>, AppError> {
    Ok(Json(set_period(&state, &ctx, id, "open").await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ledger/entries", post(post_entry))
        .route("/api/v1/ledger/source-postings", post(post_source))
        .route("/api/v1/ledger/periods/{id}/close", post(post_close))
        .route("/api/v1/ledger/periods/{id}/reopen", post(post_reopen))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_entry, post_source, post_close, post_reopen),
    components(schemas(NewLine, NewEntry, Posted, SourcePosting, PeriodStatus))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod posting_tests {
    use super::*;

    fn line(n: u128, debit: Option<&str>, credit: Option<&str>) -> NewLine {
        NewLine {
            account_id: Uuid::from_u128(n),
            debit: debit.map(str::to_owned),
            credit: credit.map(str::to_owned),
            memo: None,
        }
    }

    #[test]
    fn a_balanced_entry_is_taken_in_exact_decimals() {
        let lines = [
            line(1, Some("100.10"), None),
            line(2, Some("0.20"), None),
            line(3, None, Some("100.30")),
        ];
        let checked = check_lines(&lines).expect("balanced");
        assert_eq!(checked.len(), 3);
        assert_eq!(checked[2].2, Decimal::from_str("100.30").expect("n"));
    }

    #[test]
    fn unbalanced_entries_are_refused() {
        let err = check_lines(&[line(1, Some("100"), None), line(2, None, Some("99.99"))])
            .expect_err("unbalanced");
        assert!(err.contains("unbalanced"), "{err}");
    }

    #[test]
    fn each_line_is_one_side_and_not_zero() {
        assert!(check_lines(&[line(1, Some("5"), Some("5")), line(2, None, None)]).is_err());
        assert!(check_lines(&[line(1, Some("0"), None), line(2, None, Some("0"))]).is_err());
        assert!(check_lines(&[line(1, Some("-5"), None), line(2, None, Some("-5"))]).is_err());
        assert!(
            check_lines(&[
                line(1, Some("1.00001"), None),
                line(2, None, Some("1.00001"))
            ])
            .is_err()
        );
        assert!(
            check_lines(&[line(1, Some("5"), None)]).is_err(),
            "one line"
        );
        assert!(check_lines(&[line(1, Some("x"), None), line(2, None, Some("1"))]).is_err());
    }

    #[test]
    fn a_rule_posts_a_balanced_pair_and_reverses_a_negative_amount() {
        let (dr, cr) = (Uuid::from_u128(10), Uuid::from_u128(20));
        let lines = rule_lines(dr, cr, Decimal::from_str("1150.00").expect("n"), "INV-1");
        assert_eq!(lines[0].account_id, dr);
        assert_eq!(lines[0].debit.as_deref(), Some("1150.00"));
        assert_eq!(lines[1].credit.as_deref(), Some("1150.00"));
        assert!(check_lines(&lines).is_ok());
        let refund = rule_lines(dr, cr, Decimal::from_str("-50").expect("n"), "CN-1");
        assert_eq!(
            refund[0].account_id, cr,
            "a refund debits the credit account"
        );
        assert_eq!(refund[1].account_id, dr);
        assert!(check_lines(&refund).is_ok());
    }
}
