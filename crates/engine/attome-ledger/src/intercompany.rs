//! W5-T2: inter-company postings and their elimination.
//!
//! A company is an `organization`; an entry's `organization_ref` says whose
//! books it is in. When company A charges (or lends to) company B,
//! [`post_intercompany`] writes **both** sides in one transaction, so the
//! group's books never hold one half:
//!
//! - in A: debit A's *due from B* account, credit A's income (or cash)
//!   account;
//! - in B: debit B's expense (or asset) account, credit B's *due to A*
//!   account.
//!
//! The due-from and due-to accounts come from `gl_intercompany_account`
//! (ledger pack 0002): one row per company and counterparty. Both entries
//! carry the same `intercompany_ref` and each names the other company as
//! `counterparty_ref`; each passes the same checks as any entry (balanced,
//! open period, postable accounts) through `posting::insert_entry`.
//!
//! **Eliminations.** In group statements an inter-company entry is a
//! transfer inside the group: [`group_trial_balance`] leaves out every entry
//! with an `intercompany_ref` ([`eliminate`]), so the due-to/due-from
//! balances and the matching income and expense cancel out of the group's
//! figures while each company's own books keep them.

use std::collections::BTreeMap;
use std::str::FromStr;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::posting::{EntryCompany, EntryCreate, NewEntry, NewLine, check_lines, insert_entry};

/// `gl_entry.read`: who reads the ledger.
#[derive(Debug)]
pub struct EntryRead;

impl PrivilegeKey for EntryRead {
    const KEY: &'static str = "gl_entry.read";
}

/// An inter-company posting.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewIntercompany {
    pub journal_id: Uuid,
    pub entry_date: NaiveDate,
    /// The company that charges or lends.
    pub from_company: Uuid,
    /// The company charged or lent to.
    pub to_company: Uuid,
    /// A positive decimal string.
    pub amount: String,
    /// The account credited in the first company's books (its income or cash).
    pub from_account: Uuid,
    /// The account debited in the second company's books (its expense or asset).
    pub to_account: Uuid,
    #[serde(default)]
    pub description: Option<String>,
}

/// Both sides, posted.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntercompanyPosted {
    /// The link both entries carry.
    pub intercompany_ref: Uuid,
    pub from_entry_id: Uuid,
    pub to_entry_id: Uuid,
    pub amount: String,
}

/// The two entries' lines: `(first company's, second company's)`. Pure.
pub fn intercompany_lines(
    due_from: Uuid,
    from_account: Uuid,
    to_account: Uuid,
    due_to: Uuid,
    amount: Decimal,
    memo: &str,
) -> (Vec<NewLine>, Vec<NewLine>) {
    let a = amount.to_string();
    let line = |account: Uuid, debit: bool| NewLine {
        account_id: account,
        debit: debit.then(|| a.clone()),
        credit: (!debit).then(|| a.clone()),
        memo: Some(memo.to_owned()),
    };
    (
        vec![line(due_from, true), line(from_account, false)],
        vec![line(to_account, true), line(due_to, false)],
    )
}

/// A positive amount with at most the posting engine's places. Pure.
pub fn positive_amount(raw: &str) -> Result<Decimal, AppError> {
    let d = Decimal::from_str(raw.trim())
        .map_err(|_| AppError::Validation("amount: not a number".into()))?;
    if d <= Decimal::ZERO {
        return Err(AppError::Validation("amount: above zero".into()));
    }
    if d.scale() > crate::posting::MAX_SCALE {
        return Err(AppError::Validation(format!(
            "amount: at most {} decimal places",
            crate::posting::MAX_SCALE
        )));
    }
    Ok(d)
}

/// `(due from, due to)` of `company` toward `counterparty`.
async fn pair_accounts(
    tx: &mut attome_db::Tx<'_>,
    company: Uuid,
    counterparty: Uuid,
) -> Result<(Option<Uuid>, Option<Uuid>), AppError> {
    let row: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT due_from_account_ref, due_to_account_ref FROM gl_intercompany_account \
          WHERE company_ref = $1 AND counterparty_ref = $2 \
            AND (is_active IS NULL OR is_active = true) ORDER BY created_at LIMIT 1",
    )
    .bind(company)
    .bind(counterparty)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(row.unwrap_or((None, None)))
}

/// Posts both sides of an inter-company charge in one transaction.
pub async fn post_intercompany(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &NewIntercompany,
) -> Result<IntercompanyPosted, AppError> {
    if req.from_company == req.to_company {
        return Err(AppError::Validation(
            "to_company: an inter-company posting is between two companies".into(),
        ));
    }
    let amount = positive_amount(&req.amount)?;
    let ready: bool =
        sqlx::query_scalar("SELECT to_regclass('gl_intercompany_account') IS NOT NULL")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    let memo = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .unwrap_or("Inter-company")
        .to_owned();
    let link = Uuid::now_v7();

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (due_from, _) = pair_accounts(&mut tx, req.from_company, req.to_company).await?;
    let (_, due_to) = pair_accounts(&mut tx, req.to_company, req.from_company).await?;
    let due_from = due_from.ok_or_else(|| {
        AppError::Validation(
            "from_company: no due-from account toward to_company (gl_intercompany_account)".into(),
        )
    })?;
    let due_to = due_to.ok_or_else(|| {
        AppError::Validation(
            "to_company: no due-to account toward from_company (gl_intercompany_account)".into(),
        )
    })?;
    let (first, second) = intercompany_lines(
        due_from,
        req.from_account,
        req.to_account,
        due_to,
        amount,
        &memo,
    );
    let mut ids = Vec::with_capacity(2);
    for (company, counterparty, lines) in [
        (req.from_company, req.to_company, first),
        (req.to_company, req.from_company, second),
    ] {
        let entry = NewEntry {
            journal_id: req.journal_id,
            entry_date: req.entry_date,
            description: Some(memo.clone()),
            source_kind: None,
            source_ref: None,
            lines,
        };
        let checked = check_lines(&entry.lines).map_err(AppError::Validation)?;
        let (entry_id, _, _) = insert_entry(
            &mut tx,
            state,
            ctx,
            &entry,
            &checked,
            None,
            EntryCompany {
                organization: Some(company),
                link: Some((link, counterparty)),
            },
        )
        .await?;
        ids.push(entry_id);
    }
    attome_db::tx::commit(tx).await?;
    Ok(IntercompanyPosted {
        intercompany_ref: link,
        from_entry_id: ids[0],
        to_entry_id: ids[1],
        amount: amount.to_string(),
    })
}

/// One account's totals in a trial balance.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TrialBalanceRow {
    pub account_id: Uuid,
    pub code: Option<String>,
    pub name: Option<String>,
    pub debit: String,
    pub credit: String,
}

/// Sums lines per account, leaving out the inter-company ones: the group's
/// eliminations. Each line is `(account, debit, credit, inter-company)`.
/// Pure.
pub fn eliminate(lines: &[(Uuid, Decimal, Decimal, bool)]) -> BTreeMap<Uuid, (Decimal, Decimal)> {
    let mut totals: BTreeMap<Uuid, (Decimal, Decimal)> = BTreeMap::new();
    for (account, debit, credit, intercompany) in lines {
        if *intercompany {
            continue;
        }
        let t = totals.entry(*account).or_default();
        t.0 += *debit;
        t.1 += *credit;
    }
    totals
}

/// The range of a trial balance.
#[derive(Debug, Clone, Copy, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TrialRange {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

type LineRow = (Uuid, Option<String>, Option<String>, String, String, bool);

/// The group's trial balance over the range, inter-company entries
/// eliminated.
pub async fn group_trial_balance(
    db: &attome_db::DbPool,
    range: &TrialRange,
) -> Result<Vec<TrialBalanceRow>, AppError> {
    if range.to < range.from {
        return Err(AppError::Validation("to must not be before from".into()));
    }
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT l.account_ref, a.code, a.name, \
                COALESCE(SUM(l.debit), 0)::text, COALESCE(SUM(l.credit), 0)::text, \
                (to_jsonb(e)->>'intercompany_ref') IS NOT NULL \
           FROM gl_entry_line l \
           JOIN gl_entry e ON e.id = l.entry_ref \
           LEFT JOIN gl_account a ON a.id = l.account_ref \
          WHERE e.entry_date::date BETWEEN $1 AND $2 \
            AND (e.is_active IS NULL OR e.is_active = true) \
            AND (l.is_active IS NULL OR l.is_active = true) \
          GROUP BY l.account_ref, a.code, a.name, (to_jsonb(e)->>'intercompany_ref') IS NOT NULL",
    )
    .bind(range.from)
    .bind(range.to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut names: BTreeMap<Uuid, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut lines = Vec::with_capacity(rows.len());
    for (account, code, name, debit, credit, intercompany) in rows {
        names.entry(account).or_insert((code, name));
        let parse = |s: &str| Decimal::from_str(s).unwrap_or(Decimal::ZERO);
        lines.push((account, parse(&debit), parse(&credit), intercompany));
    }
    Ok(eliminate(&lines)
        .into_iter()
        .map(|(account, (debit, credit))| {
            let (code, name) = names.remove(&account).unwrap_or((None, None));
            TrialBalanceRow {
                account_id: account,
                code,
                name,
                debit: debit.to_string(),
                credit: credit.to_string(),
            }
        })
        .collect())
}

#[utoipa::path(
    post,
    path = "/api/v1/ledger/intercompany",
    tag = "ledger",
    request_body = NewIntercompany,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Both sides posted", body = IntercompanyPosted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.create", body = ErrorResponse),
        (status = 404, description = "The ledger pack's inter-company changeset is not applied", body = ErrorResponse),
        (status = 422, description = "Same company, no due-to/due-from account, an unbalanced side, or a closed period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_intercompany_entry(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EntryCreate>>,
    Json(body): Json<NewIntercompany>,
) -> Result<(StatusCode, Json<IntercompanyPosted>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(post_intercompany(&state, &ctx, &body).await?),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/ledger/group-trial-balance",
    tag = "ledger",
    params(TrialRange),
    responses(
        (status = 200, description = "Each account's debits and credits for the group, inter-company entries eliminated", body = Vec<TrialBalanceRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.read", body = ErrorResponse),
        (status = 422, description = "to before from", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_group_trial_balance(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EntryRead>>,
    Query(range): Query<TrialRange>,
) -> Result<Json<Vec<TrialBalanceRow>>, AppError> {
    Ok(Json(group_trial_balance(&state.base.db, &range).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ledger/intercompany", post(post_intercompany_entry))
        .route(
            "/api/v1/ledger/group-trial-balance",
            get(get_group_trial_balance),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_intercompany_entry, get_group_trial_balance),
    components(schemas(NewIntercompany, IntercompanyPosted, TrialBalanceRow))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).expect("a decimal")
    }

    #[test]
    fn both_sides_balance_and_mirror_each_other() {
        let (due_from, income, expense, due_to) = (
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        );
        let (first, second) = intercompany_lines(
            due_from,
            income,
            expense,
            due_to,
            d("1250.50"),
            "Shared services",
        );
        let a = check_lines(&first).expect("first side balances");
        let b = check_lines(&second).expect("second side balances");
        assert_eq!(
            a[0],
            (
                due_from,
                d("1250.50"),
                Decimal::ZERO,
                Some("Shared services".into())
            )
        );
        assert_eq!(a[1].0, income);
        assert_eq!(b[0].0, expense);
        assert_eq!(
            b[1],
            (
                due_to,
                Decimal::ZERO,
                d("1250.50"),
                Some("Shared services".into())
            )
        );
    }

    #[test]
    fn eliminations_leave_out_intercompany_lines() {
        let (cash, income, due_from, due_to, expense) = (
            Uuid::from_u128(10),
            Uuid::from_u128(11),
            Uuid::from_u128(12),
            Uuid::from_u128(13),
            Uuid::from_u128(14),
        );
        let lines = vec![
            // An outside sale stays in the group's figures.
            (cash, d("500"), Decimal::ZERO, false),
            (income, Decimal::ZERO, d("500"), false),
            // The inter-company charge cancels out.
            (due_from, d("100"), Decimal::ZERO, true),
            (income, Decimal::ZERO, d("100"), true),
            (expense, d("100"), Decimal::ZERO, true),
            (due_to, Decimal::ZERO, d("100"), true),
        ];
        let group = eliminate(&lines);
        assert_eq!(group.get(&cash), Some(&(d("500"), Decimal::ZERO)));
        assert_eq!(group.get(&income), Some(&(Decimal::ZERO, d("500"))));
        assert!(!group.contains_key(&due_from) && !group.contains_key(&due_to));
        assert!(!group.contains_key(&expense));
    }

    #[test]
    fn an_amount_is_positive_and_exact() {
        assert_eq!(positive_amount(" 10.25 ").expect("ok"), d("10.25"));
        assert!(positive_amount("0").is_err());
        assert!(positive_amount("-3").is_err());
        assert!(positive_amount("1.23456").is_err());
        assert!(positive_amount("ten").is_err());
    }
}
