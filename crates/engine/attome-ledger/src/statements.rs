//! W5-T3: the trial balance, the profit and loss statement and the balance
//! sheet, from the postings.
//!
//! Every statement is a sum over posted entry lines (`gl_entry_line`, by
//! `gl_entry.entry_date`) per account (`gl_account`), in exact decimals:
//!
//! - **trial balance** for a date range: each account's debits, credits and
//!   net; the totals tie (debits = credits) because every entry balanced;
//! - **profit and loss** for a date range: income accounts' credits less
//!   debits, expense accounts' debits less credits, and the net income;
//! - **balance sheet** as of a date: assets (debits less credits),
//!   liabilities and equity (credits less debits) from the beginning, with
//!   the income not yet closed into equity shown as current earnings, so
//!   assets = liabilities + equity + current earnings.
//!
//! The arithmetic is pure ([`trial_balance`], [`profit_and_loss`],
//! [`balance_sheet`]); the routes read the sums and the accounts. Reading
//! takes `gl_entry.read`. An ERP hand-off mode (entries sent to an ERP
//! through a connector instead of posted here) waits for the connector SDK
//! (S12).

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `gl_entry.read`: who reads the statements.
#[derive(Debug)]
pub struct EntryRead;

impl PrivilegeKey for EntryRead {
    const KEY: &'static str = "gl_entry.read";
}

/// An account as the statements need it.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub name_ar: Option<String>,
    /// `asset`, `liability`, `equity`, `income` or `expense`.
    pub account_type: String,
}

/// One account's posted sums.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Sums {
    pub debit: Decimal,
    pub credit: Decimal,
}

/// One statement line.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Line {
    pub account_id: Uuid,
    pub code: String,
    pub name: String,
    pub name_ar: Option<String>,
    pub account_type: String,
    pub debit: String,
    pub credit: String,
    /// Debits less credits for assets and expenses, credits less debits
    /// for the others.
    pub balance: String,
}

/// A trial balance.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TrialBalance {
    pub lines: Vec<Line>,
    pub total_debit: String,
    pub total_credit: String,
    pub balanced: bool,
}

/// A profit and loss statement.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ProfitAndLoss {
    pub income: Vec<Line>,
    pub expenses: Vec<Line>,
    pub total_income: String,
    pub total_expenses: String,
    pub net_income: String,
}

/// A balance sheet.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct BalanceSheet {
    pub assets: Vec<Line>,
    pub liabilities: Vec<Line>,
    pub equity: Vec<Line>,
    pub total_assets: String,
    pub total_liabilities: String,
    pub total_equity: String,
    /// Income less expenses not yet closed into equity.
    pub current_earnings: String,
    /// Assets = liabilities + equity + current earnings.
    pub balanced: bool,
}

fn debit_normal(account_type: &str) -> bool {
    matches!(account_type, "asset" | "expense")
}

fn balance_of(account_type: &str, sums: Sums) -> Decimal {
    if debit_normal(account_type) {
        sums.debit - sums.credit
    } else {
        sums.credit - sums.debit
    }
}

fn line(account: &Account, sums: Sums) -> Line {
    Line {
        account_id: account.id,
        code: account.code.clone(),
        name: account.name.clone(),
        name_ar: account.name_ar.clone(),
        account_type: account.account_type.clone(),
        debit: sums.debit.normalize().to_string(),
        credit: sums.credit.normalize().to_string(),
        balance: balance_of(&account.account_type, sums)
            .normalize()
            .to_string(),
    }
}

/// The accounts with postings, in code order, with their sums.
fn posted<'a>(
    accounts: &'a [Account],
    sums: &'a std::collections::HashMap<Uuid, Sums>,
) -> impl Iterator<Item = (&'a Account, Sums)> + 'a {
    let mut ordered: Vec<&Account> = accounts.iter().collect();
    ordered.sort_by(|a, b| a.code.cmp(&b.code));
    ordered
        .into_iter()
        .filter_map(move |a| sums.get(&a.id).map(|s| (a, *s)))
        .filter(|(_, s)| !s.debit.is_zero() || !s.credit.is_zero())
}

/// The trial balance of `sums`.
pub fn trial_balance(
    accounts: &[Account],
    sums: &std::collections::HashMap<Uuid, Sums>,
) -> TrialBalance {
    let mut lines = Vec::new();
    let (mut debit, mut credit) = (Decimal::ZERO, Decimal::ZERO);
    for (account, s) in posted(accounts, sums) {
        debit += s.debit;
        credit += s.credit;
        lines.push(line(account, s));
    }
    TrialBalance {
        lines,
        total_debit: debit.normalize().to_string(),
        total_credit: credit.normalize().to_string(),
        balanced: debit == credit,
    }
}

fn totals(lines: &[(Line, Decimal)]) -> Decimal {
    lines.iter().map(|(_, b)| *b).sum()
}

/// The profit and loss of `sums`.
pub fn profit_and_loss(
    accounts: &[Account],
    sums: &std::collections::HashMap<Uuid, Sums>,
) -> ProfitAndLoss {
    let mut income = Vec::new();
    let mut expenses = Vec::new();
    for (account, s) in posted(accounts, sums) {
        let entry = (line(account, s), balance_of(&account.account_type, s));
        match account.account_type.as_str() {
            "income" => income.push(entry),
            "expense" => expenses.push(entry),
            _ => {}
        }
    }
    let (ti, te) = (totals(&income), totals(&expenses));
    ProfitAndLoss {
        total_income: ti.normalize().to_string(),
        total_expenses: te.normalize().to_string(),
        net_income: (ti - te).normalize().to_string(),
        income: income.into_iter().map(|(l, _)| l).collect(),
        expenses: expenses.into_iter().map(|(l, _)| l).collect(),
    }
}

/// The balance sheet of `sums` (everything posted up to its date).
pub fn balance_sheet(
    accounts: &[Account],
    sums: &std::collections::HashMap<Uuid, Sums>,
) -> BalanceSheet {
    let mut groups: [Vec<(Line, Decimal)>; 3] = Default::default();
    let mut earnings = Decimal::ZERO;
    for (account, s) in posted(accounts, sums) {
        let balance = balance_of(&account.account_type, s);
        match account.account_type.as_str() {
            "asset" => groups[0].push((line(account, s), balance)),
            "liability" => groups[1].push((line(account, s), balance)),
            "equity" => groups[2].push((line(account, s), balance)),
            "income" => earnings += balance,
            "expense" => earnings -= balance,
            _ => {}
        }
    }
    let [assets, liabilities, equity] = groups;
    let (ta, tl, tq) = (totals(&assets), totals(&liabilities), totals(&equity));
    BalanceSheet {
        total_assets: ta.normalize().to_string(),
        total_liabilities: tl.normalize().to_string(),
        total_equity: tq.normalize().to_string(),
        current_earnings: earnings.normalize().to_string(),
        balanced: ta == tl + tq + earnings,
        assets: assets.into_iter().map(|(l, _)| l).collect(),
        liabilities: liabilities.into_iter().map(|(l, _)| l).collect(),
        equity: equity.into_iter().map(|(l, _)| l).collect(),
    }
}

async fn accounts(state: &EngineState) -> Result<Vec<Account>, AppError> {
    // The ledger pack's tables, as the posting engine checks them.
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('gl_account') IS NOT NULL AND to_regclass('gl_entry') IS NOT NULL             AND to_regclass('gl_entry_line') IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    /// id, code, name, name_ar, account_type.
    type AccountRow = (
        Uuid,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<AccountRow> = sqlx::query_as(
        "SELECT id, code, name, name_ar, account_type FROM gl_account \
              WHERE is_active IS NULL OR is_active",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, code, name, name_ar, account_type)| Account {
            id,
            code: code.unwrap_or_default(),
            name: name.unwrap_or_default(),
            name_ar,
            account_type: account_type.unwrap_or_default(),
        })
        .collect())
}

/// Each account's posted debits and credits with an entry date in
/// `[from, to]` (`from` none: from the beginning).
async fn sums(
    state: &EngineState,
    from: Option<NaiveDate>,
    to: NaiveDate,
) -> Result<std::collections::HashMap<Uuid, Sums>, AppError> {
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT l.account_ref, COALESCE(SUM(l.debit), 0)::text, COALESCE(SUM(l.credit), 0)::text \
           FROM gl_entry_line l JOIN gl_entry e ON e.id = l.entry_ref \
          WHERE ($1::date IS NULL OR e.entry_date >= $1) AND e.entry_date <= $2 \
            AND (l.is_active IS NULL OR l.is_active) AND (e.is_active IS NULL OR e.is_active) \
            AND l.account_ref IS NOT NULL \
          GROUP BY l.account_ref",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let dec = |s: Option<String>| {
        s.as_deref()
            .and_then(|s| Decimal::from_str(s).ok())
            .unwrap_or_default()
    };
    Ok(rows
        .into_iter()
        .map(|(account, debit, credit)| {
            (
                account,
                Sums {
                    debit: dec(debit),
                    credit: dec(credit),
                },
            )
        })
        .collect())
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RangeQuery {
    /// The first day (YYYY-MM-DD).
    pub from: NaiveDate,
    /// The last day (YYYY-MM-DD).
    pub to: NaiveDate,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AsOfQuery {
    /// The day the balances are as of (YYYY-MM-DD).
    pub as_of: NaiveDate,
}

fn check_range(q: &RangeQuery) -> Result<(), AppError> {
    if q.from > q.to {
        return Err(AppError::Validation("from is on or before to".into()));
    }
    Ok(())
}

/// Read the trial balance
///
/// Each account's debits, credits and balance from the posted entries over a date range, in exact
/// decimals.
#[utoipa::path(
    get,
    path = "/api/v1/ledger/statements/trial-balance",
    tag = "ledger",
    operation_id = "ledger_trial_balance",
    params(RangeQuery),
    responses(
        (status = 200, description = "Each account's debits, credits and balance", body = TrialBalance),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.read", body = ErrorResponse),
        (status = 422, description = "from after to", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_trial_balance(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EntryRead>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<TrialBalance>, AppError> {
    check_range(&q)?;
    let (accounts, sums) = (
        accounts(&state).await?,
        sums(&state, Some(q.from), q.to).await?,
    );
    Ok(Json(trial_balance(&accounts, &sums)))
}

/// Read the profit and loss statement
///
/// Income and expense accounts summed from the posted entries over a date range.
#[utoipa::path(
    get,
    path = "/api/v1/ledger/statements/profit-and-loss",
    tag = "ledger",
    operation_id = "ledger_profit_and_loss",
    params(RangeQuery),
    responses(
        (status = 200, description = "Income, expenses and net income", body = ProfitAndLoss),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.read", body = ErrorResponse),
        (status = 422, description = "from after to", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_profit_and_loss(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EntryRead>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<ProfitAndLoss>, AppError> {
    check_range(&q)?;
    let (accounts, sums) = (
        accounts(&state).await?,
        sums(&state, Some(q.from), q.to).await?,
    );
    Ok(Json(profit_and_loss(&accounts, &sums)))
}

/// Read the balance sheet
///
/// Assets, liabilities and equity from the posted entries as of a date, with income not yet closed
/// into equity shown as current earnings.
#[utoipa::path(
    get,
    path = "/api/v1/ledger/statements/balance-sheet",
    tag = "ledger",
    operation_id = "ledger_balance_sheet",
    params(AsOfQuery),
    responses(
        (status = 200, description = "Assets, liabilities, equity and current earnings", body = BalanceSheet),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks gl_entry.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_balance_sheet(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EntryRead>>,
    Query(q): Query<AsOfQuery>,
) -> Result<Json<BalanceSheet>, AppError> {
    let (accounts, sums) = (accounts(&state).await?, sums(&state, None, q.as_of).await?);
    Ok(Json(balance_sheet(&accounts, &sums)))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ledger/statements/trial-balance",
            get(get_trial_balance),
        )
        .route(
            "/api/v1/ledger/statements/profit-and-loss",
            get(get_profit_and_loss),
        )
        .route(
            "/api/v1/ledger/statements/balance-sheet",
            get(get_balance_sheet),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_trial_balance, get_profit_and_loss, get_balance_sheet),
    components(schemas(Line, TrialBalance, ProfitAndLoss, BalanceSheet))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn account(code: &str, kind: &str) -> Account {
        Account {
            id: Uuid::now_v7(),
            code: code.into(),
            name: code.into(),
            name_ar: None,
            account_type: kind.into(),
        }
    }

    /// Three balanced entries: capital in (cash / equity), a sale (cash /
    /// income), rent paid (expense / cash).
    fn book() -> (Vec<Account>, HashMap<Uuid, Sums>) {
        let cash = account("1000", "asset");
        let capital = account("3000", "equity");
        let sales = account("4000", "income");
        let rent = account("5000", "expense");
        let loan = account("2000", "liability");
        let sums = HashMap::from([
            (
                cash.id,
                Sums {
                    debit: d("1500.50"),
                    credit: d("300"),
                },
            ),
            (
                capital.id,
                Sums {
                    debit: d("0"),
                    credit: d("1000"),
                },
            ),
            (
                sales.id,
                Sums {
                    debit: d("0"),
                    credit: d("500.50"),
                },
            ),
            (
                rent.id,
                Sums {
                    debit: d("300"),
                    credit: d("0"),
                },
            ),
        ]);
        (vec![rent, sales, cash, capital, loan], sums)
    }

    #[test]
    fn statements_trial_balance_ties_out() {
        let (accounts, sums) = book();
        let tb = trial_balance(&accounts, &sums);
        assert!(tb.balanced);
        assert_eq!(tb.total_debit, "1800.5");
        assert_eq!(tb.total_credit, "1800.5");
        let codes: Vec<&str> = tb.lines.iter().map(|l| l.code.as_str()).collect();
        assert_eq!(
            codes,
            vec!["1000", "3000", "4000", "5000"],
            "code order, unposted left out"
        );
        assert_eq!(tb.lines[0].balance, "1200.5");
    }

    #[test]
    fn statements_profit_and_loss_and_balance_sheet_tie_out() {
        let (accounts, sums) = book();
        let pnl = profit_and_loss(&accounts, &sums);
        assert_eq!(pnl.total_income, "500.5");
        assert_eq!(pnl.total_expenses, "300");
        assert_eq!(pnl.net_income, "200.5");
        let bs = balance_sheet(&accounts, &sums);
        assert_eq!(bs.total_assets, "1200.5");
        assert_eq!(bs.total_equity, "1000");
        assert_eq!(
            bs.current_earnings, pnl.net_income,
            "the sheet carries the period's earnings"
        );
        assert!(
            bs.balanced,
            "assets = liabilities + equity + current earnings"
        );
    }

    #[test]
    fn statements_an_unbalanced_book_shows() {
        let (accounts, mut sums) = book();
        let cash = accounts.iter().find(|a| a.code == "1000").unwrap().id;
        sums.get_mut(&cash).unwrap().debit += d("1");
        assert!(!trial_balance(&accounts, &sums).balanced);
        assert!(!balance_sheet(&accounts, &sums).balanced);
    }
}
