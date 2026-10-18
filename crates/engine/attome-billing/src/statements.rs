//! Customer statements and receivables ageing (roadmap F4-T11).
//!
//! What counts: issued documents (invoices, credit and debit notes,
//! deposits; never drafts, void or pro forma invoices) at their grand
//! total on their issue date, less live unreversed payment allocations on
//! their allocation date, less write-offs (F4-T12) on the day they were
//! posted. So a statement's closing balance equals the sum
//! of the account's open totals once the payments are refreshed, and an
//! ageing as of today matches the open totals too. Amounts never mix
//! currencies: a statement has one section per currency, the ageing one
//! row per account and currency.
//!
//! Both read `invoice.read` and the caller's record scope on `account`:
//! a statement of an account the caller cannot read is `404`, and the
//! ageing lists only accounts the caller can read.

use std::str::FromStr;

use attome_core::EngineState;
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate_as, resolve_entity_access_level,
    rls_predicate,
};
use attome_server::security::SecurityContext;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The documents that count: issued, not void, not pro forma.
const COUNTED: &str = "COALESCE(i.status, 'draft') NOT IN ('draft', 'void') \
     AND COALESCE(i.kind, 'invoice') <> 'pro_forma' \
     AND (i.is_active IS NULL OR i.is_active = true)";

/// Live, unreversed allocations.
const ALLOCATED: &str = "COALESCE(pa.reversed, false) = false \
     AND (pa.is_active IS NULL OR pa.is_active = true)";

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatementQuery {
    /// First day of the period (default: the first of this month).
    pub from: Option<NaiveDate>,
    /// Last day of the period (default: today).
    pub to: Option<NaiveDate>,
}

/// One line of a statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct StatementEntry {
    pub date: NaiveDate,
    /// `invoice`, `credit_note`, `debit_note`, `deposit`, `payment` or
    /// `write_off`.
    pub kind: String,
    /// The document number, the payment's reference, or the write-off's
    /// reason.
    pub reference: Option<String>,
    /// The invoice the line is about.
    pub invoice_id: Uuid,
    /// What it adds to the balance (a payment or credit note is negative).
    pub amount: String,
}

/// A statement's section in one currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CurrencyStatement {
    pub currency: String,
    pub opening_balance: String,
    pub entries: Vec<StatementEntry>,
    pub closing_balance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AccountStatement {
    pub account_id: Uuid,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub currencies: Vec<CurrencyStatement>,
}

/// Whether the caller may read this account under their record scope.
async fn can_read_account(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<bool, AppError> {
    if ctx.require("account", "read").is_err() {
        return Ok(false);
    }
    let Some(entity_id) = state.entities.load().get("account").map(|m| m.entity_id) else {
        return Ok(false);
    };
    let db = &state.base.db;
    let level =
        resolve_entity_access_level(db, ctx.user_id, entity_id, "account", RecordAction::Read)
            .await?;
    let predicate = rls_predicate(
        ctx,
        entity_id,
        "a",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let rls = predicate.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT a.id FROM account a WHERE a.id = $1 \
           AND (a.is_active IS NULL OR a.is_active = true) {rls}"
    );
    let mut query = sqlx::query_as::<_, (Uuid,)>(&sql).bind(account);
    if let Some(p) = &predicate {
        query = bind_rls_predicate_as(query, &p.binds);
    }
    Ok(query
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .is_some())
}

type EntryRow = (
    NaiveDate,
    String,
    Option<String>,
    Uuid,
    Option<String>,
    Option<String>,
);

/// An account's statement for `[from, to]`.
pub async fn statement(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<AccountStatement, AppError> {
    if from > to {
        return Err(AppError::Validation("from is after to".into()));
    }
    if !can_read_account(state, ctx, account).await? {
        return Err(AppError::NotFound);
    }
    let db = &state.base.db;
    // Everything up to `to`: documents on their issue date, allocations on
    // theirs; what falls before `from` makes the opening balance.
    let sql = format!(
        "SELECT i.issued_date::date AS d, COALESCE(i.kind, 'invoice'), i.invoice_number, \
                i.id, COALESCE(i.currency, ''), i.grand_total::text \
         FROM invoice i \
         WHERE i.account_ref = $1 AND {COUNTED} AND i.issued_date::date <= $2 \
         UNION ALL \
         SELECT pa.allocated_on::date, 'payment', p.reference, i.id, \
                COALESCE(i.currency, ''), (-pa.amount)::text \
         FROM payment_allocation pa JOIN invoice i ON i.id = pa.invoice_ref \
         LEFT JOIN customer_payment p ON p.id = pa.payment_ref \
         WHERE i.account_ref = $1 AND {COUNTED} AND {ALLOCATED} \
           AND pa.allocated_on::date <= $2 \
         UNION ALL \
         SELECT o.created_at::date, 'write_off', o.payload->>'reason', i.id, \
                COALESCE(i.currency, ''), (-(o.payload->>'amount')::numeric)::text \
         FROM billing_posting_outbox o JOIN invoice i ON i.id = o.invoice_ref \
         WHERE i.account_ref = $1 AND {COUNTED} AND o.posting_kind = 'write_off' \
           AND o.created_at::date <= $2 \
         ORDER BY 1, 4, 2"
    );
    let rows: Vec<EntryRow> = sqlx::query_as(&sql)
        .bind(account)
        .bind(to)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let mut sections: Vec<(String, Decimal, Vec<StatementEntry>, Decimal)> = Vec::new();
    for (date, kind, reference, invoice_id, currency, amount) in rows {
        let amount = decimal(amount.as_deref());
        let currency = currency.unwrap_or_default();
        let index = match sections.iter().position(|s| s.0 == currency) {
            Some(i) => i,
            None => {
                sections.push((currency.clone(), Decimal::ZERO, Vec::new(), Decimal::ZERO));
                sections.len() - 1
            }
        };
        let section = &mut sections[index];
        if date < from {
            section.1 += amount;
        } else {
            section.2.push(StatementEntry {
                date,
                kind,
                reference,
                invoice_id,
                amount: amount.to_string(),
            });
        }
        section.3 += amount;
    }
    sections.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(AccountStatement {
        account_id: account,
        from,
        to,
        currencies: sections
            .into_iter()
            .map(|(currency, opening, entries, closing)| CurrencyStatement {
                currency,
                opening_balance: opening.to_string(),
                entries,
                closing_balance: closing.to_string(),
            })
            .collect(),
    })
}

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AgeingQuery {
    /// The day the ageing is taken on (default today).
    pub as_of: Option<NaiveDate>,
    /// One-based page.
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// One account's open amounts in one currency, by days past due.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgeingRow {
    pub account_id: Uuid,
    pub account_name: Option<String>,
    pub currency: String,
    /// Not yet due (and open credit, which is negative).
    pub current: String,
    pub days_1_30: String,
    pub days_31_60: String,
    pub days_61_90: String,
    pub over_90: String,
    pub total: String,
}

/// The whole book in one currency, by days past due.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgeingTotals {
    pub currency: String,
    pub current: String,
    pub days_1_30: String,
    pub days_31_60: String,
    pub days_61_90: String,
    pub over_90: String,
    pub total: String,
}

/// The open amount per document as of `$1`, with its days past due. The
/// account scope is spliced after `WHERE` as `{rls}` on alias `a`.
fn open_documents_sql(rls: &str) -> String {
    format!(
        "SELECT a.id AS account_id, a.name AS account_name, COALESCE(i.currency, '') AS currency, \
                GREATEST($1::date - COALESCE(i.due_date::date, i.issued_date::date), 0) AS days, \
                COALESCE(i.grand_total, 0) - COALESCE(( \
                    SELECT SUM(pa.amount) FROM payment_allocation pa \
                    WHERE pa.invoice_ref = i.id AND {ALLOCATED} \
                      AND pa.allocated_on::date <= $1), 0) - COALESCE(( \
                    SELECT SUM((o.payload->>'amount')::numeric) FROM billing_posting_outbox o \
                    WHERE o.invoice_ref = i.id AND o.posting_kind = 'write_off' \
                      AND o.created_at::date <= $1), 0) AS open \
         FROM invoice i JOIN account a ON a.id = i.account_ref \
         WHERE {COUNTED} AND i.issued_date::date <= $1 \
           AND (a.is_active IS NULL OR a.is_active = true) {rls}"
    )
}

const BUCKET_SUMS: &str = "SUM(open) FILTER (WHERE days <= 0)::text, \
     SUM(open) FILTER (WHERE days BETWEEN 1 AND 30)::text, \
     SUM(open) FILTER (WHERE days BETWEEN 31 AND 60)::text, \
     SUM(open) FILTER (WHERE days BETWEEN 61 AND 90)::text, \
     SUM(open) FILTER (WHERE days > 90)::text, \
     SUM(open)::text";

type BucketRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn amounts(row: &BucketRow) -> [String; 6] {
    let d = |t: &Option<String>| decimal(t.as_deref()).to_string();
    [
        d(&row.0),
        d(&row.1),
        d(&row.2),
        d(&row.3),
        d(&row.4),
        d(&row.5),
    ]
}

/// The caller's account scope on alias `a`, from placeholder `$2`.
async fn account_scope(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Option<attome_security::RlsPredicate>, AppError> {
    ctx.require("account", "read")?;
    let entity_id = state
        .entities
        .load()
        .get("account")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    let level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "account",
        RecordAction::Read,
    )
    .await?;
    Ok(rls_predicate(
        ctx,
        entity_id,
        "a",
        level,
        RecordAction::Read.share_capability(),
        2,
    ))
}

type AgeingDbRow = (
    Uuid,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The ageing per readable account and currency, a page at a time.
pub async fn ageing(
    state: &EngineState,
    ctx: &SecurityContext,
    as_of: NaiveDate,
    page: OnePageQuery,
) -> Result<PaginatedResponse<AgeingRow>, AppError> {
    let window = page.window();
    let scope = account_scope(state, ctx).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let docs = open_documents_sql(rls);
    let grouped = format!(
        "SELECT account_id, account_name, currency, {BUCKET_SUMS} \
         FROM ({docs}) d GROUP BY account_id, account_name, currency \
         HAVING SUM(open) <> 0"
    );
    let count_sql = format!("SELECT COUNT(*) FROM ({grouped}) g");
    let mut count = sqlx::query_as::<_, (i64,)>(&count_sql).bind(as_of);
    if let Some(p) = &scope {
        count = bind_rls_predicate_as(count, &p.binds);
    }
    let (total,) = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let page_sql = format!(
        "{grouped} ORDER BY account_name NULLS LAST, account_id, currency \
         LIMIT {} OFFSET {}",
        window.page_size, window.offset
    );
    let mut rows = sqlx::query_as::<_, AgeingDbRow>(&page_sql).bind(as_of);
    if let Some(p) = &scope {
        rows = bind_rls_predicate_as(rows, &p.binds);
    }
    let rows = rows
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(account_id, account_name, currency, b0, b1, b2, b3, b4, t)| {
                let [current, days_1_30, days_31_60, days_61_90, over_90, total] =
                    amounts(&(b0, b1, b2, b3, b4, t));
                AgeingRow {
                    account_id,
                    account_name,
                    currency,
                    current,
                    days_1_30,
                    days_31_60,
                    days_61_90,
                    over_90,
                    total,
                }
            },
        )
        .collect();
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
    })
}

type TotalsDbRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The ageing of every readable account, summed per currency.
pub async fn ageing_totals(
    state: &EngineState,
    ctx: &SecurityContext,
    as_of: NaiveDate,
) -> Result<Vec<AgeingTotals>, AppError> {
    let scope = account_scope(state, ctx).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let docs = open_documents_sql(rls);
    let sql = format!(
        "SELECT currency, {BUCKET_SUMS} FROM ({docs}) d \
         GROUP BY currency ORDER BY currency"
    );
    let mut query = sqlx::query_as::<_, TotalsDbRow>(&sql).bind(as_of);
    if let Some(p) = &scope {
        query = bind_rls_predicate_as(query, &p.binds);
    }
    Ok(query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(currency, b0, b1, b2, b3, b4, t)| {
            let [current, days_1_30, days_31_60, days_61_90, over_90, total] =
                amounts(&(b0, b1, b2, b3, b4, t));
            AgeingTotals {
                currency,
                current,
                days_1_30,
                days_31_60,
                days_61_90,
                over_90,
                total,
            }
        })
        .collect())
}

/// `invoice.read`: may read invoices.
#[derive(Debug)]
pub struct InvoiceRead;

impl attome_server::authz::PrivilegeKey for InvoiceRead {
    const KEY: &'static str = "invoice.read";
}

#[utoipa::path(
    get,
    path = "/api/v1/billing/accounts/{id}/statement",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The account"), StatementQuery),
    responses(
        (status = 200, description = "Opening balance, the period's documents and payments, closing balance, per currency", body = AccountStatement),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such account, or not one the caller can read", body = attome_types::ErrorResponse),
        (status = 422, description = "from is after to", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_statement(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<InvoiceRead>>,
    axum::extract::Path(account): axum::extract::Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<StatementQuery>,
) -> Result<axum::Json<AccountStatement>, AppError> {
    let today = Utc::now().date_naive();
    let to = q.to.unwrap_or(today);
    let from = q.from.unwrap_or_else(|| {
        NaiveDate::from_ymd_opt(chrono::Datelike::year(&to), chrono::Datelike::month(&to), 1)
            .unwrap_or(to)
    });
    Ok(axum::Json(
        statement(&state, &ctx, account, from, to).await?,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/billing/ageing",
    tag = "billing",
    params(AgeingQuery),
    responses(
        (status = 200, description = "Open amounts per account and currency by days past due", body = PaginatedResponse<AgeingRow>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read invoices or accounts", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_ageing(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<InvoiceRead>>,
    axum::extract::Query(q): axum::extract::Query<AgeingQuery>,
) -> Result<axum::Json<PaginatedResponse<AgeingRow>>, AppError> {
    let as_of = q.as_of.unwrap_or_else(|| Utc::now().date_naive());
    let page = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    };
    Ok(axum::Json(ageing(&state, &ctx, as_of, page).await?))
}

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AgeingTotalsQuery {
    /// The day the ageing is taken on (default today).
    pub as_of: Option<NaiveDate>,
}

#[utoipa::path(
    get,
    path = "/api/v1/billing/ageing/totals",
    tag = "billing",
    params(AgeingTotalsQuery),
    responses(
        (status = 200, description = "The ageing of every readable account, per currency (a handful of rows)", body = PaginatedResponse<AgeingTotals>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read invoices or accounts", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_ageing_totals(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<InvoiceRead>>,
    axum::extract::Query(q): axum::extract::Query<AgeingTotalsQuery>,
) -> Result<axum::Json<PaginatedResponse<AgeingTotals>>, AppError> {
    let as_of = q.as_of.unwrap_or_else(|| Utc::now().date_naive());
    // One row per currency: the whole list is one page.
    let items = ageing_totals(&state, &ctx, as_of).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(axum::Json(PaginatedResponse {
        page_size: total.max(1),
        items,
        total,
        page: 1,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_statement, get_ageing, get_ageing_totals),
    components(schemas(
        StatementEntry,
        CurrencyStatement,
        AccountStatement,
        AgeingRow,
        AgeingTotals
    ))
)]
pub(crate) struct ApiDocFragment;
