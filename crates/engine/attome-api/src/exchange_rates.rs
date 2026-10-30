//! A19-T2: dated exchange rates (`exchange_rate`, migration 0337).
//!
//! - `GET /api/v1/exchange-rates/rate?from=&to=&on=` answers the rate that
//!   applies on a day ([`attome_core::fx::rate_on`]): the newest on or before
//!   it, the deployment's preferred source (`core.fx_source`) first on a tie.
//!   Any signed-in person may read rates: they are reference data a money
//!   field shows conversions with.
//! - `GET /api/v1/exchange-rates` lists stored rates, newest first.
//! - `POST /api/v1/exchange-rates` enters one rate by hand (source `manual`
//!   unless named) and `POST /api/v1/exchange-rates/import` stores a batch
//!   from one source: what a connector or a scheduled flow reading a central
//!   bank's published rates calls. A rate for the same pair, day and source
//!   is replaced. `DELETE /api/v1/exchange-rates/{id}` removes one.
//!
//! Writes need the Deployment administration area and are audited as
//! configuration changes in their own transaction.
//!
//! - A19-T6: `GET /api/v1/reports/fx-revaluation` revalues the open amounts
//!   of one money field that converts to the base currency (its `fx`
//!   option): per currency, the base amount booked (`<field>_base`) against
//!   the amount at the rate on `as_of`, and the gain or loss. "Open" is the
//!   caller's to say (`open_field` with `open_values`); without it every live
//!   record counts. The totals cover every record, so the report needs read
//!   access to every record of the entity (Global).

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::fx::{self, AppliedRate, ExchangeRate, MANUAL_SOURCE};
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Most rates one import carries.
pub const MAX_IMPORT_RATES: usize = 1_000;

/// A stored rate.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExchangeRateRow {
    pub id: Uuid,
    pub from_currency: String,
    pub to_currency: String,
    /// One unit of `from_currency` in `to_currency`, as a decimal string.
    #[schema(value_type = String, example = "3.7500000000")]
    pub rate: Decimal,
    pub rate_date: NaiveDate,
    pub source: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One rate to store.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ExchangeRateInput {
    pub from_currency: String,
    pub to_currency: String,
    /// A decimal number or string, above zero; kept to 10 places.
    #[schema(value_type = String, example = "3.75")]
    pub rate: Decimal,
    pub rate_date: NaiveDate,
    /// Where the rate comes from; `manual` when left out.
    pub source: Option<String>,
}

/// A batch of rates from one source.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ExchangeRateImport {
    /// The source every rate in the batch comes from, such as `sama` or
    /// `cbuae`.
    pub source: String,
    pub rates: Vec<ExchangeRateImportItem>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ExchangeRateImportItem {
    pub from_currency: String,
    pub to_currency: String,
    #[schema(value_type = String, example = "0.2666")]
    pub rate: Decimal,
    pub rate_date: NaiveDate,
}

/// How many rates an import stored.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExchangeRateImported {
    pub stored: usize,
}

/// The applied rate's answer.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AppliedRateResponse {
    pub from_currency: String,
    pub to_currency: String,
    /// The rate used, as a decimal string.
    #[schema(value_type = String, example = "3.7500000000")]
    pub rate: Decimal,
    /// The day of the stored rate (on or before the day asked for).
    pub rate_date: NaiveDate,
    pub source: String,
    /// The stored rate was the opposite direction, inverted.
    pub inverted: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct RateQuery {
    /// The currency converted from.
    pub from: String,
    /// The currency converted to.
    pub to: String,
    /// The day; today (UTC) when left out.
    pub on: Option<NaiveDate>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListQuery {
    /// Only rates from this currency.
    pub from: Option<String>,
    /// Only rates to this currency.
    pub to: Option<String>,
}

/// The deployment's preferred rate source, when set.
fn preferred_source(state: &EngineState) -> Option<String> {
    attome_core::setting_registry()
        .get(fx::SOURCE_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| fx::is_source(s))
}

/// A currency code from a query, upper-cased.
fn code(value: &str, name: &str) -> Result<String, AppError> {
    let code = value.trim().to_ascii_uppercase();
    if attome_core::money::is_code(&code) {
        Ok(code)
    } else {
        Err(AppError::Validation(format!(
            "{name}: an ISO 4217 currency code"
        )))
    }
}

/// The rate that applies on a day
///
/// The rate from one currency to another on a day: the newest stored rate on or before it, the deployment's preferred source first on a tie of days, the opposite direction inverted when only that is stored. Any signed-in person.
#[utoipa::path(
    get,
    path = "/api/v1/exchange-rates/rate",
    tag = "money",
    params(RateQuery),
    responses(
        (status = 200, description = "The rate that applies", body = AppliedRateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No rate on or before the day", body = ErrorResponse),
        (status = 422, description = "A currency is not an ISO 4217 code", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn rate_on(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Query(query): Query<RateQuery>,
) -> Result<Json<AppliedRateResponse>, AppError> {
    let from = code(&query.from, "from")?;
    let to = code(&query.to, "to")?;
    let day = query.on.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let preferred = preferred_source(&state);
    let AppliedRate {
        rate,
        rate_date,
        source,
        inverted,
    } = fx::rate_on(&state.base.db, &from, &to, day, preferred.as_deref())
        .await
        .map_err(attome_db::classify)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(AppliedRateResponse {
        from_currency: from,
        to_currency: to,
        rate,
        rate_date,
        source,
        inverted,
    }))
}

type RateRow = (
    Uuid,
    String,
    String,
    String,
    NaiveDate,
    String,
    chrono::DateTime<chrono::Utc>,
);

fn row_of(
    (id, from_currency, to_currency, rate, rate_date, source, created_at): RateRow,
) -> Result<ExchangeRateRow, AppError> {
    Ok(ExchangeRateRow {
        id,
        from_currency,
        to_currency,
        rate: rate
            .parse()
            .map_err(|_| AppError::internal("exchange_rate.rate did not parse"))?,
        rate_date,
        source,
        created_at,
    })
}

/// Stored exchange rates
///
/// Stored exchange rates, newest day first, optionally for one currency pair. Any signed-in person.
#[utoipa::path(
    get,
    path = "/api/v1/exchange-rates",
    tag = "money",
    params(ListQuery, OnePageQuery),
    responses(
        (status = 200, description = "A page of rates", body = PaginatedResponse<ExchangeRateRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "A currency is not an ISO 4217 code", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn list_rates(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Query(query): Query<ListQuery>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ExchangeRateRow>>, AppError> {
    let from = query.from.as_deref().map(|c| code(c, "from")).transpose()?;
    let to = query.to.as_deref().map(|c| code(c, "to")).transpose()?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM exchange_rate \
          WHERE ($1::text IS NULL OR from_currency = $1) \
            AND ($2::text IS NULL OR to_currency = $2)",
    )
    .bind(&from)
    .bind(&to)
    .fetch_one(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let rows: Vec<RateRow> = sqlx::query_as(
        "SELECT id, from_currency::text, to_currency::text, rate::text, rate_date, source, \
                created_at \
           FROM exchange_rate \
          WHERE ($1::text IS NULL OR from_currency = $1) \
            AND ($2::text IS NULL OR to_currency = $2) \
          ORDER BY rate_date DESC, from_currency, to_currency, source \
          LIMIT $3 OFFSET $4",
    )
    .bind(&from)
    .bind(&to)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let items = rows.into_iter().map(row_of).collect::<Result<_, _>>()?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Checks a batch and returns it ready to store: codes upper-cased, rates
/// rounded, every currency known to the `currency` table.
async fn checked(
    state: &EngineState,
    rates: Vec<ExchangeRate>,
) -> Result<Vec<ExchangeRate>, AppError> {
    let mut out = Vec::with_capacity(rates.len());
    let mut codes: Vec<String> = Vec::new();
    for (i, mut rate) in rates.into_iter().enumerate() {
        rate.from_currency = rate.from_currency.trim().to_ascii_uppercase();
        rate.to_currency = rate.to_currency.trim().to_ascii_uppercase();
        rate.rate = fx::validate(&rate)
            .map_err(|reason| AppError::Validation(format!("rates[{i}]: {reason}")))?;
        codes.push(rate.from_currency.clone());
        codes.push(rate.to_currency.clone());
        out.push(rate);
    }
    codes.sort();
    codes.dedup();
    let known: Vec<String> =
        sqlx::query_scalar("SELECT code::text FROM currency WHERE code = ANY($1)")
            .bind(&codes)
            .fetch_all(&state.base.db)
            .await
            .map_err(attome_db::classify)?;
    if let Some(unknown) = codes.iter().find(|c| !known.contains(c)) {
        return Err(AppError::Validation(format!(
            "{unknown} is not a currency this deployment knows"
        )));
    }
    Ok(out)
}

/// Stores `rates` (replacing a rate for the same pair, day and source) and
/// writes the audit event, in one transaction. Returns the stored ids.
async fn store(
    state: &EngineState,
    actor: Uuid,
    rates: &[ExchangeRate],
    event: &'static str,
    comment: String,
) -> Result<Vec<Uuid>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut ids = Vec::with_capacity(rates.len());
    for rate in rates {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO exchange_rate \
                 (id, from_currency, to_currency, rate, rate_date, source, created_by) \
             VALUES ($1, $2, $3, $4::numeric, $5, $6, $7) \
             ON CONFLICT (from_currency, to_currency, rate_date, source) \
             DO UPDATE SET rate = EXCLUDED.rate, created_at = now(), \
                           created_by = EXCLUDED.created_by \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&rate.from_currency)
        .bind(&rate.to_currency)
        .bind(rate.rate.to_string())
        .bind(rate.rate_date)
        .bind(&rate.source)
        .bind(actor)
        .fetch_one(&mut *tx)
        .await
        .map_err(attome_db::classify)?;
        ids.push(id);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            actor,
            "exchange_rate",
            ids.first().copied(),
        )
        .named(event)
        .comment(comment),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ids)
}

/// Enter an exchange rate
///
/// Stores one rate for a day, replacing a rate for the same pair, day and source. Source `manual` unless named. Needs the Deployment administration area.
#[utoipa::path(
    post,
    path = "/api/v1/exchange-rates",
    tag = "money",
    request_body = ExchangeRateInput,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The rate as stored", body = ExchangeRateRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the Deployment administration area", body = ErrorResponse),
        (status = 422, description = "A code, the rate or the source is not valid, or a currency is unknown", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn create_rate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Json(input): Json<ExchangeRateInput>,
) -> Result<impl IntoResponse, AppError> {
    let rate = ExchangeRate {
        from_currency: input.from_currency,
        to_currency: input.to_currency,
        rate: input.rate,
        rate_date: input.rate_date,
        source: input.source.unwrap_or_else(|| MANUAL_SOURCE.to_owned()),
    };
    let rates = checked(&state, vec![rate]).await?;
    let r = &rates[0];
    let comment = format!(
        "exchange rate {} -> {} on {} from {}",
        r.from_currency, r.to_currency, r.rate_date, r.source
    );
    let ids = store(&state, ctx.user_id, &rates, "exchange_rate.set", comment).await?;
    let row: RateRow = sqlx::query_as(
        "SELECT id, from_currency::text, to_currency::text, rate::text, rate_date, source, \
                created_at \
           FROM exchange_rate WHERE id = $1",
    )
    .bind(ids[0])
    .fetch_one(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    Ok((StatusCode::CREATED, Json(row_of(row)?)))
}

/// Import exchange rates
///
/// Stores up to 1,000 rates from one source in one transaction, replacing rates for the same pair, day and source: what a connector or a scheduled flow calls with a central bank's published rates. Needs the Deployment administration area.
#[utoipa::path(
    post,
    path = "/api/v1/exchange-rates/import",
    tag = "money",
    request_body = ExchangeRateImport,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Every rate was stored", body = ExchangeRateImported),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the Deployment administration area", body = ErrorResponse),
        (status = 422, description = "The batch is empty or too large, or a rate is not valid; nothing was stored", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn import_rates(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Json(input): Json<ExchangeRateImport>,
) -> Result<Json<ExchangeRateImported>, AppError> {
    if input.rates.is_empty() || input.rates.len() > MAX_IMPORT_RATES {
        return Err(AppError::Validation(format!(
            "an import carries 1 to {MAX_IMPORT_RATES} rates"
        )));
    }
    let source = input.source.trim().to_owned();
    let rates = input
        .rates
        .into_iter()
        .map(|r| ExchangeRate {
            from_currency: r.from_currency,
            to_currency: r.to_currency,
            rate: r.rate,
            rate_date: r.rate_date,
            source: source.clone(),
        })
        .collect();
    let rates = checked(&state, rates).await?;
    let comment = format!("{} exchange rates imported from {source}", rates.len());
    let ids = store(&state, ctx.user_id, &rates, "exchange_rate.import", comment).await?;
    Ok(Json(ExchangeRateImported { stored: ids.len() }))
}

/// Delete an exchange rate
///
/// Removes one stored rate. Needs the Deployment administration area.
#[utoipa::path(
    delete,
    path = "/api/v1/exchange-rates/{id}",
    tag = "money",
    params(("id" = Uuid, Path, description = "The rate")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the Deployment administration area", body = ErrorResponse),
        (status = 404, description = "No such rate", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn delete_rate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed: Option<(String, String, NaiveDate, String)> = sqlx::query_as(
        "DELETE FROM exchange_rate WHERE id = $1 \
         RETURNING from_currency::text, to_currency::text, rate_date, source",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    let Some((from, to, day, source)) = removed else {
        return Err(AppError::NotFound);
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "exchange_rate",
            Some(id),
        )
        .named("exchange_rate.delete")
        .comment(format!(
            "exchange rate {from} -> {to} on {day} from {source}"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A19-T5: one currency a money amount may carry.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CurrencyRow {
    /// ISO 4217 code.
    pub code: String,
    /// The decimals an amount in it is rounded to.
    pub decimals: i16,
    pub symbol: String,
    pub name: String,
    /// The deployment's base currency (`core.base_currency`).
    pub is_base: bool,
}

/// Currencies
///
/// Every currency a money amount may carry, with its decimals and symbol, and which one is the
/// deployment's base currency. Any signed-in person.
#[utoipa::path(
    get,
    path = "/api/v1/currencies",
    tag = "money",
    responses(
        (status = 200, description = "Every currency, by code, on one page", body = PaginatedResponse<CurrencyRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn list_currencies(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Result<Json<PaginatedResponse<CurrencyRow>>, AppError> {
    let base = attome_records::money::base_currency(&state);
    let rows: Vec<(String, i16, String, String)> =
        sqlx::query_as("SELECT code::text, decimals, symbol, name FROM currency ORDER BY code")
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<CurrencyRow> = rows
        .into_iter()
        .map(|(code, decimals, symbol, name)| CurrencyRow {
            is_base: code == base,
            code,
            decimals,
            symbol,
            name,
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// `GET /api/v1/reports/fx-revaluation` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RevaluationQuery {
    /// The entity's logical name.
    pub entity: String,
    /// A money field with the `fx` option (it has `<field>_base`).
    pub attribute: String,
    /// The day whose rate revalues the amounts; today when absent.
    pub as_of: Option<NaiveDate>,
    /// A field whose value says a record is open (`status`, say).
    pub open_field: Option<String>,
    /// The comma-separated values of `open_field` that mean open.
    pub open_values: Option<String>,
}

/// One currency's revaluation.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct RevaluationLine {
    pub currency: String,
    /// Open records in this currency.
    pub records: i64,
    /// Their amounts, in this currency.
    #[schema(value_type = String)]
    pub amount: Decimal,
    /// The base amount booked for them.
    #[schema(value_type = String)]
    pub booked_base: Decimal,
    /// The rate on `as_of`, from this currency to the base; `null` when none
    /// is stored on or before it.
    #[schema(value_type = Option<String>)]
    pub rate: Option<Decimal>,
    pub rate_date: Option<NaiveDate>,
    /// The amounts at that rate, in the base currency.
    #[schema(value_type = Option<String>)]
    pub revalued_base: Option<Decimal>,
    /// `revalued_base - booked_base`: a gain when positive.
    #[schema(value_type = Option<String>)]
    pub gain_loss: Option<Decimal>,
}

/// The revaluation of one money field.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Revaluation {
    pub entity: String,
    pub attribute: String,
    pub base_currency: String,
    pub as_of: NaiveDate,
    /// Currencies other than the base, alphabetically.
    pub lines: Vec<RevaluationLine>,
    /// The sum of every line's gain or loss that has a rate.
    #[schema(value_type = String)]
    pub total_gain_loss: Decimal,
    /// Currencies with no rate on or before `as_of`, left out of the total.
    pub missing_rates: Vec<String>,
}

/// One currency's line from its sums and rate, revalued to `decimals`.
/// Pure.
pub fn revaluation_line(
    currency: String,
    records: i64,
    amount: Decimal,
    booked_base: Decimal,
    rate: Option<(Decimal, NaiveDate)>,
    decimals: u32,
) -> RevaluationLine {
    let revalued = rate.map(|(rate, _)| fx::convert(amount, rate, decimals));
    RevaluationLine {
        currency,
        records,
        amount,
        booked_base,
        rate: rate.map(|(rate, _)| rate),
        rate_date: rate.map(|(_, day)| day),
        revalued_base: revalued,
        gain_loss: revalued.map(|r| r - booked_base),
    }
}

/// Foreign-currency revaluation
///
/// For one money field converted to the base currency, the open amounts per currency: the base
/// amount booked against the amount at the rate on `as_of`, and the gain or loss. Needs read access
/// to every record of the entity.
#[utoipa::path(
    get,
    path = "/api/v1/reports/fx-revaluation",
    tag = "money",
    params(RevaluationQuery),
    responses(
        (status = 200, description = "The revaluation per currency", body = Revaluation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller cannot read every record of the entity", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "Not a money field with the fx option, or an unknown open field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn fx_revaluation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<RevaluationQuery>,
) -> Result<Json<Revaluation>, AppError> {
    use attome_security::SecurityContextExt;
    let entity = query.entity.trim().to_owned();
    let (entity_id, names): (Uuid, Vec<String>) = {
        let registry = state.entities.load();
        let meta = registry.get(&entity).ok_or(AppError::NotFound)?;
        (
            meta.entity_id,
            meta.attrs.iter().map(|a| a.logicalname.clone()).collect(),
        )
    };
    ctx.require(&entity, "read")?;
    if !ctx.is_admin {
        let level = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            entity_id,
            &entity,
            attome_security::RecordAction::Read,
        )
        .await?;
        if level != attome_server::security::AccessLevel::Global {
            return Err(AppError::Forbidden);
        }
    }
    let field = query.attribute.trim().to_owned();
    let currency_field = format!("{field}_currency");
    let base_field = fx::base_field(&field);
    let has = |name: &str| names.iter().any(|n| n == name);
    if !(has(&field) && has(&currency_field) && has(&base_field)) {
        return Err(AppError::Validation(format!(
            "{field} is not a money field with the fx option on {entity}"
        )));
    }
    let open_values: Vec<String> = query
        .open_values
        .as_deref()
        .map(|v| {
            v.split(',')
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let open_field = match query.open_field.as_deref().map(str::trim) {
        Some(open) if !has(open) => {
            return Err(AppError::Validation(format!(
                "{open} is not a field of {entity}"
            )));
        }
        Some(_) if open_values.is_empty() => {
            return Err(AppError::Validation(
                "open_values names the values of open_field that mean open".into(),
            ));
        }
        other => other.map(str::to_owned),
    };
    let base = attome_records::money::base_currency(&state);
    let as_of = query
        .as_of
        .unwrap_or_else(|| chrono::Utc::now().date_naive());
    type SumRow = (String, i64, Option<String>, Option<String>);
    let pool = state.base.read_pool(ctx.user_id).await;
    let rows: Vec<SumRow> = match open_field.as_deref() {
        Some(open) => {
            let sql = format!(
                "SELECT {cur}::text, COUNT(*), SUM({amt})::text, SUM({bas})::text FROM {t} \
                  WHERE is_active = true AND {amt} IS NOT NULL AND {bas} IS NOT NULL \
                    AND {cur} IS NOT NULL AND {cur}::text <> $1 AND {o}::text = ANY($2) \
                  GROUP BY 1 ORDER BY 1",
                cur = attome_core::quote_ident(&currency_field),
                amt = attome_core::quote_ident(&field),
                bas = attome_core::quote_ident(&base_field),
                t = attome_core::quote_ident(&entity),
                o = attome_core::quote_ident(open),
            );
            sqlx::query_as(&sql)
                .bind(&base)
                .bind(&open_values)
                .fetch_all(pool)
                .await
        }
        None => {
            let sql = format!(
                "SELECT {cur}::text, COUNT(*), SUM({amt})::text, SUM({bas})::text FROM {t} \
                  WHERE is_active = true AND {amt} IS NOT NULL AND {bas} IS NOT NULL \
                    AND {cur} IS NOT NULL AND {cur}::text <> $1 \
                  GROUP BY 1 ORDER BY 1",
                cur = attome_core::quote_ident(&currency_field),
                amt = attome_core::quote_ident(&field),
                bas = attome_core::quote_ident(&base_field),
                t = attome_core::quote_ident(&entity),
            );
            sqlx::query_as(&sql).bind(&base).fetch_all(pool).await
        }
    }
    .map_err(AppError::internal)?;
    let decimals: i16 = sqlx::query_scalar("SELECT decimals FROM currency WHERE code = $1")
        .bind(&base)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or(2);
    let decimals = u32::try_from(decimals).unwrap_or(2);
    let preferred = preferred_source(&state);
    let parse =
        |v: Option<String>| -> Decimal { v.and_then(|v| v.parse().ok()).unwrap_or_default() };
    let mut lines = Vec::new();
    let mut missing_rates = Vec::new();
    for (currency, records, amount, booked) in rows {
        let rate = fx::rate_on(
            &state.base.db,
            &currency,
            &base,
            as_of,
            preferred.as_deref(),
        )
        .await
        .map_err(attome_db::classify)?
        .map(|r| (r.rate, r.rate_date));
        if rate.is_none() {
            missing_rates.push(currency.clone());
        }
        lines.push(revaluation_line(
            currency,
            records,
            parse(amount),
            parse(booked),
            rate,
            decimals,
        ));
    }
    let total_gain_loss = lines.iter().filter_map(|l| l.gain_loss).sum();
    Ok(Json(Revaluation {
        entity,
        attribute: field,
        base_currency: base,
        as_of,
        lines,
        total_gain_loss,
        missing_rates,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/exchange-rates", get(list_rates).post(create_rate))
        .route("/api/v1/exchange-rates/rate", get(rate_on))
        .route("/api/v1/exchange-rates/import", post(import_rates))
        .route("/api/v1/exchange-rates/{id}", delete(delete_rate))
        .route("/api/v1/reports/fx-revaluation", get(fx_revaluation))
        .route("/api/v1/currencies", get(list_currencies))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        rate_on,
        list_rates,
        create_rate,
        import_rates,
        delete_rate,
        fx_revaluation,
        list_currencies
    ),
    components(schemas(
        ExchangeRateRow,
        ExchangeRateInput,
        ExchangeRateImport,
        ExchangeRateImportItem,
        ExchangeRateImported,
        AppliedRateResponse,
        Revaluation,
        RevaluationLine,
        CurrencyRow
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod revaluation_tests {
    use super::*;
    use std::str::FromStr;

    fn d(v: &str) -> Decimal {
        Decimal::from_str(v).unwrap_or_default()
    }

    /// A19-T6: the gain or loss is the amount at today's rate less the base
    /// booked; no rate leaves the line without one.
    #[test]
    fn revaluation_line_reports_gain_and_loss() {
        let day = NaiveDate::from_ymd_opt(2026, 10, 30).unwrap_or_default();
        let line = revaluation_line(
            "USD".into(),
            2,
            d("1000"),
            d("3750.00"),
            Some((d("3.76"), day)),
            2,
        );
        assert_eq!(line.revalued_base, Some(d("3760.00")));
        assert_eq!(line.gain_loss, Some(d("10.00")));
        let loss = revaluation_line(
            "EUR".into(),
            1,
            d("100"),
            d("420.00"),
            Some((d("4.1"), day)),
            2,
        );
        assert_eq!(loss.gain_loss, Some(d("-10.00")));
        let none = revaluation_line("GBP".into(), 1, d("5"), d("24"), None, 2);
        assert_eq!((none.rate, none.gain_loss), (None, None));
    }
}
