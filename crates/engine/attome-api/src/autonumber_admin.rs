//! A4-T5: the autonumber gap report. For each active rule numbering one
//! field: its counters, and the numbers stored on the entity's records (soft
//! deleted ones too: a deleted record keeps its number) grouped by the
//! counter they came from, with any number missing between the first and the
//! last, and any number given twice. A gap-free rule should show none; a
//! fast-mode rule may.

use attome_core::{EngineState, quote_ident};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most stored values one report reads.
const MAX_VALUES: i64 = 200_000;
/// The most missing or repeated numbers listed per counter.
const MAX_LISTED: usize = 100;

#[derive(Debug, Serialize, ToSchema)]
pub struct AutonumberCounter {
    /// The rendered sequence key (empty: the rule's single counter).
    pub sequence_key: String,
    /// The period (`2026`, `H1448`, empty for never).
    pub period: String,
    /// The next number this counter gives.
    pub next_value: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AutonumberGroup {
    /// The stored values of one counter, the number shown as `#`.
    pub pattern: String,
    pub first: i64,
    pub last: i64,
    pub count: i64,
    /// Numbers between the rule's initial value and the last one that no
    /// record holds (at most 100 listed).
    pub missing: Vec<i64>,
    /// Numbers more than one record holds (at most 100 listed).
    pub duplicates: Vec<i64>,
    /// More missing numbers exist than are listed.
    pub missing_more: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AutonumberRuleGaps {
    pub rule_id: Uuid,
    pub format: String,
    /// Gaps are allowed (A4-T4).
    pub fast_mode: bool,
    pub counters: Vec<AutonumberCounter>,
    pub groups: Vec<AutonumberGroup>,
    /// Stored values that do not fit the format (typed by hand or migrated).
    pub unmatched: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AutonumberGapReport {
    pub entity: String,
    pub attribute: String,
    pub rules: Vec<AutonumberRuleGaps>,
    pub values_read: i64,
    /// More than 200,000 values are stored; only that many were read.
    pub truncated: bool,
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/autonumber/{entity}/{attribute}/gaps",
        get(gaps),
    )
}

/// Autonumber gaps
///
/// A4-T5: the gap report of the numbers one field holds.
#[utoipa::path(
    get,
    path = "/api/v1/admin/autonumber/{entity}/{attribute}/gaps",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "Entity logical name"),
        ("attribute" = String, Path, description = "The numbered field"),
    ),
    responses(
        (status = 200, description = "Counters and missing or repeated numbers per rule", body = AutonumberGapReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity or field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn gaps(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((entity, attribute)): Path<(String, String)>,
) -> Result<Json<AutonumberGapReport>, AppError> {
    gap_report(&state, &entity, &attribute).await.map(Json)
}

/// Builds the report (see the module doc).
pub async fn gap_report(
    state: &EngineState,
    entity: &str,
    attribute: &str,
) -> Result<AutonumberGapReport, AppError> {
    let db = &state.base.db;
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
          WHERE e.logicalname = $1 AND a.logicalname = $2)",
    )
    .bind(entity)
    .bind(attribute)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !known
        || !attome_metadata::provision::valid_identifier(entity)
        || !attome_metadata::provision::valid_identifier(attribute)
    {
        return Err(AppError::NotFound);
    }
    #[allow(clippy::type_complexity)]
    let rules: Vec<(
        Uuid,
        Option<String>,
        Option<i64>,
        Option<bool>,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, format, initial_value::bigint, fast_mode, next_value::bigint, scope_key \
             FROM autovalue WHERE entity_logicalname = $1 AND attribute_logicalname = $2 \
               AND is_active = TRUE ORDER BY created_at, id",
    )
    .bind(entity)
    .bind(attribute)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let values: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT {col}::text FROM {table} WHERE {col} IS NOT NULL LIMIT $1",
        col = quote_ident(attribute),
        table = quote_ident(entity)
    ))
    .bind(MAX_VALUES + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let truncated = values.len() as i64 > MAX_VALUES;
    let values = &values[..values.len().min(MAX_VALUES as usize)];

    let mut report = Vec::new();
    for (rule_id, format, initial, fast, next_value, scope_key) in rules {
        let format = format.unwrap_or_else(|| "{SEQ}".to_owned());
        let initial = initial.unwrap_or(1);
        let mut counters: Vec<AutonumberCounter> = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT sequence_key, period_key, next_value FROM autovalue_counter \
             WHERE rule_id = $1 ORDER BY sequence_key, period_key",
        )
        .bind(rule_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(sequence_key, period, next_value)| AutonumberCounter {
            sequence_key,
            period,
            next_value,
        })
        .collect();
        if let Some(next_value) = next_value {
            counters.insert(
                0,
                AutonumberCounter {
                    sequence_key: String::new(),
                    period: scope_key.unwrap_or_default(),
                    next_value,
                },
            );
        }
        let mut by_pattern: BTreeMap<String, BTreeMap<i64, i64>> = BTreeMap::new();
        let mut unmatched = 0;
        for value in values {
            match attome_metadata::autovalue::split_number(&format, value) {
                Some((pattern, number)) => {
                    *by_pattern
                        .entry(pattern)
                        .or_default()
                        .entry(number)
                        .or_default() += 1;
                }
                None => unmatched += 1,
            }
        }
        let groups = by_pattern
            .into_iter()
            .map(|(pattern, numbers)| group_of(pattern, &numbers, initial))
            .collect();
        report.push(AutonumberRuleGaps {
            rule_id,
            format,
            fast_mode: fast.unwrap_or(false),
            counters,
            groups,
            unmatched,
        });
    }
    Ok(AutonumberGapReport {
        entity: entity.to_owned(),
        attribute: attribute.to_owned(),
        rules: report,
        values_read: values.len() as i64,
        truncated,
    })
}

/// One counter's numbers: the missing ones between the rule's initial value
/// and the last, and the repeated ones.
fn group_of(pattern: String, numbers: &BTreeMap<i64, i64>, initial: i64) -> AutonumberGroup {
    let first = numbers.keys().next().copied().unwrap_or(initial);
    let last = numbers.keys().next_back().copied().unwrap_or(initial);
    let mut missing = Vec::new();
    let mut missing_more = false;
    for n in initial.min(first)..=last {
        if !numbers.contains_key(&n) {
            if missing.len() == MAX_LISTED {
                missing_more = true;
                break;
            }
            missing.push(n);
        }
    }
    let duplicates = numbers
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(n, _)| *n)
        .take(MAX_LISTED)
        .collect();
    AutonumberGroup {
        pattern,
        first,
        last,
        count: numbers.values().sum(),
        missing,
        duplicates,
        missing_more,
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(gaps),
    components(schemas(
        AutonumberGapReport,
        AutonumberRuleGaps,
        AutonumberGroup,
        AutonumberCounter
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonumber_gaps_group_lists_missing_and_repeated() {
        let numbers: BTreeMap<i64, i64> = [(1, 1), (2, 2), (4, 1)].into_iter().collect();
        let group = group_of("INV-#".into(), &numbers, 1);
        assert_eq!(group.missing, [3]);
        assert_eq!(group.duplicates, [2]);
        assert_eq!(group.count, 4);
        assert_eq!((group.first, group.last), (1, 4));
    }
}
