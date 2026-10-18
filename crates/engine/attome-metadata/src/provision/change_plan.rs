//! Y12-T3: how a structure change will run before a builder makes it.
//! Every proposed change is one of three classes:
//!
//! - **instant**: a catalog-only change, or any change to a table at or under
//!   the inline limit (adding an optional or required field, a choice value,
//!   a rename; `required` is application-level, D-788, so it never scans);
//! - **online**: a build that runs beside live traffic (a concurrent index, a
//!   `max_length` CHECK added `NOT VALID` and then validated);
//! - **background**: a durable data-step run that rewrites values (a type
//!   change, a backfill, archive-and-drop).
//!
//! An estimate is the table's planner row count over a measured rate: the
//! median rows per second of the last 20 finished data-step runs of the same
//! kind, or of DDL ledger rows that recorded their rows, and
//! [`DEFAULT_ROWS_PER_SECOND`] while nothing has been measured. An instant
//! change estimates zero. Nothing here writes.

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};

use super::attribute::table_row_count_exceeds;
use super::identifiers::valid_identifier;

/// The rate an estimate assumes before any run of its kind was measured.
pub const DEFAULT_ROWS_PER_SECOND: f64 = 20_000.0;

/// How many recent runs the measured rate is the median of.
const RATE_SAMPLE: i64 = 20;

/// How a change runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    Instant,
    Online,
    Background,
}

/// One proposed structure change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StructureChange {
    AddField { field: String },
    AddChoiceValue { field: String },
    RenameField { field: String, to: String },
    SetRequired { field: String },
    AddIndex { field: String },
    SetMaxLength { field: String, max_length: i32 },
    ChangeType { field: String, to: String },
    Backfill { field: String },
    DeleteField { field: String },
}

impl StructureChange {
    /// A short label for the plan (`change_type amount -> text`).
    pub fn describe(&self) -> String {
        match self {
            Self::AddField { field } => format!("add_field {field}"),
            Self::AddChoiceValue { field } => format!("add_choice_value {field}"),
            Self::RenameField { field, to } => format!("rename_field {field} -> {to}"),
            Self::SetRequired { field } => format!("set_required {field}"),
            Self::AddIndex { field } => format!("add_index {field}"),
            Self::SetMaxLength { field, max_length } => {
                format!("set_max_length {field} {max_length}")
            }
            Self::ChangeType { field, to } => format!("change_type {field} -> {to}"),
            Self::Backfill { field } => format!("backfill {field}"),
            Self::DeleteField { field } => format!("delete_field {field}"),
        }
    }

    /// Its class on a table over the inline limit.
    fn large_table_class(&self) -> ChangeClass {
        match self {
            Self::AddField { .. }
            | Self::AddChoiceValue { .. }
            | Self::RenameField { .. }
            | Self::SetRequired { .. } => ChangeClass::Instant,
            Self::AddIndex { .. } | Self::SetMaxLength { .. } => ChangeClass::Online,
            Self::ChangeType { .. } | Self::Backfill { .. } | Self::DeleteField { .. } => {
                ChangeClass::Background
            }
        }
    }

    /// Where its rate is measured: a data-step run kind or a DDL kind.
    fn rate_source(&self) -> Option<RateSource> {
        match self {
            Self::AddIndex { .. } => Some(RateSource::Ddl("CREATE INDEX")),
            Self::SetMaxLength { .. } => Some(RateSource::Ddl("ALTER TABLE")),
            Self::ChangeType { .. } => Some(RateSource::Run("retype")),
            Self::Backfill { .. } => Some(RateSource::Run("set_default")),
            Self::DeleteField { .. } => Some(RateSource::Run("archive")),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateSource {
    Ddl(&'static str),
    Run(&'static str),
}

/// One change's class and estimate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangePlanItem {
    pub change: String,
    pub class: ChangeClass,
    pub estimate_secs: u64,
}

/// The class of `change` on a table of `large` size.
pub fn class_of(change: &StructureChange, large: bool) -> ChangeClass {
    if large {
        change.large_table_class()
    } else {
        ChangeClass::Instant
    }
}

/// Seconds for `rows` at `rows_per_second`, rounded up; zero for an instant
/// change.
pub fn estimate_secs(class: ChangeClass, rows: i64, rows_per_second: f64) -> u64 {
    if class == ChangeClass::Instant || rows <= 0 {
        return 0;
    }
    let rate = if rows_per_second.is_finite() && rows_per_second > 0.0 {
        rows_per_second
    } else {
        DEFAULT_ROWS_PER_SECOND
    };
    // An estimate in whole seconds; row counts sit far below 2^52.
    let secs = (rows as f64 / rate).ceil() as u64;
    secs.max(1)
}

/// The median rows per second of the last runs measured for `source`.
async fn rows_per_second(db: &DbPool, source: RateSource) -> Result<f64, AppError> {
    let rates: Vec<f64> = match source {
        RateSource::Run(kind) => sqlx::query_scalar(
            "SELECT (rows_scanned / GREATEST(EXTRACT(EPOCH FROM (finished_at - created_at)), 0.001))::float8 \
               FROM data_step_run \
              WHERE kind = $1 AND status = 'succeeded' AND finished_at IS NOT NULL \
                AND rows_scanned > 0 \
              ORDER BY finished_at DESC LIMIT $2",
        )
        .bind(kind)
        .bind(RATE_SAMPLE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
        RateSource::Ddl(kind) => sqlx::query_scalar(
            "SELECT (rows_touched * 1000.0 / GREATEST(duration_ms, 1))::float8 \
               FROM ddl_log \
              WHERE statement_kind = $1 AND outcome = 'ok' AND rows_touched > 0 \
              ORDER BY started_at DESC LIMIT $2",
        )
        .bind(kind)
        .bind(RATE_SAMPLE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
    };
    Ok(median(rates).unwrap_or(DEFAULT_ROWS_PER_SECOND))
}

/// The median of `values` (the mean of the middle two for an even count).
pub fn median(mut values: Vec<f64>) -> Option<f64> {
    values.retain(|v| v.is_finite() && *v > 0.0);
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        f64::midpoint(values[mid - 1], values[mid])
    } else {
        values[mid]
    })
}

/// The planner's row estimate for `entity` (0 when never analysed).
async fn estimated_rows(db: &DbPool, entity: &str) -> Result<i64, AppError> {
    let rows: Option<i64> = sqlx::query_scalar(
        "SELECT GREATEST(c.reltuples, 0)::bigint FROM pg_class c \
          WHERE c.oid = to_regclass(format('%I', $1::text))",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.unwrap_or(0))
}

/// Classifies every change in `changes` for `entity`'s table.
pub async fn plan_changes(
    db: &DbPool,
    entity: &str,
    inline_row_limit: i64,
    changes: &[StructureChange],
) -> Result<Vec<ChangePlanItem>, AppError> {
    if !valid_identifier(entity) {
        return Err(AppError::Validation(
            "invalid entity for a change plan".into(),
        ));
    }
    let large = table_row_count_exceeds(db, entity, inline_row_limit).await?;
    // Over the limit but never analysed: at least the limit.
    let rows = if large {
        estimated_rows(db, entity).await?.max(inline_row_limit + 1)
    } else {
        0
    };
    let mut items = Vec::with_capacity(changes.len());
    for change in changes {
        let class = class_of(change, large);
        let rate = match (class, change.rate_source()) {
            (ChangeClass::Instant, _) | (_, None) => DEFAULT_ROWS_PER_SECOND,
            (_, Some(source)) => rows_per_second(db, source).await?,
        };
        items.push(ChangePlanItem {
            change: change.describe(),
            class,
            estimate_secs: estimate_secs(class, rows, rate),
        });
    }
    Ok(items)
}

/// The measured rate for a change's kind, for the plan's explanation.
pub async fn measured_rate(db: &DbPool, change: &StructureChange) -> Result<f64, AppError> {
    match change.rate_source() {
        Some(source) => rows_per_second(db, source).await,
        None => Ok(DEFAULT_ROWS_PER_SECOND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retype_is_background_and_add_optional_is_instant() {
        let retype = StructureChange::ChangeType {
            field: "amount".into(),
            to: "text".into(),
        };
        let add = StructureChange::AddField {
            field: "note".into(),
        };
        let index = StructureChange::AddIndex {
            field: "note".into(),
        };
        assert_eq!(class_of(&retype, true), ChangeClass::Background);
        assert_eq!(class_of(&add, true), ChangeClass::Instant);
        assert_eq!(class_of(&index, true), ChangeClass::Online);
        // A small table runs every change inline.
        assert_eq!(class_of(&retype, false), ChangeClass::Instant);
        assert_eq!(
            estimate_secs(ChangeClass::Background, 1_000_000, 20_000.0),
            50
        );
        assert_eq!(estimate_secs(ChangeClass::Online, 10, 20_000.0), 1);
        assert_eq!(estimate_secs(ChangeClass::Instant, 1_000_000, 1.0), 0);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(vec![4.0, 1.0, 2.0, 3.0]), Some(2.5));
        assert_eq!(median(vec![]), None);
        let parsed: StructureChange =
            serde_json::from_str(r#"{"kind":"change_type","field":"a","to":"text"}"#).unwrap();
        assert_eq!(parsed.describe(), "change_type a -> text");
    }
}
