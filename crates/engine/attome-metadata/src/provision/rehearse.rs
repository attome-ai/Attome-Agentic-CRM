//! Y12-T11: rehearse a field change on a copy database and measure it.
//!
//! [`rehearse_field_change`] connects to `metadata.rehearsal_database_url`
//! (a restored copy of this deployment, never the main database: boot
//! refuses that) with one connection, counts the entity's rows there, and
//! runs the very function the real change runs ([`super::evolve_attribute_schema`]),
//! timing each step. Only the copy is written; the report says how long the
//! change took on data of this size, so an administrator can choose when to
//! run it for real.

use std::time::{Duration, Instant};

use attome_types::AppError;
use serde::Serialize;

use attome_core::quote_ident;

use super::identifiers::valid_identifier;

/// How long connecting to the copy may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One timed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RehearsalStep {
    pub name: String,
    pub duration_ms: u64,
    /// Rows the step saw, when it counts them.
    pub rows: Option<i64>,
}

/// What a rehearsal measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RehearsalReport {
    pub per_change: Vec<RehearsalStep>,
    pub total_ms: u64,
}

/// The change to rehearse: one field's target contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    pub entity: String,
    pub field: String,
    pub field_type: String,
    pub is_required: bool,
    pub max_length: Option<i32>,
    pub is_multi: bool,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Runs `change` on the copy at `url` and times it.
pub async fn rehearse_field_change(
    url: &str,
    change: &FieldChange,
) -> Result<RehearsalReport, AppError> {
    if !valid_identifier(&change.entity) || !valid_identifier(&change.field) {
        return Err(AppError::Validation("invalid schema identifier".into()));
    }
    let copy = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect(url)
        .await
        .map_err(|_| AppError::Validation("the rehearsal database did not answer".into()))?;
    let started = Instant::now();
    let mut steps = Vec::new();

    let at = Instant::now();
    let rows: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {}",
        quote_ident(&change.entity)
    ))
    .fetch_one(&copy)
    .await
    .map_err(|_| {
        AppError::Validation(format!(
            "the rehearsal database has no {} table; restore a current copy",
            change.entity
        ))
    })?;
    steps.push(RehearsalStep {
        name: format!("count {}", change.entity),
        duration_ms: millis(at.elapsed()),
        rows: Some(rows),
    });

    let at = Instant::now();
    let outcome = super::evolve_attribute_schema(
        &copy,
        &change.entity,
        &change.field,
        &change.field_type,
        change.is_required,
        change.max_length,
        change.is_multi,
    )
    .await;
    steps.push(RehearsalStep {
        name: format!("change {}.{}", change.entity, change.field),
        duration_ms: millis(at.elapsed()),
        rows: Some(rows),
    });
    copy.close().await;
    outcome?;
    Ok(RehearsalReport {
        per_change: steps,
        total_ms: millis(started.elapsed()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bad_identifiers_never_reach_the_copy() {
        let change = FieldChange {
            entity: "contact; drop".into(),
            field: "email".into(),
            field_type: "text".into(),
            is_required: false,
            max_length: Some(100),
            is_multi: false,
        };
        let refused = rehearse_field_change("postgres://nobody@127.0.0.1:1/none", &change).await;
        assert!(matches!(refused, Err(AppError::Validation(_))));
    }
}
