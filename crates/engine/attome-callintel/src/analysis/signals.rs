//! D22-T11: what call analysis tells the rest of the platform.
//!
//! - **Analysis done.** When an analysis finishes, its own transaction
//!   writes the named change-feed event [`ANALYSIS_DONE_EVENT`] on the
//!   `call_analysis` record; deal health (D19), competitive intelligence
//!   (D25) and conversation signals (O7) read the record's opportunity,
//!   tracker hits and counts from there. No transcript text travels.
//! - **Competitors become trackers.** The change-feed consumer [`CONSUMER`]
//!   (the [`JOB`] every few minutes) turns each change to a `competitor`
//!   (D25) into one `call_tracker` with `competitor_ref` set and the
//!   competitor's English and Arabic names as its exact terms; a tracker
//!   follows its competitor's renames, and is disabled when the competitor
//!   is deleted or no longer `is_tracked`. Nothing happens where the sales
//!   pack's `competitor` entity is not installed.

use attome_core::EngineState;
use attome_core::change_feed;
use attome_types::AppError;
use uuid::Uuid;

/// The named event an analysis writes when it is done.
pub const ANALYSIS_DONE_EVENT: &str = "callintel.analysis_done";
/// The change-feed consumer that follows competitors.
pub const CONSUMER: &str = "attome-callintel/competitors";
/// The job that drains it.
pub const JOB: &str = "callintel_competitor_trackers";
/// Events per batch, and batches per run.
const BATCH: i64 = 500;
const MAX_BATCHES: usize = 20;

/// The exact terms of a competitor's tracker from its names. Pure.
pub fn competitor_terms(name: &str, name_ar: Option<&str>) -> String {
    let mut terms: Vec<&str> = vec![name.trim()];
    if let Some(ar) = name_ar
        .map(str::trim)
        .filter(|a| !a.is_empty() && *a != name.trim())
    {
        terms.push(ar);
    }
    terms.retain(|t| !t.is_empty());
    terms.join("\n")
}

async fn installed(state: &EngineState) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('competitor') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Brings `competitor`'s tracker in line with it; whether a tracker was
/// written.
pub async fn sync_competitor(state: &EngineState, competitor: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let row: Option<(String, Option<String>, Option<bool>, Option<bool>)> =
        sqlx::query_as("SELECT name, name_ar, is_active, is_tracked FROM competitor WHERE id = $1")
            .bind(competitor)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let key = competitor.to_string();
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM call_tracker WHERE competitor_ref = $1 \
           AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id LIMIT 1",
    )
    .bind(&key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let wanted = row
        .as_ref()
        .is_some_and(|(_, _, live, tracked)| live.unwrap_or(true) && tracked.unwrap_or(true));
    let Some((name, name_ar, _, _)) = row.filter(|_| wanted) else {
        // Deleted or no longer tracked: disable its tracker, keep its hits.
        if let Some(tracker) = existing {
            sqlx::query(
                "UPDATE call_tracker SET enabled = false, row_version = row_version + 1 \
                  WHERE id = $1 AND enabled IS DISTINCT FROM false",
            )
            .bind(tracker)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
        return Ok(false);
    };
    let terms = competitor_terms(&name, name_ar.as_deref());
    match existing {
        Some(tracker) => {
            // A new version when the terms change, so hits name what matched.
            sqlx::query(
                "UPDATE call_tracker SET name = $2, name_ar = $3, exact_terms = $4, enabled = true, \
                        version = COALESCE(version, 1) + \
                            CASE WHEN exact_terms IS DISTINCT FROM $4 THEN 1 ELSE 0 END, \
                        row_version = row_version + 1 \
                  WHERE id = $1",
            )
            .bind(tracker)
            .bind(&name)
            .bind(&name_ar)
            .bind(&terms)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO call_tracker (id, name, name_ar, exact_terms, competitor_ref, enabled, \
                     version, is_active, row_version) \
                 VALUES ($1, $2, $3, $4, $5, true, 1, true, 0)",
            )
            .bind(Uuid::now_v7())
            .bind(&name)
            .bind(&name_ar)
            .bind(&terms)
            .bind(&key)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(true)
}

/// Reads the new competitor changes and syncs their trackers; how many
/// trackers were written.
pub async fn drain(state: &EngineState) -> Result<usize, AppError> {
    if !installed(state).await? {
        return Ok(0);
    }
    let db = &state.base.db;
    let mut written = 0;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        let mut seen = std::collections::HashSet::new();
        for event in &events {
            if event.entity_logicalname == "competitor" && seen.insert(event.record_id) {
                match sync_competitor(state, event.record_id).await {
                    Ok(true) => written += 1,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(competitor = %event.record_id, %error, "competitor tracker not synced");
                    }
                }
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn competitor_names_are_the_tracker_terms() {
        assert_eq!(competitor_terms(" Acme ", Some("أكمي")), "Acme\nأكمي");
        assert_eq!(competitor_terms("Acme", Some("Acme")), "Acme");
        assert_eq!(competitor_terms("Acme", None), "Acme");
    }
}
