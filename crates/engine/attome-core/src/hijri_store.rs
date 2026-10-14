//! The deployment's Hijri calendar (roadmap AG1-T3): the published Umm
//! al-Qura table (`attome_calendar::hijri`) with the moon-sighting
//! corrections an administrator recorded in `hijri_month`.
//!
//! # Cache
//!
//! - **Source of truth:** `hijri_month`, rows with `source = 'sighting'`.
//! - **Shape:** `EngineState.hijri`, an `ArcSwap<HijriCalendar>` built from
//!   the published table plus those rows; no key space of its own.
//! - **Refresh:** loaded at boot, re-read by every node when the newest
//!   correction's `updated_at` changes (the 20 s poll beside the settings
//!   poll in `attome-api/src/system.rs`), and swapped on the writing node
//!   right after its commit.
//! - **Failure:** a read error keeps the last good calendar; a stored
//!   correction set that no longer forms 29- and 30-day months is logged and
//!   ignored, leaving the published table.
//! - **Cold start:** the published table until the boot load finishes.
//!
//! A correction moves one month's first day by one day: that month and the
//! one before it each change length by a day and must stay 29 or 30 days.

use attome_calendar::CalendarError;
use attome_calendar::hijri::{FIRST_YEAR, HijriCalendar, LAST_YEAR};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

/// One month of `hijri_month`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema, sqlx::FromRow)]
pub struct HijriMonthRow {
    pub hijri_year: i16,
    pub hijri_month: i16,
    pub gregorian_start: NaiveDate,
    /// The day after the month's last day.
    pub gregorian_end: NaiveDate,
    /// `umm_al_qura` (the published table) or `sighting` (corrected).
    pub source: String,
}

const SIGHTINGS: &str = "SELECT hijri_year, hijri_month, gregorian_start FROM hijri_month \
     WHERE source = 'sighting' ORDER BY hijri_year, hijri_month";

fn overrides_of(rows: Vec<(i16, i16, NaiveDate)>) -> Vec<(u16, u8, NaiveDate)> {
    rows.into_iter()
        .filter_map(|(y, m, start)| Some((u16::try_from(y).ok()?, u8::try_from(m).ok()?, start)))
        .collect()
}

/// The published table with every stored sighting correction.
pub async fn load_hijri(db: &DbPool) -> Result<HijriCalendar, AppError> {
    let rows: Vec<(i16, i16, NaiveDate)> = sqlx::query_as(SIGHTINGS)
        .fetch_all(db)
        .await
        .map_err(attome_db::classify)?;
    match HijriCalendar::with_overrides(&overrides_of(rows)) {
        Ok(calendar) => Ok(calendar),
        Err(error) => {
            tracing::error!(
                %error,
                "the stored Hijri sighting corrections do not form 29- and 30-day months; \
                 using the published Umm al-Qura table until they are fixed"
            );
            Ok(HijriCalendar::umm_al_qura().clone())
        }
    }
}

/// When the newest correction was made, for the poll's change check.
pub async fn hijri_watermark(db: &DbPool) -> Result<Option<DateTime<Utc>>, AppError> {
    sqlx::query_scalar("SELECT max(updated_at) FROM hijri_month WHERE source = 'sighting'")
        .fetch_one(db)
        .await
        .map_err(attome_db::classify)
}

/// The twelve months of one Hijri year, as stored.
pub async fn year_months(db: &DbPool, year: u16) -> Result<Vec<HijriMonthRow>, AppError> {
    if !(FIRST_YEAR..=LAST_YEAR).contains(&year) {
        return Err(AppError::Validation(format!(
            "year must be between {FIRST_YEAR} and {LAST_YEAR}"
        )));
    }
    sqlx::query_as(
        "SELECT hijri_year, hijri_month, gregorian_start, gregorian_end, source \
         FROM hijri_month WHERE hijri_year = $1 ORDER BY hijri_month",
    )
    .bind(i16::try_from(year).unwrap_or(i16::MAX))
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// Why a correction is refused, before anything is written.
fn check_correction(
    current: &HijriCalendar,
    year: u16,
    month: u8,
    start: NaiveDate,
) -> Result<HijriCalendar, AppError> {
    if (year, month) == (FIRST_YEAR, 1) {
        return Err(AppError::Validation(
            "the table's first month cannot be moved".into(),
        ));
    }
    let (published, _) = HijriCalendar::umm_al_qura()
        .month_bounds(year, month)
        .map_err(|_| {
            AppError::Validation(format!(
                "year must be between {FIRST_YEAR} and {LAST_YEAR} and month between 1 and 12"
            ))
        })?;
    let (now_start, _) = current
        .month_bounds(year, month)
        .map_err(AppError::internal)?;
    if (start - published).num_days().abs() > 1 || (start - now_start).num_days().abs() > 1 {
        return Err(AppError::Validation(
            "a sighting moves a month's first day by one day at most".into(),
        ));
    }
    // The calendar with this month moved, and every other correction kept.
    let mut overrides: Vec<(u16, u8, NaiveDate)> = Vec::new();
    for y in FIRST_YEAR..=LAST_YEAR {
        for m in 1..=12u8 {
            let (s, _) = current.month_bounds(y, m).map_err(AppError::internal)?;
            let (p, _) = HijriCalendar::umm_al_qura()
                .month_bounds(y, m)
                .map_err(AppError::internal)?;
            if s != p && (y, m) != (year, month) {
                overrides.push((y, m, s));
            }
        }
    }
    overrides.push((year, month, start));
    HijriCalendar::with_overrides(&overrides).map_err(|e| match e {
        CalendarError::InvalidCalendar(_) => AppError::Validation(
            "the correction would leave a month shorter than 29 or longer than 30 days".into(),
        ),
        other => AppError::internal(other),
    })
}

/// Records a moon-sighting correction in the caller's transaction (the
/// caller writes the audit event in the same one): `year`/`month` starts on
/// `start`, and the month before it ends the day before. Serialized per
/// deployment by an advisory lock, and checked against the corrections
/// already stored, read under that lock. Returns the corrected calendar for
/// the caller to swap in after commit.
pub async fn correct_month_start_in(
    conn: &mut sqlx::PgConnection,
    year: u16,
    month: u8,
    start: NaiveDate,
) -> Result<HijriCalendar, AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-core/hijri-correction")
        .fetch_one(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    if !locked {
        return Err(AppError::Conflict(
            "another Hijri correction is being saved; retry",
        ));
    }
    let rows: Vec<(i16, i16, NaiveDate)> = sqlx::query_as(SIGHTINGS)
        .fetch_all(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    let current = HijriCalendar::with_overrides(&overrides_of(rows)).map_err(AppError::internal)?;
    let corrected = check_correction(&current, year, month, start)?;
    let (prev_year, prev_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    let as_i16 = |v: u16| i16::try_from(v).unwrap_or(i16::MAX);
    let moved = sqlx::query(
        "UPDATE hijri_month SET gregorian_start = $3, source = 'sighting', updated_at = now() \
         WHERE hijri_year = $1 AND hijri_month = $2",
    )
    .bind(as_i16(year))
    .bind(i16::from(month))
    .bind(start)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    let ended = sqlx::query(
        "UPDATE hijri_month SET gregorian_end = $3, updated_at = now() \
         WHERE hijri_year = $1 AND hijri_month = $2",
    )
    .bind(as_i16(prev_year))
    .bind(i16::from(prev_month))
    .bind(start)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if moved.rows_affected() != 1 || ended.rows_affected() != 1 {
        return Err(AppError::internal(
            "hijri_month is missing a row the published table has",
        ));
    }
    Ok(corrected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_correction_moves_at_most_one_day_and_keeps_month_lengths() {
        let table = HijriCalendar::umm_al_qura();
        let length = |m| table.month_length(1447, m).unwrap();
        let month = (2..=12u8)
            .find(|&m| length(m - 1) == 29 && length(m) == 30)
            .unwrap();
        let (start, _) = table.month_bounds(1447, month).unwrap();
        let next = start.succ_opt().unwrap();
        let corrected = check_correction(table, 1447, month, next).unwrap();
        assert_eq!(corrected.month_bounds(1447, month).unwrap().0, next);

        let two = next.succ_opt().unwrap();
        assert!(matches!(
            check_correction(table, 1447, month, two),
            Err(AppError::Validation(_))
        ));
        assert!(check_correction(table, FIRST_YEAR, 1, start).is_err());
        assert!(check_correction(table, 1501, 1, start).is_err());
    }
}
