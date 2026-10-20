//! The daily sender-reputation fetch (roadmap E6-T8): Google Postmaster
//! Tools for the sending domains (when the deliverability policy's
//! `postmaster_enabled` is on) and Microsoft SNDS for the sending IPs (when
//! `snds_enabled` is on), one `marketing_reputation_daily` row per day,
//! subject and source. The sources and their credentials are integration
//! systems (`attome_integration::connector::adapters::reputation`); the
//! data stays in the deployment.

use attome_core::EngineState;
use attome_integration::connector::adapters::reputation::{self, Reputation};
use attome_types::AppError;
use chrono::{Duration, Utc};

use crate::blocklist::policy_flag;

async fn upsert(state: &EngineState, source: &str, rows: &[Reputation]) -> Result<u32, AppError> {
    for r in rows {
        sqlx::query(
            "INSERT INTO marketing_reputation_daily (day, sending_domain, source, reputation, spam_rate) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (day, sending_domain, source) DO UPDATE \
                SET reputation = EXCLUDED.reputation, spam_rate = EXCLUDED.spam_rate",
        )
        .bind(r.day)
        .bind(&r.subject)
        .bind(source)
        .bind(&r.reputation)
        .bind(r.spam_rate)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(rows.len() as u32)
}

/// The daily run. Returns the rows written.
pub async fn run(state: &EngineState) -> Result<u32, AppError> {
    let mut written = 0;
    if policy_flag(state, "postmaster_enabled").await? {
        let domains: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT sending_domain FROM marketing_deliverability_daily \
              WHERE day >= current_date - 30 AND sending_domain <> ''",
        )
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        // Postmaster publishes a day once it is over.
        let day = (Utc::now() - Duration::days(1)).date_naive();
        match reputation::postmaster(state, &domains, day).await {
            Ok(rows) => written += upsert(state, "google_postmaster", &rows).await?,
            Err(e) => {
                tracing::warn!(error = %e, "reputation: Postmaster Tools not read; retried tomorrow")
            }
        }
    }
    if policy_flag(state, "snds_enabled").await? {
        match reputation::snds(state).await {
            Ok(rows) => written += upsert(state, "microsoft_snds", &rows).await?,
            Err(e) => tracing::warn!(error = %e, "reputation: SNDS not read; retried tomorrow"),
        }
    }
    Ok(written)
}
