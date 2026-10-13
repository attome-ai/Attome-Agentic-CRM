//! M37 Knowledge Management Phase 2 — article analytics, helpfulness votes,
//! and `review_by` reminders (D-452).
//!
//! Three raw, append-only logs (`content_page_view`, `content_page_
//! vote`, and `knowledge_chunk_retrieval` — the last one owned by
//! `attome-search`) feed one nightly rollup into `content_page_stats`, the
//! table the page stats panel actually reads. `attome-content` and `attome-search`
//! stay sibling engine crates with no dependency edge between them (D-452):
//! this module exposes [`rollup_page_stats`] taking retrieval counts as a
//! plain parameter, and the composition — reading those counts out of
//! `attome-search`'s tables — happens in `crates/server/src/jobs.rs`, the
//! established composition layer.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::model::PageStats;

/// Records one page view.
///
/// **Off the request path** — callers spawn this (`tokio::spawn`), same
/// discipline `attome-search/telemetry.rs`'s impression logging documents: a
/// page render must never be slower, and must never fail, because analytics
/// are unavailable. Scoped to the public, anonymous `/content/view` surface
/// only (`attome-api/content_public.rs`) — an authenticated editor opening a
/// page in the admin UI is authoring activity, not reader traffic, and
/// counting it would inflate "views" with the very people writing the page.
pub async fn record_page_view(db: &PgPool, page_ref: Uuid) -> Result<(), AppError> {
    sqlx::query("INSERT INTO content_page_view (page_ref) VALUES ($1)")
        .bind(page_ref)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Records one helpfulness vote. Awaited inline by the vote route (unlike
/// [`record_page_view`]): the caller needs to know the write actually
/// succeeded before returning 204, and a vote is rate-limited at the route
/// layer already, so it cannot be a volume problem the way a view counter on
/// every page load could be.
pub async fn record_helpfulness_vote(
    db: &PgPool,
    page_ref: Uuid,
    useful: bool,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO content_page_vote (page_ref, useful) VALUES ($1, $2)")
        .bind(page_ref)
        .bind(useful)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Reads the rolled-up stats row for one page — the page stats panel's only
/// query. A page with no accrued signal yet has no row; this returns a
/// zeroed [`PageStats`] rather than `None`, since "nothing has happened yet"
/// is a normal, common state for a page, not an error condition the caller
/// needs to branch on.
pub async fn page_stats(db: &PgPool, page_ref: Uuid) -> Result<PageStats, AppError> {
    let row = sqlx::query_as::<_, PageStats>(
        "SELECT page_ref, views, retrievals, helpfulness_up, helpfulness_down, \
                last_useful_at, updated_at \
         FROM content_page_stats WHERE page_ref = $1",
    )
    .bind(page_ref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.unwrap_or(PageStats {
        page_ref,
        views: 0,
        retrievals: 0,
        helpfulness_up: 0,
        helpfulness_down: 0,
        last_useful_at: None,
        updated_at: Utc::now(),
    }))
}

/// What one rollup run did — logged by the job handler, same convention as
/// every other sweep in `crates/server/src/jobs.rs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RollupStats {
    pub pages_touched: i64,
    pub views_folded_in: i64,
    pub votes_folded_in: i64,
}

/// Folds unrolled-up views, votes, and (passed in) chunk retrieval counts
/// into `content_page_stats`, one UPSERT per page that accrued any new
/// signal since its own `rolled_up_through` watermark.
///
/// `retrieval_counts` is `attome-search`'s
/// `retrieval_counts_by_source(db, since)` output, already computed by the
/// caller (`crates/server/src/jobs.rs`) against its own crate's tables — see
/// this module's doc comment for why the join happens there, not here.
///
/// Per-page, not set-based, deliberately: the watermark (`rolled_up_through`)
/// is per-page, so a page created between two rollup runs must not be
/// compared against a global "since" cutoff that predates it. The row count
/// this scans is bounded by how many *distinct* pages have new signal since
/// their own last rollup, not by the raw log's total size.
pub async fn rollup_page_stats(
    db: &PgPool,
    retrieval_counts: &HashMap<Uuid, i64>,
) -> Result<RollupStats, AppError> {
    let mut stats = RollupStats::default();

    // Every page with an unrolled-up view or vote, or a nonzero retrieval
    // count handed in by the caller. UNION rather than a three-way OR join,
    // so a page that only ever gets retrievals (no local view/vote activity
    // yet) is still picked up.
    let mut candidate_pages: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT v.page_ref FROM content_page_view v \
         LEFT JOIN content_page_stats s ON s.page_ref = v.page_ref \
         WHERE v.viewed_at > COALESCE(s.rolled_up_through, '-infinity'::timestamptz) \
         UNION \
         SELECT DISTINCT t.page_ref FROM content_page_vote t \
         LEFT JOIN content_page_stats s ON s.page_ref = t.page_ref \
         WHERE t.voted_at > COALESCE(s.rolled_up_through, '-infinity'::timestamptz)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for page_ref in retrieval_counts.keys() {
        if !candidate_pages.contains(page_ref) {
            candidate_pages.push(*page_ref);
        }
    }

    let now: DateTime<Utc> = Utc::now();
    // `since` is computed inside each query (COALESCE against this page's own
    // `rolled_up_through`, or `-infinity` if it has no stats row yet) rather
    // than fetched into Rust first — one fewer round trip, and it sidesteps
    // needing a chrono "beginning of time" constant to represent "never
    // rolled up" for a brand-new page.
    for page_ref in candidate_pages {
        let new_views: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_page_view v \
             WHERE v.page_ref = $1 AND v.viewed_at > COALESCE( \
                (SELECT rolled_up_through FROM content_page_stats WHERE page_ref = $1), \
                '-infinity'::timestamptz)",
        )
        .bind(page_ref)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;

        let (new_up, new_down, last_useful): (i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE useful), COUNT(*) FILTER (WHERE NOT useful), \
                    MAX(voted_at) FILTER (WHERE useful) \
             FROM content_page_vote t \
             WHERE t.page_ref = $1 AND t.voted_at > COALESCE( \
                (SELECT rolled_up_through FROM content_page_stats WHERE page_ref = $1), \
                '-infinity'::timestamptz)",
        )
        .bind(page_ref)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;

        let new_retrievals = retrieval_counts.get(&page_ref).copied().unwrap_or(0);

        if new_views == 0 && new_up == 0 && new_down == 0 && new_retrievals == 0 {
            continue;
        }

        sqlx::query(
            "INSERT INTO content_page_stats \
                (page_ref, views, retrievals, helpfulness_up, helpfulness_down, \
                 last_useful_at, rolled_up_through, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
             ON CONFLICT (page_ref) DO UPDATE SET \
                views = content_page_stats.views + EXCLUDED.views, \
                retrievals = content_page_stats.retrievals + EXCLUDED.retrievals, \
                helpfulness_up = content_page_stats.helpfulness_up + EXCLUDED.helpfulness_up, \
                helpfulness_down = content_page_stats.helpfulness_down + EXCLUDED.helpfulness_down, \
                last_useful_at = COALESCE(EXCLUDED.last_useful_at, content_page_stats.last_useful_at), \
                rolled_up_through = EXCLUDED.rolled_up_through, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind(page_ref)
        .bind(new_views)
        .bind(new_retrievals)
        .bind(new_up)
        .bind(new_down)
        .bind(last_useful)
        .bind(now)
        .execute(db)
        .await
        .map_err(AppError::internal)?;

        stats.pages_touched += 1;
        stats.views_folded_in += new_views;
        stats.votes_folded_in += new_up + new_down;
    }

    Ok(stats)
}

/// What one review-reminder sweep did.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReviewReminderStats {
    pub reminders_sent: i64,
}

/// Notifies each stale page's owner (`updated_by`) through M51, once per
/// page per sweep tick — the sweep runs daily (see the scheduler's doc
/// comment in `crates/server/src/jobs.rs`), so an owner who ignores the
/// reminder gets it again the next day rather than only once, ever, the
/// moment the date passed. There is no per-page "already reminded" flag:
/// idempotency of the *notification* itself is M51's concern (in-app,
/// dedupes by dispatch), and a page that stays overdue is meant to keep
/// nagging its owner, unlike the one-shot publish sweep this mirrors the
/// shape of.
pub async fn sweep_review_reminders(
    db: &PgPool,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<ReviewReminderStats, AppError> {
    let rows: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id, title, updated_by FROM content_page \
         WHERE is_deleted = FALSE AND review_by IS NOT NULL AND review_by < CURRENT_DATE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut stats = ReviewReminderStats::default();
    for (page_id, title, owner_id) in rows {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(owner_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some("A knowledge article is due for review".to_string()),
            body_html: None,
            body_text: Some(format!("\"{title}\" passed its review-by date.")),
            route: Some(format!("/content/pages/{page_id}")),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        match attome_notification::dispatch::create_dispatch(db, notification_cfg, req).await {
            Ok(_) => stats.reminders_sent += 1,
            Err(e) => tracing::error!(
                error = %e,
                page_id = %page_id,
                "review-by reminder dispatch failed"
            ),
        }
    }
    Ok(stats)
}
