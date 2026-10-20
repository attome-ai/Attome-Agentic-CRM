//! Social posts (roadmap E17-T1): a `marketing_social_post` is written
//! once and published at its time through a social channel (a J8 Meta
//! integration system: its `page_id` in config and `page_token` in the
//! credential), then its likes, comments and shares are read back daily.
//!
//! The `social_publish` job (every five minutes) takes each `scheduled`
//! post that is due. When `marketing.social_post_approval` is on, a post
//! also needs `approved_by`; without it, it waits. A post is claimed by
//! moving it to `publishing` first (only one node wins), published with no
//! transaction open, and then marked `published` with the platform's post
//! id or `failed` with the reason. A post left in `publishing` by a crash
//! is never posted twice; it shows as such for a person to check.

use attome_core::EngineState;
use attome_integration::connector::adapters::social::{self, meta};
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Posts published per run.
const PUBLISH_BATCH: i64 = 50;
/// Posts whose metrics are read per run.
const METRICS_BATCH: i64 = 100;
/// How long after publishing metrics are still read.
pub const METRICS_DAYS: i64 = 30;

/// Whether a post may be published now. Pure.
pub fn may_publish(
    status: &str,
    scheduled_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    approval_required: bool,
    approved: bool,
) -> bool {
    status == "scheduled"
        && scheduled_at.is_some_and(|at| at <= now)
        && (!approval_required || approved)
}

/// Whether a published post's metrics are due: within [`METRICS_DAYS`] of
/// publishing and not read in the last day. Pure.
pub fn metrics_due(
    published_at: Option<DateTime<Utc>>,
    metrics_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    published_at.is_some_and(|p| now - p <= Duration::days(METRICS_DAYS))
        && metrics_at.is_none_or(|m| now - m >= Duration::days(1))
}

fn approval_required(state: &EngineState) -> bool {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("marketing.social_post_approval")
        .and_then(|d| store.resolve(d, None, None).0.as_bool())
        .unwrap_or(false)
}

/// A channel's page id and token.
async fn page(state: &EngineState, system: Uuid) -> Result<(String, String), AppError> {
    let system = attome_integration::system::load(&state.base.db, system)
        .await?
        .ok_or_else(|| AppError::Validation("the post's channel is gone".into()))?;
    let config = social::config(&system);
    if config.get("social").and_then(Value::as_str) != Some("meta") {
        return Err(AppError::Validation(
            "the post's channel is not a Meta page".into(),
        ));
    }
    let page_id = config
        .get("page_id")
        .map(|v| v.to_string().trim_matches('"').to_owned())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{}: config has no page_id", system.name)))?;
    let secrets = social::secrets(state, &system).await?;
    Ok((page_id, social::secret(&secrets, "page_token")?.to_owned()))
}

type DueRow = (Uuid, Uuid, String, Option<String>);

/// Publishes the posts that are due. Returns how many were published.
pub async fn publish_due(state: &EngineState, now: DateTime<Utc>) -> Result<u32, AppError> {
    let approval = approval_required(state);
    let due: Vec<DueRow> = sqlx::query_as(
        "SELECT id, system_ref, message, link FROM marketing_social_post \
          WHERE status = 'scheduled' AND scheduled_at <= $1 AND is_active IS NOT FALSE \
            AND ($2 = FALSE OR approved_by IS NOT NULL) \
          ORDER BY scheduled_at LIMIT $3",
    )
    .bind(now)
    .bind(approval)
    .bind(PUBLISH_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut published = 0;
    for (id, system, message, link) in due {
        let claimed = sqlx::query(
            "UPDATE marketing_social_post SET status = 'publishing', modified_at = now() \
              WHERE id = $1 AND status = 'scheduled'",
        )
        .bind(id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if claimed == 0 {
            continue;
        }
        let result = match page(state, system).await {
            Ok((page_id, token)) => {
                meta::publish_page_post(&token, &page_id, &message, link.as_deref()).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(post_id) => {
                sqlx::query(
                    "UPDATE marketing_social_post SET status = 'published', external_id = $2, \
                        published_at = now(), error = NULL, modified_at = now() WHERE id = $1",
                )
                .bind(id)
                .bind(&post_id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                published += 1;
            }
            Err(e) => {
                tracing::warn!(post = %id, error = %e, "social post not published");
                sqlx::query(
                    "UPDATE marketing_social_post SET status = 'failed', error = $2, modified_at = now() \
                      WHERE id = $1",
                )
                .bind(id)
                .bind(e.to_string().chars().take(2000).collect::<String>())
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(published)
}

/// Reads the engagement of recently published posts, once a day each.
pub async fn read_metrics(state: &EngineState, now: DateTime<Utc>) -> Result<u32, AppError> {
    let posts: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, system_ref, external_id FROM marketing_social_post \
          WHERE status = 'published' AND external_id IS NOT NULL AND is_active IS NOT FALSE \
            AND published_at >= $1 - make_interval(days => $2::int) \
            AND (metrics_at IS NULL OR metrics_at <= $1 - interval '1 day') \
          ORDER BY metrics_at NULLS FIRST LIMIT $3",
    )
    .bind(now)
    .bind(METRICS_DAYS as i32)
    .bind(METRICS_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut read = 0;
    for (id, system, post_id) in posts {
        let metrics = match page(state, system).await {
            Ok((_, token)) => meta::fetch_metrics(&token, &post_id).await,
            Err(e) => Err(e),
        };
        match metrics {
            Ok(m) => {
                sqlx::query(
                    "UPDATE marketing_social_post SET likes = $2, comments = $3, shares = $4, \
                        metrics_at = now(), modified_at = now() WHERE id = $1",
                )
                .bind(id)
                .bind(m.likes)
                .bind(m.comments)
                .bind(m.shares)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                read += 1;
            }
            Err(e) => tracing::warn!(post = %id, error = %e, "social post metrics not read"),
        }
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        "2026-10-20T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn social_publish_waits_for_its_time_and_approval() {
        let past = Some(now() - Duration::minutes(1));
        let future = Some(now() + Duration::minutes(1));
        assert!(may_publish("scheduled", past, now(), false, false));
        assert!(!may_publish("scheduled", future, now(), false, false));
        assert!(!may_publish("draft", past, now(), false, false));
        assert!(!may_publish("scheduled", None, now(), false, false));
        assert!(!may_publish("scheduled", past, now(), true, false));
        assert!(may_publish("scheduled", past, now(), true, true));
    }

    #[test]
    fn social_publish_reads_metrics_daily_for_a_month() {
        let published = Some(now() - Duration::days(3));
        assert!(metrics_due(published, None, now()));
        assert!(!metrics_due(
            published,
            Some(now() - Duration::hours(2)),
            now()
        ));
        assert!(metrics_due(
            published,
            Some(now() - Duration::days(1)),
            now()
        ));
        assert!(!metrics_due(Some(now() - Duration::days(31)), None, now()));
        assert!(!metrics_due(None, None, now()));
    }

    #[test]
    fn social_publish_meta_codec() {
        let body = meta::page_post_body("Ramadan offer", Some(" https://x.com/r "));
        assert_eq!(body["link"], "https://x.com/r");
        assert!(meta::page_post_body("Hi", Some("")).get("link").is_none());
        let fields = r#"{"id": "1_2", "likes": {"data": [], "summary": {"total_count": 42}},
            "comments": {"data": [], "summary": {"total_count": 7}}, "shares": {"count": 3}}"#;
        assert_eq!(
            meta::parse_metrics(fields),
            Some(meta::PostMetrics {
                likes: 42,
                comments: 7,
                shares: 3
            })
        );
        assert_eq!(
            meta::parse_metrics(r#"{"id": "1_2"}"#),
            Some(meta::PostMetrics::default())
        );
    }
}
