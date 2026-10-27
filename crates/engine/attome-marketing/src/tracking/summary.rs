//! E14-T8: one visit summary per closed web session, on the person's
//! timeline.
//!
//! [`summarise_closed_sessions`] (the `marketing_web_visit_summary` job,
//! every ten minutes) takes sessions that are identified (a contact or a
//! lead, E14-T7), not bots, and idle for [`IDLE_MINUTES`], and writes one
//! `marketing_visit_summary` record each through the record engine, as the
//! person's owner: the pages viewed, the minutes between the first and last
//! page, the site's key pages the visitor reached, where the visit came
//! from and its campaign, and the contact's account. The timeline shows it
//! as a `web_visit` entry (attome-records), one per visit, not one per page.
//!
//! Each session is summarised once: the session's `summarised_at` is set
//! after the record is written (migration 0303), and a summary that already
//! exists for the session id is not written again, so a rerun after a crash
//! between the two adds nothing. A session whose owner cannot be resolved or
//! whose write is refused is marked and logged, so it does not come back on
//! every run.
//!
//! Engagement signals to lead scoring (D18) and the account rollup (E20)
//! are not sent: neither has an input function yet.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// The job's name.
pub const JOB: &str = "marketing_web_visit_summary";
/// Minutes without a page view after which a session is closed.
pub const IDLE_MINUTES: i64 = 30;
/// Sessions summarised per run.
const BATCH: i64 = 200;
/// Distinct pages read per session.
const MAX_PAGES: i64 = 500;

/// The path of a URL (or the text itself when it is already a path). Pure.
pub fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| {
        rest.split_once('/').map_or("", |(_, path)| path)
    });
    let path = if url.contains("://") {
        format!("/{rest}")
    } else {
        rest.to_owned()
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

/// The site's key pages (one path per line or comma) that `visited` reached:
/// a page reaches a key path that equals its path or that its path starts
/// with followed by `/`. In the site's order, each once. Pure.
pub fn key_pages_hit(visited: &[String], key_pages: &str) -> Vec<String> {
    let paths: Vec<String> = visited.iter().map(|u| path_of(u)).collect();
    key_pages
        .split(['\n', ','])
        .map(str::trim)
        .filter(|k| k.starts_with('/'))
        .filter(|k| {
            let k = k.trim_end_matches('/');
            paths.iter().any(|p| {
                let p = p.trim_end_matches('/');
                p == k || (!k.is_empty() && p.starts_with(&format!("{k}/")))
            })
        })
        .fold(Vec::new(), |mut out: Vec<String>, k| {
            let bare = k.trim_end_matches('/');
            if !out.iter().any(|o| o.trim_end_matches('/') == bare) {
                out.push(k.to_owned());
            }
            out
        })
}

/// Where a visit came from: its UTM source, else the referrer's host. Pure.
pub fn visit_source(utm_source: Option<&str>, referrer: Option<&str>) -> Option<String> {
    if let Some(s) = utm_source.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(s.to_owned());
    }
    let referrer = referrer.map(str::trim).filter(|r| !r.is_empty())?;
    let host = referrer
        .split_once("://")
        .map_or(referrer, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    (!host.is_empty()).then(|| host.to_owned())
}

type SessionRow = (
    Uuid,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    i32,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn mark(state: &EngineState, session: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE marketing_web_session SET summarised_at = now() WHERE id = $1")
        .bind(session)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Summarises the sessions closed since the last run; returns how many
/// summaries were written.
pub async fn summarise_closed_sessions(state: &EngineState) -> Result<usize, AppError> {
    let registry = state.entities.load();
    let Some(meta) = registry.get("marketing_visit_summary") else {
        return Ok(0);
    };
    let fields: std::collections::HashSet<String> =
        meta.attrs.iter().map(|a| a.logicalname.clone()).collect();
    drop(registry);
    let db = &state.base.db;
    let sessions: Vec<SessionRow> = sqlx::query_as(
        "SELECT id, site_key, started_at, last_seen_at, page_count, contact_ref, lead_ref, \
                utm_source, utm_campaign, referrer \
           FROM marketing_web_session \
          WHERE summarised_at IS NULL AND NOT is_bot \
            AND (contact_ref IS NOT NULL OR lead_ref IS NOT NULL) \
            AND last_seen_at < now() - make_interval(mins => $1::int) \
          ORDER BY last_seen_at LIMIT $2",
    )
    .bind(IDLE_MINUTES as i32)
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut written = 0;
    for (id, site_key, started, last_seen, pages, contact, lead, utm_source, campaign, referrer) in
        sessions
    {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM marketing_visit_summary WHERE session_id = $1)",
        )
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if exists {
            mark(state, id).await?;
            continue;
        }
        let site: Option<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT id, key_pages FROM marketing_tracked_site \
              WHERE site_key = $1 AND (is_active IS NULL OR is_active = true) LIMIT 1",
        )
        .bind(&site_key)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let visited: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT url FROM marketing_web_event \
              WHERE session_id = $1 AND kind = 'page_view' AND url IS NOT NULL \
                AND occurred_at >= $2 LIMIT $3",
        )
        .bind(id)
        .bind(started)
        .bind(MAX_PAGES)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let (person_entity, person) = match (contact, lead) {
            (Some(c), _) => ("contact", c),
            (None, Some(l)) => ("lead", l),
            (None, None) => continue,
        };
        let row: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(&format!(
            "SELECT COALESCE(owner_ref, created_by), {} FROM {} WHERE id = $1",
            if person_entity == "contact" {
                "account_ref"
            } else {
                "NULL::uuid"
            },
            attome_core::quote_ident(person_entity)
        ))
        .bind(person)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some((Some(owner), account)) = row else {
            tracing::warn!(session = %id, "web visit summary: the person has no owner; skipped");
            mark(state, id).await?;
            continue;
        };
        let mut values = Map::new();
        let mut put = |k: &str, v: Value| {
            if fields.contains(k) && !v.is_null() {
                values.insert(k.to_owned(), v);
            }
        };
        put(&format!("{person_entity}_ref"), json!(person.to_string()));
        put("account_ref", json!(account.map(|a| a.to_string())));
        put("site_ref", json!(site.as_ref().map(|(s, _)| s.to_string())));
        put("session_id", json!(id.to_string()));
        put("started_at", json!(started.to_rfc3339()));
        put(
            "duration_seconds",
            json!((last_seen - started).num_seconds().max(0)),
        );
        put("pages_viewed", json!(pages.max(0)));
        let keys = key_pages_hit(
            &visited,
            site.as_ref()
                .and_then(|(_, k)| k.as_deref())
                .unwrap_or_default(),
        );
        if !keys.is_empty() {
            put("key_pages", json!(keys.join(", ")));
        }
        put(
            "source",
            json!(visit_source(utm_source.as_deref(), referrer.as_deref())),
        );
        put("campaign", json!(campaign));
        let ctx = state.base.security.resolve_strict(owner).await?;
        match attome_records::entity_crud::create_record_for(
            state,
            &ctx,
            owner,
            "marketing_visit_summary",
            Value::Object(values),
        )
        .await
        {
            Ok(_) => written += 1,
            Err(error @ (AppError::Forbidden | AppError::Validation(_))) => {
                tracing::warn!(session = %id, %error, "web visit summary: not written");
            }
            Err(error) => return Err(error),
        }
        mark(state, id).await?;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visit_summary_key_pages_match_by_path() {
        let visited = vec![
            "https://acme.sa/pricing?plan=pro".to_owned(),
            "https://acme.sa/demo/book".to_owned(),
            "/blog/post-1".to_owned(),
        ];
        assert_eq!(
            key_pages_hit(&visited, "/pricing\n/demo, /careers,/pricing/"),
            ["/pricing", "/demo"]
        );
        assert!(key_pages_hit(&visited, "").is_empty());
        assert_eq!(path_of("https://acme.sa"), "/");
        assert_eq!(path_of("https://acme.sa/a#x"), "/a");
    }

    #[test]
    fn visit_summary_source_prefers_utm() {
        assert_eq!(
            visit_source(Some("linkedin"), Some("https://google.com/")).as_deref(),
            Some("linkedin")
        );
        assert_eq!(
            visit_source(None, Some("https://www.google.com/search?q=x")).as_deref(),
            Some("www.google.com")
        );
        assert_eq!(visit_source(Some("  "), None), None);
    }
}
