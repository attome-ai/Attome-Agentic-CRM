//! E13-T8: the search work behind the SEO routes: a page's settings saved
//! with their audit event, the stored findings, topic clusters, each site's
//! robots.txt and its stored sitemap.
//!
//! A site is keyed by its host name (`site_key`, as E12 uses it). The
//! robots body an administrator writes is served with [`ALWAYS_DISALLOWED`]
//! appended, so portal-only and preview paths are never crawled whatever
//! the body says. The sitemap is read from `content_sitemap` (E13-T9's job
//! builds it); a site with none answers an empty `urlset`.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::settings::PageSeo;

/// Paths no crawler is let into, whatever a site's robots body says.
pub const ALWAYS_DISALLOWED: &[&str] = &[
    "/api/v1/content/preview",
    "/api/v1/portal/",
    "/portal/",
    "/xrm/",
];

/// The robots body of a site that has none stored.
pub const DEFAULT_ROBOTS: &str = "User-agent: *\nAllow: /\n";
/// The longest robots body accepted.
pub const MAX_ROBOTS_CHARS: usize = 20_000;
/// The longest topic name.
const MAX_TOPIC_CHARS: usize = 200;
/// The most pages in one topic.
pub const MAX_TOPIC_PAGES: usize = 500;

/// A site key: a host name, lowercase letters, digits, dots and dashes.
pub fn site_key_ok(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 253
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !key.starts_with(['.', '-'])
}

/// The robots.txt served for a stored body (or none). Pure.
pub fn served_robots(stored: Option<&str>) -> String {
    let mut body = stored.unwrap_or(DEFAULT_ROBOTS).trim_end().to_owned();
    body.push_str("\n\n# Always closed to crawlers.\nUser-agent: *\n");
    for path in ALWAYS_DISALLOWED {
        body.push_str(&format!("Disallow: {path}\n"));
    }
    body
}

/// An empty sitemap. Pure.
pub fn empty_sitemap() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>\n"
        .to_owned()
}

/// Whether a language code is one a sitemap is kept for (`en`, `ar`, `ar-SA`).
pub fn lang_ok(lang: &str) -> bool {
    let mut parts = lang.split('-');
    let primary = parts.next().unwrap_or("");
    (2..=3).contains(&primary.len())
        && primary.chars().all(|c| c.is_ascii_lowercase())
        && parts.all(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// At most `max` characters of `text`. Pure.
fn clip(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The audit comment of a change: its before and after, as JSON. Pure.
pub fn before_after(before: serde_json::Value, after: serde_json::Value) -> String {
    serde_json::json!({ "before": before, "after": after }).to_string()
}

/// Saves a page's settings at `expected` with a Configuration event in the
/// same transaction, named `content_page.seo_indexing` when the canonical
/// URL or the noindex flag changed (their values before and after are in
/// its comment). Returns the new row version.
pub async fn save_page_seo(
    state: &EngineState,
    actor: Uuid,
    page: Uuid,
    body: &PageSeo,
    expected: i64,
) -> Result<i64, AppError> {
    super::settings::check(body)?;
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    let before: Option<(Option<String>, bool, i64)> = sqlx::query_as(
        "SELECT seo_canonical_url, seo_noindex, row_version FROM content_page \
          WHERE id = $1 AND is_deleted = false FOR UPDATE",
    )
    .bind(page)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (old_canonical, old_noindex, current) = before.ok_or(AppError::NotFound)?;
    if current != expected {
        return Err(AppError::VersionConflict);
    }
    let version = super::settings::write_page_seo(&mut tx, page, body).await?;
    let canonical = super::settings::filled(body.canonical_url.as_ref());
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            actor,
            "content_page",
            Some(page),
        )
        .named(
            if canonical != old_canonical || body.noindex != old_noindex {
                "content_page.seo_indexing"
            } else {
                "content_page.seo"
            },
        )
        .comment(before_after(
            serde_json::json!({ "canonical_url": old_canonical, "noindex": old_noindex }),
            serde_json::json!({ "canonical_url": canonical, "noindex": body.noindex }),
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(version)
}

/// One stored finding.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SeoFinding {
    pub id: Uuid,
    pub rule: String,
    /// `info`, `warning` or `error`.
    pub severity: String,
    pub block_ref: Option<String>,
    /// The catalog key of the message.
    pub message_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A page's stored findings, errors first, and their count.
pub async fn findings(
    db: &DbPool,
    page: Uuid,
    limit: i64,
    offset: i64,
) -> Result<(Vec<SeoFinding>, i64), AppError> {
    let rows: Vec<SeoFinding> = sqlx::query_as(
        "SELECT id, rule, severity, block_ref, detail ->> 'message_key' AS message_key, created_at \
           FROM content_seo_finding WHERE page_ref = $1 \
          ORDER BY CASE severity WHEN 'error' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, rule, id \
          LIMIT $2 OFFSET $3",
    )
    .bind(page)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_seo_finding WHERE page_ref = $1")
            .bind(page)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    Ok((rows, total))
}

/// Audits a page now, whatever the `content.seo_audit` flag says, and
/// stores the result. Returns the score.
pub async fn audit_now(db: &DbPool, page_id: Uuid) -> Result<i16, AppError> {
    let page = crate::admin::load_page(db, page_id).await?;
    let (seo, _) = super::settings::get_page_seo(db, page_id).await?;
    let inputs = super::audit::inputs_for(db, &page).await?;
    let found = super::audit::audit_page(&page, &seo, &inputs);
    let score = super::audit::score(&found);
    super::audit::persist_audit(db, page_id, &found, score).await?;
    Ok(score)
}

/// A topic cluster.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SeoTopic {
    pub id: Uuid,
    pub name: String,
    pub language: String,
    pub pillar_page_ref: Option<Uuid>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A topic to create or change.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SeoTopicBody {
    pub name: String,
    /// `en`, `ar`, or a regional form such as `ar-SA`.
    pub language: String,
    #[serde(default)]
    pub pillar_page_ref: Option<Uuid>,
}

fn check_topic(body: &SeoTopicBody) -> Result<(), AppError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > MAX_TOPIC_CHARS {
        return Err(AppError::Validation(format!(
            "a topic name has 1 to {MAX_TOPIC_CHARS} characters"
        )));
    }
    if !lang_ok(&body.language) {
        return Err(AppError::Validation(
            "language is a language code such as en or ar".into(),
        ));
    }
    Ok(())
}

const TOPIC_COLUMNS: &str =
    "id, name, language, pillar_page_ref, row_version, created_at, updated_at";

async fn live_page(tx: &mut attome_db::Tx<'_>, page: Option<Uuid>) -> Result<(), AppError> {
    let Some(page) = page else { return Ok(()) };
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM content_page WHERE id = $1 AND is_deleted = false)",
    )
    .bind(page)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if live {
        Ok(())
    } else {
        Err(AppError::Validation(
            "the pillar page does not exist".into(),
        ))
    }
}

fn topic_event(actor: Uuid, op: AuditOperation, id: Uuid, name: &str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        op,
        actor,
        "content_seo_topic",
        Some(id),
    )
    .named(name)
}

/// Every topic, by name, and the count.
pub async fn list_topics(
    db: &DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<SeoTopic>, i64), AppError> {
    let rows: Vec<SeoTopic> = sqlx::query_as(&format!(
        "SELECT {TOPIC_COLUMNS} FROM content_seo_topic ORDER BY name, id LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM content_seo_topic")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok((rows, total))
}

/// Creates a topic.
pub async fn create_topic(
    state: &EngineState,
    actor: Uuid,
    body: &SeoTopicBody,
) -> Result<SeoTopic, AppError> {
    check_topic(body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    live_page(&mut tx, body.pillar_page_ref).await?;
    let topic: SeoTopic = sqlx::query_as(&format!(
        "INSERT INTO content_seo_topic (name, language, pillar_page_ref) VALUES ($1, $2, $3) \
         RETURNING {TOPIC_COLUMNS}"
    ))
    .bind(body.name.trim())
    .bind(&body.language)
    .bind(body.pillar_page_ref)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        topic_event(
            actor,
            AuditOperation::Create,
            topic.id,
            "content_seo_topic.create",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(topic)
}

/// Changes a topic at `expected`.
pub async fn update_topic(
    state: &EngineState,
    actor: Uuid,
    id: Uuid,
    body: &SeoTopicBody,
    expected: i64,
) -> Result<SeoTopic, AppError> {
    check_topic(body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    live_page(&mut tx, body.pillar_page_ref).await?;
    let topic: Option<SeoTopic> = sqlx::query_as(&format!(
        "UPDATE content_seo_topic SET name = $3, language = $4, pillar_page_ref = $5, \
                row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $2 RETURNING {TOPIC_COLUMNS}"
    ))
    .bind(id)
    .bind(expected)
    .bind(body.name.trim())
    .bind(&body.language)
    .bind(body.pillar_page_ref)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(topic) = topic else {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM content_seo_topic WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    write_security_event(
        &mut tx,
        &audit_service(state),
        topic_event(
            actor,
            AuditOperation::Update,
            id,
            "content_seo_topic.update",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(topic)
}

/// Deletes a topic and its page links.
pub async fn delete_topic(state: &EngineState, actor: Uuid, id: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let gone = sqlx::query("DELETE FROM content_seo_topic WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if gone == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &audit_service(state),
        topic_event(
            actor,
            AuditOperation::HardDelete,
            id,
            "content_seo_topic.delete",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// Replaces a topic's cluster pages.
pub async fn set_topic_pages(
    state: &EngineState,
    actor: Uuid,
    id: Uuid,
    pages: &[Uuid],
) -> Result<(), AppError> {
    if pages.len() > MAX_TOPIC_PAGES {
        return Err(AppError::Validation(format!(
            "a topic has at most {MAX_TOPIC_PAGES} pages"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM content_seo_topic WHERE id = $1 FOR UPDATE)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let live: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT id) FROM content_page WHERE id = ANY($1) AND is_deleted = false",
    )
    .bind(pages)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let distinct: std::collections::BTreeSet<&Uuid> = pages.iter().collect();
    if usize::try_from(live).unwrap_or(0) != distinct.len() {
        return Err(AppError::Validation("every page must exist".into()));
    }
    sqlx::query("DELETE FROM content_seo_topic_page WHERE topic_ref = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO content_seo_topic_page (topic_ref, page_ref) \
         SELECT $1, p FROM unnest($2::uuid[]) AS p ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(pages)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE content_seo_topic SET row_version = row_version + 1, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        topic_event(actor, AuditOperation::Update, id, "content_seo_topic.pages"),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// A site's stored robots body and its row version (`None` when unset).
pub async fn robots(db: &DbPool, site_key: &str) -> Result<Option<(String, i64)>, AppError> {
    sqlx::query_as("SELECT body, row_version FROM content_site_robots WHERE site_key = $1")
        .bind(site_key)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)
}

/// Writes a site's robots body under the site's lock, with a Configuration
/// event carrying the body before and after. Returns the new row version.
pub async fn put_robots(
    state: &EngineState,
    actor: Uuid,
    site_key: &str,
    body: &str,
) -> Result<i64, AppError> {
    if !site_key_ok(site_key) {
        return Err(AppError::Validation("site_key is a host name".into()));
    }
    if body.chars().count() > MAX_ROBOTS_CHARS {
        return Err(AppError::Validation(format!(
            "a robots body is at most {MAX_ROBOTS_CHARS} characters"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-content/robots:{site_key}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("robots_busy"));
    }
    let before: Option<String> =
        sqlx::query_scalar("SELECT body FROM content_site_robots WHERE site_key = $1")
            .bind(site_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let version: i64 = sqlx::query_scalar(
        "INSERT INTO content_site_robots (site_key, body, updated_by) VALUES ($1, $2, $3) \
         ON CONFLICT (site_key) DO UPDATE SET body = EXCLUDED.body, \
             updated_by = EXCLUDED.updated_by, updated_at = now(), \
             row_version = content_site_robots.row_version + 1 \
         RETURNING row_version",
    )
    .bind(site_key)
    .bind(body)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            actor,
            "content_site_robots",
            None,
        )
        .named(format!("content_site_robots.put:{site_key}"))
        .comment(before_after(
            serde_json::json!({ "body": before.as_deref().map(|b| clip(b, 4_000)) }),
            serde_json::json!({ "body": clip(body, 4_000) }),
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(version)
}

/// The sitemap served for a site: the language asked for, else the first
/// language stored for the site; part 0 (the only `urlset`, or the index of
/// a split one) unless a part is asked for; an empty `urlset` when there is
/// none.
pub async fn served_sitemap(
    db: &DbPool,
    site_key: &str,
    lang: Option<&str>,
    part: i32,
) -> Result<String, AppError> {
    let lang = match lang {
        Some(lang) => Some(lang.to_owned()),
        None => sqlx::query_scalar(
            "SELECT lang FROM content_sitemap WHERE site_key = $1 ORDER BY lang LIMIT 1",
        )
        .bind(site_key)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?,
    };
    Ok(match lang {
        Some(lang) => sitemap(db, site_key, &lang, part)
            .await?
            .unwrap_or_else(empty_sitemap),
        None => empty_sitemap(),
    })
}

/// One stored part of a site's sitemap for one language (E13-T9: part 0
/// is the only `urlset`, or the index naming parts 1.. of a split one).
pub async fn sitemap(
    db: &DbPool,
    site_key: &str,
    lang: &str,
    part: i32,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT xml FROM content_sitemap WHERE site_key = $1 AND lang = $2 AND part = $3",
    )
    .bind(site_key)
    .bind(lang)
    .bind(part)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_always_closes_portal_and_preview_paths() {
        let served = served_robots(Some("User-agent: *\nDisallow: /private/\n"));
        assert!(served.starts_with("User-agent: *\nDisallow: /private/"));
        for path in ALWAYS_DISALLOWED {
            assert!(served.contains(&format!("Disallow: {path}\n")), "{path}");
        }
        let default = served_robots(None);
        assert!(default.starts_with("User-agent: *\nAllow: /"));
        assert!(default.contains("Disallow: /portal/"));
    }

    #[test]
    fn site_keys_and_languages() {
        assert!(site_key_ok("www.example.sa"));
        assert!(site_key_ok("shop-1.example.com"));
        assert!(!site_key_ok("Example.com"));
        assert!(!site_key_ok("example.com/robots"));
        assert!(!site_key_ok(""));
        assert!(!site_key_ok(".example.com"));
        assert!(lang_ok("ar"));
        assert!(lang_ok("ar-SA"));
        assert!(!lang_ok("arabic"));
        assert!(!lang_ok("a"));
        assert!(!lang_ok("ar-'x"));
    }

    #[test]
    fn empty_sitemap_is_a_urlset() {
        let xml = empty_sitemap();
        assert!(xml.contains("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"));
    }
}
