//! Crawled pages into knowledge items (D-365; K6-T4).
//!
//! [`import_pages`] promotes chosen crawled pages into `knowledge_data_item`
//! rows under the source's Data Source, through
//! `attome_records::entity_crud::create_record_for`, the same primitive the
//! generic `/api/v1/{entity}` route uses, so record security, validation
//! and audit hold as for any other write (guidelines §9).
//!
//! K6-T4: a page remembers the text hash it had when imported
//! (`webcrawl_page.imported_content_hash`). When a recrawl brings different
//! text, the item is out of date, and [`sync_after_crawl`] (run at the end of
//! every completed crawl) brings it up to date:
//!
//! - an item a person already published from a `review` source keeps its
//!   text and is flagged `needs_review`; importing the page again through
//!   the route replaces the text;
//! - any other item (a draft, or an `automatic` source's) takes the new
//!   text as its next `version`.
//!
//! Each item is updated alone through the generic update path, with its
//! `row_version`, so the knowledge index re-chunks only that item (the change
//! feed's knowledge arm, whose hash gate skips unchanged text); an item
//! someone changed meanwhile is skipped and taken up by the next crawl. An
//! `automatic` source also imports its new pages, published, on every crawl.
//! The sync acts as the person who created the source.
//!
//! K6-T7: a page whose text is the same as an imported page of the source
//! (same `content_hash`) is not imported again: it becomes that page's
//! alias (`alias_of`), and stops being one when its text changes. After a
//! complete crawl (no error stop, no page limit), every page in scope that
//! the crawl did not see has its `missing_count` raised ([`retire_missing`]);
//! at two in a row its item is retired: set `expired`, so the knowledge
//! index drops its chunks while the item and its history stay, with a
//! `webcrawl.item_retired` event.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::model::ImportResult;

/// The claim a page carries while its item is being created.
pub const NIL_CLAIM: Uuid = Uuid::nil();
/// The most pages one sync looks at, each way.
pub const MAX_SYNC_PAGES: i64 = 500;

const ITEM: &str = "knowledge_data_item";
const SOURCE: &str = "knowledge_data_source";
const PUBLISHED: &str = "published";
const EXPIRED: &str = "expired";
const AUTOMATIC: &str = "automatic";

/// What a changed page does to its item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The item takes the page's text as its next version.
    Replace,
    /// The item keeps its text and is flagged for review.
    Flag,
    /// Nothing to do (already flagged).
    Nothing,
}

/// What a changed page does to an item in `lifecycle`, from a source in
/// `import_mode`. `explicit` is a person importing the page again, which
/// always replaces. Pure.
pub fn change_for(
    import_mode: &str,
    lifecycle: Option<&str>,
    needs_review: bool,
    explicit: bool,
) -> Change {
    if explicit || import_mode == AUTOMATIC || lifecycle != Some(PUBLISHED) {
        Change::Replace
    } else if needs_review {
        Change::Nothing
    } else {
        Change::Flag
    }
}

/// Recrawls in a row a page may be missing before its item is retired.
pub const MISSING_TO_RETIRE: i32 = 2;

/// What one sync did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    pub imported: i64,
    /// K6-T7: new pages that became an imported page's alias.
    pub aliased: i64,
    pub updated: i64,
    pub flagged: i64,
    pub skipped: i64,
}

/// Which K6-T4 attributes the item entity has on this deployment.
#[derive(Debug, Clone, Copy)]
struct ItemFields {
    version: bool,
    needs_review: bool,
}

fn item_fields(state: &EngineState) -> ItemFields {
    let registry = state.entities.load();
    let has = |name: &str| {
        registry
            .get(ITEM)
            .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == name))
    };
    ItemFields {
        version: has("version"),
        needs_review: has("needs_review"),
    }
}

#[derive(sqlx::FromRow)]
struct Candidate {
    id: Uuid,
    url_path: String,
    content: Option<String>,
    content_hash: Option<String>,
    imported_data_item_ref: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct Target {
    import_mode: String,
    watch_only: bool,
    created_by: Uuid,
}

async fn load_target(state: &EngineState, target_id: Uuid) -> Result<Option<Target>, AppError> {
    sqlx::query_as(
        "SELECT import_mode, watch_only, created_by FROM webcrawl_target \
          WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(target_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The source's Data Source, created on first use.
pub async fn ensure_data_source_for_target(
    state: &EngineState,
    ctx: &SecurityContext,
    target_id: Uuid,
) -> Result<Uuid, AppError> {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT data_source_ref FROM webcrawl_target WHERE id = $1")
            .bind(target_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    if let Some(id) = existing {
        return Ok(id);
    }

    ctx.require(SOURCE, "create")?;

    let url: String = sqlx::query_scalar("SELECT url FROM webcrawl_target WHERE id = $1")
        .bind(target_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    let host = reqwest::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.clone());

    let body = json!({
        "name": host,
        "description": format!("Web crawl of {url}"),
    });
    let (new_id, _) =
        attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, SOURCE, body)
            .await?;

    // Compare-and-swap: only the first caller to claim a still-NULL
    // `data_source_ref` wins. A concurrent loser's freshly created Data
    // Source is left unreferenced: harmless orphan metadata an admin can
    // delete, not a correctness issue.
    let claimed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE webcrawl_target SET data_source_ref = $2, row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND data_source_ref IS NULL \
         RETURNING data_source_ref",
    )
    .bind(target_id)
    .bind(new_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    match claimed {
        Some(id) => Ok(id),
        None => sqlx::query_scalar("SELECT data_source_ref FROM webcrawl_target WHERE id = $1")
            .bind(target_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten()
            .ok_or_else(|| {
                AppError::internal("target lost its data_source_ref between check and use")
            }),
    }
}

/// Creates the item for one not yet imported page; `false` when another
/// import claimed it first.
async fn create_item(
    state: &EngineState,
    ctx: &SecurityContext,
    fields: ItemFields,
    data_source: Uuid,
    published: bool,
    page: &Candidate,
) -> Result<Created, AppError> {
    // K6-T7: the same text as an imported page of the source makes this an
    // alias of it, not a second item.
    if page.content_hash.is_some() {
        let aliased = sqlx::query(
            "UPDATE webcrawl_page p SET alias_of = o.id, updated_at = NOW() \
               FROM (SELECT id FROM webcrawl_page \
                      WHERE target_ref = (SELECT target_ref FROM webcrawl_page WHERE id = $1) \
                        AND id <> $1 AND content_hash = $2 AND is_deleted = FALSE \
                        AND alias_of IS NULL AND imported_data_item_ref IS NOT NULL \
                        AND imported_data_item_ref <> $3 \
                      ORDER BY id LIMIT 1) o \
              WHERE p.id = $1 AND p.imported_data_item_ref IS NULL",
        )
        .bind(page.id)
        .bind(&page.content_hash)
        .bind(NIL_CLAIM)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if aliased.rows_affected() > 0 {
            return Ok(Created::Aliased);
        }
    }
    let claim = sqlx::query(
        "UPDATE webcrawl_page SET imported_data_item_ref = $2 \
         WHERE id = $1 AND imported_data_item_ref IS NULL AND alias_of IS NULL",
    )
    .bind(page.id)
    .bind(NIL_CLAIM)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claim.rows_affected() == 0 {
        return Ok(Created::Taken);
    }

    let mut body = Map::new();
    body.insert("title".into(), json!(page.url_path));
    body.insert("text".into(), json!(page.content));
    body.insert("data_source_ref".into(), json!(data_source));
    if published {
        body.insert("lifecycle".into(), json!(PUBLISHED));
    }
    if fields.version {
        body.insert("version".into(), json!(1));
    }
    match attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        ITEM,
        Value::Object(body),
    )
    .await
    {
        Ok((record_id, _)) => {
            sqlx::query(
                "UPDATE webcrawl_page SET imported_data_item_ref = $2, imported_content_hash = $3, \
                     row_version = row_version + 1, updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(page.id)
            .bind(record_id)
            .bind(&page.content_hash)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(Created::Item)
        }
        Err(e) => {
            // Release the claim so a retry can pick this page up again.
            if let Err(release) = sqlx::query(
                "UPDATE webcrawl_page SET imported_data_item_ref = NULL \
                 WHERE id = $1 AND imported_data_item_ref = $2",
            )
            .bind(page.id)
            .bind(NIL_CLAIM)
            .execute(&state.base.db)
            .await
            {
                tracing::warn!(page = %page.id, error = %release,
                    "webcrawl: could not release an import claim");
            }
            Err(e)
        }
    }
}

/// What importing one new page did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Created {
    /// A new item.
    Item,
    /// K6-T7: an alias of an imported page with the same text.
    Aliased,
    /// Another import took the page first.
    Taken,
}

type ItemRow = (i64, Option<String>, Option<bool>, Option<f64>);

/// Brings one imported item up to date with its changed page. Returns what
/// it did; a conflict or a missing item is `Nothing` (the next crawl tries
/// again).
async fn update_item(
    state: &EngineState,
    ctx: &SecurityContext,
    fields: ItemFields,
    import_mode: &str,
    explicit: bool,
    page: &Candidate,
    item: Uuid,
) -> Result<Change, AppError> {
    // Static fragments only: an attribute the deployment lacks reads NULL.
    let sql = format!(
        "SELECT row_version, lifecycle::text, {}, {} FROM knowledge_data_item \
          WHERE id = $1 AND is_active IS DISTINCT FROM false",
        if fields.needs_review {
            "needs_review"
        } else {
            "NULL::boolean"
        },
        if fields.version {
            "version::float8"
        } else {
            "NULL::float8"
        },
    );
    let row: Option<ItemRow> = sqlx::query_as(&sql)
        .bind(item)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let Some((row_version, lifecycle, needs_review, version)) = row else {
        return Ok(Change::Nothing);
    };
    let change = change_for(
        import_mode,
        lifecycle.as_deref(),
        needs_review.unwrap_or(false),
        explicit,
    );
    let mut body = Map::new();
    match change {
        Change::Nothing => return Ok(Change::Nothing),
        Change::Flag if !fields.needs_review => return Ok(Change::Nothing),
        Change::Flag => {
            body.insert("needs_review".into(), json!(true));
        }
        Change::Replace => {
            body.insert("title".into(), json!(page.url_path));
            body.insert("text".into(), json!(page.content));
            if fields.version {
                let next = version.map_or(2, |v| (v as i64).max(1) + 1);
                body.insert("version".into(), json!(next));
            }
            if fields.needs_review {
                body.insert("needs_review".into(), json!(false));
            }
        }
    }
    match attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        ITEM,
        item,
        row_version,
        Value::Object(body),
    )
    .await
    {
        Ok(_) => {}
        Err(AppError::Conflict(_) | AppError::NotFound) => return Ok(Change::Nothing),
        Err(e) => return Err(e),
    }
    if change == Change::Replace {
        sqlx::query(
            "UPDATE webcrawl_page SET imported_content_hash = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(page.id)
        .bind(&page.content_hash)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        audit_item(
            state,
            ctx.user_id,
            item,
            "webcrawl.item_updated",
            format!("updated from {}", page.url_path),
        )
        .await;
    }
    Ok(change)
}

/// Imports the chosen pages: new pages become items, and an imported page
/// whose text changed replaces its item's text as the next version.
pub async fn import_pages(
    state: &EngineState,
    ctx: &SecurityContext,
    target_id: Uuid,
    page_ids: &[Uuid],
) -> Result<ImportResult, AppError> {
    if page_ids.is_empty() {
        return Err(AppError::Validation("page_ids must not be empty".into()));
    }
    let Some(target) = load_target(state, target_id).await? else {
        return Err(AppError::NotFound);
    };
    // K6-T9: a watch-only source reports changes and imports nothing.
    if target.watch_only {
        return Err(AppError::Validation(
            "this source only watches for changes; it imports nothing".into(),
        ));
    }

    let data_source_id = ensure_data_source_for_target(state, ctx, target_id).await?;
    ctx.require(ITEM, "create")?;
    // K6-T6: documents whose text is ready become importable pages first.
    crate::documents::absorb_documents(state, ctx, target_id).await?;
    let fields = item_fields(state);
    let published = target.import_mode == AUTOMATIC;

    let candidates = sqlx::query_as::<_, Candidate>(&format!(
        "SELECT id, url_path, content, content_hash, imported_data_item_ref FROM webcrawl_page \
         WHERE target_ref = $1 AND id = ANY($2) AND is_deleted = FALSE \
           AND status IN ('crawled', 'document') AND content IS NOT NULL \
           AND {IN_LANGUAGE} \
           AND ((imported_data_item_ref IS NULL AND alias_of IS NULL) \
                OR (imported_data_item_ref <> $3 \
                    AND content_hash IS DISTINCT FROM imported_content_hash))"
    ))
    .bind(target_id)
    .bind(page_ids)
    .bind(NIL_CLAIM)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut imported = 0i64;
    let mut updated = 0i64;
    let mut aliased = 0i64;
    for candidate in &candidates {
        match candidate.imported_data_item_ref {
            None => {
                match create_item(state, ctx, fields, data_source_id, published, candidate).await? {
                    Created::Item => imported += 1,
                    Created::Aliased => aliased += 1,
                    Created::Taken => {}
                }
            }
            Some(item) => {
                ctx.require(ITEM, "update")?;
                let change = update_item(
                    state,
                    ctx,
                    fields,
                    &target.import_mode,
                    true,
                    candidate,
                    item,
                )
                .await?;
                if change == Change::Replace {
                    updated += 1;
                }
            }
        }
    }

    if imported > 0 {
        sqlx::query(
            "UPDATE webcrawl_target SET pages_imported = pages_imported + $2, row_version = row_version + 1, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(target_id)
        .bind(i32::try_from(imported).unwrap_or(i32::MAX))
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }

    Ok(ImportResult {
        data_source_ref: data_source_id,
        imported_count: imported,
        updated_count: updated,
        aliased_count: aliased,
    })
}

/// K6-T4: after a completed crawl, brings changed imported items up to
/// date and, for an `automatic` source, imports its new pages. Acts as the
/// source's creator; a creator who can no longer do it leaves everything
/// for an administrator's import.
pub async fn sync_after_crawl(state: &EngineState, target_id: Uuid) -> Result<SyncStats, AppError> {
    let mut stats = SyncStats::default();
    let Some(target) = load_target(state, target_id).await? else {
        return Ok(stats);
    };
    if target.watch_only {
        return Ok(stats);
    }
    let ctx = match state.base.security.resolve(target.created_by).await {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::warn!(%target_id, error = %e,
                "webcrawl: the source's creator cannot be resolved; imported items stay as they are");
            return Ok(stats);
        }
    };
    let fields = item_fields(state);

    // K6-T6: documents whose text is ready become pages like any other.
    if let Err(e) = crate::documents::absorb_documents(state, &ctx, target_id).await {
        tracing::warn!(%target_id, error = %e, "webcrawl: linked documents were not taken up");
    }

    // K6-T7: an alias whose text now differs from its page's stops being one.
    sqlx::query(
        "UPDATE webcrawl_page p SET alias_of = NULL, updated_at = NOW() \
           FROM webcrawl_page o \
          WHERE p.alias_of = o.id AND p.target_ref = $1 \
            AND p.content_hash IS DISTINCT FROM o.content_hash",
    )
    .bind(target_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    if ctx.require(ITEM, "update").is_ok() {
        let changed = sqlx::query_as::<_, Candidate>(
            "SELECT id, url_path, content, content_hash, imported_data_item_ref FROM webcrawl_page \
             WHERE target_ref = $1 AND is_deleted = FALSE AND status IN ('crawled', 'document') \
               AND content IS NOT NULL AND imported_data_item_ref IS NOT NULL \
               AND imported_data_item_ref <> $2 \
               AND content_hash IS DISTINCT FROM imported_content_hash \
             ORDER BY id LIMIT $3",
        )
        .bind(target_id)
        .bind(NIL_CLAIM)
        .bind(MAX_SYNC_PAGES)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for page in &changed {
            let Some(item) = page.imported_data_item_ref else {
                continue;
            };
            match update_item(state, &ctx, fields, &target.import_mode, false, page, item).await {
                Ok(Change::Replace) => stats.updated += 1,
                Ok(Change::Flag) => stats.flagged += 1,
                Ok(Change::Nothing) => stats.skipped += 1,
                Err(e) => {
                    tracing::warn!(%target_id, page = %page.id, error = %e,
                        "webcrawl: a changed page's item was not updated");
                    stats.skipped += 1;
                }
            }
        }
    } else {
        tracing::warn!(%target_id,
            "webcrawl: the source's creator may not update knowledge items; changed pages wait");
    }

    if target.import_mode == AUTOMATIC && ctx.require(ITEM, "create").is_ok() {
        let fresh = sqlx::query_as::<_, Candidate>(&format!(
            "SELECT id, url_path, content, content_hash, imported_data_item_ref FROM webcrawl_page \
             WHERE target_ref = $1 AND is_deleted = FALSE AND status IN ('crawled', 'document') \
               AND content IS NOT NULL AND imported_data_item_ref IS NULL \
               AND alias_of IS NULL AND {IN_LANGUAGE} \
             ORDER BY id LIMIT $2"
        ))
        .bind(target_id)
        .bind(MAX_SYNC_PAGES)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if !fresh.is_empty() {
            let data_source = ensure_data_source_for_target(state, &ctx, target_id).await?;
            for page in &fresh {
                match create_item(state, &ctx, fields, data_source, true, page).await {
                    Ok(Created::Item) => stats.imported += 1,
                    Ok(Created::Aliased) => stats.aliased += 1,
                    Ok(Created::Taken) => {}
                    Err(e) => {
                        tracing::warn!(%target_id, page = %page.id, error = %e,
                            "webcrawl: a new page of an automatic source was not imported");
                        stats.skipped += 1;
                    }
                }
            }
            if stats.imported > 0 {
                sqlx::query(
                    "UPDATE webcrawl_target SET pages_imported = pages_imported + $2, \
                         row_version = row_version + 1, updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(target_id)
                .bind(i32::try_from(stats.imported).unwrap_or(i32::MAX))
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(stats)
}

/// K6-T7: after a complete crawl that started at `seen_since`, raises the
/// `missing_count` of every page in the source's scope the crawl did not
/// touch, and retires the item of each page now missing
/// [`MISSING_TO_RETIRE`] times in a row (set `expired`, so its chunks leave
/// the knowledge index; the item and its history stay). Acts as the
/// source's creator. Answers how many items it retired.
pub async fn retire_missing(
    state: &EngineState,
    target_id: Uuid,
    seen_since: chrono::DateTime<chrono::Utc>,
) -> Result<i64, AppError> {
    let scope: Option<(String, String, Uuid)> = sqlx::query_as(
        "SELECT include_patterns, exclude_patterns, created_by FROM webcrawl_target \
          WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(target_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((include, exclude, creator)) = scope else {
        return Ok(0);
    };
    let include = crate::crawl::parse_patterns(&include);
    let exclude = crate::crawl::parse_patterns(&exclude);
    let unseen: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, url_path FROM webcrawl_page \
          WHERE target_ref = $1 AND is_deleted = FALSE AND updated_at < $2",
    )
    .bind(target_id)
    .bind(seen_since)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = unseen
        .into_iter()
        .filter(|(_, path)| crate::crawl::in_scope(path, &include, &exclude))
        .map(|(id, _)| id)
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let due: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "UPDATE webcrawl_page SET missing_count = missing_count + 1 \
          WHERE id = ANY($1) \
          RETURNING id, url_path, CASE WHEN missing_count >= $2 THEN imported_data_item_ref END",
    )
    .bind(&ids)
    .bind(MISSING_TO_RETIRE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<(String, Uuid)> = due
        .into_iter()
        .filter_map(|(_, path, item)| item.filter(|i| *i != NIL_CLAIM).map(|i| (path, i)))
        .collect();
    if items.is_empty() {
        return Ok(0);
    }
    let ctx = match state.base.security.resolve(creator).await {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::warn!(%target_id, error = %e,
                "webcrawl: the source's creator cannot be resolved; missing pages keep their items");
            return Ok(0);
        }
    };
    if ctx.require(ITEM, "update").is_err() {
        return Ok(0);
    }
    let mut retired = 0;
    for (path, item) in items {
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT row_version, lifecycle::text FROM knowledge_data_item \
              WHERE id = $1 AND is_active IS DISTINCT FROM false",
        )
        .bind(item)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((row_version, lifecycle)) = row else {
            continue;
        };
        if lifecycle.as_deref() == Some(EXPIRED) {
            continue;
        }
        match attome_records::entity_crud::update_record_for(
            state,
            &ctx,
            ctx.user_id,
            ITEM,
            item,
            row_version,
            json!({ "lifecycle": EXPIRED }),
        )
        .await
        {
            Ok(_) => {
                retired += 1;
                audit_item(
                    state,
                    ctx.user_id,
                    item,
                    "webcrawl.item_retired",
                    format!("{path} was missing from {MISSING_TO_RETIRE} crawls in a row"),
                )
                .await;
            }
            Err(AppError::Conflict(_) | AppError::NotFound) => {}
            Err(e) => {
                tracing::warn!(%target_id, %item, error = %e, "webcrawl: an item was not retired");
            }
        }
    }
    Ok(retired)
}

/// K6-T1: a page in a language its source keeps: one the source lists (by
/// its primary subtag, so `en-GB` is `en`), or any page when the source
/// lists none or the page declared none.
const IN_LANGUAGE: &str = "(webcrawl_page.language IS NULL OR NOT EXISTS ( \
    SELECT 1 FROM webcrawl_target t WHERE t.id = webcrawl_page.target_ref \
       AND cardinality(t.languages) > 0 \
       AND NOT (split_part(lower(webcrawl_page.language), '-', 1) = ANY(t.languages))))";

/// The business event for an item a recrawl updated (`webcrawl.item_updated`)
/// or retired (`webcrawl.item_retired`), beside the change's own entity
/// audit row. Best effort, as the source's other business events.
async fn audit_item(state: &EngineState, user_id: Uuid, item: Uuid, event: &str, comment: String) {
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    let record = attome_audit::AuditEvent {
        organization_ref: org_ref,
        category: attome_audit::AuditCategory::BusinessEvent,
        entity_name: Some(ITEM.to_string()),
        record_id: Some(item),
        operation: attome_audit::AuditOperation::Update,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: attome_audit::AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event.to_string()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let audit_service =
        attome_audit::AuditService::new(&state.base.db, state.audit_signer.as_deref())
            .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
            .with_chainer_enabled(state.base.config.audit.chainer_enabled)
            .with_erasure_key(state.audit_erasure_key.clone());
    if let Err(e) = audit_service.write(record).await {
        tracing::warn!(error = %e, event, "webcrawl: item audit write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_published_item_from_a_review_source_is_flagged_not_replaced() {
        assert_eq!(
            change_for("review", Some("published"), false, false),
            Change::Flag
        );
        assert_eq!(
            change_for("review", Some("published"), true, false),
            Change::Nothing,
            "flagged once"
        );
        assert_eq!(
            change_for("review", Some("published"), true, true),
            Change::Replace,
            "a person importing again replaces"
        );
    }

    #[test]
    fn drafts_and_automatic_sources_take_the_new_text() {
        assert_eq!(
            change_for("review", Some("draft"), false, false),
            Change::Replace
        );
        assert_eq!(change_for("review", None, false, false), Change::Replace);
        assert_eq!(
            change_for("automatic", Some("published"), false, false),
            Change::Replace
        );
    }
}
