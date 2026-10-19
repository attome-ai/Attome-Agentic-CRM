//! G11-T1: knowledge articles as a content page type.
//!
//! An `article` page is an ordinary content page (blocks, versions,
//! approval, audience, translations) that also names the knowledge data
//! source it is filed under, a category and the products it covers. While it
//! is published, it is projected into one `knowledge_data_item` record —
//! title, the blocks as text, source, category, products, audience and review
//! date — which the knowledge index (`attome_search::knowledge_index`) chunks
//! from the change feed like every other item, so published articles are
//! retrievable with no search-side code here. Unpublishing or deleting the
//! page sets the item back to `draft`, and the index removes its chunks.
//!
//! **Who writes the item.** The projection runs as a durable job
//! (`EngineJob::ContentArticleIndex`, enqueued in the transaction that
//! publishes, unpublishes, deletes or reconfigures the page) under the
//! security context of the person who made the page an article
//! (`knowledge_author`), resolved fresh, through the generic entity engine:
//! their privileges on `knowledge_data_item` decide, and the item's own
//! validation, audit and change event apply. Scheduled publishes have no
//! person behind them, which is why the author is recorded rather than the
//! publisher.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::put,
};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json as SqlxJson;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::model::{Block, BlockKind};

/// The knowledge item an article is projected into.
pub const ITEM_ENTITY: &str = "knowledge_data_item";
/// The knowledge data source an article is filed under.
pub const SOURCE_ENTITY: &str = "knowledge_data_source";
/// Most products one article names.
pub const MAX_PRODUCTS: usize = 50;
/// Longest category or product name.
pub const MAX_NAME_CHARS: usize = 200;

/// `PUT .../article`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ArticleBody {
    /// The knowledge data source to file the article under; `null` makes the
    /// page an ordinary page again.
    pub knowledge_source_id: Option<Uuid>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub products: Vec<String>,
}

/// A page's article settings.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ArticleSettings {
    pub id: Uuid,
    /// `page` or `article`.
    pub page_type: String,
    pub knowledge_source_id: Option<Uuid>,
    pub article_category: Option<String>,
    pub article_products: Vec<String>,
    /// The knowledge item the article is projected into, once it has been.
    pub knowledge_item_id: Option<Uuid>,
}

/// A category or product name: trimmed, non-empty, at most
/// [`MAX_NAME_CHARS`]. Pure.
fn clean_name(name: &str, what: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(AppError::Validation(format!(
            "each {what} is 1 to {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(name.to_owned())
}

/// The products as stored: trimmed, each once, at most [`MAX_PRODUCTS`].
/// Pure.
pub fn clean_products(products: &[String]) -> Result<Vec<String>, AppError> {
    let mut out: Vec<String> = Vec::new();
    for product in products {
        let product = clean_name(product, "product")?;
        if !out.iter().any(|p| p.eq_ignore_ascii_case(&product)) {
            out.push(product);
        }
    }
    if out.len() > MAX_PRODUCTS {
        return Err(AppError::Validation(format!(
            "an article names at most {MAX_PRODUCTS} products"
        )));
    }
    Ok(out)
}

fn push_blocks(blocks: &[Block], out: &mut Vec<String>) {
    for block in blocks {
        let text = |field: &str| {
            block
                .props
                .get(field)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
        };
        match block.kind {
            BlockKind::Heading => {
                if let Some(t) = text("text") {
                    out.push(format!("## {t}"));
                }
            }
            BlockKind::RichText => {
                if let Some(html) = text("html") {
                    let plain = attome_html::html_to_text(html);
                    if !plain.trim().is_empty() {
                        out.push(plain.trim().to_owned());
                    }
                }
            }
            BlockKind::Alert => {
                if let Some(t) = text("message") {
                    out.push(t.to_owned());
                }
            }
            BlockKind::Image => {
                if let Some(t) = text("alt") {
                    out.push(t.to_owned());
                }
            }
            BlockKind::Columns => {
                let columns = block.props.get("columns").and_then(Value::as_array);
                for column in columns.into_iter().flatten() {
                    if let Some(inner) = column
                        .get("blocks")
                        .and_then(|b| serde_json::from_value::<Vec<Block>>(b.clone()).ok())
                    {
                        push_blocks(&inner, out);
                    }
                }
            }
            // Live data, forms and components carry no article text.
            BlockKind::DataTable | BlockKind::Chart | BlockKind::Form | BlockKind::Component => {}
        }
    }
}

/// An article's blocks as indexable text: headings as `## ` lines (the
/// knowledge chunker splits on them), rich text without its markup, alert
/// messages and image descriptions, columns in order. Pure.
pub fn article_text(blocks: &[Block]) -> String {
    let mut out = Vec::new();
    push_blocks(blocks, &mut out);
    out.join("\n\n")
}

/// The published page as it is read for projection.
#[derive(Debug, sqlx::FromRow)]
pub struct ArticleRow {
    pub title: String,
    pub status: String,
    pub is_deleted: bool,
    pub page_type: String,
    pub audience: String,
    pub review_by: Option<NaiveDate>,
    pub blocks_published: Option<SqlxJson<Vec<Block>>>,
    pub knowledge_source_id: Option<Uuid>,
    pub article_category: Option<String>,
    pub article_products: Vec<String>,
    pub knowledge_author: Option<Uuid>,
    pub knowledge_item_id: Option<Uuid>,
}

impl ArticleRow {
    /// Whether the page should be retrievable now.
    pub fn is_live(&self) -> bool {
        !self.is_deleted
            && self.status == "published"
            && self.page_type == "article"
            && self.knowledge_source_id.is_some()
    }
}

/// The knowledge item's fields for a page: everything while it is live, only
/// `lifecycle = draft` once it is not. Pure.
pub fn item_body(page_id: Uuid, row: &ArticleRow) -> Value {
    if !row.is_live() {
        return json!({ "lifecycle": "draft" });
    }
    let blocks = row
        .blocks_published
        .as_ref()
        .map(|b| b.0.as_slice())
        .unwrap_or_default();
    json!({
        "title": row.title,
        "text": article_text(blocks),
        "data_source_ref": row.knowledge_source_id,
        "lifecycle": "published",
        "review_by": row.review_by,
        "source_entity": "content_page",
        "source_record_id": page_id.to_string(),
        "category": row.article_category,
        "products": (!row.article_products.is_empty()).then(|| row.article_products.join(", ")),
        "audience": row.audience,
    })
}

/// Queues the page's projection, in the caller's transaction, when the page
/// is an article or was projected before. Called by every path that
/// publishes, unpublishes, deletes or reconfigures a page.
pub async fn enqueue_sync_in_tx(tx: &mut attome_db::Tx<'_>, page_id: Uuid) -> Result<(), AppError> {
    let wanted: Option<bool> = sqlx::query_scalar(
        "SELECT page_type = 'article' OR knowledge_item_id IS NOT NULL \
           FROM content_page WHERE id = $1",
    )
    .bind(page_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if wanted == Some(true) {
        attome_jobs::enqueue_in_tx(
            tx,
            attome_core::jobs::EngineJob::ContentArticleIndex { page_id },
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// [`enqueue_sync_in_tx`] for a caller with no transaction of its own.
pub async fn enqueue_sync(db: &attome_db::DbPool, page_id: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    enqueue_sync_in_tx(&mut tx, page_id).await?;
    tx.commit().await.map_err(AppError::internal)
}

/// Worker for `EngineJob::ContentArticleIndex`: brings the page's knowledge
/// item in line with the page. Idempotent; one page at a time (a second
/// worker on the same page answers `Conflict` and is retried).
pub async fn sync(state: &EngineState, page_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    // Serialises projections of one page, so two workers never both create
    // an item for it. The transaction only holds the lock.
    let mut lock_tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-content/article-sync:{page_id}"))
        .fetch_one(&mut *lock_tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this article is already being indexed"));
    }

    let row: Option<ArticleRow> = sqlx::query_as(
        "SELECT title, status, is_deleted, page_type, audience, review_by, blocks_published, \
                knowledge_source_id, article_category, article_products, knowledge_author, \
                knowledge_item_id \
           FROM content_page WHERE id = $1",
    )
    .bind(page_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(());
    };
    let live = row.is_live();
    if !live && row.knowledge_item_id.is_none() {
        return Ok(());
    }
    let Some(author) = row.knowledge_author else {
        tracing::warn!(%page_id, "article has no knowledge author; not indexed");
        return Ok(());
    };
    let ctx = attome_security::resolve_uncached(db, author).await?;
    let body = item_body(page_id, &row);

    let existing = match row.knowledge_item_id {
        Some(item_id) => {
            match attome_records::entity_crud::read_record(state, &ctx, ITEM_ENTITY, item_id).await
            {
                Ok(record) => Some((item_id, record.row_version())),
                Err(AppError::NotFound) => None,
                Err(e) => return Err(e),
            }
        }
        None => None,
    };
    match existing {
        Some((item_id, row_version)) => {
            ctx.require(ITEM_ENTITY, "update")?;
            attome_records::entity_crud::update_record_for(
                state,
                &ctx,
                author,
                ITEM_ENTITY,
                item_id,
                row_version,
                body,
            )
            .await?;
        }
        None if live => {
            ctx.require(ITEM_ENTITY, "create")?;
            let (item_id, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                author,
                ITEM_ENTITY,
                body,
            )
            .await?;
            sqlx::query("UPDATE content_page SET knowledge_item_id = $2 WHERE id = $1")
                .bind(page_id)
                .bind(item_id)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
        }
        // The item is gone and the page is not live: nothing to retract.
        None => {}
    }
    lock_tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Makes a page a knowledge article, or an ordinary page again (G11-T1).
///
/// An article names the knowledge data source it is filed under, a category
/// and products; while published it is searchable as a knowledge item
/// written as the caller, who needs to be able to create knowledge items.
/// `knowledge_source_id: null` makes it an ordinary page and withdraws it
/// from search.
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/pages/{id}/article",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id")),
    request_body = ArticleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The page's article settings", body = ArticleSettings),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, may not create knowledge items, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 422, description = "A bad category or product, or a knowledge source the caller cannot see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_article(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<ArticleBody>,
) -> Result<Json<ArticleSettings>, AppError> {
    let category = body
        .category
        .as_deref()
        .map(|c| clean_name(c, "category"))
        .transpose()?;
    let products = clean_products(&body.products)?;
    if let Some(source_id) = body.knowledge_source_id {
        ctx.require(ITEM_ENTITY, "create")?;
        match attome_records::entity_crud::read_record(&state, &ctx, SOURCE_ENTITY, source_id).await
        {
            Ok(_) => {}
            Err(AppError::NotFound) => {
                return Err(AppError::Validation(
                    "knowledge_source_id does not name a knowledge source you can see".into(),
                ));
            }
            Err(e) => return Err(e),
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let settings: Option<ArticleSettings> = sqlx::query_as(
        "UPDATE content_page \
            SET page_type = CASE WHEN $2::uuid IS NULL THEN 'page' ELSE 'article' END, \
                knowledge_source_id = $2, article_category = $3, article_products = $4, \
                knowledge_author = $5, row_version = row_version + 1, updated_at = NOW(), \
                updated_by = $5 \
          WHERE id = $1 AND is_deleted = FALSE \
          RETURNING id, page_type, knowledge_source_id, article_category, article_products, \
                    knowledge_item_id",
    )
    .bind(id)
    .bind(body.knowledge_source_id)
    .bind(&category)
    .bind(&products)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let settings = settings.ok_or(AppError::NotFound)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.article")
        .comment(format!("page type {}", settings.page_type)),
    )
    .await?;
    enqueue_sync_in_tx(&mut tx, id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(settings))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/content/pages/{id}/article", put(set_article))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(set_article))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(kind: BlockKind, props: Value) -> Block {
        Block {
            id: Uuid::nil(),
            kind,
            props,
        }
    }

    fn row(status: &str, page_type: &str) -> ArticleRow {
        ArticleRow {
            title: "Resetting a password".into(),
            status: status.into(),
            is_deleted: false,
            page_type: page_type.into(),
            audience: "public".into(),
            review_by: None,
            blocks_published: Some(SqlxJson(vec![block(
                BlockKind::Heading,
                json!({"text": "Steps"}),
            )])),
            knowledge_source_id: Some(Uuid::nil()),
            article_category: Some("Accounts".into()),
            article_products: vec!["Portal".into(), "App".into()],
            knowledge_author: Some(Uuid::nil()),
            knowledge_item_id: None,
        }
    }

    #[test]
    fn knowledge_article_text_keeps_headings_and_drops_markup() {
        let blocks = vec![
            block(BlockKind::Heading, json!({"text": "Before you start"})),
            block(
                BlockKind::RichText,
                json!({"html": "<p>Open <b>Settings</b>.</p>"}),
            ),
            block(
                BlockKind::Columns,
                json!({"columns": [{"blocks": [
                    {"id": Uuid::nil(), "kind": "alert", "props": {"message": "Keep it safe"}}
                ]}]}),
            ),
            block(BlockKind::Chart, json!({"query_id": Uuid::nil()})),
        ];
        let text = article_text(&blocks);
        assert!(text.starts_with("## Before you start"), "{text}");
        assert!(text.contains("Settings"), "{text}");
        assert!(!text.contains("<b>"), "{text}");
        assert!(text.ends_with("Keep it safe"), "{text}");
    }

    #[test]
    fn knowledge_article_is_indexed_only_while_published() {
        let page = Uuid::now_v7();
        let live = item_body(page, &row("published", "article"));
        assert_eq!(live["lifecycle"], "published");
        assert_eq!(live["category"], "Accounts");
        assert_eq!(live["products"], "Portal, App");
        assert_eq!(live["source_record_id"], page.to_string());
        assert_eq!(live["text"], "## Steps");
        assert_eq!(
            item_body(page, &row("draft", "article")),
            json!({"lifecycle": "draft"})
        );
        assert_eq!(
            item_body(page, &row("published", "page")),
            json!({"lifecycle": "draft"})
        );
    }

    #[test]
    fn knowledge_article_products_are_trimmed_and_named_once() {
        let products = clean_products(&[" Portal ".into(), "portal".into(), "App".into()]);
        assert_eq!(products.unwrap_or_default(), vec!["Portal", "App"]);
        assert!(clean_products(&[" ".into()]).is_err());
        let many: Vec<String> = (0..=MAX_PRODUCTS).map(|i| format!("p{i}")).collect();
        assert!(clean_products(&many).is_err());
    }
}
