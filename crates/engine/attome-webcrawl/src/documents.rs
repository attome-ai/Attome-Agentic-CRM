//! K6-T6: documents a crawled page links to (PDF, Word, Excel) become
//! knowledge items like pages do.
//!
//! The walk records an in-scope link to a document as a page of status
//! `document` without fetching it ([`is_document_path`], or
//! [`is_document_type`] for an address that answers with a document). After
//! a completed crawl, [`queue_documents`] queues one `CrawlDocument` job per
//! document page, so a slow or large file never holds up the walk. The job
//! ([`fetch_document`]) fetches the file through the same SSRF-safe client
//! and source access as the pages, conditionally on its last ETag and at
//! most [`MAX_DOCUMENT_BYTES`] (and the deployment's upload limit), and hands
//! it to the file pipeline as the `file` of an `attome_document` on the
//! source's Data Source (`attome_document::files::ingest`, as call
//! recordings are): the virus scan (K2) runs on it, and a clean file has its
//! text extracted (`document_text`, K1-T4).
//!
//! [`absorb_documents`] (run before every import and post-crawl sync) takes
//! each document page whose upload is clean and whose text is extracted,
//! attaches the file to its document record, and makes the text the page's
//! content; from there it is imported, versioned, aliased and retired
//! exactly as a page is (`crate::import`). A file the scan rejects is never
//! attached and gives no text.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use reqwest::Url;
use serde_json::json;
use uuid::Uuid;

use crate::safety;

/// The largest document fetched.
pub const MAX_DOCUMENT_BYTES: usize = 20 * 1024 * 1024;
/// Document pages one crawl queues.
pub const MAX_QUEUED: i64 = 200;
/// Document pages one absorb takes.
const MAX_ABSORBED: i64 = 500;

/// File extensions that make a link a document.
pub const DOCUMENT_EXTENSIONS: [&str; 4] = ["pdf", "docx", "doc", "xlsx"];

/// Content types that make an answer a document.
const DOCUMENT_TYPES: [&str; 4] = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
];

/// Whether a path names a document by its extension. Pure.
pub fn is_document_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    last.rsplit_once('.').is_some_and(|(name, ext)| {
        !name.is_empty() && DOCUMENT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
    })
}

/// Whether a content type is a document's. Pure.
pub fn is_document_type(content_type: &str) -> bool {
    let base = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    DOCUMENT_TYPES.contains(&base.as_str())
}

/// The file name a document is stored under: the path's last part, or
/// `document` when it has none. Pure.
pub fn file_name(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default().trim();
    if last.is_empty() {
        "document".to_owned()
    } else {
        last.chars().take(200).collect()
    }
}

/// After a completed crawl: one `CrawlDocument` job per document page of the
/// source (at most [`MAX_QUEUED`]). Answers how many it queued.
pub async fn queue_documents(state: &EngineState, target_id: Uuid) -> Result<u64, AppError> {
    let pages: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM webcrawl_page \
          WHERE target_ref = $1 AND status = 'document' AND is_deleted = FALSE \
          ORDER BY document_fetched_at NULLS FIRST, id LIMIT $2",
    )
    .bind(target_id)
    .bind(MAX_QUEUED)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if pages.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for page_id in &pages {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::CrawlDocument { page_id: *page_id },
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(pages.len() as u64)
}

type DocumentRow = (
    Uuid,
    String,
    Option<String>,
    Option<Uuid>,
    String,
    String,
    Option<String>,
    bool,
    Uuid,
);

/// The `CrawlDocument` job: fetches one document page's file and hands it
/// to the file pipeline (scan, then text). A file unchanged since its last
/// fetch is left as it is. A fetch failure is logged on the page and does
/// not fail the job: the next crawl queues the page again.
pub async fn fetch_document(state: &EngineState, page_id: Uuid) -> Result<(), AppError> {
    let row: Option<DocumentRow> = sqlx::query_as(
        "SELECT p.target_ref, p.url_path, p.document_etag, p.document_ref, \
                t.url, t.allow_host, t.credential_ref, t.watch_only, t.created_by \
           FROM webcrawl_page p JOIN webcrawl_target t ON t.id = p.target_ref \
          WHERE p.id = $1 AND p.status = 'document' AND p.is_deleted = FALSE \
            AND t.is_deleted = FALSE",
    )
    .bind(page_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((
        target_id,
        url_path,
        etag,
        document_ref,
        root,
        allow_host,
        credential_ref,
        watch_only,
        creator,
    )) = row
    else {
        return Ok(());
    };
    if watch_only {
        return Ok(());
    }
    let Ok(root) = Url::parse(&root) else {
        return Ok(());
    };
    let Ok(url) = root.join(&url_path) else {
        return Ok(());
    };
    let access =
        crate::crawl::source_access(state, &root, &allow_host, credential_ref.as_deref()).await?;
    let cfg = state.base.config.webcrawl.clone();
    let client =
        safety::build_client_for(cfg.request_timeout_secs, &access).map_err(AppError::internal)?;
    let max = MAX_DOCUMENT_BYTES.min(
        usize::try_from(state.base.config.storage.max_upload_size_bytes).unwrap_or(usize::MAX),
    );
    let fetched = match safety::fetch_bytes(
        &client,
        &url,
        max,
        &crate::crawl::user_agent(),
        etag.as_deref(),
        None,
        &access,
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(e) => {
            tracing::info!(%page_id, error = %e, "webcrawl: a linked document was not fetched");
            mark_fetched(state, page_id, etag.as_deref(), None, None).await?;
            return Ok(());
        }
    };
    if fetched.not_modified {
        return mark_fetched(state, page_id, etag.as_deref(), None, None).await;
    }

    let ctx = state.base.security.resolve(creator).await?;
    ctx.require("attome_document", "create")?;
    let data_source = crate::import::ensure_data_source_for_target(state, &ctx, target_id).await?;
    let name = file_name(&url_path);
    let document = match document_ref {
        Some(document) => document,
        None => {
            let (document, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                ctx.user_id,
                "attome_document",
                json!({
                    "name": name,
                    "entity_name": "knowledge_data_source",
                    "record_id": data_source.to_string(),
                    "folder": "Web crawl",
                }),
            )
            .await?;
            document
        }
    };
    let content_type = fetched
        .content_type
        .split(';')
        .next()
        .unwrap_or("application/octet-stream")
        .trim()
        .to_owned();
    let session = attome_document::files::ingest(
        state,
        attome_document::files::FileOwner::Staff(ctx.user_id),
        "attome_document",
        document,
        "file",
        &name,
        &content_type,
        fetched.body,
    )
    .await?;
    mark_fetched(
        state,
        page_id,
        fetched.etag.as_deref(),
        Some(document),
        Some(session),
    )
    .await
}

async fn mark_fetched(
    state: &EngineState,
    page_id: Uuid,
    etag: Option<&str>,
    document: Option<Uuid>,
    session: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webcrawl_page \
            SET document_etag = $2, document_fetched_at = NOW(), \
                document_ref = COALESCE($3, document_ref), \
                document_session_id = COALESCE($4, document_session_id), \
                updated_at = NOW() \
          WHERE id = $1",
    )
    .bind(page_id)
    .bind(etag)
    .bind(document)
    .bind(session)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

type ReadyRow = (Uuid, Uuid, String, String, Option<String>);

/// Takes every document page of the source whose file is clean and whose
/// text is extracted: attaches the file to its document record (once) and
/// makes the text the page's content, so the import treats it as a page.
/// Acts as `ctx`. Answers how many pages took new text.
pub async fn absorb_documents(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    target_id: Uuid,
) -> Result<u64, AppError> {
    let ready: Vec<ReadyRow> = sqlx::query_as(
        "SELECT p.id, p.document_ref, s.final_key, x.content_text, p.content_hash \
           FROM webcrawl_page p \
           JOIN upload_session s ON s.id = p.document_session_id \
           JOIN document_text x ON x.file_key = s.final_key \
          WHERE p.target_ref = $1 AND p.status = 'document' AND p.is_deleted = FALSE \
            AND p.document_ref IS NOT NULL AND s.status = 'clean' \
          ORDER BY p.id LIMIT $2",
    )
    .bind(target_id)
    .bind(MAX_ABSORBED)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut absorbed = 0;
    for (page_id, document, final_key, text, old_hash) in ready {
        let hash = crate::crawl::text_hash(&text);
        if old_hash.as_deref() == Some(hash.as_str()) {
            continue;
        }
        attach(state, ctx, document, &final_key).await?;
        sqlx::query(
            "UPDATE webcrawl_page SET content = $2, content_hash = $3, \
                    size_bytes = $4, row_version = row_version + 1, updated_at = NOW() \
              WHERE id = $1",
        )
        .bind(page_id)
        .bind(&text)
        .bind(&hash)
        .bind(i32::try_from(text.len()).unwrap_or(i32::MAX))
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        absorbed += 1;
    }
    Ok(absorbed)
}

/// Sets the document record's `file` to the clean file, unless it holds it.
async fn attach(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    document: Uuid,
    final_key: &str,
) -> Result<(), AppError> {
    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT row_version, file::text FROM attome_document \
          WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(document)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((version, file)) = row else {
        return Ok(());
    };
    if file.as_deref() == Some(final_key) {
        return Ok(());
    }
    match attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "attome_document",
        document,
        version,
        json!({ "file": final_key }),
    )
    .await
    {
        Ok(_) | Err(AppError::Conflict(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_are_known_by_extension_and_type() {
        assert!(is_document_path("/files/Price-List.PDF"));
        assert!(is_document_path("/a/terms.docx?v=2"));
        assert!(is_document_path("/a/report.xlsx"));
        assert!(!is_document_path("/a/page.html"));
        assert!(!is_document_path("/a/.pdf"));
        assert!(!is_document_path("/pdf"));
        assert!(is_document_type("application/pdf"));
        assert!(is_document_type("application/msword; charset=binary"));
        assert!(!is_document_type("text/html; charset=utf-8"));
    }

    #[test]
    fn a_document_is_stored_under_its_last_path_part() {
        assert_eq!(file_name("/files/terms.pdf?x=1"), "terms.pdf");
        assert_eq!(file_name("/"), "document");
    }
}
