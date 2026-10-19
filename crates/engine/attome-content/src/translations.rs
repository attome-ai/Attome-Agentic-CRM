//! K5-T4: linked translations with stale flags.
//!
//! A translation is its own page — its own URL, draft, versions, audience and
//! approval — that names the page it translates (`translation_of`) and the
//! source version it was last brought up to date with
//! (`translated_from_version`). Creating one copies the source's published
//! blocks (its draft when it was never published) into the new page's draft,
//! ready to be translated; one translation per language.
//!
//! **Stale.** A translation is stale while its source has a published version
//! newer than the one it was brought up to date with. It is worked out when
//! read, from the source's version history (K5-T1), so every publish path —
//! direct, approved, scheduled, restored — marks translations stale with no
//! write of its own. Marking a translation current (`.../translation/current`)
//! records the source's latest version against it.
//!
//! **Drafting (N20).** The translation's text is drafted through the
//! `text.translate` action (`POST /api/v1/actions/text.translate/invoke`),
//! which keeps the deployment's glossary and passes the AI gate and budget;
//! the editor saves the drafted blocks through the ordinary page update.
//! This crate does not call the model itself.

use attome_core::EngineState;
use attome_db::is_unique_violation;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::model::validate_url_path;

/// `POST .../translations`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTranslationBody {
    /// The translation's language code, e.g. `ar` or `en-GB`.
    pub language: String,
    pub title: String,
    /// The translation's own URL path.
    pub url_path: String,
}

/// One translation of a page.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct TranslationSummary {
    pub id: Uuid,
    pub language: Option<String>,
    pub title: String,
    pub url_path: String,
    pub status: String,
    /// The source version this translation was last brought up to date with.
    pub translated_from_version: Option<i32>,
    /// The source has a newer published version than that.
    #[sqlx(skip)]
    pub stale: bool,
}

/// A page and its translations.
#[derive(Debug, Serialize, ToSchema)]
pub struct TranslationSet {
    pub source_id: Uuid,
    /// The source's latest published version; none when never published.
    pub source_version: Option<i32>,
    pub translations: Vec<TranslationSummary>,
}

/// A language code: 2 to 8 letters, optionally with region parts
/// (`ar`, `en-GB`). Pure.
pub fn valid_language(code: &str) -> bool {
    let mut parts = code.split('-');
    let primary = parts.next().unwrap_or_default();
    (2..=8).contains(&primary.len())
        && primary.chars().all(|c| c.is_ascii_alphabetic())
        && parts.all(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Whether a translation brought up to date with `translated_from` is behind
/// a source whose latest published version is `source_latest`. Pure.
pub fn is_stale(source_latest: Option<i32>, translated_from: Option<i32>) -> bool {
    match (source_latest, translated_from) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(latest), Some(from)) => from < latest,
    }
}

async fn latest_version(db: &attome_db::DbPool, page_id: Uuid) -> Result<Option<i32>, AppError> {
    sqlx::query_scalar("SELECT max(version_number) FROM content_page_version WHERE page_id = $1")
        .bind(page_id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Creates a linked translation of a page (K5-T4).
///
/// The new page sits beside its source (same space and parent) with the
/// source's published blocks as its draft, ready to translate; it starts up to
/// date with the source's latest version. A translation cannot itself be
/// translated: translate its source.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/translations",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The source page's id")),
    request_body = CreateTranslationBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The translation was created", body = TranslationSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 409, description = "The url_path is taken, or the page already has a translation into this language", body = ErrorResponse),
        (status = 422, description = "Bad language, title or url_path, or the page is itself a translation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_translation(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(source_id): Path<Uuid>,
    Json(body): Json<CreateTranslationBody>,
) -> Result<(StatusCode, Json<TranslationSummary>), AppError> {
    let language = body.language.trim();
    if !valid_language(language) {
        return Err(AppError::Validation(
            "language is a language code such as ar or en-GB".into(),
        ));
    }
    let title = body.title.trim();
    if title.is_empty() {
        return Err(AppError::Validation("title must not be empty".into()));
    }
    validate_url_path(&body.url_path).map_err(AppError::Validation)?;

    let source: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT translation_of, language FROM content_page WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(source_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (translation_of, source_language) = source.ok_or(AppError::NotFound)?;
    if translation_of.is_some() {
        return Err(AppError::Validation(
            "this page is a translation; translate its source page instead".into(),
        ));
    }
    if source_language.as_deref() == Some(language) {
        return Err(AppError::Validation(
            "the source page is already in this language".into(),
        ));
    }
    let source_version = latest_version(&state.base.db, source_id).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut row: TranslationSummary = sqlx::query_as(
        "INSERT INTO content_page \
            (parent_page_id, content_space_id, title, url_path, template_id, blocks_draft, \
             created_by, updated_by, audience, language, translation_of, translated_from_version) \
         SELECT s.parent_page_id, s.content_space_id, $2, $3, s.template_id, \
                COALESCE(s.blocks_published, s.blocks_draft), $4, $4, s.audience, $5, s.id, $6 \
           FROM content_page s WHERE s.id = $1 AND s.is_deleted = FALSE \
         RETURNING id, language, title, url_path, status, translated_from_version",
    )
    .bind(source_id)
    .bind(title)
    .bind(&body.url_path)
    .bind(ctx.user_id)
    .bind(language)
    .bind(source_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            AppError::Conflict(
                "the url_path is taken, or the page already has a translation into this language",
            )
        } else {
            AppError::internal(e)
        }
    })?
    .ok_or(AppError::NotFound)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "content_page",
            Some(row.id),
        )
        .named("content_page.translation_create")
        .comment(format!("{language} translation of {source_id}")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    row.stale = is_stale(source_version, row.translated_from_version);
    Ok((StatusCode::CREATED, Json(row)))
}

/// A page's translations and whether each is stale (K5-T4).
///
/// Asked of a source page or of any of its translations, it answers the
/// source and every translation of it.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/translations",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "A source page's id, or a translation's")),
    responses(
        (status = 200, description = "The source and its translations", body = TranslationSet),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_translations(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<TranslationSet>, AppError> {
    let source_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT COALESCE(translation_of, id) FROM content_page WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let source_id = source_id.ok_or(AppError::NotFound)?;
    let source_version = latest_version(&state.base.db, source_id).await?;
    let mut translations: Vec<TranslationSummary> = sqlx::query_as(
        "SELECT id, language, title, url_path, status, translated_from_version \
           FROM content_page \
          WHERE translation_of = $1 AND is_deleted = FALSE \
          ORDER BY language, id",
    )
    .bind(source_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for t in &mut translations {
        t.stale = is_stale(source_version, t.translated_from_version);
    }
    Ok(Json(TranslationSet {
        source_id,
        source_version,
        translations,
    }))
}

/// Marks a translation up to date with its source (K5-T4).
///
/// Records the source's latest published version against the translation,
/// so it is no longer stale until the source is published again. Asked of a
/// page that is not a translation, it answers 404.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/translation/current",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The translation's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The translation is up to date", body = TranslationSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "No such translation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn mark_current(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<TranslationSummary>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<TranslationSummary> = sqlx::query_as(
        "UPDATE content_page p \
            SET translated_from_version = (SELECT max(v.version_number) \
                                             FROM content_page_version v \
                                            WHERE v.page_id = p.translation_of), \
                row_version = row_version + 1, updated_at = NOW(), updated_by = $2 \
          WHERE p.id = $1 AND p.is_deleted = FALSE AND p.translation_of IS NOT NULL \
          RETURNING id, language, title, url_path, status, translated_from_version",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
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
        .named("content_page.translation_current")
        .comment(format!(
            "up to date with source version {}",
            row.translated_from_version
                .map_or_else(|| "none".to_owned(), |v| v.to_string())
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(row))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/pages/{id}/translations",
            get(list_translations).post(create_translation),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/translation/current",
            post(mark_current),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(create_translation, list_translations, mark_current))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_translations_are_stale_while_the_source_is_newer() {
        assert!(!is_stale(None, None));
        assert!(is_stale(Some(1), None));
        assert!(is_stale(Some(3), Some(2)));
        assert!(!is_stale(Some(3), Some(3)));
    }

    #[test]
    fn page_translations_take_language_codes() {
        for ok in ["ar", "en", "en-GB", "zh-Hant-TW"] {
            assert!(valid_language(ok), "{ok}");
        }
        for bad in ["", "a", "e1", "en_GB", "en-", "arabic-language-x"] {
            assert!(!valid_language(bad), "{bad}");
        }
    }
}
