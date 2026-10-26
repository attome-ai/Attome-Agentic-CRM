//! Search administration (roadmap A25-T9): what an administrator tunes about
//! search, through the API.
//!
//! - `GET`/`PUT /api/v1/admin/search/entities/{entity}`: whether an entity is
//!   searched, how far back, its boost and embedding switches, and each
//!   attribute's mode (`key`, `text`, `off`) and weight. The `PUT` takes
//!   `If-Match: "<row_version>"` (`"0"` for an entity never set).
//! - `/api/v1/admin/search/synonyms`, `/stopwords`, `/pins`: list, add and
//!   remove (A25-T3 applies them).
//! - `GET /api/v1/admin/search/size` (index rows per entity and bytes);
//!   `/status` (A25-T5, `routes.rs`) and `/quality` (A25-T8) sit beside it.
//!
//! Every change writes a Configuration security event in its own
//! transaction and drops this node's ranking-controls snapshot; other nodes
//! pick it up within [`crate::controls::CONTROLS_TTL_SECS`].

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// Most terms in one synonym group.
pub const MAX_TERMS: usize = 20;
/// Longest term, stop word or pinned query.
pub const MAX_TERM_CHARS: usize = 100;
/// The deepest pin position.
pub const MAX_PIN_POSITION: i32 = 50;
const MODES: [&str; 3] = ["key", "text", "off"];
const LANGS: [&str; 2] = ["en", "ar"];

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?
        .to_str()
        .map_err(|_| AppError::Validation("If-Match must be ASCII".into()))?;
    raw.trim()
        .trim_matches('"')
        .parse()
        .map_err(|_| AppError::Validation("If-Match must be a row_version".into()))
}

fn event(actor: Uuid, operation: AuditOperation, name: &str, comment: String) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "search_settings",
        None,
    )
    .named(name)
    .comment(comment)
}

fn require_entity(state: &EngineState, entity: &str) -> Result<(), AppError> {
    if state.entities.load().get(entity).is_some() {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// One cleaned term: trimmed, 1 to [`MAX_TERM_CHARS`] characters, no
/// control characters. Pure.
pub fn clean_term(term: &str) -> Result<String, AppError> {
    let t = term.trim();
    if t.is_empty() || t.chars().count() > MAX_TERM_CHARS || t.chars().any(char::is_control) {
        return Err(AppError::Validation(format!(
            "a term is 1 to {MAX_TERM_CHARS} characters with no control characters"
        )));
    }
    Ok(t.to_owned())
}

// ── Entity settings ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SearchAttributeSetting {
    pub attribute: String,
    /// `key`, `text` or `off`.
    pub mode: String,
    /// 0 to 10.
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SearchEntitySettings {
    pub entity: String,
    pub enabled: bool,
    pub max_age_days: Option<i32>,
    pub image_embedding: bool,
    pub document_embedding: bool,
    pub boost: f32,
    pub attributes: Vec<SearchAttributeSetting>,
    /// 0 while the entity has never been set.
    pub row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchEntitySettingsBody {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub max_age_days: Option<i32>,
    #[serde(default)]
    pub image_embedding: bool,
    #[serde(default)]
    pub document_embedding: bool,
    #[serde(default = "one")]
    pub boost: f32,
    /// Replaces every attribute setting of the entity.
    #[serde(default)]
    pub attributes: Vec<SearchAttributeSetting>,
}

fn yes() -> bool {
    true
}

fn one() -> f32 {
    1.0
}

/// Checks a body against the entity's attributes. Pure.
pub fn check_settings(
    body: &SearchEntitySettingsBody,
    attributes: &[String],
) -> Result<(), AppError> {
    if !(0.0..=10.0).contains(&body.boost) {
        return Err(AppError::Validation("boost is 0 to 10".into()));
    }
    if body.max_age_days.is_some_and(|d| d < 1) {
        return Err(AppError::Validation("max_age_days is at least 1".into()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for a in &body.attributes {
        if !attributes.contains(&a.attribute) {
            return Err(AppError::Validation(format!(
                "{} is not an attribute of this entity",
                a.attribute
            )));
        }
        if !seen.insert(a.attribute.as_str()) {
            return Err(AppError::Validation(format!(
                "{} is listed twice",
                a.attribute
            )));
        }
        if !MODES.contains(&a.mode.as_str()) {
            return Err(AppError::Validation("mode is key, text or off".into()));
        }
        if !(0.0..=10.0).contains(&a.weight) {
            return Err(AppError::Validation("weight is 0 to 10".into()));
        }
    }
    Ok(())
}

async fn read_settings(
    conn: &mut sqlx::PgConnection,
    entity: &str,
) -> Result<SearchEntitySettings, AppError> {
    let row: Option<(bool, Option<i32>, bool, bool, f32, i64)> = sqlx::query_as(
        "SELECT enabled, max_age_days, image_embedding, document_embedding, boost, row_version \
           FROM search_entity_setting WHERE entity_logicalname = $1",
    )
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let attributes: Vec<(String, String, f32)> = sqlx::query_as(
        "SELECT attribute_logicalname, mode, weight FROM search_attribute_setting \
          WHERE entity_logicalname = $1 ORDER BY attribute_logicalname",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let (enabled, max_age_days, image_embedding, document_embedding, boost, row_version) =
        row.unwrap_or((true, None, false, false, 1.0, 0));
    Ok(SearchEntitySettings {
        entity: entity.to_owned(),
        enabled,
        max_age_days,
        image_embedding,
        document_embedding,
        boost,
        attributes: attributes
            .into_iter()
            .map(|(attribute, mode, weight)| SearchAttributeSetting {
                attribute,
                mode,
                weight,
            })
            .collect(),
        row_version,
    })
}

/// An entity's search settings
///
/// A25-T9: whether an entity is searched, how far back, its boost and
/// embedding switches, and each attribute's mode and weight. Defaults (and
/// `row_version` 0) for an entity never set.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/entities/{entity}",
    tag = "search",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "The settings", body = SearchEntitySettings),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_entity_settings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity): Path<String>,
) -> Result<Json<SearchEntitySettings>, AppError> {
    require_entity(&state, &entity)?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(Json(read_settings(&mut conn, &entity).await?))
}

/// Set an entity's search settings
///
/// A25-T9: replaces an entity's search settings and attribute modes.
/// `If-Match: "<row_version>"` is required (`"0"` the first time).
#[utoipa::path(
    put,
    path = "/api/v1/admin/search/entities/{entity}",
    tag = "search",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("If-Match" = String, Header, description = "The settings' row_version, quoted; \"0\" the first time"),
    ),
    request_body = SearchEntitySettingsBody,
    responses(
        (status = 200, description = "The settings now", body = SearchEntitySettings),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Missing If-Match, an unknown attribute or a value out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn put_entity_settings(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SearchEntitySettingsBody>,
) -> Result<Json<SearchEntitySettings>, AppError> {
    let expected = if_match(&headers)?;
    let attributes: Vec<String> = state
        .entities
        .load()
        .get(&entity)
        .map(|m| m.attrs.iter().map(|a| a.logicalname.clone()).collect())
        .ok_or(AppError::NotFound)?;
    check_settings(&body, &attributes)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let written = if expected == 0 {
        sqlx::query(
            "INSERT INTO search_entity_setting \
                (entity_logicalname, enabled, max_age_days, image_embedding, document_embedding, \
                 boost, row_version) \
             VALUES ($1, $2, $3, $4, $5, $6, 1) ON CONFLICT (entity_logicalname) DO NOTHING",
        )
        .bind(&entity)
        .bind(body.enabled)
        .bind(body.max_age_days)
        .bind(body.image_embedding)
        .bind(body.document_embedding)
        .bind(body.boost)
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query(
            "UPDATE search_entity_setting SET enabled = $2, max_age_days = $3, \
                    image_embedding = $4, document_embedding = $5, boost = $6, \
                    row_version = row_version + 1 \
              WHERE entity_logicalname = $1 AND row_version = $7",
        )
        .bind(&entity)
        .bind(body.enabled)
        .bind(body.max_age_days)
        .bind(body.image_embedding)
        .bind(body.document_embedding)
        .bind(body.boost)
        .bind(expected)
        .execute(&mut *tx)
        .await
    }
    .map_err(AppError::internal)?
    .rows_affected();
    if written == 0 {
        return Err(AppError::VersionConflict);
    }
    sqlx::query("DELETE FROM search_attribute_setting WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for a in &body.attributes {
        sqlx::query(
            "INSERT INTO search_attribute_setting \
                (entity_logicalname, attribute_logicalname, mode, weight) VALUES ($1, $2, $3, $4)",
        )
        .bind(&entity)
        .bind(&a.attribute)
        .bind(&a.mode)
        .bind(a.weight)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            ctx.user_id,
            AuditOperation::Update,
            "search.entity_settings",
            format!("search settings of {entity} changed"),
        ),
    )
    .await?;
    let settings = read_settings(&mut tx, &entity).await?;
    attome_db::tx::commit(tx).await?;
    crate::controls::invalidate();
    Ok(Json(settings))
}

// ── Synonyms ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, sqlx::FromRow)]
pub struct SearchSynonym {
    pub id: Uuid,
    pub terms: Vec<String>,
    pub lang: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchSynonymBody {
    /// 2 to 20 terms that mean the same.
    pub terms: Vec<String>,
    /// `en`, `ar`, or none for both.
    #[serde(default)]
    pub lang: Option<String>,
}

/// The cleaned, distinct terms of a group. Pure.
pub fn clean_terms(terms: &[String]) -> Result<Vec<String>, AppError> {
    let mut out: Vec<String> = Vec::with_capacity(terms.len());
    for term in terms {
        let t = clean_term(term)?;
        if !out.iter().any(|o| o.to_lowercase() == t.to_lowercase()) {
            out.push(t);
        }
    }
    if out.len() < 2 || out.len() > MAX_TERMS {
        return Err(AppError::Validation(format!(
            "a synonym group has 2 to {MAX_TERMS} different terms"
        )));
    }
    Ok(out)
}

fn check_lang(lang: Option<&str>) -> Result<(), AppError> {
    match lang {
        Some(l) if !LANGS.contains(&l) => Err(AppError::Validation("lang is en or ar".into())),
        _ => Ok(()),
    }
}

/// Synonym groups
///
/// A25-T9: the synonym groups, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/synonyms",
    tag = "search",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of synonym groups", body = PaginatedResponse<SearchSynonym>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_synonyms(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SearchSynonym>>, AppError> {
    let window = page.window();
    let rows: Vec<SearchSynonym> = sqlx::query_as(
        "SELECT id, terms, lang FROM search_synonym ORDER BY id DESC LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM search_synonym")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a synonym group
///
/// A25-T9: a group of terms that mean the same; a search for one also runs
/// with the others.
#[utoipa::path(
    post,
    path = "/api/v1/admin/search/synonyms",
    tag = "search",
    request_body = SearchSynonymBody,
    responses(
        (status = 201, description = "The group", body = SearchSynonym),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Fewer than two terms, too many, or an unknown lang", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_synonym(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SearchSynonymBody>,
) -> Result<(StatusCode, Json<SearchSynonym>), AppError> {
    let terms = clean_terms(&body.terms)?;
    check_lang(body.lang.as_deref())?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: SearchSynonym = sqlx::query_as(
        "INSERT INTO search_synonym (terms, lang, created_by) VALUES ($1, $2, $3) \
         RETURNING id, terms, lang",
    )
    .bind(&terms)
    .bind(&body.lang)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            ctx.user_id,
            AuditOperation::Create,
            "search.synonym_added",
            format!("synonym group {} added", row.id),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::controls::invalidate();
    Ok((StatusCode::CREATED, Json(row)))
}

/// Remove a synonym group
///
/// A25-T9: removes one synonym group.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/search/synonyms/{id}",
    tag = "search",
    params(("id" = Uuid, Path, description = "The synonym group")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such group", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
)]
async fn delete_synonym(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    remove(
        &state,
        ctx.user_id,
        sqlx::query("DELETE FROM search_synonym WHERE id = $1").bind(id),
        "search.synonym_removed",
        format!("synonym group {id} removed"),
    )
    .await
}

/// Deletes the row `query` names with its audit event; 404 when none.
async fn remove(
    state: &EngineState,
    actor: Uuid,
    query: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
    name: &str,
    comment: String,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed = query
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        event(actor, AuditOperation::Delete, name, comment),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::controls::invalidate();
    Ok(StatusCode::NO_CONTENT)
}

// ── Stop words ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct SearchStopword {
    pub word: String,
    /// `en` or `ar`.
    pub lang: String,
}

/// Stop words
///
/// A25-T9: the words a search drops (unless the whole query is stop words).
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/stopwords",
    tag = "search",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of stop words", body = PaginatedResponse<SearchStopword>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_stopwords(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SearchStopword>>, AppError> {
    let window = page.window();
    let rows: Vec<SearchStopword> = sqlx::query_as(
        "SELECT word, lang FROM search_stopword ORDER BY lang, word LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM search_stopword")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a stop word
///
/// A25-T9: a word a search drops; adding one already there changes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/admin/search/stopwords",
    tag = "search",
    request_body = SearchStopword,
    responses(
        (status = 201, description = "The stop word", body = SearchStopword),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "An empty word or an unknown lang", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_stopword(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SearchStopword>,
) -> Result<(StatusCode, Json<SearchStopword>), AppError> {
    let word = crate::normalize_ar(&clean_term(&body.word)?);
    check_lang(Some(body.lang.as_str()))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO search_stopword (word, lang) VALUES ($1, $2) \
         ON CONFLICT (word) DO UPDATE SET lang = EXCLUDED.lang",
    )
    .bind(&word)
    .bind(&body.lang)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            ctx.user_id,
            AuditOperation::Create,
            "search.stopword_added",
            format!("stop word added ({})", body.lang),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::controls::invalidate();
    Ok((
        StatusCode::CREATED,
        Json(SearchStopword {
            word,
            lang: body.lang,
        }),
    ))
}

/// Remove a stop word
///
/// A25-T9: a removed word takes part in searches again.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/search/stopwords/{word}",
    tag = "search",
    params(("word" = String, Path, description = "The stop word")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such stop word", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
)]
async fn delete_stopword(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(word): Path<String>,
) -> Result<StatusCode, AppError> {
    let word = crate::normalize_ar(word.trim());
    remove(
        &state,
        ctx.user_id,
        sqlx::query("DELETE FROM search_stopword WHERE word = $1").bind(word),
        "search.stopword_removed",
        "stop word removed".to_owned(),
    )
    .await
}

// ── Pins ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, sqlx::FromRow)]
pub struct SearchPin {
    pub id: Uuid,
    /// The normalised query the pin answers.
    pub query_norm: String,
    pub entity_logicalname: String,
    pub record_id: Uuid,
    pub position: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchPinBody {
    /// The query, as people type it; it is normalised.
    pub query: String,
    pub entity: String,
    pub record_id: Uuid,
    /// 1 to 50; 1 when absent.
    #[serde(default)]
    pub position: Option<i32>,
}

/// Pinned results
///
/// A25-T9: records placed at a position for a query. A pin shows only to
/// people who may read its record.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/pins",
    tag = "search",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of pins", body = PaginatedResponse<SearchPin>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_pins(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SearchPin>>, AppError> {
    let window = page.window();
    let rows: Vec<SearchPin> = sqlx::query_as(
        "SELECT id, query_norm, entity_logicalname, record_id, position FROM search_pin \
          ORDER BY query_norm, position, id LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM search_pin")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// Pin a result
///
/// A25-T9: places a record at a position for a query. Pinning the same
/// record for the same query again moves it.
#[utoipa::path(
    post,
    path = "/api/v1/admin/search/pins",
    tag = "search",
    request_body = SearchPinBody,
    responses(
        (status = 201, description = "The pin", body = SearchPin),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "An empty query or a position out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_pin(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SearchPinBody>,
) -> Result<(StatusCode, Json<SearchPin>), AppError> {
    let query_norm = crate::normalize_ar(&clean_term(&body.query)?);
    require_entity(&state, &body.entity)?;
    let position = body.position.unwrap_or(1);
    if !(1..=MAX_PIN_POSITION).contains(&position) {
        return Err(AppError::Validation(format!(
            "position is 1 to {MAX_PIN_POSITION}"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let pin: SearchPin = sqlx::query_as(
        "INSERT INTO search_pin (query_norm, entity_logicalname, record_id, position) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (query_norm, entity_logicalname, record_id) \
           DO UPDATE SET position = EXCLUDED.position \
         RETURNING id, query_norm, entity_logicalname, record_id, position",
    )
    .bind(&query_norm)
    .bind(&body.entity)
    .bind(body.record_id)
    .bind(position)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            ctx.user_id,
            AuditOperation::Create,
            "search.pin_added",
            format!("{}:{} pinned at {position}", body.entity, body.record_id),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::controls::invalidate();
    Ok((StatusCode::CREATED, Json(pin)))
}

/// Remove a pin
///
/// A25-T9: removes one pinned result.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/search/pins/{id}",
    tag = "search",
    params(("id" = Uuid, Path, description = "The pin")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such pin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
)]
async fn delete_pin(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    remove(
        &state,
        ctx.user_id,
        sqlx::query("DELETE FROM search_pin WHERE id = $1").bind(id),
        "search.pin_removed",
        format!("pin {id} removed"),
    )
    .await
}

// ── Size ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SearchEntitySize {
    pub entity: String,
    pub rows: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SearchIndexSize {
    pub rows: i64,
    /// The index table with its indexes, in bytes.
    pub bytes: i64,
    pub entities: Vec<SearchEntitySize>,
}

/// Search index size
///
/// A25-T9: the index's rows per entity and its size on disk.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/size",
    tag = "search",
    responses(
        (status = 200, description = "The index size", body = SearchIndexSize),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_size(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<SearchIndexSize>, AppError> {
    let db = &state.base.db;
    let entities: Vec<(String, i64)> = sqlx::query_as(
        "SELECT entity_logicalname, COUNT(*) FROM search_index \
          GROUP BY entity_logicalname ORDER BY 2 DESC, 1",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let bytes: i64 = sqlx::query_scalar("SELECT pg_total_relation_size('search_index')")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(SearchIndexSize {
        rows: entities.iter().map(|(_, n)| n).sum(),
        bytes,
        entities: entities
            .into_iter()
            .map(|(entity, rows)| SearchEntitySize { entity, rows })
            .collect(),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/search/entities/{entity}",
            get(get_entity_settings).put(put_entity_settings),
        )
        .route(
            "/api/v1/admin/search/synonyms",
            get(list_synonyms).post(create_synonym),
        )
        .route("/api/v1/admin/search/synonyms/{id}", delete(delete_synonym))
        .route(
            "/api/v1/admin/search/stopwords",
            get(list_stopwords).post(create_stopword),
        )
        .route(
            "/api/v1/admin/search/stopwords/{word}",
            delete(delete_stopword),
        )
        .route("/api/v1/admin/search/pins", get(list_pins).post(create_pin))
        .route("/api/v1/admin/search/pins/{id}", delete(delete_pin))
        .route("/api/v1/admin/search/size", get(get_size))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_entity_settings,
        put_entity_settings,
        list_synonyms,
        create_synonym,
        delete_synonym,
        list_stopwords,
        create_stopword,
        delete_stopword,
        list_pins,
        create_pin,
        delete_pin,
        get_size
    ),
    components(schemas(
        SearchAttributeSetting,
        SearchEntitySettings,
        SearchEntitySettingsBody,
        SearchSynonym,
        SearchSynonymBody,
        SearchStopword,
        SearchPin,
        SearchPinBody,
        SearchEntitySize,
        SearchIndexSize
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synonym_groups_are_distinct_and_bounded() {
        let t = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            clean_terms(&t(&[" CR ", "cr", "commercial registration"])).unwrap(),
            vec!["CR".to_owned(), "commercial registration".to_owned()]
        );
        assert!(clean_terms(&t(&["only"])).is_err());
        assert!(clean_terms(&t(&["a", ""])).is_err());
        assert!(clean_term(&"x".repeat(MAX_TERM_CHARS + 1)).is_err());
    }

    #[test]
    fn entity_settings_are_checked_against_the_entity() {
        let attrs = vec!["title".to_owned(), "code".to_owned()];
        let body = |a: Vec<SearchAttributeSetting>, boost: f32| SearchEntitySettingsBody {
            enabled: true,
            max_age_days: None,
            image_embedding: false,
            document_embedding: false,
            boost,
            attributes: a,
        };
        let a = |name: &str, mode: &str| SearchAttributeSetting {
            attribute: name.into(),
            mode: mode.into(),
            weight: 1.0,
        };
        assert!(
            check_settings(
                &body(vec![a("title", "text"), a("code", "key")], 2.0),
                &attrs
            )
            .is_ok()
        );
        assert!(check_settings(&body(vec![a("missing", "text")], 1.0), &attrs).is_err());
        assert!(check_settings(&body(vec![a("title", "fuzzy")], 1.0), &attrs).is_err());
        assert!(
            check_settings(
                &body(vec![a("title", "text"), a("title", "off")], 1.0),
                &attrs
            )
            .is_err()
        );
        assert!(check_settings(&body(Vec::new(), 11.0), &attrs).is_err());
    }
}
