//! Tags on any record (roadmap B4-T1, B4-T2, B4-T4).
//!
//! A tag is **shared** (whoever can read the record sees it; adding or
//! removing it needs update access to the record) or **personal** (only its
//! owner sees it; reading the record is enough). A shared tag may belong to a
//! group whose policy says who may create tags in it: anyone, holders of one
//! privilege, or nobody (the group's tags are fixed). Names match through the
//! SQL `normalize_ar`, so `محمد` and `مُحَمَّد`, or `VIP` and `vip`, are one tag,
//! and suggestions rank by how often a tag is used.
//!
//! Every list resolves records through [`super::resolve_visible`]: a record
//! the caller may not read is never shown, on the tag page or anywhere else.

use std::collections::HashMap;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_security::record_action::Read;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Admin, Authorized, RecordScoped, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::access::{require_record_access_any_active_state, require_record_read};
use super::resolve::resolve_entity;

/// Tags one record may carry.
pub const MAX_TAGS_PER_RECORD: i64 = 50;
/// Suggestions returned at once.
const SUGGEST_LIMIT: i64 = 10;
/// Records a tag page returns.
const TAG_PAGE_LIMIT: i64 = 200;

// ── Wire types ──────────────────────────────────────────────────────────────

/// One tag as the caller sees it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct TagView {
    pub id: Uuid,
    pub name: String,
    pub colour: Option<String>,
    pub group_id: Option<Uuid>,
    /// Only the caller sees it.
    pub personal: bool,
}

/// `POST /api/v1/{entity}/{id}/tags`: an existing tag, or a name to find or
/// create.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddTag {
    pub tag_id: Option<Uuid>,
    pub name: Option<String>,
    /// A new personal tag (only with `name`).
    #[serde(default)]
    pub personal: bool,
    /// The group a new shared tag joins (only with `name`).
    pub group_id: Option<Uuid>,
    pub colour: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SuggestQuery {
    /// What the person has typed; matched from the start of the name,
    /// ignoring case, Arabic diacritics and letter forms.
    pub q: String,
}

/// A suggestion: the tag and how many records carry it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct TagSuggestion {
    pub id: Uuid,
    pub name: String,
    pub colour: Option<String>,
    pub personal: bool,
    pub uses: i64,
}

/// One record carrying a tag, as the caller may see it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TaggedRecord {
    pub entity: String,
    pub record_id: Uuid,
    pub label: Option<String>,
}

/// `POST /api/v1/admin/tag-groups`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TagGroupInput {
    pub name: String,
    pub colour: Option<String>,
    /// `anyone`, `privilege` or `nobody`.
    #[serde(default = "anyone")]
    pub create_policy: String,
    /// The privilege key `privilege` needs.
    pub create_privilege: Option<String>,
}

fn anyone() -> String {
    "anyone".to_owned()
}

#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct TagGroup {
    pub id: Uuid,
    pub name: String,
    pub colour: Option<String>,
    pub create_policy: String,
    pub create_privilege: Option<String>,
}

// ── Checks ──────────────────────────────────────────────────────────────────

fn check_colour(colour: Option<&str>) -> Result<(), AppError> {
    match colour {
        Some(c)
            if !(c.len() == 7
                && c.starts_with('#')
                && c[1..].chars().all(|h| h.is_ascii_hexdigit())) =>
        {
            Err(AppError::Validation("colour must be #rrggbb".into()))
        }
        _ => Ok(()),
    }
}

fn check_name(name: &str, max: usize) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > max {
        return Err(AppError::Validation(format!(
            "name must be 1 to {max} characters"
        )));
    }
    Ok(name.to_owned())
}

/// Whether `ctx` may create a tag in a group with this policy.
fn may_create(ctx: &SecurityContext, policy: &str, privilege: Option<&str>) -> bool {
    match policy {
        "anyone" => true,
        "privilege" => ctx.is_admin || privilege.is_some_and(|p| ctx.privileges.contains(p)),
        _ => false,
    }
}

const TAG_COLUMNS: &str =
    "t.id, t.name, t.colour, t.group_id, (t.owner_user IS NOT NULL) AS personal";

// ── Engine ──────────────────────────────────────────────────────────────────

/// The tags on one record the caller may see, after checking they may read it.
pub async fn record_tags(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
) -> Result<Vec<TagView>, AppError> {
    let (entity_id, entity, _, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "read")?;
    require_record_read(state, ctx, entity_id, &entity, record_id).await?;
    tags_on(&state.base.db, ctx.user_id, &entity, record_id).await
}

async fn tags_on(
    db: &attome_db::DbPool,
    user_id: Uuid,
    entity: &str,
    record_id: Uuid,
) -> Result<Vec<TagView>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {TAG_COLUMNS} FROM tag_link l JOIN tag t ON t.id = l.tag_id \
         WHERE l.entity = $1 AND l.record_id = $2 \
           AND (l.expires_at IS NULL OR l.expires_at > now()) \
           AND (t.owner_user IS NULL OR t.owner_user = $3) \
         ORDER BY t.owner_user NULLS FIRST, t.name"
    ))
    .bind(entity)
    .bind(record_id)
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// Puts a tag on a record: an existing one by id, or one found or created by
/// name. A shared tag needs update access to the record and, for a new tag,
/// the group's create policy; a personal tag needs read access.
pub async fn add_tag(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    input: &AddTag,
) -> Result<Vec<TagView>, AppError> {
    let (entity_id, entity, _, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "read")?;
    require_record_read(state, ctx, entity_id, &entity, record_id).await?;
    check_colour(input.colour.as_deref())?;

    let db = &state.base.db;
    let tag: TagView = match (input.tag_id, input.name.as_deref()) {
        (Some(id), None) => sqlx::query_as(&format!(
            "SELECT {TAG_COLUMNS} FROM tag t WHERE t.id = $1 AND (t.owner_user IS NULL OR t.owner_user = $2)"
        ))
        .bind(id)
        .bind(ctx.user_id)
        .fetch_optional(db)
        .await
        .map_err(attome_db::classify)?
        .ok_or(AppError::NotFound)?,
        (None, Some(name)) => find_or_create(state, ctx, &check_name(name, 80)?, input).await?,
        _ => {
            return Err(AppError::Validation(
                "give exactly one of tag_id or name".into(),
            ));
        }
    };
    if !tag.personal {
        require_record_access_any_active_state(
            state,
            ctx,
            entity_id,
            &entity,
            record_id,
            RecordAction::Update,
            true,
        )
        .await?;
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tag_link WHERE entity = $1 AND record_id = $2")
            .bind(&entity)
            .bind(record_id)
            .fetch_one(db)
            .await
            .map_err(attome_db::classify)?;
    if count >= MAX_TAGS_PER_RECORD {
        return Err(AppError::Validation(format!(
            "a record carries at most {MAX_TAGS_PER_RECORD} tags"
        )));
    }
    sqlx::query(
        "INSERT INTO tag_link (tag_id, entity, record_id, created_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tag_id, entity, record_id) DO UPDATE SET expires_at = NULL",
    )
    .bind(tag.id)
    .bind(&entity)
    .bind(record_id)
    .bind(ctx.user_id)
    .execute(db)
    .await
    .map_err(attome_db::classify)?;
    if !tag.personal {
        attome_audit::write_business_event(
            state,
            &entity,
            record_id,
            AuditOperation::Update,
            "record.tag_added",
            ctx.user_id,
            None,
            None,
            format!("tag \"{}\" added", tag.name),
        )
        .await;
    }
    tags_on(db, ctx.user_id, &entity, record_id).await
}

async fn find_or_create(
    state: &EngineState,
    ctx: &SecurityContext,
    name: &str,
    input: &AddTag,
) -> Result<TagView, AppError> {
    let db = &state.base.db;
    let existing: Option<TagView> = sqlx::query_as(&format!(
        "SELECT {TAG_COLUMNS} FROM tag t WHERE t.normalized_name = normalize_ar($1) \
           AND (($2 AND t.owner_user = $3) OR (NOT $2 AND t.owner_user IS NULL))"
    ))
    .bind(name)
    .bind(input.personal)
    .bind(ctx.user_id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)?;
    if let Some(tag) = existing {
        return Ok(tag);
    }
    if input.personal && input.group_id.is_some() {
        return Err(AppError::Validation("a personal tag has no group".into()));
    }
    if let Some(group_id) = input.group_id {
        let group: (String, Option<String>) =
            sqlx::query_as("SELECT create_policy, create_privilege FROM tag_group WHERE id = $1")
                .bind(group_id)
                .fetch_optional(db)
                .await
                .map_err(attome_db::classify)?
                .ok_or(AppError::NotFound)?;
        if !may_create(ctx, &group.0, group.1.as_deref()) {
            return Err(AppError::Forbidden);
        }
    }
    sqlx::query_as(&format!(
        "WITH inserted AS ( \
             INSERT INTO tag (group_id, name, colour, owner_user, created_by) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT DO NOTHING RETURNING id, name, colour, group_id, owner_user) \
         SELECT t.id, t.name, t.colour, t.group_id, (t.owner_user IS NOT NULL) AS personal FROM inserted t \
         UNION ALL \
         SELECT {TAG_COLUMNS} FROM tag t WHERE t.normalized_name = normalize_ar($2) \
           AND t.owner_user IS NOT DISTINCT FROM $4 AND NOT EXISTS (SELECT 1 FROM inserted) \
         LIMIT 1"
    ))
    .bind(input.group_id)
    .bind(name)
    .bind(input.colour.as_deref())
    .bind(input.personal.then_some(ctx.user_id))
    .bind(ctx.user_id)
    .fetch_one(db)
    .await
    .map_err(attome_db::classify)
}

/// Takes a tag off a record. A shared tag needs update access to the record.
pub async fn remove_tag(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    tag_id: Uuid,
) -> Result<Vec<TagView>, AppError> {
    let (entity_id, entity, _, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "read")?;
    require_record_read(state, ctx, entity_id, &entity, record_id).await?;
    let db = &state.base.db;
    let tag: TagView = sqlx::query_as(&format!(
        "SELECT {TAG_COLUMNS} FROM tag t WHERE t.id = $1 AND (t.owner_user IS NULL OR t.owner_user = $2)"
    ))
    .bind(tag_id)
    .bind(ctx.user_id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    if !tag.personal {
        require_record_access_any_active_state(
            state,
            ctx,
            entity_id,
            &entity,
            record_id,
            RecordAction::Update,
            true,
        )
        .await?;
    }
    let removed =
        sqlx::query("DELETE FROM tag_link WHERE tag_id = $1 AND entity = $2 AND record_id = $3")
            .bind(tag_id)
            .bind(&entity)
            .bind(record_id)
            .execute(db)
            .await
            .map_err(attome_db::classify)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    if !tag.personal {
        attome_audit::write_business_event(
            state,
            &entity,
            record_id,
            AuditOperation::Update,
            "record.tag_removed",
            ctx.user_id,
            None,
            None,
            format!("tag \"{}\" removed", tag.name),
        )
        .await;
    }
    tags_on(db, ctx.user_id, &entity, record_id).await
}

/// Tags whose name starts with what was typed, most used first.
pub async fn suggest(
    db: &attome_db::DbPool,
    user_id: Uuid,
    typed: &str,
) -> Result<Vec<TagSuggestion>, AppError> {
    let typed = typed.trim();
    if typed.chars().count() > 80 {
        return Err(AppError::Validation("q is at most 80 characters".into()));
    }
    sqlx::query_as(
        "SELECT t.id, t.name, t.colour, (t.owner_user IS NOT NULL) AS personal, \
                (SELECT COUNT(*) FROM tag_link l WHERE l.tag_id = t.id) AS uses \
         FROM tag t \
         WHERE (t.owner_user IS NULL OR t.owner_user = $1) \
           AND starts_with(t.normalized_name, normalize_ar($2)) \
         ORDER BY uses DESC, t.name LIMIT $3",
    )
    .bind(user_id)
    .bind(typed)
    .bind(SUGGEST_LIMIT)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// B4-T4: the records carrying a tag, across entities, that the caller may
/// read; a personal tag only for its owner.
pub async fn tagged_records(
    state: &EngineState,
    ctx: &SecurityContext,
    tag_id: Uuid,
) -> Result<Vec<TaggedRecord>, AppError> {
    let db = &state.base.db;
    let visible: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM tag WHERE id = $1 AND (owner_user IS NULL OR owner_user = $2))",
    )
    .bind(tag_id)
    .bind(ctx.user_id)
    .fetch_one(db)
    .await
    .map_err(attome_db::classify)?;
    if !visible {
        return Err(AppError::NotFound);
    }
    let links: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT entity, record_id FROM tag_link \
         WHERE tag_id = $1 AND (expires_at IS NULL OR expires_at > now()) \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(tag_id)
    .bind(TAG_PAGE_LIMIT)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let mut by_entity: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for (entity, id) in &links {
        by_entity.entry(entity.as_str()).or_default().push(*id);
    }
    let mut names: HashMap<(String, Uuid), Option<String>> = HashMap::new();
    for (entity, ids) in by_entity {
        if ctx.require(entity, "read").is_err() {
            continue;
        }
        let Some(entity_id) = state.entities.load().get(entity).map(|m| m.entity_id) else {
            continue;
        };
        for (id, found) in super::resolve_visible(state, ctx, entity_id, &ids).await {
            if found.exists && found.is_active {
                names.insert((entity.to_owned(), id), found.name);
            }
        }
    }
    Ok(links
        .into_iter()
        .filter_map(|(entity, record_id)| {
            let label = names.get(&(entity.clone(), record_id))?.clone();
            Some(TaggedRecord {
                entity,
                record_id,
                label,
            })
        })
        .collect())
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// B4-T1: the tags on a record the caller may see.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/tags",
    tag = "entity",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The record's tags", body = PaginatedResponse<TagView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_record_tags(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<Json<PaginatedResponse<TagView>>, AppError> {
    let tags = record_tags(&state, &ctx, &entity, id).await?;
    Ok(Json(page_of(tags)))
}

/// B4-T1: puts a tag on a record (an existing one, or one found or created
/// by name).
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/tags",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = AddTag,
    responses(
        (status = 200, description = "The record's tags after the change", body = PaginatedResponse<TagView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "No update access for a shared tag, or the group is closed", body = ErrorResponse),
        (status = 404, description = "No such record or tag", body = ErrorResponse),
        (status = 422, description = "Invalid tag, or too many tags", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn add_record_tag(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id)): Path<(String, Uuid)>,
    Json(body): Json<AddTag>,
) -> Result<Json<PaginatedResponse<TagView>>, AppError> {
    let tags = add_tag(&state, &ctx, &entity, id, &body).await?;
    Ok(Json(page_of(tags)))
}

/// B4-T1: takes a tag off a record.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/tags/{tag_id}",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("entity" = String, Path), ("id" = Uuid, Path), ("tag_id" = Uuid, Path)),
    responses(
        (status = 200, description = "The record's tags after the change", body = PaginatedResponse<TagView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "No update access for a shared tag", body = ErrorResponse),
        (status = 404, description = "No such record, tag or link", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn remove_record_tag(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id, tag_id)): Path<(String, Uuid, Uuid)>,
) -> Result<Json<PaginatedResponse<TagView>>, AppError> {
    let tags = remove_tag(&state, &ctx, &entity, id, tag_id).await?;
    Ok(Json(page_of(tags)))
}

/// Records one bulk tag request may touch.
pub const MAX_BULK_TAG_RECORDS: usize = 500;

/// `POST /api/v1/{entity}/tags/bulk`: add one tag to, or take one tag off,
/// the selected records.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkTagRequest {
    /// The selected records, at most 500.
    pub ids: Vec<Uuid>,
    /// The tag to add (an existing one, or a name to find or create).
    pub add: Option<AddTag>,
    /// The tag to take off.
    pub remove_tag_id: Option<Uuid>,
}

/// One record a bulk tag request could not change.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkTagFailure {
    pub id: Uuid,
    /// `not_found`, `forbidden`, `invalid` or `failed`.
    pub code: &'static str,
}

/// What a bulk tag request did.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkTagResult {
    pub changed: usize,
    pub failed: Vec<BulkTagFailure>,
}

/// B4-T4: tags or untags each selected record through [`add_tag`] or
/// [`remove_tag`], so every record is checked on its own; a record the
/// caller may not change is reported, not skipped silently.
pub async fn bulk_tag(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    request: &BulkTagRequest,
) -> Result<BulkTagResult, AppError> {
    if request.ids.is_empty() || request.ids.len() > MAX_BULK_TAG_RECORDS {
        return Err(AppError::Validation(format!(
            "select 1 to {MAX_BULK_TAG_RECORDS} records"
        )));
    }
    #[derive(Clone, Copy)]
    enum Change<'a> {
        Add(&'a AddTag),
        Remove(Uuid),
    }
    let change = match (&request.add, request.remove_tag_id) {
        (Some(add), None) => Change::Add(add),
        (None, Some(tag_id)) => Change::Remove(tag_id),
        _ => {
            return Err(AppError::Validation(
                "give exactly one of add or remove_tag_id".into(),
            ));
        }
    };
    let mut ids = request.ids.clone();
    ids.sort_unstable();
    ids.dedup();
    let mut result = BulkTagResult {
        changed: 0,
        failed: Vec::new(),
    };
    for id in ids {
        let outcome = match change {
            Change::Add(add) => add_tag(state, ctx, entity_input, id, add).await,
            Change::Remove(tag_id) => remove_tag(state, ctx, entity_input, id, tag_id).await,
        };
        match outcome {
            Ok(_) => result.changed += 1,
            Err(AppError::NotFound) => result.failed.push(BulkTagFailure {
                id,
                code: "not_found",
            }),
            Err(AppError::Forbidden) => result.failed.push(BulkTagFailure {
                id,
                code: "forbidden",
            }),
            Err(AppError::Validation(_)) => result.failed.push(BulkTagFailure {
                id,
                code: "invalid",
            }),
            Err(error) => {
                tracing::warn!(%error, record_id = %id, "bulk tag could not change a record");
                result.failed.push(BulkTagFailure { id, code: "failed" });
            }
        }
    }
    Ok(result)
}

/// B4-T4: adds a tag to, or takes one off, up to 500 selected records. Each
/// record is checked as a single change would be; the ones that could not
/// change are listed with a reason.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/tags/bulk",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("entity" = String, Path)),
    request_body = BulkTagRequest,
    responses(
        (status = 200, description = "How many records changed, and which could not", body = BulkTagResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "No read access to the entity", body = ErrorResponse),
        (status = 422, description = "No records, too many, or not exactly one of add and remove", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn bulk_tag_records(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path(entity): Path<String>,
    Json(body): Json<BulkTagRequest>,
) -> Result<Json<BulkTagResult>, AppError> {
    Ok(Json(bulk_tag(&state, &ctx, &entity, &body).await?))
}

/// B4-T2: tags starting with what was typed, most used first.
#[utoipa::path(
    get,
    path = "/api/v1/tags/suggest",
    tag = "entity",
    params(SuggestQuery),
    responses(
        (status = 200, description = "Matching tags", body = PaginatedResponse<TagSuggestion>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn suggest_tags(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<SuggestQuery>,
) -> Result<Json<PaginatedResponse<TagSuggestion>>, AppError> {
    let found = suggest(&state.base.db, ctx.user_id, &query.q).await?;
    Ok(Json(page_of(found)))
}

/// B4-T4: every record carrying a tag that the caller may read.
#[utoipa::path(
    get,
    path = "/api/v1/tags/{tag_id}/records",
    tag = "entity",
    params(("tag_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Records carrying the tag", body = PaginatedResponse<TaggedRecord>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such tag for the caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_tagged_records(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(tag_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<TaggedRecord>>, AppError> {
    let records = tagged_records(&state, &ctx, tag_id).await?;
    Ok(Json(page_of(records)))
}

/// B4-T2: tag groups.
#[utoipa::path(
    get,
    path = "/api/v1/admin/tag-groups",
    tag = "admin",
    responses(
        (status = 200, description = "Every tag group", body = PaginatedResponse<TagGroup>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_tag_groups(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<TagGroup>>, AppError> {
    let groups: Vec<TagGroup> = sqlx::query_as(
        "SELECT id, name, colour, create_policy, create_privilege FROM tag_group ORDER BY name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    Ok(Json(page_of(groups)))
}

/// B4-T2: creates a tag group with its create policy. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/tag-groups",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    request_body = TagGroupInput,
    responses(
        (status = 201, description = "Created", body = TagGroup),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 409, description = "A group with this name exists", body = ErrorResponse),
        (status = 422, description = "Invalid name, colour or policy", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_tag_group(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<TagGroupInput>,
) -> Result<(StatusCode, Json<TagGroup>), AppError> {
    let name = check_name(&body.name, 100)?;
    check_colour(body.colour.as_deref())?;
    if !["anyone", "privilege", "nobody"].contains(&body.create_policy.as_str()) {
        return Err(AppError::Validation(
            "create_policy must be anyone, privilege or nobody".into(),
        ));
    }
    if body.create_policy == "privilege"
        && body.create_privilege.as_deref().is_none_or(str::is_empty)
    {
        return Err(AppError::Validation(
            "create_privilege is required for the privilege policy".into(),
        ));
    }
    let id = Uuid::now_v7();
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Create,
        ctx.user_id,
        "tag_group",
        Some(id),
    )
    .named("tag_group.created");
    let mut stx = SecurityTx::begin(&state, event).await?;
    let group: TagGroup = sqlx::query_as(
        "INSERT INTO tag_group (id, name, colour, create_policy, create_privilege, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, name, colour, create_policy, create_privilege",
    )
    .bind(id)
    .bind(&name)
    .bind(body.colour.as_deref())
    .bind(&body.create_policy)
    .bind(body.create_privilege.as_deref())
    .bind(ctx.user_id)
    .fetch_one(&mut *stx)
    .await
    .map_err(attome_db::classify)?;
    stx.commit().await?;
    Ok((StatusCode::CREATED, Json(group)))
}

fn page_of<T>(items: Vec<T>) -> PaginatedResponse<T> {
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    PaginatedResponse::new(items, total, 1, total.max(1))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_record_tags,
    add_record_tag,
    remove_record_tag,
    bulk_tag_records,
    suggest_tags,
    list_tagged_records,
    list_tag_groups,
    create_tag_group,
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_and_names_are_checked() {
        assert!(check_colour(Some("#1a2B3c")).is_ok());
        assert!(check_colour(None).is_ok());
        assert!(check_colour(Some("red")).is_err());
        assert!(check_colour(Some("#12345g")).is_err());
        assert_eq!(check_name("  VIP ", 80).unwrap(), "VIP");
        assert!(check_name("   ", 80).is_err());
        assert!(check_name(&"x".repeat(81), 80).is_err());
    }
}
