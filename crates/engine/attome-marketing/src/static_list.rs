//! Static list operations (roadmap E7-T5): people added to and removed
//! from a `static` marketing list by hand, from a view selection, from a
//! form or a flow, or by importing a CSV document — and an import undone.
//!
//! Every operation needs `marketing_list.update`, refuses a `segment` list
//! (its members are its query's), adds only people the caller may read,
//! and writes the members, one membership event per change, the list's
//! count and a change-feed event in one transaction under the list's
//! advisory lock (the one segment refresh takes). A direct call takes at
//! most [`MAX_DIRECT`] ids; more is an import.
//!
//! **Import.** The CSV is a document (K1: uploaded, scanned and stored
//! through the file pipeline) the caller can read. [`queue_import`] records
//! the import and queues the `marketing_list_import` job; the job
//! ([`run_import`]) reads the file, takes the first column of each row as
//! an email or a record id, resolves them in batches of [`BATCH`] to the
//! list's people the importer may read, and adds them tagged with the
//! import's id, keeping its progress. [`undo_import`] removes exactly the
//! members that import added, within [`UNDO_DAYS`] days of its finish.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// Most ids one direct call adds or removes.
pub const MAX_DIRECT: usize = 1_000;
/// Rows resolved per import batch.
pub const BATCH: usize = 1_000;
/// Most rows one import reads.
pub const MAX_IMPORT_ROWS: usize = 200_000;
/// How long an import can be undone.
pub const UNDO_DAYS: i64 = 7;
/// The import job's registered name.
pub const IMPORT_JOB: &str = "marketing_list_import";

/// Where a member came from (`marketing_list_member.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Manual,
    Form,
    Flow,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Form => "form",
            Self::Flow => "flow",
        }
    }
}

/// What a change did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct MemberChange {
    /// People added or removed.
    pub changed: usize,
    /// Ids skipped: already in (or not in) the list, or not readable.
    pub skipped: usize,
}

/// One CSV cell as a person key. Pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonKey {
    Id(Uuid),
    Email(String),
}

/// The person keys in a CSV: the first column of each non-empty row, an id
/// or an email (lower-cased); anything else (a header) is skipped. Pure.
pub fn csv_keys(text: &str) -> Vec<PersonKey> {
    text.lines()
        .take(MAX_IMPORT_ROWS)
        .filter_map(|line| {
            let first = line.split([',', ';', '\t']).next()?.trim();
            let first = first.trim_matches('"').trim();
            if let Ok(id) = Uuid::parse_str(first) {
                Some(PersonKey::Id(id))
            } else if crate::address_check::check_syntax(first).is_ok() {
                Some(PersonKey::Email(first.to_lowercase()))
            } else {
                None
            }
        })
        .collect()
}

fn require_update(ctx: &SecurityContext) -> Result<(), AppError> {
    ctx.require("marketing_list", "update")
}

/// The list's target entity, refusing a segment list. `NotFound` for no list.
async fn static_target(state: &EngineState, list: Uuid) -> Result<String, AppError> {
    let (kind, target): (String, String) = sqlx::query_as(
        "SELECT COALESCE(kind, 'static'), COALESCE(target_entity, 'contact') \
           FROM marketing_list WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if kind != "static" {
        return Err(AppError::Validation(
            "list.not_static: a segment list's members come from its query".into(),
        ));
    }
    Ok(target)
}

async fn lock(tx: &mut attome_db::Tx<'_>, list: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-marketing/segment_refresh:{list}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict("this list is being changed; try again"))
    }
}

async fn finish(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    list: Uuid,
    actor: Uuid,
    name: &str,
    comment: String,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE marketing_list SET member_count = \
            (SELECT COUNT(*) FROM marketing_list_member WHERE list_id = $1), \
            modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(list)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_named(
        tx,
        "marketing_list",
        list,
        attome_core::change_feed::ChangeOperation::Update,
        "marketing.list.members_changed",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "marketing_list",
            list,
            attome_audit::AuditOperation::Update,
            name,
            actor,
        )
        .comment(comment),
    )
    .await?;
    Ok(())
}

/// Adds readable people to the list in one transaction; `import` tags them
/// with an import's id.
async fn insert_members(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    target: &str,
    ids: &[Uuid],
    source: &str,
    import: Option<Uuid>,
) -> Result<MemberChange, AppError> {
    let readable = crate::segment_insight::readable(state, ctx, target, ids).await?;
    let wanted: Vec<Uuid> = ids
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|id| readable.contains(id))
        .collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, list).await?;
    let added: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO marketing_list_member (list_id, person_id, person_entity, source, import_job_id) \
         SELECT $1, p, $2, $3, $4 FROM unnest($5::uuid[]) AS p \
         ON CONFLICT (list_id, person_id) DO NOTHING RETURNING person_id",
    )
    .bind(list)
    .bind(target)
    .bind(source)
    .bind(import)
    .bind(&wanted)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason) \
         SELECT $1, p, 'entered', $2 FROM unnest($3::uuid[]) AS p",
    )
    .bind(list)
    .bind(source)
    .bind(&added)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !added.is_empty() {
        finish(
            &mut tx,
            state,
            list,
            ctx.user_id,
            "marketing_list.members_added",
            format!("{} added ({source})", added.len()),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(MemberChange {
        changed: added.len(),
        skipped: ids.len() - added.len(),
    })
}

/// Adds people to a static list by hand or from a view selection.
pub async fn add_members(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    ids: &[Uuid],
) -> Result<MemberChange, AppError> {
    require_update(ctx)?;
    if ids.len() > MAX_DIRECT {
        return Err(AppError::Validation(format!(
            "at most {MAX_DIRECT} people at once; import a file for more"
        )));
    }
    let target = static_target(state, list).await?;
    insert_members(
        state,
        ctx,
        list,
        &target,
        ids,
        Source::Manual.as_str(),
        None,
    )
    .await
}

/// Adds one person from a form (E10) or a flow (M1), as the caller.
pub async fn add_member_from_source(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    person: Uuid,
    source: Source,
) -> Result<MemberChange, AppError> {
    require_update(ctx)?;
    let target = static_target(state, list).await?;
    insert_members(state, ctx, list, &target, &[person], source.as_str(), None).await
}

/// Removes people from a static list.
pub async fn remove_members(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    ids: &[Uuid],
) -> Result<MemberChange, AppError> {
    require_update(ctx)?;
    if ids.len() > MAX_DIRECT {
        return Err(AppError::Validation(format!(
            "at most {MAX_DIRECT} people at once"
        )));
    }
    static_target(state, list).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, list).await?;
    let removed = delete_members(&mut tx, list, ids, None, "manual").await?;
    if !removed.is_empty() {
        finish(
            &mut tx,
            state,
            list,
            ctx.user_id,
            "marketing_list.members_removed",
            format!("{} removed", removed.len()),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(MemberChange {
        changed: removed.len(),
        skipped: ids.len() - removed.len(),
    })
}

async fn delete_members(
    tx: &mut attome_db::Tx<'_>,
    list: Uuid,
    ids: &[Uuid],
    import: Option<Uuid>,
    reason: &str,
) -> Result<Vec<Uuid>, AppError> {
    let removed: Vec<Uuid> = match import {
        Some(import) => {
            sqlx::query_scalar(
                "DELETE FROM marketing_list_member WHERE list_id = $1 AND import_job_id = $2 \
             RETURNING person_id",
            )
            .bind(list)
            .bind(import)
            .fetch_all(&mut **tx)
            .await
        }
        None => {
            sqlx::query_scalar(
                "DELETE FROM marketing_list_member WHERE list_id = $1 AND person_id = ANY($2) \
             RETURNING person_id",
            )
            .bind(list)
            .bind(ids)
            .fetch_all(&mut **tx)
            .await
        }
    }
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason) \
         SELECT $1, p, 'left', $2 FROM unnest($3::uuid[]) AS p",
    )
    .bind(list)
    .bind(reason)
    .bind(&removed)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(removed)
}

/// An import's state.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ListImport {
    pub id: Uuid,
    pub list_id: Uuid,
    pub document_id: Uuid,
    /// `queued`, `running`, `done`, `failed` or `undone`.
    pub status: String,
    pub rows_read: i32,
    pub added: i32,
    pub skipped: i32,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

const IMPORT_COLUMNS: &str = "id, list_id, document_id, status, rows_read, added, skipped, error, \
     created_at, finished_at";

/// One import of a list.
pub async fn import_status(
    state: &EngineState,
    list: Uuid,
    import: Uuid,
) -> Result<ListImport, AppError> {
    sqlx::query_as::<_, ListImport>(&format!(
        "SELECT {IMPORT_COLUMNS} FROM marketing_list_import WHERE id = $1 AND list_id = $2"
    ))
    .bind(import)
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Records an import of `document` into the list and queues its job.
pub async fn queue_import(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    document: Uuid,
) -> Result<ListImport, AppError> {
    require_update(ctx)?;
    static_target(state, list).await?;
    if !attome_records::entity_crud::referenced_record_visible(
        state,
        ctx,
        "attome_document",
        document,
    )
    .await?
    {
        return Err(AppError::NotFound);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let import: ListImport = sqlx::query_as(&format!(
        "INSERT INTO marketing_list_import (list_id, document_id, created_by) \
         VALUES ($1, $2, $3) RETURNING {IMPORT_COLUMNS}"
    ))
    .bind(list)
    .bind(document)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let job = attome_core::jobs::JOB_TYPES
        .job(IMPORT_JOB, &json!({ "import_id": import.id }))
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(import)
}

async fn set_import(
    state: &EngineState,
    import: Uuid,
    status: &str,
    progress: (usize, usize, usize),
    error: Option<&str>,
) -> Result<(), AppError> {
    let as_i32 = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
    sqlx::query(
        "UPDATE marketing_list_import SET status = $2, rows_read = $3, added = $4, skipped = $5, \
             error = $6, finished_at = CASE WHEN $2 IN ('done', 'failed') THEN now() END \
         WHERE id = $1",
    )
    .bind(import)
    .bind(status)
    .bind(as_i32(progress.0))
    .bind(as_i32(progress.1))
    .bind(as_i32(progress.2))
    .bind(error)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The import job: reads the document's CSV and adds its people, as the
/// person who started it. A finished or undone import is not run again.
pub async fn run_import(state: &EngineState, import: Uuid) -> Result<(), AppError> {
    let row: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT list_id, document_id, created_by, status FROM marketing_list_import WHERE id = $1",
    )
    .bind(import)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((list, document, user, status)) = row else {
        return Ok(());
    };
    if !matches!(status.as_str(), "queued" | "running") {
        return Ok(());
    }
    set_import(state, import, "running", (0, 0, 0), None).await?;
    match import_rows(state, import, list, document, user).await {
        Ok(progress) => set_import(state, import, "done", progress, None).await,
        Err(error) => {
            tracing::warn!(%import, %error, "list import failed");
            set_import(state, import, "failed", (0, 0, 0), Some(&error.to_string())).await
        }
    }
}

async fn import_rows(
    state: &EngineState,
    import: Uuid,
    list: Uuid,
    document: Uuid,
    user: Uuid,
) -> Result<(usize, usize, usize), AppError> {
    let ctx = state.base.security.resolve(user).await?;
    require_update(&ctx)?;
    let target = static_target(state, list).await?;
    if !attome_records::entity_crud::referenced_record_visible(
        state,
        &ctx,
        "attome_document",
        document,
    )
    .await?
    {
        return Err(AppError::Validation(
            "the import file is not readable".into(),
        ));
    }
    let key: Option<String> = sqlx::query_scalar("SELECT file FROM attome_document WHERE id = $1")
        .bind(document)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten();
    let key = key.ok_or_else(|| AppError::Validation("the document has no file".into()))?;
    // The network read happens before any transaction.
    let bytes = attome_storage::mirror::read_object(&state.base.storage, &key)
        .await
        .map_err(AppError::internal)?;
    let text = String::from_utf8_lossy(&bytes);
    let keys = csv_keys(&text);
    let has_email = state
        .entities
        .load()
        .get(&target)
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "email"));
    let (mut added, mut skipped) = (0, 0);
    for chunk in keys.chunks(BATCH) {
        let mut ids: Vec<Uuid> = Vec::new();
        let mut emails: Vec<String> = Vec::new();
        for key in chunk {
            match key {
                PersonKey::Id(id) => ids.push(*id),
                PersonKey::Email(email) => emails.push(email.clone()),
            }
        }
        if has_email && !emails.is_empty() {
            let found: Vec<Uuid> = sqlx::query_scalar(&format!(
                "SELECT id FROM {} WHERE lower(email) = ANY($1) AND is_active IS NOT FALSE",
                attome_core::quote_ident(&target)
            ))
            .bind(&emails)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            ids.extend(found);
        }
        let change =
            insert_members(state, &ctx, list, &target, &ids, "import", Some(import)).await?;
        added += change.changed;
        skipped += chunk.len().saturating_sub(change.changed);
        set_import(state, import, "running", (keys.len(), added, skipped), None).await?;
    }
    Ok((keys.len(), added, skipped))
}

/// Whether an import that finished at `finished` can still be undone at
/// `now`. Pure.
pub fn undo_open(finished: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    finished.is_some_and(|f| now - f < Duration::days(UNDO_DAYS))
}

/// Removes exactly the members an import added, within [`UNDO_DAYS`].
pub async fn undo_import(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    import: Uuid,
) -> Result<MemberChange, AppError> {
    require_update(ctx)?;
    static_target(state, list).await?;
    let current = import_status(state, list, import).await?;
    if current.status != "done" {
        return Err(AppError::Conflict("only a finished import can be undone"));
    }
    if !undo_open(current.finished_at, Utc::now()) {
        return Err(AppError::Conflict("list.undo_window_passed"));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, list).await?;
    let removed = delete_members(&mut tx, list, &[], Some(import), "import_undone").await?;
    sqlx::query("UPDATE marketing_list_import SET status = 'undone' WHERE id = $1")
        .bind(import)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    finish(
        &mut tx,
        state,
        list,
        ctx.user_id,
        "marketing_list.import_undone",
        format!("import {import} undone: {} removed", removed.len()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(MemberChange {
        changed: removed.len(),
        skipped: 0,
    })
}

// ── Routes ───────────────────────────────────────────────────────────────────

use attome_server::authz::{Authorized, Privilege};
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;

use crate::sms_campaign::ListUpdate;

#[derive(Debug, Deserialize, ToSchema)]
pub struct MembersBody {
    /// The people (records of the list's target entity), at most 1,000.
    pub person_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportBody {
    /// The CSV document (`attome_document`) to import.
    pub document_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/members",
    operation_id = "add_marketing_list_members",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The static list")),
    request_body = MembersBody,
    responses(
        (status = 200, description = "People added", body = MemberChange),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
        (status = 409, description = "The list is being changed", body = ErrorResponse),
        (status = 422, description = "A segment list, or more than 1,000 people", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Add people to a static list.
///
/// By hand or from a view selection; only people the caller may read are
/// added, and people already in the list are skipped.
async fn post_members(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<MembersBody>,
) -> Result<Json<MemberChange>, AppError> {
    add_members(&state, &ctx, list, &body.person_ids)
        .await
        .map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/members/remove",
    operation_id = "remove_marketing_list_members",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The static list")),
    request_body = MembersBody,
    responses(
        (status = 200, description = "People removed", body = MemberChange),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
        (status = 409, description = "The list is being changed", body = ErrorResponse),
        (status = 422, description = "A segment list, or more than 1,000 people", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Remove people from a static list.
///
/// Each removal is a membership event; people not in the list are skipped.
async fn post_members_remove(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<MembersBody>,
) -> Result<Json<MemberChange>, AppError> {
    remove_members(&state, &ctx, list, &body.person_ids)
        .await
        .map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/imports",
    operation_id = "import_marketing_list_members",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The static list")),
    request_body = ImportBody,
    responses(
        (status = 202, description = "The import is queued", body = ListImport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list, or the document is not readable", body = ErrorResponse),
        (status = 422, description = "A segment list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Import people into a static list from a CSV document.
///
/// Queues the import; its first column is an email or a record id per row.
/// Follow it with the import's status route.
async fn post_import(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<ImportBody>,
) -> Result<(StatusCode, Json<ListImport>), AppError> {
    let import = queue_import(&state, &ctx, list, body.document_id).await?;
    Ok((StatusCode::ACCEPTED, Json(import)))
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/imports/{import_id}",
    operation_id = "get_marketing_list_import",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The static list"),
        ("import_id" = Uuid, Path, description = "The import"),
    ),
    responses(
        (status = 200, description = "The import's progress", body = ListImport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such import", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Read a list import's progress.
///
/// Rows read, people added and skipped, and whether it finished or failed.
async fn get_import(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<crate::segment_insight::ListRead>>,
    Path((list, import)): Path<(Uuid, Uuid)>,
) -> Result<Json<ListImport>, AppError> {
    import_status(&state, list, import).await.map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/imports/{import_id}/undo",
    operation_id = "undo_marketing_list_import",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The static list"),
        ("import_id" = Uuid, Path, description = "The import"),
    ),
    responses(
        (status = 200, description = "The import's members removed", body = MemberChange),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such import", body = ErrorResponse),
        (status = 409, description = "Not finished, or finished more than seven days ago", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Undo a list import.
///
/// Removes exactly the people that import added, within seven days of its
/// finish.
async fn post_undo(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path((list, import)): Path<(Uuid, Uuid)>,
) -> Result<Json<MemberChange>, AppError> {
    undo_import(&state, &ctx, list, import).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/lists/{id}/members", post(post_members))
        .route(
            "/api/v1/marketing/lists/{id}/members/remove",
            post(post_members_remove),
        )
        .route("/api/v1/marketing/lists/{id}/imports", post(post_import))
        .route(
            "/api/v1/marketing/lists/{id}/imports/{import_id}",
            get(get_import),
        )
        .route(
            "/api/v1/marketing/lists/{id}/imports/{import_id}/undo",
            post(post_undo),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_members, post_members_remove, post_import, get_import, post_undo),
    components(schemas(MembersBody, ImportBody, MemberChange, ListImport))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_rows_become_ids_and_emails() {
        let id = Uuid::now_v7();
        let csv = format!("email,name\nSara@Acme.sa,Sara\n\"{id}\",x\nnot an email\n\n");
        assert_eq!(
            csv_keys(&csv),
            vec![PersonKey::Email("sara@acme.sa".into()), PersonKey::Id(id)]
        );
    }

    #[test]
    fn undo_stays_open_for_seven_days() {
        let now = Utc::now();
        assert!(undo_open(Some(now - Duration::days(6)), now));
        assert!(!undo_open(Some(now - Duration::days(8)), now));
        assert!(!undo_open(None, now));
    }
}
