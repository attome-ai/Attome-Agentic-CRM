//! Recent records and favourites (roadmap B9-T1, B9-T2).
//!
//! **Recent.** The web app reports the records a person opens, a batch at a
//! time (`POST /api/v1/me/recent`); the last [`MAX_RECENT`] per person are
//! kept. **Favourites.** Lists of records, views and pages: a person's own
//! folders (`/api/v1/me/favourites/lists`) and lists shared with a team
//! (`/api/v1/teams/{team_id}/favourites/lists`), each replaced whole on save,
//! in order, with up to [`MAX_PINNED`] pinned items a list (Ctrl+1..9).
//!
//! Every read resolves record items through
//! [`super::lookup_names::resolve_visible`], under the caller's own record
//! rules: a record the caller may not read, or that no longer exists, is
//! left out; a deleted one is returned with `deleted: true`, so the client
//! points to its restore instead of a dead link. A person's own lists and
//! recents are their UI state (no audit event); a team list is shared
//! configuration, written with a `Configuration` event in the same
//! transaction.

use std::collections::HashMap;

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Recent rows kept per person.
pub const MAX_RECENT: i64 = 200;
/// Opens accepted in one report.
pub const MAX_RECENT_BATCH: usize = 50;
/// Items in one list.
pub const MAX_ITEMS: usize = 100;
/// Pinned items in one list: the Ctrl+1..9 shortcuts.
pub const MAX_PINNED: usize = 9;
/// Lists one person, or one team, may keep.
pub const MAX_LISTS: i64 = 50;

const KINDS: [&str; 3] = ["record", "view", "page"];

// ── Wire types ──────────────────────────────────────────────────────────────

/// One record a person opened.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RecentOpen {
    pub entity: String,
    pub record_id: Uuid,
}

/// `POST /api/v1/me/recent`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecentReport {
    /// Up to 50 opens, newest last.
    pub items: Vec<RecentOpen>,
}

/// One recent record, as the caller may see it now.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecentItem {
    pub entity: String,
    pub record_id: Uuid,
    /// The record's primary name, when its entity declares one.
    pub label: Option<String>,
    /// UTC ISO-8601.
    pub opened_at: DateTime<Utc>,
    /// Deleted since it was opened: restore it rather than open it.
    pub deleted: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct RecentQuery {
    /// How many, newest first; default 20, at most 200.
    pub limit: Option<i64>,
}

/// One item to keep in a list.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct FavouriteItemInput {
    /// `record`, `view` or `page`.
    pub kind: String,
    /// The record's entity; required for a record.
    pub entity: Option<String>,
    /// The record id, the view id, or the page's route.
    #[serde(rename = "ref")]
    pub reference: String,
    /// What to show; a record's own name wins when it has one.
    pub label: Option<String>,
    #[serde(default)]
    pub pinned: bool,
}

/// A list's whole content, as saved.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FavouriteListInput {
    pub name: String,
    /// In display order.
    #[serde(default)]
    pub items: Vec<FavouriteItemInput>,
}

/// One kept item, as the caller may see it now.
#[derive(Debug, Serialize, ToSchema)]
pub struct FavouriteItem {
    pub id: Uuid,
    pub kind: String,
    pub entity: Option<String>,
    #[serde(rename = "ref")]
    pub reference: String,
    pub label: Option<String>,
    pub pinned: bool,
    /// A record deleted since it was kept.
    pub deleted: bool,
}

/// One list: the caller's own (`team_id` null) or a team's.
#[derive(Debug, Serialize, ToSchema)]
pub struct FavouriteList {
    pub id: Uuid,
    pub name: String,
    pub team_id: Option<Uuid>,
    pub items: Vec<FavouriteItem>,
}

// ── Validation ──────────────────────────────────────────────────────────────

fn known_entity(state: &EngineState, entity: &str) -> Option<Uuid> {
    state.entities.load().get(entity).map(|m| m.entity_id)
}

/// The list's name and items, checked; each item's `ref` trimmed.
fn checked(
    state: &EngineState,
    input: FavouriteListInput,
) -> Result<(String, Vec<FavouriteItemInput>), AppError> {
    let name = input.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::Validation(
            "name must be 1 to 100 characters".into(),
        ));
    }
    check_items(&input.items, |entity| known_entity(state, entity).is_some())?;
    let items = input
        .items
        .into_iter()
        .map(|mut item| {
            item.reference = item.reference.trim().to_owned();
            item
        })
        .collect();
    Ok((name, items))
}

/// The rules every list's items keep. `entity_known` says whether an entity
/// exists.
fn check_items(
    items: &[FavouriteItemInput],
    entity_known: impl Fn(&str) -> bool,
) -> Result<(), AppError> {
    if items.len() > MAX_ITEMS {
        return Err(AppError::Validation(format!(
            "a list holds at most {MAX_ITEMS} items"
        )));
    }
    if items.iter().filter(|i| i.pinned).count() > MAX_PINNED {
        return Err(AppError::Validation(format!(
            "at most {MAX_PINNED} items a list can be pinned"
        )));
    }
    for (n, item) in items.iter().enumerate() {
        let at = |what: &str| AppError::Validation(format!("items[{n}]: {what}"));
        if !KINDS.contains(&item.kind.as_str()) {
            return Err(at("kind must be record, view or page"));
        }
        let reference = item.reference.trim();
        if reference.is_empty() || reference.chars().count() > 500 {
            return Err(at("ref must be 1 to 500 characters"));
        }
        if item.label.as_ref().is_some_and(|l| l.chars().count() > 200) {
            return Err(at("label must be at most 200 characters"));
        }
        match item.kind.as_str() {
            "record" => {
                let entity = item
                    .entity
                    .as_deref()
                    .ok_or_else(|| at("a record needs its entity"))?;
                if !entity_known(entity) {
                    return Err(at("unknown entity"));
                }
                Uuid::parse_str(reference).map_err(|_| at("a record's ref is its id"))?;
            }
            "view" => {
                Uuid::parse_str(reference).map_err(|_| at("a view's ref is its id"))?;
            }
            _ => {
                if !reference.starts_with('/') {
                    return Err(at("a page's ref is its route, starting with /"));
                }
            }
        }
    }
    Ok(())
}

/// A team list is for the team's members (and administrators). Anyone else
/// gets the same answer as for a list that does not exist.
fn require_team(ctx: &SecurityContext, team_id: Uuid) -> Result<(), AppError> {
    if ctx.is_admin || ctx.team_ids.contains(&team_id) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

// ── Recent ──────────────────────────────────────────────────────────────────

/// Records the opens in `items` (unknown entities are skipped) and trims the
/// caller's history to [`MAX_RECENT`].
pub async fn report_opens(
    state: &EngineState,
    user_id: Uuid,
    items: &[RecentOpen],
) -> Result<(), AppError> {
    if items.len() > MAX_RECENT_BATCH {
        return Err(AppError::Validation(format!(
            "report at most {MAX_RECENT_BATCH} opens at a time"
        )));
    }
    // One row per record: the same record twice in one statement would be a
    // second update of the row `ON CONFLICT` already touched.
    let mut seen = std::collections::HashSet::new();
    let (entities, ids): (Vec<String>, Vec<Uuid>) = items
        .iter()
        .rev()
        .filter(|o| known_entity(state, &o.entity).is_some())
        .filter(|o| seen.insert((o.entity.clone(), o.record_id)))
        .map(|o| (o.entity.clone(), o.record_id))
        .unzip();
    if entities.is_empty() {
        return Ok(());
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "INSERT INTO user_recent (user_id, entity, record_id) \
         SELECT $1, e, r FROM UNNEST($2::text[], $3::uuid[]) AS t(e, r) \
         ON CONFLICT (user_id, entity, record_id) DO UPDATE SET opened_at = now()"
    ))
    .bind(user_id)
    .bind(&entities)
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "DELETE FROM user_recent WHERE user_id = $1 AND (entity, record_id) NOT IN ( \
             SELECT entity, record_id FROM user_recent WHERE user_id = $1 \
             ORDER BY opened_at DESC LIMIT $2)"
    ))
    .bind(user_id)
    .bind(MAX_RECENT)
    .execute(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    attome_db::tx::commit(tx).await
}

/// Empties the caller's recent history.
pub async fn clear_recent(state: &EngineState, user_id: Uuid) -> Result<(), AppError> {
    sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "DELETE FROM user_recent WHERE user_id = $1"
    ))
    .bind(user_id)
    .execute(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    Ok(())
}

/// The caller's last `limit` opens they may still see, newest first.
pub async fn recent(
    state: &EngineState,
    ctx: &SecurityContext,
    limit: i64,
) -> Result<Vec<RecentItem>, AppError> {
    let rows: Vec<(String, Uuid, DateTime<Utc>)> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.favourites",
        "SELECT entity, record_id, opened_at FROM user_recent WHERE user_id = $1 \
         ORDER BY opened_at DESC LIMIT $2"
    ))
    .bind(ctx.user_id)
    .bind(limit.clamp(1, MAX_RECENT))
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let seen = visible_records(
        state,
        ctx,
        rows.iter().map(|(entity, id, _)| (entity.as_str(), *id)),
    )
    .await;
    Ok(rows
        .into_iter()
        .filter_map(|(entity, record_id, opened_at)| {
            let (label, live) = seen.get(&(entity.clone(), record_id))?.clone();
            Some(RecentItem {
                entity,
                record_id,
                label,
                opened_at,
                deleted: !live,
            })
        })
        .collect())
}

/// Every `(entity, id)` the caller may read, with its name and whether it is
/// live. One query per entity; an id missing from the map is hidden or gone.
async fn visible_records<'a>(
    state: &EngineState,
    ctx: &SecurityContext,
    refs: impl Iterator<Item = (&'a str, Uuid)>,
) -> HashMap<(String, Uuid), (Option<String>, bool)> {
    let mut by_entity: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for (entity, id) in refs {
        by_entity.entry(entity).or_default().push(id);
    }
    let mut out = HashMap::new();
    for (entity, ids) in by_entity {
        let Some(entity_id) = known_entity(state, entity) else {
            continue;
        };
        for (id, found) in super::resolve_visible(state, ctx, entity_id, &ids).await {
            if found.exists {
                out.insert((entity.to_owned(), id), (found.name, found.is_active));
            }
        }
    }
    out
}

// ── Favourites ──────────────────────────────────────────────────────────────

/// The caller's own lists, then their teams' lists, each with the items the
/// caller may see.
pub async fn lists_for(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<FavouriteList>, AppError> {
    load_lists(state, ctx, None).await
}

/// [`lists_for`], plus `also` (a list whose access the caller already
/// checked, such as a team list an administrator just saved).
async fn load_lists(
    state: &EngineState,
    ctx: &SecurityContext,
    also: Option<Uuid>,
) -> Result<Vec<FavouriteList>, AppError> {
    let lists: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.favourites",
        "SELECT id, name, team_id FROM favourite_list \
         WHERE owner_user = $1 OR team_id = ANY($2) OR id = $3 \
         ORDER BY team_id NULLS FIRST, created_at, id"
    ))
    .bind(ctx.user_id)
    .bind(&ctx.team_ids)
    .bind(also)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let ids: Vec<Uuid> = lists.iter().map(|l| l.0).collect();
    type ItemRow = (
        Uuid,
        Uuid,
        String,
        Option<String>,
        String,
        Option<String>,
        bool,
    );
    let items: Vec<ItemRow> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.favourites",
        "SELECT list_id, id, kind, entity, ref, label, pinned FROM favourite_item \
         WHERE list_id = ANY($1) ORDER BY list_id, position"
    ))
    .bind(&ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let seen = visible_records(
        state,
        ctx,
        items
            .iter()
            .filter(|i| i.2 == "record")
            .filter_map(|i| Some((i.3.as_deref()?, Uuid::parse_str(&i.4).ok()?))),
    )
    .await;
    let mut by_list: HashMap<Uuid, Vec<FavouriteItem>> = HashMap::new();
    for (list_id, id, kind, entity, reference, label, pinned) in items {
        let mut item = FavouriteItem {
            id,
            kind,
            entity,
            reference,
            label,
            pinned,
            deleted: false,
        };
        if item.kind == "record" {
            let key = (
                item.entity.clone().unwrap_or_default(),
                Uuid::parse_str(&item.reference).unwrap_or_default(),
            );
            // Hidden from this caller, or gone: left out.
            let Some((name, live)) = seen.get(&key) else {
                continue;
            };
            if name.is_some() {
                item.label.clone_from(name);
            }
            item.deleted = !live;
        }
        by_list.entry(list_id).or_default().push(item);
    }
    Ok(lists
        .into_iter()
        .map(|(id, name, team_id)| FavouriteList {
            items: by_list.remove(&id).unwrap_or_default(),
            id,
            name,
            team_id,
        })
        .collect())
}

/// Replaces `list_id`'s items with `items`, in order.
async fn write_items(
    conn: &mut sqlx::PgConnection,
    list_id: Uuid,
    items: &[FavouriteItemInput],
) -> Result<(), AppError> {
    sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "DELETE FROM favourite_item WHERE list_id = $1"
    ))
    .bind(list_id)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if items.is_empty() {
        return Ok(());
    }
    let kinds: Vec<&str> = items.iter().map(|i| i.kind.as_str()).collect();
    let entities: Vec<Option<&str>> = items.iter().map(|i| i.entity.as_deref()).collect();
    let refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
    let labels: Vec<Option<&str>> = items.iter().map(|i| i.label.as_deref()).collect();
    let pinned: Vec<bool> = items.iter().map(|i| i.pinned).collect();
    sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "INSERT INTO favourite_item (list_id, kind, entity, ref, label, pinned, position) \
         SELECT $1, k, e, r, l, p, (n - 1)::int \
         FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::bool[]) \
              WITH ORDINALITY AS t(k, e, r, l, p, n)"
    ))
    .bind(list_id)
    .bind(&kinds)
    .bind(&entities)
    .bind(&refs)
    .bind(&labels)
    .bind(&pinned)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(())
}

/// The lists `owner` (a user, or a team) keeps.
async fn list_count(
    conn: &mut sqlx::PgConnection,
    owner_user: Option<Uuid>,
    team_id: Option<Uuid>,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        attome_db::tagged_sql!("entity.favourites", "SELECT COUNT(*) FROM favourite_list \
         WHERE ($1::uuid IS NOT NULL AND owner_user = $1) OR ($2::uuid IS NOT NULL AND team_id = $2)"),
    )
    .bind(owner_user)
    .bind(team_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(attome_db::classify)
}

async fn insert_list(
    conn: &mut sqlx::PgConnection,
    created_by: Uuid,
    owner_user: Option<Uuid>,
    team_id: Option<Uuid>,
    name: &str,
    items: &[FavouriteItemInput],
) -> Result<Uuid, AppError> {
    if list_count(conn, owner_user, team_id).await? >= MAX_LISTS {
        return Err(AppError::Validation(format!(
            "at most {MAX_LISTS} lists are kept"
        )));
    }
    let id: Uuid = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.favourites",
        "INSERT INTO favourite_list (owner_user, team_id, name, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING id"
    ))
    .bind(owner_user)
    .bind(team_id)
    .bind(name)
    .bind(created_by)
    .fetch_one(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    write_items(conn, id, items).await?;
    Ok(id)
}

/// Renames `list_id` and replaces its items; `false` when no such list has
/// that owner.
async fn update_list(
    conn: &mut sqlx::PgConnection,
    list_id: Uuid,
    owner_user: Option<Uuid>,
    team_id: Option<Uuid>,
    name: &str,
    items: &[FavouriteItemInput],
) -> Result<bool, AppError> {
    let updated = sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "UPDATE favourite_list SET name = $4, updated_at = now() \
         WHERE id = $1 AND owner_user IS NOT DISTINCT FROM $2 AND team_id IS NOT DISTINCT FROM $3"
    ))
    .bind(list_id)
    .bind(owner_user)
    .bind(team_id)
    .bind(name)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }
    write_items(conn, list_id, items).await?;
    Ok(true)
}

async fn remove_list(
    conn: &mut sqlx::PgConnection,
    list_id: Uuid,
    owner_user: Option<Uuid>,
    team_id: Option<Uuid>,
) -> Result<bool, AppError> {
    let deleted = sqlx::query(attome_db::tagged_sql!(
        "entity.favourites",
        "DELETE FROM favourite_list \
         WHERE id = $1 AND owner_user IS NOT DISTINCT FROM $2 AND team_id IS NOT DISTINCT FROM $3"
    ))
    .bind(list_id)
    .bind(owner_user)
    .bind(team_id)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(deleted.rows_affected() > 0)
}

/// One list as the caller sees it after a write.
async fn reread(
    state: &EngineState,
    ctx: &SecurityContext,
    list_id: Uuid,
) -> Result<FavouriteList, AppError> {
    load_lists(state, ctx, Some(list_id))
        .await?
        .into_iter()
        .find(|l| l.id == list_id)
        .ok_or(AppError::NotFound)
}

fn team_event(operation: AuditOperation, actor: Uuid, list_id: Option<Uuid>) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "favourite_list",
        list_id,
    )
    .named("favourite_list.team")
}

// ── Routes: recent ──────────────────────────────────────────────────────────

/// B9-T2: the records the caller opened lately and may still see, newest
/// first; a deleted one carries `deleted: true`.
#[utoipa::path(
    get,
    path = "/api/v1/me/recent",
    tag = "entity",
    params(RecentQuery),
    responses(
        (status = 200, description = "Recent records, newest first", body = PaginatedResponse<RecentItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_recent(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<RecentQuery>,
) -> Result<Json<PaginatedResponse<RecentItem>>, AppError> {
    let limit = query.limit.unwrap_or(20).clamp(1, MAX_RECENT);
    let items = recent(&state, &ctx, limit).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, limit)))
}

/// B9-T1: reports records the caller opened, up to 50 at a time.
#[utoipa::path(
    post,
    path = "/api/v1/me/recent",
    tag = "entity",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "the caller's own recently-opened list; no security, sharing or business effect"
    )))),
    request_body = RecentReport,
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "More than 50 opens", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn report_recent(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<RecentReport>,
) -> Result<StatusCode, AppError> {
    report_opens(&state, ctx.user_id, &body.items).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// B9-T2: empties the caller's recent list.
#[utoipa::path(
    delete,
    path = "/api/v1/me/recent",
    tag = "entity",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "clears the caller's own recently-opened list"
    )))),
    responses(
        (status = 204, description = "Cleared"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_recent(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<StatusCode, AppError> {
    clear_recent(&state, ctx.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Routes: the caller's own lists ──────────────────────────────────────────

/// B9-T2: the caller's own lists, then their teams' shared lists, with the
/// items the caller may see.
#[utoipa::path(
    get,
    path = "/api/v1/me/favourites",
    tag = "entity",
    responses(
        (status = 200, description = "Every list the caller keeps or shares", body = PaginatedResponse<FavouriteList>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_favourites(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<PaginatedResponse<FavouriteList>>, AppError> {
    let lists = lists_for(&state, &ctx).await?;
    let total = i64::try_from(lists.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(lists, total, 1, total.max(1))))
}

/// B9-T2: creates one of the caller's own lists.
#[utoipa::path(
    post,
    path = "/api/v1/me/favourites/lists",
    tag = "entity",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a list only its owner sees"
    )))),
    request_body = FavouriteListInput,
    responses(
        (status = 201, description = "Created", body = FavouriteList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Invalid name or items, or too many lists", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_my_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<FavouriteListInput>,
) -> Result<(StatusCode, Json<FavouriteList>), AppError> {
    let (name, items) = checked(&state, body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = insert_list(&mut tx, ctx.user_id, Some(ctx.user_id), None, &name, &items).await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(reread(&state, &ctx, id).await?)))
}

/// B9-T2: renames one of the caller's own lists and replaces its items, in
/// order (drag to reorder, pin and unpin are all a save of the whole list).
#[utoipa::path(
    put,
    path = "/api/v1/me/favourites/lists/{id}",
    tag = "entity",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a list only its owner sees"
    )))),
    params(("id" = Uuid, Path, description = "The list")),
    request_body = FavouriteListInput,
    responses(
        (status = 200, description = "Saved", body = FavouriteList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such list of the caller's", body = ErrorResponse),
        (status = 422, description = "Invalid name or items", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn replace_my_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<FavouriteListInput>,
) -> Result<Json<FavouriteList>, AppError> {
    let (name, items) = checked(&state, body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !update_list(&mut tx, id, Some(ctx.user_id), None, &name, &items).await? {
        return Err(AppError::NotFound);
    }
    attome_db::tx::commit(tx).await?;
    Ok(Json(reread(&state, &ctx, id).await?))
}

/// B9-T2: deletes one of the caller's own lists.
#[utoipa::path(
    delete,
    path = "/api/v1/me/favourites/lists/{id}",
    tag = "entity",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a list only its owner sees"
    )))),
    params(("id" = Uuid, Path, description = "The list")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such list of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_my_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !remove_list(&mut tx, id, Some(ctx.user_id), None).await? {
        return Err(AppError::NotFound);
    }
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Routes: team lists ──────────────────────────────────────────────────────

/// B9-T2: creates a list shared with a team the caller belongs to.
#[utoipa::path(
    post,
    path = "/api/v1/teams/{team_id}/favourites/lists",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (AuditCategory::Configuration, AuditOperation::Create),
    ])))),
    params(("team_id" = Uuid, Path, description = "The team")),
    request_body = FavouriteListInput,
    responses(
        (status = 201, description = "Created", body = FavouriteList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not a team of the caller's", body = ErrorResponse),
        (status = 422, description = "Invalid name or items, or too many lists", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_team_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<FavouriteListInput>,
) -> Result<(StatusCode, Json<FavouriteList>), AppError> {
    require_team(&ctx, team_id)?;
    let (name, items) = checked(&state, body)?;
    let mut stx = SecurityTx::begin(
        &state,
        team_event(AuditOperation::Create, ctx.user_id, None),
    )
    .await?;
    let id = insert_list(&mut stx, ctx.user_id, None, Some(team_id), &name, &items).await?;
    stx.event_mut().set_record_id(id);
    stx.commit().await?;
    Ok((StatusCode::CREATED, Json(reread(&state, &ctx, id).await?)))
}

/// B9-T2: renames a team list and replaces its items, in order.
#[utoipa::path(
    put,
    path = "/api/v1/teams/{team_id}/favourites/lists/{id}",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (AuditCategory::Configuration, AuditOperation::Update),
    ])))),
    params(
        ("team_id" = Uuid, Path, description = "The team"),
        ("id" = Uuid, Path, description = "The list"),
    ),
    request_body = FavouriteListInput,
    responses(
        (status = 200, description = "Saved", body = FavouriteList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such list of the caller's teams", body = ErrorResponse),
        (status = 422, description = "Invalid name or items", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn replace_team_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((team_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<FavouriteListInput>,
) -> Result<Json<FavouriteList>, AppError> {
    require_team(&ctx, team_id)?;
    let (name, items) = checked(&state, body)?;
    let mut stx = SecurityTx::begin(
        &state,
        team_event(AuditOperation::Update, ctx.user_id, Some(id)),
    )
    .await?;
    if !update_list(&mut stx, id, None, Some(team_id), &name, &items).await? {
        return Err(AppError::NotFound);
    }
    stx.commit().await?;
    Ok(Json(reread(&state, &ctx, id).await?))
}

/// B9-T2: deletes a team list.
#[utoipa::path(
    delete,
    path = "/api/v1/teams/{team_id}/favourites/lists/{id}",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (AuditCategory::Configuration, AuditOperation::HardDelete),
    ])))),
    params(
        ("team_id" = Uuid, Path, description = "The team"),
        ("id" = Uuid, Path, description = "The list"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such list of the caller's teams", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_team_list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((team_id, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    require_team(&ctx, team_id)?;
    let mut stx = SecurityTx::begin(
        &state,
        team_event(AuditOperation::HardDelete, ctx.user_id, Some(id)),
    )
    .await?;
    if !remove_list(&mut stx, id, None, Some(team_id)).await? {
        return Err(AppError::NotFound);
    }
    stx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_recent,
    report_recent,
    delete_recent,
    list_favourites,
    create_my_list,
    replace_my_list,
    delete_my_list,
    create_team_list,
    replace_team_list,
    delete_team_list,
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: &str, entity: Option<&str>, reference: &str, pinned: bool) -> FavouriteItemInput {
        FavouriteItemInput {
            kind: kind.into(),
            entity: entity.map(Into::into),
            reference: reference.into(),
            label: None,
            pinned,
        }
    }

    #[test]
    fn items_are_checked_by_kind() {
        let known = |e: &str| e == "party";
        let id = Uuid::now_v7().to_string();
        assert!(check_items(&[item("record", Some("party"), &id, true)], known).is_ok());
        assert!(check_items(&[item("view", None, &id, false)], known).is_ok());
        assert!(check_items(&[item("page", None, "/dashboard", false)], known).is_ok());
        assert!(check_items(&[item("record", None, &id, false)], known).is_err());
        assert!(check_items(&[item("record", Some("nope"), &id, false)], known).is_err());
        assert!(check_items(&[item("record", Some("party"), "x", false)], known).is_err());
        assert!(check_items(&[item("page", None, "dashboard", false)], known).is_err());
        assert!(check_items(&[item("file", None, "/x", false)], known).is_err());
    }

    #[test]
    fn a_list_pins_at_most_nine() {
        let known = |_: &str| true;
        let nine: Vec<_> = (0..9)
            .map(|n| item("page", None, &format!("/p{n}"), true))
            .collect();
        assert!(check_items(&nine, known).is_ok());
        let mut ten = nine;
        ten.push(item("page", None, "/p9", true));
        assert!(check_items(&ten, known).is_err());
        let many: Vec<_> = (0..=MAX_ITEMS)
            .map(|n| item("page", None, &format!("/p{n}"), false))
            .collect();
        assert!(check_items(&many, known).is_err());
    }
}
