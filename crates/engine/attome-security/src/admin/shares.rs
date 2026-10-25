//! Record shares (D-133 (2)/(4)). record_share is one table serving
//! three purposes: explicit F137 sharing, the implicit creator-share
//! (written by entity_crud's create_record, never through this admin
//! surface), and admin-exempt deny (capability=2). This admin surface covers
//! the explicit-grant and explicit-deny cases — the implicit creator-share is
//! never listed/created/revoked here, it is entity_crud's own concern.
//!
//! Also carries entity default shares (D-133 (4)): same shape as record
//! shares, minus record_id — a blanket grant applying to every record of one
//! entity ("the Admin Team always has action on every Employee record"),
//! configured once per entity rather than once per record.
//!
//! Solution 7 Phase 1 (D-785): entity default shares are configuration and
//! are recorded (`set_entity_default_share` / `remove_entity_default_share`,
//! target `{ entity, share }` with `share` = `shared::default_share_key`).
//! Record shares are per-record access, not configuration, and are not.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::shared::{
    default_share_key, parse_owner_layer, principal_natural_key, resolve_entity_ref,
    resolve_entity_ref_and_name, security_op, snapshot_row,
};

/// `entity_default_share`'s snapshot, entity by logical key.
const DEFAULT_SHARE_SNAPSHOT: &str = "SELECT ds.id, ds.entity_ref, ei.logicalname AS entity, \
     ds.principal_type, ds.principal_id, ds.capability, ds.granted_by, ds.granted_at, \
     ds.owner_layer \
     FROM entity_default_share ds \
     JOIN entity_info ei ON ei.id = ds.entity_ref \
     WHERE ds.id = $1";

/// [`ShareRow`] plus the default share's `owner_layer`.
type DefaultShareRow = (
    Uuid,
    i16,
    Uuid,
    i16,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    String,
);
use attome_types::ErrorResponse;
use utoipa::{IntoParams, ToSchema};

/// A `record_share`/`entity_default_share` row: (id, principal_type,
/// principal_id, capability, granted_by, granted_at) — both tables share this
/// exact column shape (D-133), so `list_record_shares`/`list_entity_default_shares`
/// use the same alias.
type ShareRow = (Uuid, i16, Uuid, i16, Option<Uuid>, Option<DateTime<Utc>>);

/// Resolves a principal (`user_email` XOR `team_name`) to
/// `(principal_type, principal_id)` — 0=user, 1=team, matching
/// `record_share.principal_type`'s convention (migration 0051).
/// Exactly one of the two body fields must be set; the caller picks which
/// kind of principal by which field they populate, mirroring how
/// `grants::CreateGrantBody`/`teams::AddTeamMemberBody` already resolve
/// email → id rather than accepting a raw user_id (an admin operating this
/// API works from emails/names, not UUIDs).
pub(super) async fn resolve_principal(
    db: &attome_db::DbPool,
    user_email: Option<&str>,
    team_name: Option<&str>,
) -> Result<(i16, Uuid), AppError> {
    match (user_email, team_name) {
        (Some(email), None) => {
            let email = email.trim();
            if email.is_empty() {
                return Err(AppError::Validation("user_email must not be empty".into()));
            }
            let user_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM user_account WHERE lower(email) = lower($1)")
                    .bind(email)
                    .fetch_optional(db)
                    .await
                    .map_err(AppError::internal)?;
            let user_id = user_id.ok_or_else(|| {
                AppError::Validation(format!("no user found with email '{email}'"))
            })?;
            Ok((0, user_id))
        }
        (None, Some(name)) => {
            let name = name.trim();
            if name.is_empty() {
                return Err(AppError::Validation("team_name must not be empty".into()));
            }
            let team_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM team WHERE name = $1 AND is_deleted = false")
                    .bind(name)
                    .fetch_optional(db)
                    .await
                    .map_err(AppError::internal)?;
            let team_id = team_id
                .ok_or_else(|| AppError::Validation(format!("no team found with name '{name}'")))?;
            Ok((1, team_id))
        }
        (Some(_), Some(_)) => Err(AppError::Validation(
            "specify exactly one of user_email or team_name, not both".into(),
        )),
        (None, None) => Err(AppError::Validation(
            "specify exactly one of user_email or team_name".into(),
        )),
    }
}

/// `record_share.capability`/`entity_default_share.capability`
/// string ↔ i16 mapping for the wire format — `attome_security::rls::Capability`
/// only models `view`/`action` (the two an access *check* ever requires);
/// this admin surface also needs to accept/return `deny`, which is
/// grant-only, never a check argument.
pub(super) fn capability_to_i16(s: &str) -> Result<i16, AppError> {
    match s {
        "view" => Ok(0),
        "action" => Ok(1),
        "deny" => Ok(2),
        other => Err(AppError::Validation(format!(
            "capability must be 'view', 'action', or 'deny', got '{other}'"
        ))),
    }
}

fn capability_to_str(level: i16) -> &'static str {
    match level {
        0 => "view",
        1 => "action",
        2 => "deny",
        _ => "unknown",
    }
}

#[derive(Serialize, ToSchema)]
pub struct RecordShareItem {
    id: Uuid,
    record_id: Uuid,
    entity: String,
    principal_type: &'static str,
    principal_id: Uuid,
    capability: &'static str,
    granted_by: Option<Uuid>,
    granted_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for RecordShareItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordShareItem").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateRecordShareBody {
    entity: String,
    record_id: Uuid,
    capability: String,
    #[serde(default)]
    user_email: Option<String>,
    #[serde(default)]
    team_name: Option<String>,
}

/// Lists every share on one record — `?entity=...&record_id=...` (both
/// required; `record_id` alone is not unique across entities, matching
/// `record_share`'s own composite key shape).
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct ListRecordSharesQuery {
    /// Only this entity (its logical name).
    entity: String,
    /// Only this record.
    record_id: Uuid,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List record shares
///
/// Explicit shares and denials on individual records. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/record-shares",
    tag = "admin-security",
    params(ListRecordSharesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RecordShareItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_record_shares(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListRecordSharesQuery>,
) -> Result<Json<PaginatedResponse<RecordShareItem>>, AppError> {
    let entity_ref = resolve_entity_ref(&state.base.db, &query.entity).await?;
    let window = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let rows: Vec<ShareRow> = sqlx::query_as(
        "SELECT id, principal_type, principal_id, capability, granted_by, granted_at \
         FROM record_share WHERE record_id = $1 AND entity_ref = $2 \
         ORDER BY granted_at DESC NULLS LAST LIMIT $3 OFFSET $4",
    )
    .bind(query.record_id)
    .bind(entity_ref)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_share WHERE record_id = $1 AND entity_ref = $2",
    )
    .bind(query.record_id)
    .bind(entity_ref)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(id, principal_type, principal_id, capability, granted_by, granted_at)| {
                RecordShareItem {
                    id,
                    record_id: query.record_id,
                    entity: query.entity.clone(),
                    principal_type: if principal_type == 0 { "user" } else { "team" },
                    principal_id,
                    capability: capability_to_str(capability),
                    granted_by,
                    granted_at,
                }
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Share a record
///
/// Creates (or reactivates) a share/deny row on one record. Never touches
/// the implicit creator-share — that row is written only by
/// `entity_crud::create_record`, with `principal_id` fixed to the caller
/// who made the record; this endpoint is for every OTHER grant (F137
/// sharing, deny).
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/record-shares",
    tag = "admin-security",
    request_body = CreateRecordShareBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = RecordShareItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_record_share(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateRecordShareBody>,
) -> Result<(StatusCode, Json<RecordShareItem>), AppError> {
    let entity_ref = resolve_entity_ref(&state.base.db, &body.entity).await?;
    let capability = capability_to_i16(&body.capability)?;
    let (principal_type, principal_id) = resolve_principal(
        &state.base.db,
        body.user_email.as_deref(),
        body.team_name.as_deref(),
    )
    .await?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "record_share",
        None,
    )
    .await?;
    let row: (Uuid, Option<DateTime<Utc>>) = sqlx::query_as(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) \
         DO UPDATE SET granted_by = EXCLUDED.granted_by \
         RETURNING id, granted_at",
    )
    .bind(body.record_id)
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(row.0);
    tx.commit().await?;

    // Only a user-principal share invalidates a specific cached
    // SecurityContext directly — a team-principal share affects every
    // current/future team member, none of whose SecurityContext caches an
    // enumerable "records shared with my team" set (rls_predicate resolves
    // shares live, per-request, not into the cached context) — so nothing
    // to invalidate for the team case; the share takes effect on that
    // principal's very next request either way, since entity_crud's RLS
    // check queries record_share directly, uncached.
    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }

    Ok((
        StatusCode::CREATED,
        Json(RecordShareItem {
            id: row.0,
            record_id: body.record_id,
            entity: body.entity,
            principal_type: if principal_type == 0 { "user" } else { "team" },
            principal_id,
            capability: capability_to_str(capability),
            granted_by: Some(ctx.user_id),
            granted_at: row.1,
        }),
    ))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct ReassignOwnerBody {
    entity: String,
    record_id: Uuid,
    #[serde(default)]
    user_email: Option<String>,
    #[serde(default)]
    team_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OwnerItem {
    record_id: Uuid,
    entity: String,
    owner_type: &'static str,
    owner_id: Uuid,
}

impl std::fmt::Debug for OwnerItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerItem").finish_non_exhaustive()
    }
}

/// D-137: reassigns a record's denormalized `owner_ref`/`owner_type` columns
/// (`attome_metadata::provision::provision_table`'s generic column set — never
/// consulted by `rls_predicate`, see `attome_core::sql_ident::ALL_SYSTEM_COLS`'s
/// doc comment) and ensures the new owner holds an `action`-capability
/// `record_share` row, so reassignment also grants access — matching
/// D365's "Assign" semantics — in one transaction. Deliberately does NOT
/// touch the previous owner's existing share row: D-133 (2) already treats a
/// deactivated/former owner's leftover share as a `Team+` actor's manual
/// cleanup concern, not an automatic cascade, and this endpoint carries that
/// same posture forward rather than inventing a second policy for it.
///
/// admin-gated for now, the same scope boundary every other `record-shares`
/// mutation in this file already has — opening this to a non-admin caller who
/// merely holds `BusinessUnit+`/`Team+` `update` access on their own team's
/// records would need a dedicated `{entity}.share` privilege verb that does
/// not exist yet in the seeded four (`read`/`create`/`update`/`delete`).
/// Named here as a deliberate boundary, not a silently dropped requirement.
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/record-shares/reassign-owner",
    tag = "admin-security",
    request_body = ReassignOwnerBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::OwnerChange)])))),
    responses(
        (status = 200, description = "Success", body = OwnerItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such record", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn reassign_owner(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<ReassignOwnerBody>,
) -> Result<Json<OwnerItem>, AppError> {
    let done = reassign_owner_for(
        &state,
        ctx.user_id,
        &body.entity,
        body.record_id,
        body.user_email.as_deref(),
        body.team_name.as_deref(),
    )
    .await?;
    Ok(Json(OwnerItem {
        record_id: done.record_id,
        owner_type: done.owner_type,
        owner_id: done.owner_id,
        entity: done.entity,
    }))
}

/// The new owner of a reassigned record (N6-T2: `reassign_owner_for` is the
/// one implementation the admin route and the agent action share).
#[derive(Debug, Clone)]
pub struct Reassigned {
    pub record_id: Uuid,
    /// `user` | `team`.
    pub owner_type: &'static str,
    pub owner_id: Uuid,
    pub entity: String,
}

/// Reassigns a record's owner to a user (by email) or a team (by name), with
/// an action share for the new owner, audited as an owner change in the same
/// transaction. The caller has already checked that `actor` may do this.
pub async fn reassign_owner_for(
    state: &EngineState,
    actor: Uuid,
    entity: &str,
    record_id: Uuid,
    user_email: Option<&str>,
    team_name: Option<&str>,
) -> Result<Reassigned, AppError> {
    // Resolved via the DB's own stored copy of the logicalname, not the raw
    // request string — `canonical_entity` is what reaches dynamic SQL below,
    // never `body.entity` (guidelines §4: dynamic identifiers come from
    // validated metadata, not the request). See
    // `resolve_entity_ref_and_name`'s doc comment.
    let (entity_ref, canonical_entity) =
        resolve_entity_ref_and_name(&state.base.db, entity).await?;
    let (principal_type, principal_id) =
        resolve_principal(&state.base.db, user_email, team_name).await?;

    // `canonical_entity` is the DB's own stored `entity_info.logicalname`
    // for this row (`resolve_entity_ref_and_name` above) — the only path that
    // ever inserts such a row (`attome_metadata::provision::ensure_entity`)
    // already ran it through `valid_identifier`'s charset/length check, so
    // this is DB-confirmed safe the same way `entity_crud.rs`'s
    // registry-sourced entity names are (see that file's "entity_name is
    // DB-sourced, safe for dynamic SQL" comment). `quote_ident` still escapes
    // embedded quotes as defense in depth, same reasoning as everywhere else
    // in this codebase a validated identifier reaches raw SQL.
    let table = attome_core::quote_ident(&canonical_entity);

    let mut tx = super::shared::access_tx(
        state,
        AuditOperation::OwnerChange,
        actor,
        &canonical_entity,
        Some(record_id),
    )
    .await?;

    let rows_affected = sqlx::query(&format!(
        "UPDATE {table} \
         SET owner_ref = $1, owner_type = $2, modified_by = $3, modified_at = NOW(), \
             row_version = row_version + 1 \
         WHERE id = $4 AND is_active = true"
    ))
    .bind(principal_id)
    .bind(principal_type)
    .bind(actor)
    .bind(record_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows_affected == 0 {
        // No explicit rollback — same convention every other early-return in
        // this file's transactional handlers uses (e.g. account_state's
        // disable/enable handler): `tx` drops here, and sqlx's
        // `Transaction::drop` rolls back automatically.
        return Err(AppError::NotFound);
    }

    // Upsert (never DO NOTHING — a re-assign to the same principal must still
    // refresh granted_by) an action-capability share for the new owner. This
    // can never collide with a capability=2 (deny) row for the same
    // principal — capability is part of the conflict key, so a deny row and
    // this action row are different keys entirely and coexist; a deny still
    // overrides this grant in `rls_predicate`, same as any other allow row.
    sqlx::query(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
         VALUES ($1, $2, $3, $4, 1, $5) \
         ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) \
         DO UPDATE SET granted_by = EXCLUDED.granted_by",
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await?;

    // Same reasoning as create_record_share: only a user-principal grant
    // invalidates a specific cached SecurityContext directly.
    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }

    Ok(Reassigned {
        record_id,
        owner_type: if principal_type == 0 { "user" } else { "team" },
        owner_id: principal_id,
        entity: canonical_entity,
    })
}

/// Remove a record share
///
/// Ends one share or denial on a record. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/record-shares/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The record share")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_record_share(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(share_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "record_share",
        Some(share_id),
    )
    .await?;
    let row: Option<(i16, Uuid)> = sqlx::query_as(
        "DELETE FROM record_share WHERE id = $1 RETURNING principal_type, principal_id",
    )
    .bind(share_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (principal_type, principal_id) = row.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct EntityDefaultShareItem {
    id: Uuid,
    entity: String,
    principal_type: &'static str,
    principal_id: Uuid,
    capability: &'static str,
    granted_by: Option<Uuid>,
    granted_at: Option<DateTime<Utc>>,
    /// Solution 7 (D-785): the layer that owns this default share.
    owner_layer: String,
}

impl std::fmt::Debug for EntityDefaultShareItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityDefaultShareItem")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateEntityDefaultShareBody {
    entity: String,
    capability: String,
    #[serde(default)]
    user_email: Option<String>,
    #[serde(default)]
    team_name: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct ListEntityDefaultSharesQuery {
    /// Only this entity (its logical name).
    entity: String,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List default shares
///
/// Blanket shares that apply to every record of an entity. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/entity-default-shares",
    tag = "admin-security",
    params(ListEntityDefaultSharesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<EntityDefaultShareItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_entity_default_shares(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListEntityDefaultSharesQuery>,
) -> Result<Json<PaginatedResponse<EntityDefaultShareItem>>, AppError> {
    let entity_ref = resolve_entity_ref(&state.base.db, &query.entity).await?;
    let window = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let rows: Vec<DefaultShareRow> = sqlx::query_as(
        "SELECT id, principal_type, principal_id, capability, granted_by, granted_at, \
                owner_layer \
         FROM entity_default_share WHERE entity_ref = $1 \
         ORDER BY granted_at DESC NULLS LAST LIMIT $2 OFFSET $3",
    )
    .bind(entity_ref)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM entity_default_share WHERE entity_ref = $1")
            .bind(entity_ref)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                principal_type,
                principal_id,
                capability,
                granted_by,
                granted_at,
                owner_layer,
            )| {
                EntityDefaultShareItem {
                    id,
                    entity: query.entity.clone(),
                    principal_type: if principal_type == 0 { "user" } else { "team" },
                    principal_id,
                    capability: capability_to_str(capability),
                    granted_by,
                    granted_at,
                    owner_layer,
                }
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a default share
///
/// Shares every record of an entity with a user, team or role, configured once for the entity. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/entity-default-shares",
    tag = "admin-security",
    request_body = CreateEntityDefaultShareBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = EntityDefaultShareItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_entity_default_share(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateEntityDefaultShareBody>,
) -> Result<(StatusCode, Json<EntityDefaultShareItem>), AppError> {
    let entity_ref = resolve_entity_ref(&state.base.db, &body.entity).await?;
    let capability = capability_to_i16(&body.capability)?;
    let (principal_type, principal_id) = resolve_principal(
        &state.base.db,
        body.user_email.as_deref(),
        body.team_name.as_deref(),
    )
    .await?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "entity_default_share",
        None,
    )
    .await?;
    // Re-granting an existing share only refreshes `granted_by` (who, not
    // what): no configuration changes, so nothing is recorded and the row
    // keeps its layer.
    let existed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_default_share \
         WHERE entity_ref = $1 AND principal_type = $2 AND principal_id = $3 \
           AND capability = $4)",
    )
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row: (Uuid, Option<DateTime<Utc>>, String) = sqlx::query_as(
        "INSERT INTO entity_default_share \
            (entity_ref, principal_type, principal_id, capability, granted_by, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (entity_ref, principal_type, principal_id, capability) \
         DO UPDATE SET granted_by = EXCLUDED.granted_by \
         RETURNING id, granted_at, owner_layer",
    )
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .bind(ctx.user_id)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !existed {
        let principal = principal_natural_key(&mut tx, principal_type, principal_id).await?;
        let snapshot = snapshot_row(&mut tx, DEFAULT_SHARE_SNAPSHOT, row.0).await?;
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::SetEntityDefaultShare,
                    "entity_default_share",
                    row.0,
                    serde_json::json!({
                        "entity": body.entity,
                        "share": default_share_key(
                            principal_type,
                            &principal,
                            capability_to_str(capability),
                        ),
                    }),
                    snapshot,
                ),
            )
            .await?;
    }
    tx.event_mut().set_record_id(row.0);
    tx.commit().await?;

    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }

    Ok((
        StatusCode::CREATED,
        Json(EntityDefaultShareItem {
            id: row.0,
            entity: body.entity,
            principal_type: if principal_type == 0 { "user" } else { "team" },
            principal_id,
            capability: capability_to_str(capability),
            granted_by: Some(ctx.user_id),
            granted_at: row.1,
            owner_layer: row.2,
        }),
    ))
}

/// Remove a default share
///
/// Removes a blanket share of an entity's records. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/entity-default-shares/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The default share")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the share is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_entity_default_share(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(share_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "entity_default_share",
        Some(share_id),
    )
    .await?;
    // The share is hard-deleted, so its snapshot is taken before the DELETE.
    let live: Option<(String, String, i16)> = sqlx::query_as(
        "SELECT ds.owner_layer, ei.logicalname, ds.capability \
         FROM entity_default_share ds \
         JOIN entity_info ei ON ei.id = ds.entity_ref \
         WHERE ds.id = $1 FOR UPDATE OF ds",
    )
    .bind(share_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (owner, entity, capability) = live.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner)?)?;
    let snapshot = snapshot_row(&mut tx, DEFAULT_SHARE_SNAPSHOT, share_id).await?;
    let row: Option<(i16, Uuid)> = sqlx::query_as(
        "DELETE FROM entity_default_share WHERE id = $1 RETURNING principal_type, principal_id",
    )
    .bind(share_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (principal_type, principal_id) = row.ok_or(AppError::NotFound)?;
    let principal = principal_natural_key(&mut tx, principal_type, principal_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::RemoveEntityDefaultShare,
                "entity_default_share",
                share_id,
                serde_json::json!({
                    "entity": entity,
                    "share": default_share_key(
                        principal_type,
                        &principal,
                        capability_to_str(capability),
                    ),
                }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    if principal_type == 0 {
        state.base.security.invalidate_sync(principal_id).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/record-shares",
            get(list_record_shares).post(create_record_share),
        )
        .route(
            "/api/v1/admin/security/record-shares/{id}",
            axum::routing::delete(delete_record_share),
        )
        .route(
            // D-137: a literal path segment, matched ahead of the `{id}`
            // param route above by axum's trie-based dispatch regardless of
            // registration order — never reachable as a `{id}` value since
            // `share_id` there is a `Uuid` path param and `Path<Uuid>`
            // extraction would reject the literal string "reassign-owner"
            // with a 400 even if it somehow matched.
            "/api/v1/admin/security/record-shares/reassign-owner",
            axum::routing::put(reassign_owner),
        )
        .route(
            "/api/v1/admin/security/entity-default-shares",
            get(list_entity_default_shares).post(create_entity_default_share),
        )
        .route(
            "/api/v1/admin/security/entity-default-shares/{id}",
            axum::routing::delete(delete_entity_default_share),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_record_shares,
    create_record_share,
    delete_record_share,
    reassign_owner,
    list_entity_default_shares,
    create_entity_default_share,
    delete_entity_default_share
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
