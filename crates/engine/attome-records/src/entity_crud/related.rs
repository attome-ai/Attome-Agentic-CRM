//! M01 Core P3 gap (D-455): `GET`/`POST`/`DELETE
//! /api/v1/{entity}/{id}/related/{relationship}` — the generic record-level
//! link/unlink/list API for a named many-to-many relationship
//! (`relationship_info`).
//!
//! `{entity}`/`{id}` name one side (the route's "anchor" record); the join
//! table's OTHER column (resolved via `RelationshipDef::other_side`) names
//! the side being listed/linked/unlinked. A relationship is symmetric in
//! this API — either endpoint entity can be the route's `{entity}`, and the
//! handler resolves which physical column (`a_id`/`b_id`) is "this side" vs
//! "the other side" from the relationship definition.
//!
//! Authorization: `update` privilege + record-level access on BOTH sides is
//! required for POST (link) and DELETE (unlink) — linking two records is a
//! mutation on both of them, same reasoning `guard_cascade_dependent_access`
//! already applies to a cross-entity cascade. GET only needs `read` on both
//! sides. The anchor side uses `require_record_access` directly (same as
//! `hierarchy.rs`); the other side has no route segment naming it, so it
//! follows `require_referenced_record_access`'s shape: resolve, entity-level
//! `ctx.require`, then record-level `require_record_access`.

use attome_audit::{AuditCategory, AuditOperation};
use attome_core::{ChangeOperation, EngineState, RelationshipDef, change_feed, quote_ident};
use attome_security::record_action::{Read, Update};
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::entity_mutation::MutationResult;
use crate::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};

use super::access::require_record_access;
use super::resolve::resolve_entity;
use super::response::{EntityRecordResponse, build_response};

/// Resolves `{relationship}` to its definition and confirms `entity_name`
/// is really one of its two sides — `AppError::NotFound` for an unknown
/// name (never leaks whether a name exists to a caller with no read access
/// on either side, same posture `resolve_entity` already takes for an
/// entity name), `AppError::Validation` for a real relationship that simply
/// doesn't touch this entity (a caller error, not a lookup miss).
fn resolve_relationship(
    state: &EngineState,
    relationship: &str,
    entity_name: &str,
) -> Result<RelationshipDef, AppError> {
    let registry = state.relationships.load();
    let def = registry.get(relationship).ok_or(AppError::NotFound)?;
    if !def.is_active {
        return Err(AppError::NotFound);
    }
    if def.other_side(entity_name).is_none() {
        return Err(AppError::Validation(format!(
            "relationship '{relationship}' does not connect entity '{entity_name}'"
        )));
    }
    Ok(def.clone())
}

/// Authorizes `read`/`update` on the OTHER side's record — the side with no
/// route segment naming it. Mirrors `access::require_referenced_record_access`
/// (private to `mutations.rs`) rather than reusing it directly, since that
/// function is hardcoded to `RecordAction::Read`; link/unlink need `Update`.
async fn require_other_side_access(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    other_entity_name: &str,
    other_record_id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }
    let (other_entity_id, other_entity_name, _, _) =
        resolve_entity(state, other_entity_name).await?;
    ctx.require(&other_entity_name, action.as_str())
        .map_err(|_| AppError::NotFound)?;
    require_record_access(
        state,
        ctx,
        other_entity_id,
        &other_entity_name,
        other_record_id,
        action,
    )
    .await
}

// ── GET /api/v1/{entity}/{id}/related/{relationship} ───────────────────────

/// `GET /api/v1/{entity}/{id}/related/{relationship}` — every live record on
/// the relationship's other side currently linked (through a live join row)
/// to the anchor record, paginated. Both endpoints' `is_active` and the
/// join row's own `is_active` are filtered — this is what makes
/// "soft-deleting either side hides the link" true unconditionally,
/// independent of the relationship's `cascade` policy (metadata-only in
/// this phase — see `RelationshipCascade`'s doc comment).
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/related/{relationship}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("relationship" = String, Path),
        OnePageQuery,
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<EntityRecordResponse>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Entity, record, or relationship not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_related(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, relationship)): Path<(String, Uuid, String)>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<EntityRecordResponse>>, AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;

    let def = resolve_relationship(&state, &relationship, &entity_name)?;
    let side = def.other_side(&entity_name).ok_or(AppError::NotFound)?;
    let (other_entity_id, other_entity_name, other_attrs, _) =
        resolve_entity(&state, side.other_entity).await?;
    if !ctx.is_admin {
        ctx.require(&other_entity_name, "read")
            .map_err(|_| AppError::NotFound)?;
    }

    let window = q.window();

    let join_table = quote_ident(&def.join_table);
    let other_table = quote_ident(&other_entity_name);
    let this_col = side.this_column;
    let other_col = side.other_column;

    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        other_entity_id,
        &other_entity_name,
        RecordAction::Read,
    )
    .await?;
    let owner_visible = resolve_owner_visible(
        &state.base.db,
        ctx.user_id,
        other_entity_id,
        &other_entity_name,
        RecordAction::Read,
    )
    .await?;
    let privilege_key = format!("{other_entity_name}.read");
    let pred = rls_predicate_with_conditions(
        &ctx,
        other_entity_id,
        "t",
        access_level,
        RecordAction::Read.share_capability(),
        &privilege_key,
        &other_attrs,
        owner_visible,
        2,
    );
    let (pred_sql, next_idx) = match &pred {
        Some(p) => {
            let consumed = if p.tier_binds.is_some() {
                attome_security::RLS_BIND_COUNT
            } else {
                0
            } + p.condition_binds.len();
            (p.sql.clone(), 2 + consumed)
        }
        None => (String::new(), 2),
    };

    let cols = attome_core::select_columns_filtered(&other_attrs, |attr| {
        ctx.has_field_read_grant(&other_entity_name, &attr.logicalname)
    });

    let count_sql = format!(
        "SELECT COUNT(*) FROM {join_table} j \
         JOIN {other_table} t ON t.id = j.{other_col} \
         WHERE j.{this_col} = $1 AND j.is_active = true \
           AND (t.is_active IS NULL OR t.is_active = true) {pred_sql}"
    );
    let select_sql = format!(
        "SELECT row_to_json(t) FROM {join_table} j \
         JOIN (SELECT {cols} FROM {other_table}) t ON t.id = j.{other_col} \
         WHERE j.{this_col} = $1 AND j.is_active = true \
           AND (t.is_active IS NULL OR t.is_active = true) {pred_sql} \
         ORDER BY t.id LIMIT ${limit_idx} OFFSET ${offset_idx}",
        limit_idx = next_idx,
        offset_idx = next_idx + 1,
    );

    // sqlx's query builder has no `.bind_all(iter)` and the predicate's bind
    // set is heterogeneous (a fixed `RLS_BIND_COUNT`-tuple of typed tier
    // binds, via `bind_rls_predicate`, then a dynamic list of plain-text
    // condition binds) — the fixed half is now one shared helper
    // (`attome_security::bind_rls_predicate`) rather than hand-copied per call
    // site; only the dynamic condition loop still repeats, since its length
    // varies per request.
    let total: i64 = {
        let mut q = sqlx::query_scalar::<_, i64>(&count_sql).bind(record_id);
        if let Some(p) = &pred {
            if let Some(tb) = &p.tier_binds {
                q = bind_rls_predicate(q, tb);
            }
            for bind in &p.condition_binds {
                q = q.bind(bind);
            }
        }
        q.fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?
    };

    let mut sq = sqlx::query_scalar::<_, serde_json::Value>(&select_sql).bind(record_id);
    if let Some(p) = &pred {
        if let Some(tb) = &p.tier_binds {
            sq = bind_rls_predicate(sq, tb);
        }
        for bind in &p.condition_binds {
            sq = sq.bind(bind);
        }
    }
    let rows: Vec<serde_json::Value> = sq
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|row| {
            build_response(
                other_entity_id,
                row,
                &other_attrs,
                None,
                &ctx,
                &other_entity_name,
            )
        })
        .collect();

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

// ── POST /api/v1/{entity}/{id}/related/{relationship} (link) ───────────────
// ── DELETE /api/v1/{entity}/{id}/related/{relationship} (unlink) ───────────

#[derive(Deserialize, utoipa::ToSchema)]
pub(super) struct LinkBody {
    /// The other side's record id to link/unlink.
    id: Uuid,
}

/// `POST /api/v1/{entity}/{id}/related/{relationship}` — links the anchor
/// record to `body.id` on the relationship's other side. Idempotent
/// upsert-by-natural-key (`ON CONFLICT (a_id, b_id) DO UPDATE`): linking an
/// already-linked pair is a no-op that also reactivates a previously
/// unlinked (soft-deleted) join row, rather than erroring.
///
/// Requires `update` privilege AND record-level access on BOTH sides —
/// linking two records is a mutation on both of them, same reasoning
/// `guard_cascade_dependent_access` already applies to a cross-entity
/// cascade delete.
///
/// C-09 (M01 §7) gives this a real audit header + change-feed rows +
/// rw-pin (see the body). It does NOT stamp `modified_by`/`modified_at` on
/// the `DO UPDATE` reactivation branch below, as that item's text also
/// asks for: `attome_metadata::provision::relationship::provision_join_table`'s
/// `CREATE TABLE` never gave the join-table schema those two columns (only
/// `a_id`/`b_id`/`is_active`/`created_at`/`created_by`/`row_version`) — every
/// already-provisioned `mm_*` table in every deployment is missing
/// them too. Adding them is a real (if small) schema-evolution change in
/// `attome-metadata`, outside this fix's file scope; flagged here rather than
/// silently worked around.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/related/{relationship}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("relationship" = String, Path),
    ),
    request_body = LinkBody,
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Entity, record, or relationship not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
pub(super) async fn link_related(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, relationship)): Path<(String, Uuid, String)>,
    Json(body): Json<LinkBody>,
) -> Result<StatusCode, AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let def = resolve_relationship(&state, &relationship, &entity_name)?;
    let side = def.other_side(&entity_name).ok_or(AppError::NotFound)?;
    require_other_side_access(
        &state,
        &ctx,
        side.other_entity,
        body.id,
        RecordAction::Update,
    )
    .await?;
    // `side.other_entity` is already a DB-trusted, resolved logicalname —
    // `RelationshipDef::entity_a`/`entity_b` are populated once, at
    // relationship-creation time, via `entity_crud::resolve_entity`
    // (`relationship_admin.rs`/the bundle apply step) — so this needs no
    // second `resolve_entity` round trip just to get an owned copy for the
    // change-feed/audit calls below.
    let other_entity_name = side.other_entity.to_owned();
    crate::entity_mutation::require_metadata_table_unlocked(&state, &ctx, &def.join_table).await?;

    let join_table = quote_ident(&def.join_table);
    let this_col = side.this_column;
    let other_col = side.other_column;
    // Solution 7 (D-785): join tables that carry `owner_layer` (the role
    // join tables) lost its default in migration 0525 — stamp the Phase 1
    // auto layer, the value the default used to supply. A constant literal.
    let (layer_col, layer_val) =
        if attome_core::changeset::OWNER_LAYER_TABLES.contains(&def.join_table.as_str()) {
            (", owner_layer", ", 'project'")
        } else {
            ("", "")
        };
    let sql = format!(
        "INSERT INTO {join_table} ({this_col}, {other_col}, created_by{layer_col}) \
         VALUES ($1, $2, $3{layer_val}) \
         ON CONFLICT ({this_col}, {other_col}) \
         DO UPDATE SET is_active = true, row_version = {join_table}.row_version + 1"
    );

    // C-09 (M01 §7): a link is a real mutation, not a bare join-row write —
    // it needs the same audit/change-feed/rw-pin orchestration
    // `entity_mutation.rs`'s create/update primitives already give ordinary
    // entity writes (`entity_crud/mutations.rs`'s `create_record_for`/
    // `update_record` are the template this follows): mutate -> change-feed
    // (both endpoints) -> audit -> commit -> rw-pin.
    //
    // No dedicated `AuditOperation::Link` exists (only the numbered
    // Create/Update/SoftDelete/... range plus later appends, none named for
    // a relationship) — reusing `Create` here is deliberate, not a
    // placeholder: physically, a link is exactly an upsert-insert of the
    // join row, `AuditCategory::Relationship` (already reserved, unused
    // until now) is what actually distinguishes this from an ordinary
    // entity `Create`, and `event_name`/`event_comment` below name the
    // relationship and the other side explicitly.
    //
    // C-10: the audit-write/commit/rw-pin sequence now goes through
    // `MutationRing::commit_mutation` — the ring this comment used to say
    // "isn't built yet". No share grant, no file mirror: a relationship join
    // row is not a generic entity write either primitive applies to, so both
    // halves of `MutationSideEffects` stay `false`; `GrantInvalidation::Skip`
    // for the same reason `invalidate_privilege_grant_target` was never
    // called here before this item — a join row can never itself be the
    // `user_account_mm_privilege` entity.
    let actor = MutationActor::fetch(&state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(&sql)
        .bind(record_id)
        .bind(body.id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // Both endpoints changed from a caller's point of view (a workflow
    // entry trigger or derived index watching either entity must re-read
    // it), so both get a row — same "emit for every entity a write actually
    // touches" posture `apply_dependents_on_delete`'s cascade emit already
    // takes for a dependent record in another entity.
    change_feed::emit_tx(&mut tx, &entity_name, record_id, ChangeOperation::Update).await?;
    change_feed::emit_tx(
        &mut tx,
        &other_entity_name,
        body.id,
        ChangeOperation::Update,
    )
    .await?;

    let mut audit = MutationAudit::new();
    audit.category = AuditCategory::Relationship;
    audit.event_name = Some(relationship.clone());
    audit.event_comment = Some(format!(
        "linked {entity_name}:{record_id} to {other_entity_name}:{}",
        body.id
    ));

    MutationRing::new(&state)
        .commit_mutation(
            tx,
            &ctx,
            entity_id,
            &entity_name,
            &[],
            &actor,
            AuditOperation::Create,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::Skip,
            audit,
            "link entity_input",
            MutationResult {
                record_id,
                old_row: None,
                new_row: None,
                cascade_summary: Vec::new(),
                approval: None,
                warnings: Vec::new(),
            },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, IntoParams)]
pub(super) struct UnlinkQuery {
    /// The other side's record id to unlink.
    id: Uuid,
}

/// `DELETE /api/v1/{entity}/{id}/related/{relationship}?id=...` — unlinks
/// `?id=` from the anchor record (soft-deletes the join row: `is_active =
/// false`). A query parameter, not a JSON body: `DELETE` requests
/// conventionally carry no body, and `@attome/base`'s `ApiService.delete`
/// has never needed to send one — adding that capability there for this one
/// caller was worse than the alternative of a query-string identifier,
/// which every other id-bearing `DELETE` in this platform's contract
/// already carries in the path instead (this one can't, since the id names
/// the *other* side, not the resource path already identifies). Same
/// both-sides `update` authorization as `link_related`. `NotFound` when no
/// live join row matched (already unlinked, or never linked) — same
/// not-found-not-forbidden convention every other record-scoped mutation in
/// this module uses.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/related/{relationship}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("relationship" = String, Path),
        UnlinkQuery,
    ),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Entity, record, relationship, or live link not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::SoftDelete)])))),
)]
pub(super) async fn unlink_related(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, relationship)): Path<(String, Uuid, String)>,
    Query(q): Query<UnlinkQuery>,
) -> Result<StatusCode, AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let def = resolve_relationship(&state, &relationship, &entity_name)?;
    let side = def.other_side(&entity_name).ok_or(AppError::NotFound)?;
    require_other_side_access(&state, &ctx, side.other_entity, q.id, RecordAction::Update).await?;
    // Same "already a resolved, DB-trusted logicalname" reasoning as
    // `link_related` — see its comment.
    let other_entity_name = side.other_entity.to_owned();
    crate::entity_mutation::require_metadata_table_unlocked(&state, &ctx, &def.join_table).await?;

    let join_table = quote_ident(&def.join_table);
    let this_col = side.this_column;
    let other_col = side.other_column;
    let sql = format!(
        "UPDATE {join_table} SET is_active = false, row_version = row_version + 1 \
         WHERE {this_col} = $1 AND {other_col} = $2 AND is_active = true"
    );

    // C-09 (M01 §7) — same orchestration as `link_related`: mutate ->
    // change-feed (both endpoints) -> audit -> commit -> rw-pin, all inside
    // one transaction so a failed audit/change-feed write rolls the unlink
    // back too. C-10: the audit-write/commit/rw-pin sequence now goes
    // through `MutationRing::commit_mutation`, same as `link_related` — see
    // its comment. `MutationActor::fetch` runs unconditionally before the
    // row is known to exist, same as `mutations.rs::delete_record` does
    // before `delete_one` — the wasted round trip on the rare 404 path is
    // the existing convention, not a new cost introduced here.
    let actor = MutationActor::fetch(&state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(&sql)
        .bind(record_id)
        .bind(q.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        // Nothing live matched -- `tx` is dropped here uncommitted (rolls
        // back on Drop; there is nothing to roll back anyway, since the
        // UPDATE itself touched zero rows), and NotFound is reported, same
        // not-found-not-forbidden convention every other record-scoped
        // mutation in this module uses.
        return Err(AppError::NotFound);
    }

    change_feed::emit_tx(&mut tx, &entity_name, record_id, ChangeOperation::Update).await?;
    change_feed::emit_tx(&mut tx, &other_entity_name, q.id, ChangeOperation::Update).await?;

    let mut audit = MutationAudit::new();
    audit.category = AuditCategory::Relationship;
    audit.event_name = Some(relationship.clone());
    audit.event_comment = Some(format!(
        "unlinked {entity_name}:{record_id} from {other_entity_name}:{}",
        q.id
    ));

    MutationRing::new(&state)
        .commit_mutation(
            tx,
            &ctx,
            entity_id,
            &entity_name,
            &[],
            &actor,
            // No dedicated `AuditOperation::Unlink` exists — see
            // `link_related`'s comment on `Create`. `SoftDelete` is the same
            // reasoning mirrored: physically, an unlink is exactly a
            // soft-delete of the join row.
            AuditOperation::SoftDelete,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::Skip,
            audit,
            "unlink entity_input",
            MutationResult {
                record_id,
                old_row: None,
                new_row: None,
                cascade_summary: Vec::new(),
                approval: None,
                warnings: Vec::new(),
            },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_related, link_related, unlink_related))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
