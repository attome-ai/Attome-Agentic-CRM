use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::record_action::Read;
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::Value;
use uuid::Uuid;

use crate::entity_mutation::MAX_HIERARCHY_DEPTH;

use super::access::require_record_access;
use super::resolve::resolve_entity;
use super::response::{EntityRecordResponse, build_response};
use attome_types::ErrorResponse;

// â”€â”€ GET /api/v1/{entity}/{id}/ancestors, /descendants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// F019 â€” finds the entity's self-referencing hierarchy field: a lookup
/// attribute whose `lookup_entity_ref` is the entity's own id. Exactly one
/// is supported today (the "org/case tree" shape the plan describes) â€”
/// zero is a 422 naming the gap, and more than one is a 422 asking for the
/// (currently unbuilt) disambiguation a `?field=` query param would need,
/// rather than silently guessing which hierarchy the caller meant.
///
/// D23-T3: `field` names which self lookup to walk (a contact's `reports_to`
/// or its dotted-line manager), and must be one; without it the entity must
/// have exactly one.
pub(crate) fn hierarchy_field<'a>(
    entity_id: Uuid,
    attrs: &'a [AttrInfo],
    field: Option<&str>,
) -> Result<&'a AttrInfo, AppError> {
    let is_self_lookup =
        |a: &&AttrInfo| a.field_type_int == 11 && a.lookup_entity_ref == Some(entity_id);
    if let Some(name) = field {
        return attrs
            .iter()
            .filter(is_self_lookup)
            .find(|a| a.logicalname == name)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "field: {name} is not a lookup from this entity to itself"
                ))
            });
    }
    let mut candidates = attrs.iter().filter(is_self_lookup);
    let field = candidates.next().ok_or_else(|| {
        AppError::Validation("entity has no self-referencing hierarchy lookup field".into())
    })?;
    if candidates.next().is_some() {
        return Err(AppError::Validation(
            "entity has more than one self-referencing lookup field; name one with ?field=".into(),
        ));
    }
    Ok(field)
}

/// Shared by `list_ancestors`/`list_descendants`: runs `sql` (a `WITH
/// RECURSIVE` query already shaped to select `row_to_json(t)` per matched
/// row, ordered by hierarchy depth) and builds the same response shape a
/// single-record read would, minus the tombstone/`lookups` enrichment
/// (`resolve_lookup_meta`) â€” a deliberate simplification: a hierarchy walk
/// can return many rows, and that enrichment is one extra query per row.
///
/// D-102 follow-up: each caller's final join now sources the row from
/// `(SELECT {cols} FROM {table}) t` instead of bare `{table} t`, `{cols}`
/// built by the same `attome_core::select_columns(&attrs, ctx.is_admin)`
/// `get_record` uses â€” the recursive CTE definition itself is untouched
/// (it only ever needs `id`/the hierarchy field/`depth` to walk the graph,
/// never the full row, and structural traversal must see every row
/// regardless of field-level visibility; only the final row-fetch join is
/// privilege-projected). Unverified against a live Postgres in this
/// session â€” see this repo's `/testing` skill before trusting it in
/// production; a wrong column reference here would surface as a query error
/// on first real use, not silently.
async fn hierarchy_rows(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    attrs: &[AttrInfo],
    sql: &str,
    record_id: Uuid,
) -> Result<Vec<EntityRecordResponse>, AppError> {
    let pool = state.base.read_pool(ctx.user_id).await;

    // D-133 follow-up: the recursive walk above deliberately reads the raw
    // table (structural traversal must see every row), but the final
    // row-fetch join was never record-level filtered â€” only field-level
    // (`select_columns_filtered`). Without this, a narrowed-access caller
    // who can see the starting record could still receive ancestors/
    // descendants they have no record-level access to. $1/$2 are always
    // `record_id`/`MAX_HIERARCHY_DEPTH` in both callers' SQL, so the
    // predicate's placeholders start at $3; both callers' final SELECT ends
    // in a `WHERE ...` clause the fragment (`AND (...)`) can append to.
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity_name,
        RecordAction::Read,
    )
    .await?;
    let owner_visible = resolve_owner_visible(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity_name,
        RecordAction::Read,
    )
    .await?;
    let privilege_key = format!("{entity_name}.read");
    let rls = rls_predicate_with_conditions(
        ctx,
        entity_id,
        "t",
        access_level,
        RecordAction::Read.share_capability(),
        &privilege_key,
        attrs,
        owner_visible,
        3,
    );
    let sql = match &rls {
        Some(pred) => sql.replacen(
            "ORDER BY chain.depth",
            &format!("{} ORDER BY chain.depth", pred.sql),
            1,
        ),
        None => sql.to_owned(),
    };

    let sql = attome_db::tag_dynamic("entity.hierarchy", &sql);
    let mut q = sqlx::query_scalar(&sql)
        .bind(record_id)
        .bind(MAX_HIERARCHY_DEPTH as i32);
    if let Some(pred) = &rls {
        if let Some(tb) = &pred.tier_binds {
            q = bind_rls_predicate(q, tb);
        }
        for bind in &pred.condition_binds {
            q = q.bind(bind);
        }
    }
    let rows: Vec<Value> = q.fetch_all(pool).await.map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|row| build_response(entity_id, row, attrs, None, ctx, entity_name))
        .collect())
}

/// D23-T3: which self lookup a hierarchy walk follows.
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HierarchyQuery {
    /// The self-referencing lookup to walk; needed when the entity has more
    /// than one.
    pub field: Option<String>,
}

/// A record's ancestors
///
/// P-api-contract Phase 4(b): returns `attome_types::PaginatedResponse<T>`
/// instead of a bare `{"items": [...]}` — a genuine breaking response-shape
/// change for any existing client (see DECISIONS.md and the CHANGELOG
/// **Breaking** entry this session added). This endpoint has no `page`/
/// `page_size` *request* parameter — it always walks the full chain up to
/// `MAX_HIERARCHY_DEPTH` in one shot — so honest pagination metadata here
/// means "page 1 of 1, everything returned": `total` is the actual row count
/// returned (never a separate, un-fetched count), `page_size` is the
/// structural ceiling (`MAX_HIERARCHY_DEPTH`), not a caller-chosen value.
/// This does NOT add offset/cursor paging semantics nobody asked for — see
/// the plan's own Phase 4 gating discussion for why that would have been a
/// bigger, undesired change (a `page_size` with no way to request page 2).
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/ancestors",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        HierarchyQuery,
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<EntityRecordResponse>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_ancestors(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    axum::extract::Query(hq): axum::extract::Query<HierarchyQuery>,
) -> Result<Json<PaginatedResponse<EntityRecordResponse>>, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;
    let field = hierarchy_field(entity_id, &attrs, hq.field.as_deref())?;

    let table = quote_ident(&entity_name);
    let field_ident = quote_ident(&field.logicalname);
    // `chain` walks depth-by-depth from the given record ($1) up to
    // MAX_HIERARCHY_DEPTH ($2) steps; `chain.id` at depth N is the Nth
    // ancestor's own id (depth 0 is the starting record itself, excluded
    // below), so joining back to the table by that id fetches each
    // ancestor's full row, nearest-first. The recursive `chain` definition
    // reads the real `{table}` unprojected (structural walk, needs every
    // row regardless of field visibility); only the final row-fetch join
    // (D-102) sources from a privilege-projected subquery, since that's the
    // one whose output actually becomes `row_to_json(t)`.
    let cols = attome_core::select_columns_filtered(&attrs, |attr| {
        ctx.has_field_read_grant(&entity_name, &attr.logicalname)
    });
    let sql = format!(
        "WITH RECURSIVE chain AS ( \
            SELECT id, {field_ident} AS parent_id, 0 AS depth FROM {table} WHERE id = $1 \
            UNION ALL \
            SELECT t.id, t.{field_ident}, chain.depth + 1 \
            FROM {table} t JOIN chain ON t.id = chain.parent_id \
            WHERE chain.depth < $2 \
         ) \
         SELECT row_to_json(t) FROM chain JOIN (SELECT {cols} FROM {table}) t ON t.id = chain.id \
         WHERE chain.depth > 0 AND (t.is_active IS NULL OR t.is_active = true) \
         ORDER BY chain.depth"
    );

    let items = hierarchy_rows(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        &sql,
        record_id,
    )
    .await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_HIERARCHY_DEPTH as i64,
    )))
}

/// A record's descendants
///
/// See `list_ancestors`'s doc comment (P-api-contract Phase 4(b)) — same
/// "page 1 of 1, everything returned" reasoning applies here.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/descendants",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        HierarchyQuery,
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<EntityRecordResponse>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_descendants(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    axum::extract::Query(hq): axum::extract::Query<HierarchyQuery>,
) -> Result<Json<PaginatedResponse<EntityRecordResponse>>, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;
    let field = hierarchy_field(entity_id, &attrs, hq.field.as_deref())?;

    let table = quote_ident(&entity_name);
    let field_ident = quote_ident(&field.logicalname);
    // `chain` starts at the given record's direct children (depth 0: rows
    // whose hierarchy field equals $1) and walks downward â€” every row this
    // recursion ever adds is by construction a descendant, so unlike
    // ancestors there's no self-row to exclude. Same D-102 split as
    // `list_ancestors`: the recursive `chain` definition stays unprojected
    // (structural walk), only the final row-fetch join is privilege-projected.
    let cols = attome_core::select_columns_filtered(&attrs, |attr| {
        ctx.has_field_read_grant(&entity_name, &attr.logicalname)
    });
    let sql = format!(
        "WITH RECURSIVE chain AS ( \
            SELECT id, 0 AS depth FROM {table} \
             WHERE {field_ident} = $1 AND (is_active IS NULL OR is_active = true) \
            UNION ALL \
            SELECT t.id, chain.depth + 1 \
            FROM {table} t JOIN chain ON t.{field_ident} = chain.id \
            WHERE chain.depth < $2 AND (t.is_active IS NULL OR t.is_active = true) \
         ) \
         SELECT row_to_json(t) FROM chain JOIN (SELECT {cols} FROM {table}) t ON t.id = chain.id \
         WHERE 1 = 1 \
         ORDER BY chain.depth"
    );

    let items = hierarchy_rows(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        &sql,
        record_id,
    )
    .await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_HIERARCHY_DEPTH as i64,
    )))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
/// `GET /api/v1/{entity}/{id}/move-preview`.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MovePreviewQuery {
    /// The new parent; absent to move the record to the root.
    pub parent: Option<Uuid>,
}

/// What moving a record (with everything under it) would do.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct MovePreview {
    /// The record and its descendants: every record that moves.
    pub moving: i64,
    /// Whether the move would be accepted.
    pub allowed: bool,
    /// Why not, when it would be refused: `cycle` (the new parent is the
    /// record or under it) or `too_deep` (the tree would pass the depth cap).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<&'static str>,
}

/// Why a move would be refused, from the subtree's size and height and the
/// new parent's depth. `None` when it would be accepted.
pub fn move_refusal(
    parent_in_subtree: bool,
    parent_depth: i32,
    subtree_height: i32,
) -> Option<&'static str> {
    if parent_in_subtree {
        Some("cycle")
    } else if parent_depth + 1 + subtree_height >= MAX_HIERARCHY_DEPTH as i32 {
        Some("too_deep")
    } else {
        None
    }
}

/// Preview a move
///
/// A17-T4: what moving a record under `parent` would do, without moving
/// anything: how many records go with it (the record and its descendants),
/// and whether the move would be refused for a cycle or the depth cap.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/move-preview",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), MovePreviewQuery),
    responses(
        (status = 200, description = "What the move would do", body = MovePreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "The entity has no hierarchy", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn move_preview(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    axum::extract::Query(query): axum::extract::Query<MovePreviewQuery>,
) -> Result<Json<MovePreview>, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;
    let field = hierarchy_field(entity_id, &attrs, None)?;
    let table = quote_ident(&entity_name);
    let field_ident = quote_ident(&field.logicalname);
    let (moving, parent_in_subtree, height): (i64, bool, i32) =
        sqlx::query_as(&attome_db::tag_dynamic(
            "entity.hierarchy",
            &format!(
                "WITH RECURSIVE subtree(id, depth) AS ( \
             SELECT id, 0 FROM {table} WHERE id = $1 \
             UNION ALL \
             SELECT c.id, s.depth + 1 FROM {table} c JOIN subtree s ON c.{field_ident} = s.id \
             WHERE s.depth < $2 AND (c.is_active IS NULL OR c.is_active = true) \
         ) \
         SELECT count(*), COALESCE(bool_or(id = $3), false), COALESCE(max(depth), 0) FROM subtree"
            ),
        ))
        .bind(record_id)
        .bind(MAX_HIERARCHY_DEPTH as i32)
        .bind(query.parent)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let parent_depth: i32 = match query.parent {
        None => -1,
        Some(parent) => sqlx::query_scalar(&attome_db::tag_dynamic("entity.hierarchy", &format!(
            "WITH RECURSIVE chain(id, depth) AS ( \
                 SELECT {field_ident}, 0 FROM {table} WHERE id = $1 \
                 UNION ALL \
                 SELECT t.{field_ident}, chain.depth + 1 FROM {table} t JOIN chain ON t.id = chain.id \
                 WHERE chain.depth < $2 \
             ) \
             SELECT COALESCE(max(depth), 0) FROM chain WHERE id IS NOT NULL"
        )))
        .bind(parent)
        .bind(MAX_HIERARCHY_DEPTH as i32)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?,
    };
    let refusal = move_refusal(parent_in_subtree, parent_depth, height);
    Ok(Json(MovePreview {
        moving,
        allowed: refusal.is_none(),
        refusal,
    }))
}

#[cfg(test)]
mod move_tests {
    use super::*;

    #[test]
    fn a_move_is_refused_into_its_own_subtree_or_past_the_depth_cap() {
        assert_eq!(move_refusal(true, 0, 0), Some("cycle"));
        assert_eq!(move_refusal(false, 2, 3), None);
        let cap = MAX_HIERARCHY_DEPTH as i32;
        assert_eq!(move_refusal(false, cap - 2, 1), Some("too_deep"));
        assert_eq!(move_refusal(false, -1, 0), None);
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_ancestors, list_descendants, move_preview))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
