//! M18 Data Catalog Phase 1 (D-466) — `GET /api/v1/catalog/entities`
//! (search/browse) and `GET /api/v1/catalog/entities/{logicalname}`
//! (aggregated detail: schema summary, lineage, usage, glossary terms), plus
//! two background jobs this catalog's data depends on:
//!
//! * [`run_dashboard_lineage_sweep`] — `EngineJob::CatalogDashboardLineageSweep`'s
//!   handler. `dashboard_widget` is a generic-CRUD entity (no bespoke
//!   save handler `query_admin.rs`'s writer could hook the way
//!   `attome-workflow`'s publish handler is hooked — see migration `0356`'s
//!   header), so its lineage is derived off the entity-change-feed outbox
//!   instead: every widget create/update event is resolved to its
//!   `query_id`'s already-recorded query lineage and copied under
//!   `from_kind = "dashboard"`. This also naturally backfills every
//!   pre-existing widget with no separate one-shot job, because the outbox
//!   cursor starts at the beginning of history — see this function's own
//!   doc for why that is safe here.
//! * [`run_usage_rollup`] — `EngineJob::CatalogUsageRollup`'s handler.
//!   Nightly per-entity snapshot (record count, last write, 30-day search
//!   impressions) into `catalog_usage_rollup` (migration `0358`),
//!   read by the entity-detail endpoint below.
//!
//! L4-T3: the two catalogue routes need the `metadata.read` privilege (an
//! administrator holds every privilege) and show only what the caller may
//! read: entities they may read, and of those entities the attributes they
//! may read (a sensitive attribute needs its field read grant). A hidden
//! attribute is never named, not in the fields, not in the lineage. With the
//! setting `catalog.show_hidden_existence` on (off by default) a hidden
//! attribute is listed by its name only, marked `hidden` so the screen can
//! offer to request access. The lineage impact route stays administrators'.

use attome_core::{EngineState, change_feed};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::ErrorResponse;
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, OnePageQuery, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header::IF_MATCH},
    routing::{get, patch, post},
};

use crate::catalog_index;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ── Catalog browse/detail routes ────────────────────────────────────────────

/// L4-T3: the privilege the catalogue routes need.
pub const METADATA_READ: &str = "metadata.read";

/// L4-T3: whether a hidden attribute is listed by name, marked hidden.
const SHOW_HIDDEN_SETTING: &str = "catalog.show_hidden_existence";

/// The entities `ctx` may read, by logical name; `None` for an
/// administrator, who may read every one.
fn readable_entities(state: &EngineState, ctx: &SecurityContext) -> Option<Vec<String>> {
    if ctx.is_admin {
        return None;
    }
    let registry = state.entities.load();
    Some(
        registry
            .iter()
            .map(|meta| meta.logicalname.as_str())
            .filter(|name| ctx.require(name, "read").is_ok())
            .map(str::to_owned)
            .collect(),
    )
}

/// Whether `ctx` may read attribute `field` of `entity`: any attribute that
/// is not sensitive, a sensitive one with its field read grant. Pure.
fn attribute_readable(
    ctx: &SecurityContext,
    entity: &str,
    field: &str,
    is_sensitive: bool,
) -> bool {
    !is_sensitive || ctx.is_admin || ctx.has_field_read_grant(entity, field)
}

fn show_hidden_existence(state: &EngineState) -> bool {
    attome_core::setting_registry()
        .get(SHOW_HIDDEN_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct CatalogListQuery {
    /// Matches against logicalname or display name, case-insensitive substring.
    q: Option<String>,
    /// `data_domain.id` (M15) — restricts to entities assigned to
    /// this domain.
    domain: Option<Uuid>,
    /// `attribute_info.data_classification` (`0087`) — restricts
    /// to entities with at least one attribute at this classification.
    classification: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
struct CatalogEntitySummary {
    id: Uuid,
    logicalname: String,
    name: Option<String>,
    category: Option<String>,
    domain_ref: Option<Uuid>,
}

/// Entity catalogue
///
/// Entity catalogue: the entities the caller may read. Needs `metadata.read`.
#[utoipa::path(
    get,
    path = "/api/v1/catalog/entities",
    operation_id = "list_catalog_entities",
    tag = "catalog",
    // Disambiguates from `admin::entity::list_entities` — utoipa defaults an
    // operation id to the function name, and both crates happened to name
    // their handler identically. Pre-existing collision, unrelated to this
    // module; fixed incidentally here because it broke `ng build` for every
    // consumer of the generated OpenAPI types, not just this file's own.
    operation_id = "catalog_list_entities",
    params(CatalogListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<CatalogEntitySummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_entities(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<PaginatedResponse<CatalogEntitySummary>>, AppError> {
    ctx.require_key(METADATA_READ)?;
    let readable = readable_entities(&state, &ctx);
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );
    // Metadata bootstrap tables — same "admin-gated route, use the migrator
    // pool" convention `schema.rs`'s own `get_schema` documents (attome_readonly
    // cannot SELECT entity_info/attribute_info).
    let pool = &state.base.db_migrator;

    let items: Vec<CatalogEntitySummary> = sqlx::query_as(
        r#"SELECT e.id, e.logicalname, e.name, e.category, e.domain_ref
           FROM entity_info e
           WHERE (e.is_active IS NULL OR e.is_active = true)
             AND ($1::text IS NULL OR e.logicalname ILIKE '%' || $1 || '%'
                                    OR e.name ILIKE '%' || $1 || '%')
             AND ($2::uuid IS NULL OR e.domain_ref = $2)
             AND ($3::varchar IS NULL OR EXISTS (
                   SELECT 1 FROM attribute_info a
                   WHERE a.entity_ref = e.id
                     AND (a.is_active IS NULL OR a.is_active = true)
                     AND a.data_classification = $3
                 ))
             AND ($6::text[] IS NULL OR e.logicalname = ANY($6))
           ORDER BY e.logicalname
           LIMIT $4 OFFSET $5"#,
    )
    .bind(query.q.as_deref())
    .bind(query.domain)
    .bind(query.classification.as_deref())
    .bind(page_size)
    .bind(offset)
    .bind(readable.as_deref())
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM entity_info e
           WHERE (e.is_active IS NULL OR e.is_active = true)
             AND ($1::text IS NULL OR e.logicalname ILIKE '%' || $1 || '%'
                                    OR e.name ILIKE '%' || $1 || '%')
             AND ($2::uuid IS NULL OR e.domain_ref = $2)
             AND ($3::varchar IS NULL OR EXISTS (
                   SELECT 1 FROM attribute_info a
                   WHERE a.entity_ref = e.id
                     AND (a.is_active IS NULL OR a.is_active = true)
                     AND a.data_classification = $3
                 ))
             AND ($4::text[] IS NULL OR e.logicalname = ANY($4))"#,
    )
    .bind(query.q.as_deref())
    .bind(query.domain)
    .bind(query.classification.as_deref())
    .bind(readable.as_deref())
    .fetch_one(pool)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Serialize, ToSchema)]
struct CatalogFieldSummary {
    logicalname: String,
    display_name: String,
    field_type: String,
    data_classification: String,
    is_required: bool,
    /// L4-T3: listed by name only because the caller may not read it (only
    /// when the deployment shows hidden attributes; ask for access).
    hidden: bool,
}

#[derive(Serialize, ToSchema)]
struct CatalogLineageEntry {
    /// `"query" | "workflow" | "dashboard" | "rule"` — see migration `0356`.
    from_kind: String,
    from_ref: Uuid,
    from_label: String,
    /// `None` for an entity-level reference (0356's empty-string sentinel).
    to_attribute: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
struct CatalogUsage {
    record_count: i64,
    last_write_at: Option<DateTime<Utc>>,
    search_impressions_30d: i64,
    computed_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct CatalogGlossaryTerm {
    id: Uuid,
    term: String,
    definition: String,
    status: String,
}

#[derive(Serialize, ToSchema)]
struct CatalogEntityDetail {
    id: Uuid,
    logicalname: String,
    name: Option<String>,
    category: Option<String>,
    domain_ref: Option<Uuid>,
    fields: Vec<CatalogFieldSummary>,
    lineage: Vec<CatalogLineageEntry>,
    usage: Option<CatalogUsage>,
    glossary_terms: Vec<CatalogGlossaryTerm>,
}

/// Bounds the lineage panel — this backs a UI detail page, not an export
/// (same reasoning `attome_core::references_to_entity`'s own doc gives).
const LINEAGE_LIMIT: i64 = 200;

#[derive(sqlx::FromRow)]
struct EntityInfoRow {
    id: Uuid,
    name: Option<String>,
    category: Option<String>,
    domain_ref: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct AttributeSummaryRow {
    logicalname: Option<String>,
    name: Option<String>,
    field_type_int: Option<i32>,
    data_classification: String,
    required: Option<bool>,
    is_sensitive: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct GlossaryTermRow {
    id: Uuid,
    term: Option<String>,
    definition: Option<String>,
    status: Option<String>,
}

/// One entity in the catalogue
///
/// One entity in the catalogue, with the attributes the caller may read.
/// Needs `metadata.read` and read access to the entity.
#[utoipa::path(
    get,
    path = "/api/v1/catalog/entities/{logicalname}",
    operation_id = "get_catalog_entity",
    tag = "catalog",
    // See `list_entities`'s own comment above — same collision, this time
    // with `admin::entity::get_entity`.
    operation_id = "catalog_get_entity",
    params(("logicalname" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "Success", body = CatalogEntityDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Entity not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_entity(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(logicalname): Path<String>,
) -> Result<Json<CatalogEntityDetail>, AppError> {
    ctx.require_key(METADATA_READ)?;
    // An entity the caller may not read is as absent as one that is not there.
    if !ctx.is_admin && ctx.require(&logicalname, "read").is_err() {
        return Err(AppError::NotFound);
    }
    let show_hidden = show_hidden_existence(&state);
    let meta_pool = &state.base.db_migrator;

    let entity_row: Option<EntityInfoRow> = sqlx::query_as(
        "SELECT id, name, category, domain_ref FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&logicalname)
    .fetch_optional(meta_pool)
    .await
    .map_err(AppError::internal)?;
    let EntityInfoRow {
        id,
        name,
        category,
        domain_ref,
    } = entity_row.ok_or(AppError::NotFound)?;

    let field_rows: Vec<AttributeSummaryRow> = sqlx::query_as(
        "SELECT a.logicalname, a.name, a.\"type\" AS field_type_int, a.data_classification, \
                a.required, a.is_sensitive \
         FROM attribute_info a \
         WHERE a.entity_ref = $1 AND (a.is_active IS NULL OR a.is_active = true) \
         ORDER BY a.sort_order ASC, a.created_at ASC NULLS LAST, a.logicalname",
    )
    .bind(id)
    .fetch_all(meta_pool)
    .await
    .map_err(AppError::internal)?;
    let entity_name = logicalname.clone();
    let mut hidden_names: Vec<String> = Vec::new();
    let fields = field_rows
        .into_iter()
        .filter_map(|row| {
            let logicalname = row.logicalname.unwrap_or_default();
            if attribute_readable(
                &ctx,
                &entity_name,
                &logicalname,
                row.is_sensitive.unwrap_or(false),
            ) {
                return Some(CatalogFieldSummary {
                    display_name: row.name.unwrap_or_else(|| logicalname.clone()),
                    field_type: crate::schema::int_to_type(row.field_type_int.unwrap_or(3))
                        .to_owned(),
                    logicalname,
                    data_classification: row.data_classification,
                    is_required: row.required.unwrap_or(false),
                    hidden: false,
                });
            }
            hidden_names.push(logicalname.clone());
            // L4-T3: by name only, when the deployment shows that it exists.
            show_hidden.then(|| CatalogFieldSummary {
                display_name: logicalname.clone(),
                field_type: String::new(),
                logicalname,
                data_classification: String::new(),
                is_required: false,
                hidden: true,
            })
        })
        .collect();

    // Lineage/usage/glossary all live on ordinary runtime-owned tables, not
    // the metadata bootstrap set above — the normal runtime pool, same as
    // `query_admin.rs`'s own reads of `sql_query`.
    let runtime_pool = &state.base.db;

    let lineage = attome_core::references_to_entity(runtime_pool, &logicalname, LINEAGE_LIMIT)
        .await?
        .into_iter()
        // A hidden attribute is never named through its lineage.
        .filter(|r| !hidden_names.contains(&r.to_attribute))
        .map(|r| CatalogLineageEntry {
            from_kind: r.from_kind,
            from_ref: r.from_ref,
            from_label: r.from_label,
            to_attribute: if r.to_attribute.is_empty() {
                None
            } else {
                Some(r.to_attribute)
            },
            created_at: r.created_at,
        })
        .collect();

    // `CatalogUsage` doubles as its own row type (its shape already matches
    // `catalog_usage_rollup` column-for-column) — no separate tuple
    // needed.
    let usage: Option<CatalogUsage> = sqlx::query_as(
        "SELECT record_count, last_write_at, search_impressions_30d, computed_at \
         FROM catalog_usage_rollup WHERE entity_logicalname = $1",
    )
    .bind(&logicalname)
    .fetch_optional(runtime_pool)
    .await
    .map_err(AppError::internal)?;

    // `glossary_term` is itself a generic-CRUD entity (glossary_seed.rs)
    // — an ordinary runtime-pool read, same as any other entity table.
    let glossary_rows: Vec<GlossaryTermRow> = sqlx::query_as(
        "SELECT id, term, definition, status FROM glossary_term \
         WHERE primary_entity_logicalname = $1 AND is_active IS NOT FALSE \
         ORDER BY term",
    )
    .bind(&logicalname)
    .fetch_all(runtime_pool)
    .await
    .map_err(AppError::internal)?;
    let glossary_terms = glossary_rows
        .into_iter()
        .map(|row| CatalogGlossaryTerm {
            id: row.id,
            term: row.term.unwrap_or_default(),
            definition: row.definition.unwrap_or_default(),
            status: row.status.unwrap_or_default(),
        })
        .collect();

    Ok(Json(CatalogEntityDetail {
        id,
        logicalname,
        name,
        category,
        domain_ref,
        fields,
        lineage,
        usage,
        glossary_terms,
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ImpactQuery {
    /// Only this entity (its logical name).
    entity: String,
    /// The attribute; without it, the change is to the entity.
    attribute: Option<String>,
    /// `delete`, `retype`, `rename` or `other` (the default).
    change: Option<String>,
    /// Edges walked downstream, 1 to 10 (default 5).
    depth: Option<u8>,
}

/// Impact of a draft change
///
/// The impact of a draft change, for the publish preview.
///
/// L5-T3: every definition downstream of the change in the lineage graph
/// (direct uses at depth 1, then what uses those), and the ones it would
/// break: a deleted or retyped attribute read, derived from or written by a
/// definition no field hook adjusts (dashboards, metrics, model
/// definitions). Deleting or retyping the field is refused with the same
/// list. Items the caller may not see are counted in `hidden`.
#[utoipa::path(
    get,
    path = "/api/v1/admin/lineage/impact",
    tag = "admin",
    params(ImpactQuery),
    responses(
        (status = 200, description = "The impact report", body = attome_core::lineage::impact::ImpactReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown change, or depth out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn lineage_impact(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ImpactQuery>,
) -> Result<Json<attome_core::lineage::impact::ImpactReport>, AppError> {
    use attome_core::lineage::impact::{ChangeKind, DEFAULT_DEPTH, MAX_DEPTH, MetadataChange};
    let kind = match q.change.as_deref().unwrap_or("other") {
        "delete" => ChangeKind::DeleteAttribute,
        "retype" => ChangeKind::ChangeAttributeType,
        "rename" => ChangeKind::RenameAttribute,
        "other" => ChangeKind::Other,
        _ => {
            return Err(AppError::Validation(
                "change is delete, retype, rename or other".into(),
            ));
        }
    };
    let depth = q.depth.unwrap_or(DEFAULT_DEPTH);
    if !(1..=MAX_DEPTH).contains(&depth) {
        return Err(AppError::Validation(format!("depth is 1 to {MAX_DEPTH}")));
    }
    let change = MetadataChange {
        entity: q.entity,
        attribute: q.attribute.filter(|a| !a.is_empty()),
        kind,
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    // Administrators see every definition.
    let report =
        attome_core::lineage::impact::impact(&mut conn, &[change], depth, |_, _| true).await?;
    Ok(Json(report))
}

// ── L4-T4: the asset catalogue ──────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct AssetSearchQuery {
    /// Words matched against names and descriptions in English and Arabic.
    q: Option<String>,
    /// One asset kind (`entity`, `attribute`, `view`, …).
    kind: Option<String>,
    /// One data domain.
    domain: Option<Uuid>,
    /// One label.
    label: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// A page of assets with the facet counts.
#[derive(Serialize, ToSchema)]
struct CatalogAssetSearch {
    #[serde(flatten)]
    page: PaginatedResponse<catalog_index::CatalogAssetSummary>,
    facets: catalog_index::CatalogFacets,
}

/// `If-Match`'s row version, required.
fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match is required".into()))?;
    raw.to_str()
        .ok()
        .map(|s| s.trim().trim_matches('"'))
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AppError::Validation("If-Match must be the asset's row_version".into()))
}

/// Search the catalogue
///
/// The assets the caller may see (entities and attributes they may read,
/// and every other kind), best match first, with counts by kind, domain and
/// label. Needs `metadata.read`.
#[utoipa::path(
    get,
    path = "/api/v1/catalog/assets",
    operation_id = "catalog_search_assets",
    tag = "catalog",
    params(AssetSearchQuery),
    responses(
        (status = 200, description = "A page of assets and the facet counts", body = CatalogAssetSearch),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks metadata.read", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn search_assets(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<AssetSearchQuery>,
) -> Result<Json<CatalogAssetSearch>, AppError> {
    ctx.require_key(METADATA_READ)?;
    let window = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );
    let scope = catalog_index::asset_scope(&state, &ctx);
    let filter = catalog_index::AssetFilter {
        q: query.q,
        kind: query.kind,
        domain: query.domain,
        label: query.label,
    };
    let (items, total, facets) =
        catalog_index::search_assets(&state, &scope, &filter, window.page_size, window.offset)
            .await?;
    Ok(Json(CatalogAssetSearch {
        page: PaginatedResponse::new(items, total, window.page, window.page_size),
        facets,
    }))
}

/// One asset's page
///
/// The asset with its domain, label, glossary terms, quality, profile,
/// lineage, usage, certification and history; a fact whose feature this
/// deployment lacks is null. Needs `metadata.read` and sight of the asset.
#[utoipa::path(
    get,
    path = "/api/v1/catalog/assets/{id}",
    operation_id = "catalog_get_asset",
    tag = "catalog",
    params(("id" = Uuid, Path, description = "The asset")),
    responses(
        (status = 200, description = "The asset page", body = catalog_index::CatalogAssetPage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks metadata.read", body = ErrorResponse),
        (status = 404, description = "No such asset the caller may see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_asset(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<catalog_index::CatalogAssetPage>, AppError> {
    ctx.require_key(METADATA_READ)?;
    let scope = catalog_index::asset_scope(&state, &ctx);
    Ok(Json(catalog_index::asset_page(&state, &scope, id).await?))
}

/// Propose an asset's description
///
/// Sets the English and/or Arabic description of an asset the caller may
/// see; it is a draft until a builder approves it. Send the asset's
/// `row_version` in `If-Match`. Needs `metadata.read`.
#[utoipa::path(
    patch,
    path = "/api/v1/catalog/assets/{id}/description",
    operation_id = "catalog_set_description",
    tag = "catalog",
    params(
        ("id" = Uuid, Path, description = "The asset"),
        ("If-Match" = String, Header, description = "The asset's row_version"),
    ),
    request_body = catalog_index::CatalogDescriptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The drafted description", body = catalog_index::CatalogAssetSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks metadata.read", body = ErrorResponse),
        (status = 404, description = "No such asset the caller may see", body = ErrorResponse),
        (status = 409, description = "The asset changed since it was read", body = ErrorResponse),
        (status = 422, description = "A missing If-Match, no description, or one too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn patch_description(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<catalog_index::CatalogDescriptionBody>,
) -> Result<Json<catalog_index::CatalogAssetSummary>, AppError> {
    ctx.require_key(METADATA_READ)?;
    let expected = if_match(&headers)?;
    let scope = catalog_index::asset_scope(&state, &ctx);
    Ok(Json(
        catalog_index::set_description(&state, &ctx, &scope, id, expected, &body).await?,
    ))
}

/// Approve an asset's description
///
/// Marks a drafted description reviewed. Builders (administrators) only.
/// Send the asset's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/catalog/assets/{id}/description/approve",
    operation_id = "catalog_approve_description",
    tag = "catalog",
    params(
        ("id" = Uuid, Path, description = "The asset"),
        ("If-Match" = String, Header, description = "The asset's row_version"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The approved description", body = catalog_index::CatalogAssetSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such asset", body = ErrorResponse),
        (status = 409, description = "The asset changed, or its description is not a draft", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn approve_description(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<catalog_index::CatalogAssetSummary>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        catalog_index::approve_description(&state, &ctx, id, expected).await?,
    ))
}

/// Ask for access to an asset
///
/// Records why the caller needs access (and the role, when they know it)
/// for the asset's owner to decide. One pending request per person and
/// asset. Needs `metadata.read`.
#[utoipa::path(
    post,
    path = "/api/v1/catalog/assets/{id}/access-requests",
    operation_id = "catalog_request_access",
    tag = "catalog",
    params(("id" = Uuid, Path, description = "The asset")),
    request_body = catalog_index::CatalogAccessRequestBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Submitted)])))),
    responses(
        (status = 200, description = "The request", body = catalog_index::CatalogAccessRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks metadata.read", body = ErrorResponse),
        (status = 404, description = "No such asset", body = ErrorResponse),
        (status = 409, description = "The caller already has a pending request for it", body = ErrorResponse),
        (status = 422, description = "No reason, or one too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_access_request(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<catalog_index::CatalogAccessRequestBody>,
) -> Result<Json<catalog_index::CatalogAccessRequest>, AppError> {
    ctx.require_key(METADATA_READ)?;
    Ok(Json(
        catalog_index::request_access(&state, &ctx, id, &body).await?,
    ))
}

/// Decide an access request
///
/// The asset's owner (an administrator, or the steward or deputy of its data
/// domain) grants a role or refuses. A grant takes the same path as the
/// admin role assignment: step-up, the grant ceiling and the approval gate,
/// so a gated grant waits for a second administrator.
#[utoipa::path(
    post,
    path = "/api/v1/catalog/access-requests/{id}/decide",
    operation_id = "catalog_decide_access",
    tag = "catalog",
    params(("id" = Uuid, Path, description = "The access request")),
    request_body = catalog_index::CatalogAccessDecisionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant),
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Rejected),
    ])))),
    responses(
        (status = 200, description = "The decided request", body = catalog_index::CatalogAccessRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The role carries privileges the owner lacks, or step-up is needed", body = ErrorResponse),
        (status = 404, description = "No such request the caller owns", body = ErrorResponse),
        (status = 409, description = "The request is already decided", body = ErrorResponse),
        (status = 422, description = "A grant without a role", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn decide_access_request(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    Path(id): Path<Uuid>,
    Json(body): Json<catalog_index::CatalogAccessDecisionBody>,
) -> Result<Json<catalog_index::CatalogAccessRequest>, AppError> {
    Ok(Json(
        catalog_index::decide_access(&state, caller, &ctx, id, &body).await?,
    ))
}

/// Export the catalogue
///
/// Every asset's metadata (names, descriptions, domain, label,
/// certification; never record values) for a harvester such as Purview or
/// Collibra. Administrators only, and only while `catalog.export_enabled`
/// is on (404 otherwise).
#[utoipa::path(
    get,
    path = "/api/v1/catalog/export",
    operation_id = "catalog_export",
    tag = "catalog",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of the catalogue", body = PaginatedResponse<catalog_index::CatalogExportAsset>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "The export is turned off", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_catalog(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<catalog_index::CatalogExportAsset>>, AppError> {
    let window = query.window();
    let (items, total) =
        catalog_index::export_assets(&state, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/catalog/entities", get(list_entities))
        .route("/api/v1/catalog/entities/{logicalname}", get(get_entity))
        .route("/api/v1/admin/lineage/impact", get(lineage_impact))
        // L4-T4: the asset catalogue.
        .route("/api/v1/catalog/assets", get(search_assets))
        .route("/api/v1/catalog/assets/{id}", get(get_asset))
        .route(
            "/api/v1/catalog/assets/{id}/description",
            patch(patch_description),
        )
        .route(
            "/api/v1/catalog/assets/{id}/description/approve",
            post(approve_description),
        )
        .route(
            "/api/v1/catalog/assets/{id}/access-requests",
            post(post_access_request),
        )
        .route(
            "/api/v1/catalog/access-requests/{id}/decide",
            post(decide_access_request),
        )
        .route("/api/v1/catalog/export", get(export_catalog))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document (see `schema.rs`'s identical fragment for why this is split per
/// file).
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_entities,
    get_entity,
    lineage_impact,
    search_assets,
    get_asset,
    patch_description,
    approve_description,
    post_access_request,
    decide_access_request,
    export_catalog
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Dashboard-widget lineage sweep (EngineJob::CatalogDashboardLineageSweep) ─

/// `change_consumer_cursor.consumer` key — see `attome_core::
/// change_feed`'s module doc for the non-destructive per-consumer cursor
/// model every consumer added from D-358 onward uses.
const DASHBOARD_LINEAGE_CONSUMER: &str = "catalog/dashboard-lineage";
const DASHBOARD_LINEAGE_BATCH: i64 = 500;

#[derive(Default, Debug)]
pub struct DashboardLineageStats {
    pub events_processed: usize,
    pub widgets_synced: usize,
}

/// `EngineJob::CatalogDashboardLineageSweep`'s handler. Because the
/// outbox cursor for this brand-new consumer starts at the very beginning
/// of `entity_change_event` (never time-windowed —
/// `change_feed::read_batch`'s own doc), the very first ticks after this
/// ships walk every `dashboard_widget` create/update event ever
/// recorded, which is exactly a historical backfill with no separate job
/// needed — see migration `0356`'s header for why dashboards, alone among
/// the four `from_kind`s, don't need an entry in the
/// `metadata_reference_backfill_progress` table.
pub async fn run_dashboard_lineage_sweep(
    state: &EngineState,
) -> Result<DashboardLineageStats, AppError> {
    let mut stats = DashboardLineageStats::default();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = change_feed::read_batch(
        &mut conn,
        DASHBOARD_LINEAGE_CONSUMER,
        DASHBOARD_LINEAGE_BATCH,
    )
    .await?;
    if events.is_empty() {
        return Ok(stats);
    }

    let mut seen = std::collections::HashSet::new();
    for event in &events {
        stats.events_processed += 1;
        // P10-T1: a metric's own lineage (what it reads) follows its
        // definition, on the same sweep.
        if event.entity_logicalname == "dashboard_metric_definition" {
            if !seen.insert(event.record_id) {
                continue;
            }
            if let Err(e) =
                attome_metric::lineage_graph::sync_metric_lineage(&state.base.db, event.record_id)
                    .await
            {
                tracing::warn!(
                    metric_id = %event.record_id,
                    error = %e,
                    "catalog lineage sweep: syncing one metric failed, continuing"
                );
            }
            continue;
        }
        if event.entity_logicalname != "dashboard_widget" {
            continue;
        }
        if !seen.insert(event.record_id) {
            continue;
        }
        if let Err(e) = sync_widget_lineage(state, event.record_id).await {
            // One widget's sync failing (a transient DB error, a widget
            // deleted mid-batch) must not stall the whole sweep — same "one
            // record's failure doesn't stop the tick" posture
            // `duplicates_match::run_match_sweep` takes for the same reason.
            tracing::warn!(
                widget_id = %event.record_id,
                error = %e,
                "catalog dashboard lineage sweep: syncing one widget failed, continuing"
            );
            continue;
        }
        stats.widgets_synced += 1;
    }

    if let Some(last) = events.last() {
        change_feed::advance(&mut conn, DASHBOARD_LINEAGE_CONSUMER, last).await?;
    }
    Ok(stats)
}

/// Recomputes `from_kind = "dashboard"` lineage for one widget from its
/// CURRENT row: copies whatever `metadata_reference` already holds
/// for `from_kind = "query"`/`from_ref = widget.query_id` (the query's own
/// writer, `query_admin::write_catalog_lineage`, already derived that set
/// correctly — re-deriving it a second time here from raw SQL would be a
/// second implementation of the same lint). A widget with no `query_id`
/// (a metric-backed widget, `widget_registry.rs`'s doc) or one that no
/// longer exists (deleted, or deactivated) gets an empty reference set,
/// which `replace_references` turns into "delete any lineage rows this
/// widget previously had" — the correct "current state, not audit history"
/// behavior 0356's header documents.
async fn sync_widget_lineage(state: &EngineState, widget_id: Uuid) -> Result<(), AppError> {
    let row: Option<(Option<String>, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT name, query_id, to_jsonb(w) FROM dashboard_widget w \
         WHERE id = $1 AND is_active = true",
    )
    .bind(widget_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let (label, refs): (String, Vec<attome_core::MetadataReferenceInput>) = match row {
        None => (String::new(), Vec::new()),
        Some((name, query_id, widget)) => {
            let mut refs = match query_id.as_deref().map(Uuid::parse_str) {
                Some(Ok(query_id)) => {
                    attome_core::references_from(&state.base.db, "query", query_id).await?
                }
                _ => Vec::new(),
            };
            // P10-T1: a KPI widget references the metrics it shows.
            refs.extend(
                attome_dashboard::execution::kpi_metric_refs(&widget)
                    .into_iter()
                    .map(attome_core::MetadataReferenceInput::metric),
            );
            (name.unwrap_or_default(), refs)
        }
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_core::replace_references(&mut tx, "dashboard", widget_id, &label, &refs).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// P10-T1: one bounded batch of the backfill that records which metrics
/// existing dashboard widgets show (widgets saved before widget lineage
/// carried metrics), kind `dashboard-metrics`, keyset-paginated by id; 0 once
/// complete. Each widget's whole lineage is rewritten, as the sweep does.
pub async fn backfill_widget_metric_lineage(
    state: &EngineState,
    batch_limit: i64,
) -> Result<usize, AppError> {
    const KIND: &str = "dashboard-metrics";
    let db = &state.base.db;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let progress = attome_core::backfill_progress(&mut conn, KIND).await?;
    if progress.completed {
        return Ok(0);
    }
    let cursor = progress.last_ref.unwrap_or(Uuid::nil());
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM dashboard_widget WHERE id > $1 AND is_active = true ORDER BY id LIMIT $2",
    )
    .bind(cursor)
    .bind(batch_limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    drop(conn);
    let mut last = cursor;
    for id in &ids {
        sync_widget_lineage(state, *id).await?;
        last = *id;
    }
    let completed = (ids.len() as i64) < batch_limit;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    attome_core::advance_backfill_progress(&mut conn, KIND, last, ids.len() as i64, completed)
        .await?;
    Ok(ids.len())
}

// ── Usage rollup (EngineJob::CatalogUsageRollup) ──────────────────────────

#[derive(Default, Debug)]
pub struct UsageRollupStats {
    pub entities_computed: usize,
}

/// `EngineJob::CatalogUsageRollup`'s handler — nightly per-entity snapshot
/// into `catalog_usage_rollup` (migration `0358`). A plain UPSERT
/// per entity, same shape 0358's header compares it to
/// (`api_usage`'s rollup) — never on the request path.
pub async fn run_usage_rollup(db: &DbPool) -> Result<UsageRollupStats, AppError> {
    let mut stats = UsageRollupStats::default();
    let entities: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info WHERE is_active IS NULL OR is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for entity in &entities {
        // Metadata-sourced identifier (just read from entity_info
        // above), quoted through the established helper before reaching
        // dynamic SQL — guidelines §4.
        let table = attome_core::quote_ident(entity);
        let usage_row: Result<(i64, Option<DateTime<Utc>>), sqlx::Error> = sqlx::query_as(
            &format!("SELECT COUNT(*), MAX(modified_at) FROM {table} WHERE is_active = true"),
        )
        .fetch_one(db)
        .await;
        // A logicalname registered in entity_info but whose
        // physical table provisioning is somehow incomplete/missing must
        // not abort the whole nightly rollup for every other entity — skip
        // and continue, same posture the dashboard sweep takes per-widget.
        let (record_count, last_write_at) = match usage_row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    entity = %entity,
                    error = %e,
                    "catalog usage rollup: counting one entity failed, continuing"
                );
                continue;
            }
        };

        let impressions_30d: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM search_impression_row r \
             JOIN search_impression i ON i.id = r.impression_ref \
             WHERE r.entity_logicalname = $1 AND i.created_at > NOW() - INTERVAL '30 days'",
        )
        .bind(entity)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;

        sqlx::query(
            "INSERT INTO catalog_usage_rollup \
                (entity_logicalname, record_count, last_write_at, search_impressions_30d, computed_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (entity_logicalname) DO UPDATE SET \
                record_count = EXCLUDED.record_count, \
                last_write_at = EXCLUDED.last_write_at, \
                search_impressions_30d = EXCLUDED.search_impressions_30d, \
                computed_at = EXCLUDED.computed_at",
        )
        .bind(entity)
        .bind(record_count)
        .bind(last_write_at)
        .bind(impressions_30d)
        .execute(db)
        .await
        .map_err(AppError::internal)?;

        stats.entities_computed += 1;
    }

    Ok(stats)
}
