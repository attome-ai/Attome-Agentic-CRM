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
//! Routes are admin-gated (`Authorized<Admin>`), same shape as the closest
//! sibling read surface, `schema.rs`'s `GET /api/v1/schema/{logicalname}` —
//! a dedicated "metadata read" privilege bit is reasonable future work, not
//! built here (this is a new surface, not a behavior change to an existing
//! one, so erring toward the more restrictive existing gate is the safe
//! Phase 1 default).

use attome_core::{EngineState, change_feed};
use attome_db::DbPool;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ── Catalog browse/detail routes ────────────────────────────────────────────

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
/// Entity catalogue. Administrators only.
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
    _ctx: Authorized<Admin>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<PaginatedResponse<CatalogEntitySummary>>, AppError> {
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
           ORDER BY e.logicalname
           LIMIT $4 OFFSET $5"#,
    )
    .bind(query.q.as_deref())
    .bind(query.domain)
    .bind(query.classification.as_deref())
    .bind(page_size)
    .bind(offset)
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
                 ))"#,
    )
    .bind(query.q.as_deref())
    .bind(query.domain)
    .bind(query.classification.as_deref())
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
/// One entity in the catalogue. Administrators only.
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
    _ctx: Authorized<Admin>,
    Path(logicalname): Path<String>,
) -> Result<Json<CatalogEntityDetail>, AppError> {
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
                a.required \
         FROM attribute_info a \
         WHERE a.entity_ref = $1 AND (a.is_active IS NULL OR a.is_active = true) \
         ORDER BY a.sort_order ASC, a.created_at ASC NULLS LAST, a.logicalname",
    )
    .bind(id)
    .fetch_all(meta_pool)
    .await
    .map_err(AppError::internal)?;
    let fields = field_rows
        .into_iter()
        .map(|row| {
            let logicalname = row.logicalname.unwrap_or_default();
            CatalogFieldSummary {
                display_name: row.name.unwrap_or_else(|| logicalname.clone()),
                field_type: crate::schema::int_to_type(row.field_type_int.unwrap_or(3)).to_owned(),
                logicalname,
                data_classification: row.data_classification,
                is_required: row.required.unwrap_or(false),
            }
        })
        .collect();

    // Lineage/usage/glossary all live on ordinary runtime-owned tables, not
    // the metadata bootstrap set above — the normal runtime pool, same as
    // `query_admin.rs`'s own reads of `sql_query`.
    let runtime_pool = &state.base.db;

    let lineage = attome_core::references_to_entity(runtime_pool, &logicalname, LINEAGE_LIMIT)
        .await?
        .into_iter()
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

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/catalog/entities", get(list_entities))
        .route("/api/v1/catalog/entities/{logicalname}", get(get_entity))
        .route("/api/v1/admin/lineage/impact", get(lineage_impact))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document (see `schema.rs`'s identical fragment for why this is split per
/// file).
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_entities, get_entity, lineage_impact))]
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
