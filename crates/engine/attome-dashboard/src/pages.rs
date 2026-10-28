//! D-520 / D-527 — the one canonical way to add a page to a dashboard, and the
//! editor's draft tree in a single request.
//!
//! **Why these routes exist.** A page belongs to exactly one dashboard through
//! `dashboard_page.dashboard_id` (D-520), and a page's authoring contract is
//! exactly one root grid section (D-527). Generic entity CRUD can create a page
//! row, but it cannot create the page and its root section atomically, and the
//! old editor worked around that by creating the missing section inside a
//! *read* path (`dashboard.service.ts::loadPageWidgets`). The page is now created
//! here, together with its root section, in one transaction under the
//! dashboard's lifecycle lock — the same lock publish, clone and restore hold —
//! through `layout::insert_page_node`, so it is validated against the same
//! entity metadata and emits the same change events as every other tree write.
//!
//! The draft tree (`GET .../tree`) replaces the editor's per-page/per-section
//! fan-out of generic list calls, which silently truncated at 50 pages and 200
//! sections or widgets. It returns the whole draft in one response, and refuses
//! a tree over the documented ceilings with 422 instead of cutting it short.
//! Drafts are editor data (D-521): the route requires record-level Update on the
//! dashboard, not merely Read.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;
use crate::auth::DashboardUpdate;
use crate::layout::{self, IdPolicy, SnapshotPage, SnapshotSection};

/// D-527 — the one section every page is created with.
fn root_section() -> SnapshotSection {
    SnapshotSection {
        section_type: "container".to_string(),
        layout_mode: "grid".to_string(),
        sequence: Some(0.0),
        ..Default::default()
    }
}

// ── Page creation ──────────────────────────────────────────────────────────

/// The page fields a caller may set when adding a page. `dashboard_id` is not
/// accepted — it always comes from the path — and neither are sections, which
/// the page gets exactly one of (D-527).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPageBody {
    pub name: String,
    pub name_ar: Option<String>,
    pub slug: Option<String>,
    pub sequence: Option<f64>,
    pub is_visible: Option<bool>,
    pub icon: Option<String>,
    pub settings: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedPage {
    pub id: Uuid,
    pub root_section_id: Uuid,
}

async fn ensure_dashboard_live(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dashboard_id: Uuid,
) -> Result<(), AppError> {
    let live: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM attome_dashboard \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    live.map(|_| ()).ok_or(AppError::NotFound)
}

/// Creates a page under `dashboard_id` with its root grid section, in one
/// transaction under the dashboard's lifecycle lock. `pub` for the same
/// test-ergonomics reason as `lifecycle.rs`'s `do_*` functions; performs no
/// authorization of its own.
pub async fn do_create_page(
    state: &EngineState,
    dashboard_id: Uuid,
    body: NewPageBody,
    actor_id: Uuid,
) -> Result<CreatedPage, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    crate::lifecycle::lock_dashboard(&mut tx, dashboard_id).await?;
    ensure_dashboard_live(&mut tx, dashboard_id).await?;

    let attrs = layout::resolve_tree_attrs(state).await?;
    let page = SnapshotPage {
        id: None,
        name: body.name,
        name_ar: body.name_ar,
        slug: body.slug,
        sequence: body.sequence,
        is_visible: body.is_visible,
        icon: body.icon,
        background_kind: None,
        background_value: None,
        padding: None,
        settings: body.settings,
        sections: vec![root_section()],
    };
    let (page_id, sections) = layout::insert_page_node(
        &mut tx,
        &attrs,
        dashboard_id,
        page,
        IdPolicy::GenerateNewIds,
        actor_id,
    )
    .await?;
    let root_section_id = sections
        .first()
        .copied()
        .ok_or_else(|| AppError::internal("page created without its root section"))?;
    // D-062 / audit plan 3.6: the event commits with the page or not at all.
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Update,
            "dashboard.page_create",
            actor_id,
        )
        .comment(format!(
            "page {page_id} added to dashboard {dashboard_id} with root section {root_section_id}"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(CreatedPage {
        id: page_id,
        root_section_id,
    })
}

/// Provisions the root section of an existing page that has none (D-527) —
/// the explicit repair for pages created before this route existed. Refuses
/// with 409 when the page already has any active section, and with 404 when
/// the page does not belong to `dashboard_id`.
pub async fn do_repair_root_section(
    state: &EngineState,
    dashboard_id: Uuid,
    page_id: Uuid,
    actor_id: Uuid,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    crate::lifecycle::lock_dashboard(&mut tx, dashboard_id).await?;
    ensure_dashboard_live(&mut tx, dashboard_id).await?;

    let page_live: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM dashboard_page \
         WHERE id = $1 AND dashboard_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(page_id)
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if page_live.is_none() {
        return Err(AppError::NotFound);
    }
    let sections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_section \
         WHERE page_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(page_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if sections > 0 {
        return Err(AppError::Conflict("this page already has a section"));
    }

    let attrs = layout::resolve_tree_attrs(state).await?;
    let section_id = layout::apply_section(
        &mut tx,
        &attrs,
        page_id,
        None,
        root_section(),
        IdPolicy::GenerateNewIds,
        actor_id,
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Update,
            "dashboard.page_root_section_repair",
            actor_id,
        )
        .comment(format!(
            "root section {section_id} provisioned for page {page_id}"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(section_id)
}

// ── Draft tree ─────────────────────────────────────────────────────────────

/// One row of the draft tree, in the same `{id, row_version, data}` shape the
/// generic entity list returns, so the editor can keep sending `If-Match`
/// updates through generic CRUD with the `row_version` it read here.
#[derive(Debug, Serialize, ToSchema)]
pub struct TreeRecord {
    pub id: Uuid,
    pub row_version: i64,
    #[schema(value_type = Object)]
    pub data: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DraftTree {
    pub dashboard: TreeRecord,
    /// Ordered by `sequence`, then id.
    pub pages: Vec<TreeRecord>,
    /// Every active section under those pages, ordered by `sequence`, then id.
    pub sections: Vec<TreeRecord>,
    /// Every active widget under those sections, ordered by `sequence`, then id.
    pub widgets: Vec<TreeRecord>,
    /// Pages with no active section — reported, never repaired on read
    /// (D-527); `POST .../pages/{page_id}/root-section` repairs one.
    pub pages_needing_root_section: Vec<Uuid>,
}

/// Selects one entity's rows as `{id, row_version, data}` records. Columns come
/// from the entity's live metadata with the same sensitive-field gate generic
/// CRUD applies, so this route never returns a field the caller could not read
/// through `/api/v1/{entity}`.
async fn select_tree_records(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    filter_sql: &str,
    bind: TreeBind<'_>,
) -> Result<Vec<TreeRecord>, AppError> {
    let (_, logicalname, attrs, _) =
        attome_records::entity_crud::resolve_entity(state, entity).await?;
    // D-589: dashboards are a bulk surface.
    let primary_name = state
        .entities
        .load()
        .get(&logicalname)
        .and_then(|m| m.primary_name_attribute.clone());
    let cols = attome_security::field_gate::bulk_columns(
        ctx,
        &logicalname,
        &attrs,
        primary_name.as_deref(),
    );
    let table = attome_core::quote_ident(&logicalname);
    // Ordered by the table's own `sequence` when the entity has one (the
    // dashboard record itself does not), whether or not the caller may read
    // that column; the helper column is stripped from the returned row.
    let order = if attrs.iter().any(|attr| attr.logicalname == "sequence") {
        "\"sequence\""
    } else {
        "NULL::double precision"
    };
    let sql = format!(
        "SELECT to_jsonb(r) - '__tree_order' \
         FROM (SELECT {cols}, {order} AS __tree_order FROM {table} \
             WHERE {filter_sql} AND (is_active IS NULL OR is_active = true)) r \
         ORDER BY r.__tree_order NULLS LAST, r.id"
    );
    let query = sqlx::query_scalar::<_, Value>(&sql);
    let rows = match bind {
        TreeBind::One(id) => query.bind(id).fetch_all(&state.base.db).await,
        TreeBind::Many(ids) => query.bind(ids).fetch_all(&state.base.db).await,
    }
    .map_err(AppError::internal)?;
    rows.into_iter().map(tree_record).collect()
}

enum TreeBind<'a> {
    One(Uuid),
    Many(&'a [Uuid]),
}

fn tree_record(row: Value) -> Result<TreeRecord, AppError> {
    let Value::Object(data) = row else {
        return Err(AppError::internal("tree row is not a JSON object"));
    };
    let id = data
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("tree row has no id"))?;
    let row_version = data
        .get("row_version")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    Ok(TreeRecord {
        id,
        row_version,
        data,
    })
}

async fn count(state: &EngineState, sql: &str, bind: TreeBind<'_>) -> Result<i64, AppError> {
    let query = sqlx::query_scalar::<_, i64>(sql);
    match bind {
        TreeBind::One(id) => query.bind(id).fetch_one(&state.base.db).await,
        TreeBind::Many(ids) => query.bind(ids).fetch_one(&state.base.db).await,
    }
    .map_err(AppError::internal)
}

fn over_ceiling(what: &str, found: i64, max: usize) -> Result<(), AppError> {
    if found > max as i64 {
        return Err(AppError::Validation(format!(
            "this dashboard has {found} {what}, more than the {max} a draft tree may carry"
        )));
    }
    Ok(())
}

/// Loads `dashboard_id`'s whole draft tree. Counts are checked against
/// `layout::MAX_PAGES`/`MAX_SECTIONS`/`MAX_WIDGETS` before any rows are read,
/// so an oversized tree is refused rather than truncated. Performs no
/// authorization of its own.
pub async fn do_load_draft_tree(
    state: &EngineState,
    ctx: &SecurityContext,
    dashboard_id: Uuid,
) -> Result<DraftTree, AppError> {
    let mut dashboards = select_tree_records(
        state,
        ctx,
        "attome_dashboard",
        "id = $1",
        TreeBind::One(dashboard_id),
    )
    .await?;
    let dashboard = dashboards.pop().ok_or(AppError::NotFound)?;

    let page_count = count(
        state,
        "SELECT COUNT(*) FROM dashboard_page \
         WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true)",
        TreeBind::One(dashboard_id),
    )
    .await?;
    over_ceiling("pages", page_count, layout::MAX_PAGES)?;
    let pages = select_tree_records(
        state,
        ctx,
        "dashboard_page",
        "dashboard_id = $1",
        TreeBind::One(dashboard_id),
    )
    .await?;
    let page_ids: Vec<Uuid> = pages.iter().map(|p| p.id).collect();

    let section_count = count(
        state,
        "SELECT COUNT(*) FROM dashboard_section \
         WHERE page_id = ANY($1) AND (is_active IS NULL OR is_active = true)",
        TreeBind::Many(&page_ids),
    )
    .await?;
    over_ceiling("sections", section_count, layout::MAX_SECTIONS)?;
    let sections = select_tree_records(
        state,
        ctx,
        "dashboard_section",
        "page_id = ANY($1)",
        TreeBind::Many(&page_ids),
    )
    .await?;
    let section_ids: Vec<Uuid> = sections.iter().map(|s| s.id).collect();

    let widget_count = count(
        state,
        "SELECT COUNT(*) FROM dashboard_widget \
         WHERE section_id = ANY($1) AND (is_active IS NULL OR is_active = true)",
        TreeBind::Many(&section_ids),
    )
    .await?;
    over_ceiling("widgets", widget_count, layout::MAX_WIDGETS)?;
    let widgets = select_tree_records(
        state,
        ctx,
        "dashboard_widget",
        "section_id = ANY($1)",
        TreeBind::Many(&section_ids),
    )
    .await?;

    let pages_needing_root_section = pages
        .iter()
        .filter(|page| {
            !sections.iter().any(|section| {
                section.data.get("page_id").and_then(Value::as_str)
                    == Some(page.id.to_string().as_str())
            })
        })
        .map(|page| page.id)
        .collect();

    Ok(DraftTree {
        dashboard,
        pages,
        sections,
        widgets,
        pages_needing_root_section,
    })
}

// ── HTTP surface ─────────────────────────────────────────────────────────

/// Add a page to a dashboard
///
/// Creates the page together with its root grid section in one transaction, under the dashboard's
/// lifecycle lock. Dashboard editors only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/pages",
    // `create_page` is already attome-content's operation id.
    operation_id = "create_dashboard_page",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("id" = Uuid, Path, description = "The dashboard")),
    request_body = NewPageBody,
    responses(
        (status = 201, description = "Page created with its root section", body = CreatedPage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Another request is changing this dashboard", body = ErrorResponse),
        (status = 422, description = "Invalid page fields", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_page(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(dashboard_id): Path<Uuid>,
    Json(body): Json<NewPageBody>,
) -> Result<(StatusCode, Json<CreatedPage>), AppError> {
    ctx.require_key("dashboard_page.create")?;
    require_dashboard_access(&state, &ctx, dashboard_id, RecordAction::Update).await?;
    let created = do_create_page(&state, dashboard_id, body, ctx.user_id).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepairedRootSection {
    pub id: Uuid,
}

/// Give a page its root section
///
/// Adds the root grid section to a page that has none. Needs the right to create sections. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/pages/{page_id}/root-section",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("id" = Uuid, Path, description = "The dashboard"), ("page_id" = Uuid, Path, description = "The page")),
    responses(
        (status = 201, description = "Root section provisioned", body = RepairedRootSection),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, or the page is not on it", body = ErrorResponse),
        (status = 409, description = "The page already has a section, or the dashboard is busy", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn repair_root_section(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path((dashboard_id, page_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<RepairedRootSection>), AppError> {
    ctx.require_key("dashboard_section.create")?;
    require_dashboard_access(&state, &ctx, dashboard_id, RecordAction::Update).await?;
    let id = do_repair_root_section(&state, dashboard_id, page_id, ctx.user_id).await?;
    Ok((StatusCode::CREATED, Json(RepairedRootSection { id })))
}

/// Read a dashboard's draft tree
///
/// The working copy's pages, sections and widgets in one response, for the editor. Needs update
/// rights on the dashboard.
#[utoipa::path(
    get,
    path = "/api/v1/attome-dashboard/{id}/tree",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The dashboard")),
    responses(
        (status = 200, description = "The dashboard's whole draft tree", body = DraftTree),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, or the caller may not edit it", body = ErrorResponse),
        (status = 422, description = "The tree exceeds the page, section or widget ceiling", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn draft_tree(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(dashboard_id): Path<Uuid>,
) -> Result<Json<DraftTree>, AppError> {
    require_dashboard_access(&state, &ctx, dashboard_id, RecordAction::Update).await?;
    Ok(Json(do_load_draft_tree(&state, &ctx, dashboard_id).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/attome-dashboard/{id}/pages", post(create_page))
        .route(
            "/api/v1/attome-dashboard/{id}/pages/{page_id}/root-section",
            post(repair_root_section),
        )
        .route("/api/v1/attome-dashboard/{id}/tree", get(draft_tree))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(create_page, repair_root_section, draft_tree))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
