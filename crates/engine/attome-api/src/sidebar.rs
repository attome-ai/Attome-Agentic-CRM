use attome_core::EngineState;
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_modules::MODULE_MAP;
use attome_security::SecurityContextExt;
use attome_security::context::SidebarManage;
use attome_server::authz::{AdminArea, Authorized, Privilege, SelfService};
use attome_server::security::SecurityContext;
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, patch},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin_hooks as hooks;
use crate::bundle::model::SidebarDef;
use attome_core::changeset::{Op, RecordedOp, Recording, RecordingCtx};
use attome_records::query_admin::{
    ReconcileStep, customized_marker, map_unique_violation, reconcile_step,
};

/// `sidebar` row: (id, name, route, icon, color, parent_ref, display_order, module_key, is_disabled).
type SidebarRow = (
    Uuid,
    String,
    String,
    String,
    String,
    Option<Uuid>,
    i32,
    Option<String>,
    bool,
);

/// True when `module_key` is unset, or names a currently-enabled license
/// module. An unrecognized name (shouldn't happen — `validate_mutation`
/// rejects anything not in `MODULE_MAP` before it can be stored) fails open
/// rather than permanently hiding a misconfigured item with no way to tell
/// why from the UI.
fn module_visible(active: &attome_modules::ModuleSet, module_key: &Option<String>) -> bool {
    match module_key {
        None => true,
        Some(name) => MODULE_MAP
            .iter()
            .find(|(known, _)| known == name)
            .is_none_or(|(_, id)| active.has(*id)),
    }
}

/// Q10-T11: what opening a menu item's page needs, so the menu shows an item
/// exactly when the API behind its page admits the caller.
#[derive(Debug, PartialEq, Eq)]
enum RouteGate {
    /// Nothing beyond the item's own privilege links.
    Open,
    /// `{entity}.read`, the check the record routes make.
    Entity(String),
    /// The administration area the page's API requires (Q12-T2).
    Area(AdminArea),
    /// `system.admin`: an admin page with no area of its own.
    Admin,
}

/// The area each `/xrm/admin/...` page's API requires, by the first path
/// segments; the longest match wins. An admin page not listed needs
/// `system.admin`, so a new page stays hidden from delegated administrators
/// until it is listed.
const ADMIN_ROUTE_GATES: &[(&str, Option<AdminArea>)] = &[
    ("approvals", Some(AdminArea::Automation)),
    ("audit", Some(AdminArea::Audit)),
    ("branding", Some(AdminArea::Deployment)),
    ("caches", Some(AdminArea::Deployment)),
    ("calendars", Some(AdminArea::Automation)),
    ("changes", Some(AdminArea::Integrations)),
    ("config-starts", Some(AdminArea::Security)),
    ("console", Some(AdminArea::Deployment)),
    ("content", Some(AdminArea::Communication)),
    ("data/catalog", Some(AdminArea::Compliance)),
    ("data/quality", Some(AdminArea::DataModel)),
    ("data-protection", Some(AdminArea::Compliance)),
    ("dependencies", Some(AdminArea::Deployment)),
    ("entities", Some(AdminArea::DataModel)),
    ("jobs", Some(AdminArea::Deployment)),
    ("knowledge", Some(AdminArea::Ai)),
    ("license", Some(AdminArea::Deployment)),
    ("ops", Some(AdminArea::Deployment)),
    ("portals", Some(AdminArea::Users)),
    ("profiler", Some(AdminArea::Deployment)),
    ("queries", Some(AdminArea::DataModel)),
    ("rules", Some(AdminArea::Automation)),
    ("s2s", Some(AdminArea::Security)),
    ("search", Some(AdminArea::DataModel)),
    ("secrets", Some(AdminArea::Security)),
    ("security", Some(AdminArea::Roles)),
    ("security/impersonation", Some(AdminArea::Security)),
    ("security/mfa", Some(AdminArea::Users)),
    ("security/record-shares", Some(AdminArea::Security)),
    ("security/users", Some(AdminArea::Users)),
    // Self-service: the caller's own resolved access.
    ("security/whoami", None),
    ("settings", Some(AdminArea::Deployment)),
    // Gated by its `sidebar.manage` link, like its routes.
    ("sidebar", None),
    ("slo", Some(AdminArea::Deployment)),
    ("state-models", Some(AdminArea::Automation)),
    ("timers", Some(AdminArea::Deployment)),
    ("views", Some(AdminArea::DataModel)),
    ("webcrawl", Some(AdminArea::Integrations)),
    ("workflow", Some(AdminArea::Automation)),
];

fn route_gate(route: &str) -> RouteGate {
    if let Some(rest) = route.strip_prefix("/xrm/entity/") {
        return match rest.split('/').next() {
            Some(entity) if !entity.is_empty() => RouteGate::Entity(entity.to_owned()),
            _ => RouteGate::Open,
        };
    }
    let Some(page) = route.strip_prefix("/xrm/admin/") else {
        return RouteGate::Open;
    };
    let page = page.split(['?', '#']).next().unwrap_or_default();
    ADMIN_ROUTE_GATES
        .iter()
        .filter(|(prefix, _)| {
            page == *prefix
                || page
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|(prefix, _)| prefix.len())
        .map_or(RouteGate::Admin, |(_, area)| {
            area.map_or(RouteGate::Open, RouteGate::Area)
        })
}

/// Whether `ctx` may open the page at `route` (Q10-T11).
fn route_visible(ctx: &SecurityContext, route: &str) -> bool {
    if ctx.is_admin {
        return true;
    }
    match route_gate(route) {
        RouteGate::Open => true,
        RouteGate::Entity(entity) => ctx.allows(&entity, "read"),
        RouteGate::Area(area) => area.held_by(ctx),
        RouteGate::Admin => false,
    }
}

/// Drops groups (no route of their own) left with nothing to open.
fn prune_empty_groups(items: &mut Vec<SidebarItem>) {
    for item in items.iter_mut() {
        prune_empty_groups(&mut item.child);
    }
    items.retain(|item| !item.route.is_empty() || !item.child.is_empty());
}

#[derive(Serialize, ToSchema)]
pub struct SidebarItem {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub color: String,
    pub route: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_disabled: bool,
    /// The nav tree is one level deep in practice but the type is recursive,
    /// so utoipa needs `no_recursion` to stop expanding it inline — without
    /// it, building the document recurses until the stack overflows. The
    /// emitted schema still carries the `$ref` back to `SidebarItem`, so a
    /// generated client keeps the recursive type.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(no_recursion)]
    pub child: Vec<SidebarItem>,
}

impl std::fmt::Debug for SidebarItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarItem").finish_non_exhaustive()
    }
}

/// D-792 (FLEET-CONSOLE-DESIGN.md §7.2) — a serve-time addition to
/// `GET /api/v1/sidebar/get`, for a menu group that must never be stored in
/// `sidebar` (so no customer database ever carries a dead link to it).
/// The only implementer is the fleet console's, registered by the gated boot
/// path in `crates/server`; without it the answer is exactly the stored menu.
pub trait SidebarContributor: Send + Sync + 'static {
    /// Items appended after the stored menu's roots for this caller. Called
    /// once per request; must not block.
    fn contribute(&self, is_admin: bool) -> Vec<SidebarItem>;
}

/// The request extension `get_sidebar` reads: the composition root layers
/// `Extension(SidebarContributions(..))` onto the app when a contributor is
/// registered. Absent, nothing is added.
#[derive(Clone)]
pub struct SidebarContributions(pub Arc<dyn SidebarContributor>);

impl std::fmt::Debug for SidebarContributions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarContributions")
            .finish_non_exhaustive()
    }
}

/// Appends every contributed item after the stored menu (D-792).
fn append_contributions(
    items: &mut Vec<SidebarItem>,
    contributions: Option<&SidebarContributions>,
    is_admin: bool,
) {
    if let Some(contributions) = contributions {
        items.extend(contributions.0.contribute(is_admin));
    }
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct SidebarAdminItem {
    pub id: Uuid,
    pub name: String,
    pub route: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub parent_ref: Option<Uuid>,
    pub display_order: i32,
    pub is_active: bool,
    pub is_disabled: bool,
    pub row_version: i64,
    pub module_key: Option<String>,
    pub privilege_ids: Vec<Uuid>,
    /// Solution 7 (D-785) — the layer that owns this item: `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer
    /// may update or deactivate it (409 `layer_mismatch` otherwise).
    pub owner_layer: String,
}

impl std::fmt::Debug for SidebarAdminItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarAdminItem").finish_non_exhaustive()
    }
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct SidebarPrivilegeItem {
    pub id: Uuid,
    pub key: String,
    pub name: String,
}

impl std::fmt::Debug for SidebarPrivilegeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarPrivilegeItem")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SidebarMutation {
    pub name: String,
    pub route: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub parent_ref: Option<Uuid>,
    pub display_order: i32,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub is_disabled: bool,
    pub row_version: Option<i64>,
    #[serde(default)]
    pub module_key: Option<String>,
    #[serde(default)]
    pub privilege_ids: Vec<Uuid>,
}

impl std::fmt::Debug for SidebarMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarMutation").finish_non_exhaustive()
    }
}

fn default_true() -> bool {
    true
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn validate_mutation(body: &mut SidebarMutation) -> Result<(), AppError> {
    body.name = body.name.trim().to_owned();
    body.route = clean_optional(body.route.take());
    body.icon = clean_optional(body.icon.take());
    body.color = clean_optional(body.color.take());
    body.module_key = clean_optional(body.module_key.take());

    if body.name.is_empty() || body.name.len() > 120 {
        return Err(AppError::Validation(
            "name must contain between 1 and 120 characters".into(),
        ));
    }
    if let Some(route) = &body.route
        && (!route.starts_with('/') || route.len() > 500)
    {
        return Err(AppError::Validation(
            "route must be an application-relative path beginning with '/'".into(),
        ));
    }
    if body.icon.as_ref().is_some_and(|v| v.len() > 120) {
        return Err(AppError::Validation("icon is too long".into()));
    }
    if body.color.as_ref().is_some_and(|v| v.len() > 32) {
        return Err(AppError::Validation("color is too long".into()));
    }
    if let Some(module_key) = &body.module_key
        && !MODULE_MAP.iter().any(|(known, _)| known == module_key)
    {
        return Err(AppError::Validation(format!(
            "unknown module: {module_key}"
        )));
    }
    Ok(())
}

/// List sidebar items
///
/// List sidebar items. Needs the sidebar management privilege.
#[utoipa::path(
    get,
    path = "/api/v1/sidebar/admin",
    tag = "sidebar",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SidebarAdminItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_sidebar_admin(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<SidebarManage>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SidebarAdminItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let items = sqlx::query_as::<_, SidebarAdminItem>(
        "SELECT s.id, s.name, s.route, s.icon, s.color, s.parent_ref, s.display_order,
                s.is_active, s.is_disabled, s.row_version, s.module_key,
                COALESCE(array_agg(sp.privilege_ref) FILTER (WHERE sp.privilege_ref IS NOT NULL),
                         ARRAY[]::uuid[]) AS privilege_ids,
                s.owner_layer
         FROM sidebar s
         LEFT JOIN sidebar_mm_privilege sp
           ON sp.sidebar_ref = s.id AND sp.is_deleted = false
         WHERE s.is_deleted = false
         GROUP BY s.id
         ORDER BY s.display_order, s.name
         LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sidebar s WHERE s.is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Unpaginated fetch of every sidebar item, for internal reuse by the
/// mutation handlers below (find-just-written-item-by-id, and the
/// deactivate handler's whole-tree refresh) — sidebar counts are bounded
/// (an admin-authored nav tree, not a per-record list), so unlike
/// `list_sidebar_admin`'s public paginated contract, these callers need the
/// full set, not one page of it.
async fn fetch_all_sidebar_admin_items(
    db: &attome_db::DbPool,
) -> Result<Vec<SidebarAdminItem>, AppError> {
    sqlx::query_as::<_, SidebarAdminItem>(
        "SELECT s.id, s.name, s.route, s.icon, s.color, s.parent_ref, s.display_order,
                s.is_active, s.is_disabled, s.row_version, s.module_key,
                COALESCE(array_agg(sp.privilege_ref) FILTER (WHERE sp.privilege_ref IS NOT NULL),
                         ARRAY[]::uuid[]) AS privilege_ids,
                s.owner_layer
         FROM sidebar s
         LEFT JOIN sidebar_mm_privilege sp
           ON sp.sidebar_ref = s.id AND sp.is_deleted = false
         WHERE s.is_deleted = false
         GROUP BY s.id
         ORDER BY s.display_order, s.name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// One sidebar item in the admin shape, read inside `tx` — the post-write
/// snapshot a recorded op carries and the create/update response.
async fn read_sidebar_item_in_tx(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
) -> Result<SidebarAdminItem, AppError> {
    sqlx::query_as::<_, SidebarAdminItem>(
        "SELECT s.id, s.name, s.route, s.icon, s.color, s.parent_ref, s.display_order,
                s.is_active, s.is_disabled, s.row_version, s.module_key,
                COALESCE(array_agg(sp.privilege_ref) FILTER (WHERE sp.privilege_ref IS NOT NULL),
                         ARRAY[]::uuid[]) AS privilege_ids,
                s.owner_layer
         FROM sidebar s
         LEFT JOIN sidebar_mm_privilege sp
           ON sp.sidebar_ref = s.id AND sp.is_deleted = false
         WHERE s.id = $1 AND s.is_deleted = false
         GROUP BY s.id",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The item's root-first name path joined with `/` (`SidebarDef::path`,
/// its logical key, D-374), read inside `tx`. Bounded at 64 levels so a
/// corrupt parent cycle cannot loop.
async fn sidebar_path_in_tx(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<String, AppError> {
    let path: Option<String> = sqlx::query_scalar(
        "WITH RECURSIVE chain AS (
             SELECT id, parent_ref, name, 0 AS depth FROM sidebar WHERE id = $1
             UNION ALL
             SELECT s.id, s.parent_ref, s.name, c.depth + 1
             FROM sidebar s JOIN chain c ON s.id = c.parent_ref
             WHERE c.depth < 64
         )
         SELECT string_agg(name, '/' ORDER BY depth DESC) FROM chain",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    path.ok_or(AppError::NotFound)
}

/// Locks the non-deleted item `id` and applies the owner-layer rule (D-785
/// §1). `None` when there is no such item (each caller maps that to its own
/// established status); 409 `layer_mismatch` when another layer owns it.
async fn lock_sidebar_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<Option<()>, AppError> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM sidebar WHERE id = $1 AND is_deleted = false FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    match owner {
        None => Ok(None),
        Some(owner) => hooks::check_row_owner(recording, &owner).map(Some),
    }
}

/// The recorded op for a sidebar item: target `{path: "<root>/…/<name>"}`.
async fn sidebar_op(
    tx: &mut attome_db::Tx<'_>,
    op: Op,
    item: &SidebarAdminItem,
) -> Result<RecordedOp, AppError> {
    let path = sidebar_path_in_tx(tx, item.id).await?;
    hooks::recorded(
        op,
        "sidebar_item",
        item.id,
        serde_json::json!({ "path": path }),
        item,
    )
}

/// Privileges for sidebar items
///
/// Privileges for sidebar items. Needs the sidebar management privilege.
#[utoipa::path(
    get,
    path = "/api/v1/sidebar/admin/privileges",
    tag = "sidebar",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SidebarPrivilegeItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_sidebar_privileges(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<SidebarManage>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SidebarPrivilegeItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let items = sqlx::query_as::<_, SidebarPrivilegeItem>(
        "SELECT id, key, name FROM privilege WHERE is_active = true
         ORDER BY key LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privilege WHERE is_active = true")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

async fn replace_privileges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sidebar_id: Uuid,
    privilege_ids: &[Uuid],
) -> Result<(), AppError> {
    let unique: std::collections::HashSet<Uuid> = privilege_ids.iter().copied().collect();
    if unique.len() != privilege_ids.len() {
        return Err(AppError::Validation(
            "privilege assignments contain duplicates".into(),
        ));
    }
    if !unique.is_empty() {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM privilege WHERE id = ANY($1) AND is_active = true",
        )
        .bind(privilege_ids)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if count != privilege_ids.len() as i64 {
            return Err(AppError::Validation(
                "one or more assigned privileges do not exist or are inactive".into(),
            ));
        }
    }
    sqlx::query("DELETE FROM sidebar_mm_privilege WHERE sidebar_ref = $1")
        .bind(sidebar_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    for privilege_id in privilege_ids {
        sqlx::query(
            "INSERT INTO sidebar_mm_privilege (sidebar_ref, privilege_ref) VALUES ($1, $2)",
        )
        .bind(sidebar_id)
        .bind(privilege_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn ensure_parent(db: &attome_db::DbPool, parent_ref: Option<Uuid>) -> Result<(), AppError> {
    let Some(parent_id) = parent_ref else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sidebar WHERE id = $1 AND is_deleted = false)",
    )
    .bind(parent_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::Validation(
            "parent sidebar item does not exist".into(),
        ));
    }
    Ok(())
}

/// Create a sidebar item
///
/// Create a sidebar item. Needs the sidebar management privilege. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sidebar/admin",
    tag = "sidebar",
    request_body = SidebarMutation,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Success", body = SidebarAdminItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_sidebar_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SidebarManage>>,
    recording: RecordingCtx,
    Json(mut body): Json<SidebarMutation>,
) -> Result<Json<SidebarAdminItem>, AppError> {
    validate_mutation(&mut body)?;
    ensure_parent(&state.base.db, body.parent_ref).await?;
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let item = create_sidebar_item_in_tx(&mut tx, &recording, &body).await?;
    // D-541 rule 4: sidebar items are shared navigation configuration; the
    // event commits with the change (D-062).
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "sidebar",
            Some(item.id),
        )
        .named("sidebar.create"),
    )
    .await?;
    let op = sidebar_op(&mut tx, Op::UpsertSidebarItem, &item).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(item))
}

/// The admin create's write, transaction-scoped (D-785 §3: one
/// implementation per write, shared with the changeset applier). `body` must
/// already have passed `validate_mutation` and `ensure_parent`.
pub(crate) async fn create_sidebar_item_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    body: &SidebarMutation,
) -> Result<SidebarAdminItem, AppError> {
    let layer = recording.stamp()?;
    // P-environment-promotion §5 step 5: an admin write marks the row
    // `is_customized` (the seed then leaves it alone); a duplicate
    // (parent, name) among live rows hits `uq_xrm_sidebar_parent_name`
    // (0133) and is a 409, not a 500.
    let item_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sidebar
             (id, name, route, icon, color, parent_ref, display_order, is_active, is_disabled, module_key,
              is_customized, owner_layer)
         VALUES (uuidv7(), $1, $2, $3, $4, $5, $6, $7, $8, $9, true, $10)
         RETURNING id",
    )
    .bind(&body.name)
    .bind(&body.route)
    .bind(&body.icon)
    .bind(&body.color)
    .bind(body.parent_ref)
    .bind(body.display_order)
    .bind(body.is_active)
    .bind(body.is_disabled)
    .bind(&body.module_key)
    .bind(layer.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(map_unique_violation)?;
    replace_privileges(tx, item_id, &body.privilege_ids).await?;
    read_sidebar_item_in_tx(tx, item_id).await
}

/// The admin PATCH's write, transaction-scoped: owner check, then the
/// optimistic-concurrency update. `NotFound` for a missing item,
/// `VersionConflict` for a stale `expected_version`.
pub(crate) async fn update_sidebar_item_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    expected_version: i64,
    body: &SidebarMutation,
) -> Result<SidebarAdminItem, AppError> {
    lock_sidebar_owner(tx, recording, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let updated_id = sqlx::query_scalar::<_, Uuid>(
        "UPDATE sidebar
         SET name = $1, route = $2, icon = $3, color = $4, parent_ref = $5,
             display_order = $6, is_active = $7, is_disabled = $8, module_key = $9, updated_at = NOW(),
             is_customized = true, row_version = row_version + 1
         WHERE id = $10 AND row_version = $11 AND is_deleted = false
         RETURNING id",
    )
    .bind(&body.name)
    .bind(&body.route)
    .bind(&body.icon)
    .bind(&body.color)
    .bind(body.parent_ref)
    .bind(body.display_order)
    .bind(body.is_active)
    .bind(body.is_disabled)
    .bind(&body.module_key)
    .bind(id)
    .bind(expected_version)
    .fetch_optional(&mut **tx)
    .await
    // A rename/move onto an existing live sibling name: 409 (0133).
    .map_err(map_unique_violation)?;
    // The row is locked and not deleted, so no update means a stale version.
    let updated_id = updated_id.ok_or(AppError::VersionConflict)?;
    replace_privileges(tx, updated_id, &body.privilege_ids).await?;
    read_sidebar_item_in_tx(tx, updated_id).await
}

/// The admin DELETE's write: deactivates the item and its active subtree.
/// Its contract never tells "not found" from "stale": both are
/// `VersionConflict`. The owner-layer rule is checked on the named item (the
/// subtree follows it, as `retire_sidebar_item` does).
pub(crate) async fn deactivate_sidebar_item_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    expected_version: i64,
) -> Result<SidebarAdminItem, AppError> {
    lock_sidebar_owner(tx, recording, id)
        .await?
        .ok_or(AppError::VersionConflict)?;
    // `is_customized = true` on deactivate too ("any admin write that touches
    // the row"): a seeded item an admin deliberately hid must not come back
    // on the next boot's reseed.
    let updated = sqlx::query(
        "UPDATE sidebar SET is_active = false, is_customized = true, updated_at = NOW(),
             row_version = row_version + 1
         WHERE id = $1 AND row_version = $2 AND is_deleted = false",
    )
    .bind(id)
    .bind(expected_version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::VersionConflict);
    }
    sqlx::query(
        "WITH RECURSIVE descendants AS (
             SELECT id FROM sidebar WHERE parent_ref = $1 AND is_deleted = false
             UNION ALL
             SELECT s.id FROM sidebar s JOIN descendants d ON s.parent_ref = d.id
             WHERE s.is_deleted = false
         )
         UPDATE sidebar SET is_active = false, is_customized = true, updated_at = NOW(),
             row_version = row_version + 1
         WHERE id IN (SELECT id FROM descendants) AND is_active = true",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    read_sidebar_item_in_tx(tx, id).await
}

/// Update a sidebar item
///
/// Update a sidebar item. Needs the sidebar management privilege. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/sidebar/admin/{id}",
    tag = "sidebar",
    params(("id" = Uuid, Path, description = "The sidebar item")),
    request_body = SidebarMutation,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = SidebarAdminItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_sidebar_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SidebarManage>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(mut body): Json<SidebarMutation>,
) -> Result<Json<SidebarAdminItem>, AppError> {
    validate_mutation(&mut body)?;
    let expected_version = body
        .row_version
        .ok_or_else(|| AppError::Validation("row_version is required".into()))?;
    if body.parent_ref == Some(id) {
        return Err(AppError::Validation(
            "an item cannot be its own parent".into(),
        ));
    }
    ensure_parent(&state.base.db, body.parent_ref).await?;

    if let Some(parent_id) = body.parent_ref {
        let creates_cycle: bool = sqlx::query_scalar(
            "WITH RECURSIVE descendants AS (
                 SELECT id FROM sidebar WHERE parent_ref = $1 AND is_deleted = false
                 UNION ALL
                 SELECT s.id FROM sidebar s JOIN descendants d ON s.parent_ref = d.id
                 WHERE s.is_deleted = false
             )
             SELECT EXISTS(SELECT 1 FROM descendants WHERE id = $2)",
        )
        .bind(id)
        .bind(parent_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if creates_cycle {
            return Err(AppError::Validation(
                "parent selection would create a cycle".into(),
            ));
        }
    }

    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let item = update_sidebar_item_in_tx(&mut tx, &recording, id, expected_version, &body).await?;
    // D-541 rule 4: sidebar items are shared navigation configuration; the
    // event commits with the change (D-062).
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "sidebar",
            Some(item.id),
        )
        .named("sidebar.update"),
    )
    .await?;
    let op = sidebar_op(&mut tx, Op::UpsertSidebarItem, &item).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(item))
}

#[derive(Deserialize, ToSchema)]
struct SidebarDelete {
    row_version: i64,
}

/// Delete a sidebar item
///
/// Delete a sidebar item. Needs the sidebar management privilege. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/sidebar/admin/{id}",
    tag = "sidebar",
    params(("id" = Uuid, Path, description = "The sidebar item")),
    request_body = SidebarDelete,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 200, description = "Success", body = Vec<SidebarAdminItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn deactivate_sidebar_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SidebarManage>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<SidebarDelete>,
) -> Result<Json<Vec<SidebarAdminItem>>, AppError> {
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let item = deactivate_sidebar_item_in_tx(&mut tx, &recording, id, body.row_version).await?;
    // D-541 rule 4: sidebar items are shared navigation configuration; the
    // event commits with the change (D-062).
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "sidebar",
            Some(id),
        )
        .named("sidebar.deactivate"),
    )
    .await?;
    let op = sidebar_op(&mut tx, Op::RetireSidebarItem, &item).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(fetch_all_sidebar_admin_items(&state.base.db).await?))
}

// ── Service reconcile API (P-environment-promotion §5 step 13) ────────────────

/// Resolves a root-first name path to the id of the item it names: each
/// segment is looked up under the previous one among non-deleted rows,
/// preferring an active row (a retired ancestor still anchors its subtree,
/// so reactivating parents before children works in either order). `None`
/// when any segment is missing.
async fn resolve_sidebar_path(
    db: &attome_db::DbPool,
    path: &[String],
) -> Result<Option<Uuid>, AppError> {
    let mut parent: Option<Uuid> = None;
    for segment in path {
        let found: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM sidebar \
             WHERE name = $1 AND parent_ref IS NOT DISTINCT FROM $2 AND is_deleted = false \
             ORDER BY is_active DESC, created_at DESC, id DESC LIMIT 1",
        )
        .bind(segment.trim())
        .bind(parent)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        match found {
            Some(id) => parent = Some(id),
            None => return Ok(None),
        }
    }
    Ok(parent)
}

/// The row a `reconcile_sidebar_item` probe finds for `(parent, name)` — the
/// live one if there is one, else the most recently created retired one
/// (`uq_xrm_sidebar_parent_name` is partial on `is_active`, so both can
/// exist; reactivating the retired one is what keeps its children attached).
#[derive(sqlx::FromRow)]
struct SidebarProbeRow {
    id: Uuid,
    route: Option<String>,
    icon: Option<String>,
    color: Option<String>,
    display_order: i32,
    is_container: bool,
    entity_logical_name: Option<String>,
    module_key: Option<String>,
    is_disabled: bool,
    is_active: bool,
    is_customized: bool,
}

/// Create-or-update one sidebar item to match `desc`, keyed by its
/// root-first name path (`path[..n-1]` must already exist — apply parents
/// before children). Field validation is `validate_mutation`'s, the same
/// rules the admin POST/PATCH enforce; privilege keys must name active
/// privileges. Compare-first; `Seed` skips an `is_customized` row; `Admin`
/// marks it; `Bundle` carries the marker; a retired row with the same key is
/// reactivated. Returns `(item_id, outcome)`. Mirrors the admin handlers: no
/// metadata lock, change log or doorbell — the sidebar is not in the entity
/// metadata registry.
pub async fn reconcile_sidebar_item(
    state: &EngineState,
    desc: &SidebarDef,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let Some((name, parents)) = desc.path.split_last() else {
        return Err(AppError::Validation(
            "sidebar path must have at least one segment".into(),
        ));
    };
    // Reuse the admin handlers' validation verbatim (trim/clean + bounds +
    // known module_key); the privilege ids are resolved separately below.
    let mut cleaned = SidebarMutation {
        name: name.clone(),
        route: desc.route.clone(),
        icon: desc.icon.clone(),
        color: desc.color.clone(),
        parent_ref: None,
        display_order: desc.display_order,
        is_active: true,
        is_disabled: desc.is_disabled,
        row_version: None,
        module_key: desc.module_key.clone(),
        privilege_ids: Vec::new(),
    };
    validate_mutation(&mut cleaned)?;
    let entity = clean_optional(desc.entity.clone());
    let db = &state.base.db;
    let key = desc.path_display();

    let parent_ref = if parents.is_empty() {
        None
    } else {
        Some(resolve_sidebar_path(db, parents).await?.ok_or_else(|| {
            AppError::Validation(format!(
                "parent sidebar item '{}' does not exist",
                parents.join("/")
            ))
        })?)
    };

    // Privilege keys -> ids (active only, as `replace_privileges` requires).
    let mut wanted_keys: Vec<String> = desc
        .privileges
        .iter()
        .map(|k| k.trim().to_owned())
        .collect();
    wanted_keys.sort();
    wanted_keys.dedup();
    let resolved: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, key FROM privilege WHERE key = ANY($1) AND is_active = true")
            .bind(&wanted_keys)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    if resolved.len() != wanted_keys.len() {
        let found: BTreeSet<&str> = resolved.iter().map(|(_, k)| k.as_str()).collect();
        let missing: Vec<&str> = wanted_keys
            .iter()
            .map(String::as_str)
            .filter(|k| !found.contains(k))
            .collect();
        return Err(AppError::Validation(format!(
            "sidebar item '{key}': unknown or inactive privilege(s): {}",
            missing.join(", ")
        )));
    }
    let wanted_ids: BTreeSet<Uuid> = resolved.iter().map(|(id, _)| *id).collect();

    let current: Option<SidebarProbeRow> = sqlx::query_as(
        "SELECT id, route, icon, color, display_order, is_container, entity_logical_name, \
                module_key, is_disabled, is_active, is_customized \
         FROM sidebar \
         WHERE name = $1 AND parent_ref IS NOT DISTINCT FROM $2 AND is_deleted = false \
         ORDER BY is_active DESC, created_at DESC, id DESC LIMIT 1",
    )
    .bind(&cleaned.name)
    .bind(parent_ref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let state_differs = match current.as_ref() {
        Some(row) => {
            let cur_ids: BTreeSet<Uuid> = sqlx::query_scalar(
                "SELECT privilege_ref FROM sidebar_mm_privilege \
                 WHERE sidebar_ref = $1 AND is_deleted = false",
            )
            .bind(row.id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
            row.route != cleaned.route
                || row.icon != cleaned.icon
                || row.color != cleaned.color
                || row.display_order != cleaned.display_order
                || row.is_container != desc.is_container
                || row.entity_logical_name != entity
                || row.module_key != cleaned.module_key
                || row.is_disabled != cleaned.is_disabled
                || cur_ids != wanted_ids
        }
        None => false,
    };
    let status = current.as_ref().map(|r| (r.is_customized, r.is_active));
    let step = reconcile_step(policy, status, state_differs);

    match step {
        ReconcileStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(sidebar_item = %key, "sidebar reconcile: seed skipped a customized sidebar row (is_customized = true)");
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        ReconcileStep::Create | ReconcileStep::Update => {
            let mut tx = attome_db::tx::begin(db).await?;
            let id = match current.as_ref() {
                Some(row) => {
                    let n = sqlx::query(
                        "UPDATE sidebar \
                         SET route = $2, icon = $3, color = $4, display_order = $5, is_container = $6, \
                             entity_logical_name = $7, module_key = $8, is_disabled = $9, \
                             is_active = true, is_customized = COALESCE($10, is_customized), \
                             updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1 AND is_deleted = false",
                    )
                    .bind(row.id)
                    .bind(&cleaned.route)
                    .bind(&cleaned.icon)
                    .bind(&cleaned.color)
                    .bind(cleaned.display_order)
                    .bind(desc.is_container)
                    .bind(&entity)
                    .bind(&cleaned.module_key)
                    .bind(cleaned.is_disabled)
                    .bind(customized_marker(policy))
                    .execute(&mut *tx)
                    .await
                    // Reactivating a retired row while a live one with the
                    // same key appeared meanwhile: 0133's index says 409.
                    .map_err(map_unique_violation)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict("sidebar row vanished during reconcile"));
                    }
                    row.id
                }
                None => sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO sidebar \
                         (id, name, route, icon, color, parent_ref, display_order, is_container, \
                          entity_logical_name, module_key, is_disabled, is_active, is_customized, \
                          owner_layer) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true, $12, $13) \
                     RETURNING id",
                )
                .bind(desired_id.unwrap_or_else(Uuid::now_v7))
                .bind(&cleaned.name)
                .bind(&cleaned.route)
                .bind(&cleaned.icon)
                .bind(&cleaned.color)
                .bind(parent_ref)
                .bind(cleaned.display_order)
                .bind(desc.is_container)
                .bind(&entity)
                .bind(&cleaned.module_key)
                .bind(cleaned.is_disabled)
                .bind(customized_marker(policy).unwrap_or(false))
                .bind(hooks::reconcile_layer(policy).as_str())
                .fetch_one(&mut *tx)
                .await
                // Two concurrent creates of the same key: the loser hits
                // `uq_xrm_sidebar_parent_name` -> Conflict; a re-run converges.
                .map_err(map_unique_violation)?,
            };
            let ids: Vec<Uuid> = wanted_ids.iter().copied().collect();
            replace_privileges(&mut tx, id, &ids).await?;
            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(sidebar_item = %key, ?outcome, ?policy, "sidebar reconcile: reconciled sidebar item");
            Ok((id, outcome))
        }
    }
}

/// Soft-retire (`is_active = false`) the item at `path` **and its active
/// descendants** — the same cascade `deactivate_sidebar_item` performs, and
/// for the same reason: `get_sidebar` promotes any node whose parent is not
/// in the visible set to a root, so hiding only the parent would surface its
/// children at the top level. Idempotent: `Unchanged` when the path does not
/// resolve or the item is already inactive. Never deletes.
pub async fn retire_sidebar_item(
    state: &EngineState,
    path: &[String],
) -> Result<ReconcileOutcome, AppError> {
    let db = &state.base.db;
    let Some(id) = resolve_sidebar_path(db, path).await? else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let mut tx = attome_db::tx::begin(db).await?;
    let n = sqlx::query(
        "UPDATE sidebar SET is_active = false, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_active = true AND is_deleted = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    sqlx::query(
        "WITH RECURSIVE descendants AS (
             SELECT id FROM sidebar WHERE parent_ref = $1 AND is_deleted = false
             UNION ALL
             SELECT s.id FROM sidebar s JOIN descendants d ON s.parent_ref = d.id
             WHERE s.is_deleted = false
         )
         UPDATE sidebar SET is_active = false, updated_at = NOW(), row_version = row_version + 1
         WHERE id IN (SELECT id FROM descendants) AND is_active = true",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(sidebar_item = %path.join("/"), "sidebar reconcile: retired item and its subtree");
    Ok(ReconcileOutcome::Updated)
}

/// Reactivate the item at `path` (the item only — reactivate parents before
/// children; a retired parent still resolves, see `resolve_sidebar_path`).
/// Idempotent. A live sibling with the same name created meanwhile makes
/// this a 409 (`uq_xrm_sidebar_parent_name`).
pub async fn reactivate_sidebar_item(
    state: &EngineState,
    path: &[String],
) -> Result<ReconcileOutcome, AppError> {
    let db = &state.base.db;
    let Some(id) = resolve_sidebar_path(db, path).await? else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let n = sqlx::query(
        "UPDATE sidebar SET is_active = true, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_active = false AND is_deleted = false",
    )
    .bind(id)
    .execute(db)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(sidebar_item = %path.join("/"), "sidebar reconcile: reactivated item");
    Ok(ReconcileOutcome::Updated)
}

/// M05 Phase 1 (D-426) — `?locale=` on `GET /api/v1/sidebar/get`.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct SidebarQuery {
    /// A BCP-47 tag, e.g. `"ar-AE"`. Omit to resolve straight to the
    /// deployment default.
    locale: Option<String>,
}

/// My navigation menu
///
/// The caller's own navigation menu. Authenticated-only by design: the route
/// is not gated, each *row* is filtered below by whether the caller holds the
/// privileges that sidebar item requires (`$1 = ctx.is_admin`, `$2 =
/// privilege_keys`), so a caller with no privileges simply gets a short menu
/// rather than a 403. Contrast `list_sidebar_admin` and the mutation handlers,
/// which manage everyone's menu and take `Privilege<SidebarManage>`.
#[utoipa::path(
    get,
    path = "/api/v1/sidebar/get",
    tag = "sidebar",
    params(SidebarQuery),
    responses(
        (status = 200, description = "Success", body = Vec<SidebarItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_sidebar(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    contributions: Option<Extension<SidebarContributions>>,
    Query(query): Query<SidebarQuery>,
) -> Result<Json<Vec<SidebarItem>>, AppError> {
    let privilege_keys: Vec<String> = ctx.privileges.iter().cloned().collect();
    // M05 Phase 1 (D-426) — same fallback chain `schema.rs::get_schema` uses.
    // `object_ref` for a sidebar item is its "/"-joined path from the root
    // (0201's header), built while walking the tree below.
    let requested_locale = query.locale.as_deref();
    let dep_locale = state.deployment_locale();
    let labels = state.labels.load();

    let mut rows: Vec<SidebarRow> = sqlx::query_as(
        "SELECT id,
                    COALESCE(name, '')         AS name,
                    COALESCE(route, '')        AS route,
                    COALESCE(icon, '')         AS icon,
                    COALESCE(color, '')        AS color,
                    parent_ref,
                    COALESCE(display_order, 0) AS display_order,
                    module_key,
                    is_disabled
             FROM sidebar
             WHERE COALESCE(is_active, true) = true
               AND is_deleted = false
               AND (
                    $1
                    OR NOT EXISTS (
                        SELECT 1 FROM sidebar_mm_privilege sp
                        WHERE sp.sidebar_ref = sidebar.id AND sp.is_deleted = false
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM sidebar_mm_privilege sp
                        JOIN privilege p ON p.id = sp.privilege_ref
                        WHERE sp.sidebar_ref = sidebar.id
                          AND sp.is_deleted = false
                          AND p.is_active = true
                          AND p.key = ANY($2)
                    )
               )",
    )
    .bind(ctx.is_admin)
    .bind(privilege_keys)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // Module-gate applies to every caller, including admins (unlike the
    // privilege check above): disabling a module via
    // /api/v1/admin/license/modules is meant to hide that module's nav
    // everywhere until it's re-enabled, not just for non-admin users.
    let active_license = state.modules.load();
    rows.retain(|row| module_visible(&active_license, &row.7));
    // Q10-T11: and the page behind the item must admit the caller.
    rows.retain(|row| route_visible(&ctx, &row.2));

    struct RawNode {
        id: String,
        name: String,
        route: String,
        icon: String,
        color: String,
        display_order: i32,
        parent_id: Option<String>,
        is_disabled: bool,
    }

    let mut node_map: HashMap<String, RawNode> = HashMap::new();
    let mut child_map: HashMap<String, Vec<String>> = HashMap::new();

    for (id, name, route, icon, color, parent_ref, display_order, _module_key, is_disabled) in &rows
    {
        let id_str = id.to_string();
        let parent_str = parent_ref.map(|p| p.to_string());

        if let Some(ref pid) = parent_str {
            child_map
                .entry(pid.clone())
                .or_default()
                .push(id_str.clone());
        }

        node_map.insert(
            id_str.clone(),
            RawNode {
                id: id_str,
                name: name.clone(),
                route: route.clone(),
                icon: icon.clone(),
                color: color.clone(),
                display_order: *display_order,
                parent_id: parent_str,
                is_disabled: *is_disabled,
            },
        );
    }

    for kids in child_map.values_mut() {
        kids.sort_by(|a, b| {
            let na = &node_map[a];
            let nb = &node_map[b];
            na.display_order
                .cmp(&nb.display_order)
                .then_with(|| na.name.cmp(&nb.name))
        });
    }

    // D-426: `object_ref` for a sidebar item is its "/"-joined path from the
    // root (0201's header) — built by threading the accumulated parent path
    // down through this recursion, one segment (the raw `name`, matching how
    // `SidebarDef::path_display` and `resolve_sidebar_path` key a sidebar item
    // elsewhere in this file) per level.
    #[allow(clippy::too_many_arguments)]
    fn build(
        id: &str,
        node_map: &HashMap<String, RawNode>,
        child_map: &HashMap<String, Vec<String>>,
        parent_path: &[String],
        labels: &attome_core::LabelSnapshot,
        requested_locale: Option<&str>,
        dep_locale: &str,
    ) -> SidebarItem {
        let n = &node_map[id];
        let mut path = parent_path.to_vec();
        path.push(n.name.clone());
        let object_ref = path.join("/");
        let name = labels
            .resolve("sidebar", &object_ref, requested_locale, dep_locale)
            .map(|r| r.display_name.clone())
            .unwrap_or_else(|| n.name.clone());
        let child = child_map
            .get(id)
            .map(|kids| {
                kids.iter()
                    .map(|cid| {
                        build(
                            cid,
                            node_map,
                            child_map,
                            &path,
                            labels,
                            requested_locale,
                            dep_locale,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        SidebarItem {
            id: n.id.clone(),
            name,
            icon: n.icon.clone(),
            color: n.color.clone(),
            route: transform_route(&n.route),
            is_disabled: n.is_disabled,
            child,
        }
    }

    // Normalizes stale raw-logicalname routes migrations 0007/0008 seeded
    // directly into the database before either the "/xrm/entity/…" URL
    // convention or D-222's later pure `_` -> `/` mapping existed (e.g.
    // `/xrm/entity/s2s_client`, no action suffix). `sidebar_seed.rs`
    // now always writes fully-formed, current-convention routes on every
    // boot via its idempotent upserts, so this only ever fires for a row
    // that predates the seed's fix on some older, not-yet-re-seeded
    // deployment — kept as a defensive normalizer, not the primary source
    // of correct routes.
    fn transform_route(route: &str) -> String {
        // Only rewrite the old /xrm/entity/… seed shape
        let Some(rest) = route.strip_prefix("/xrm/entity/") else {
            return route.to_owned();
        };
        if rest.is_empty() {
            return route.to_owned();
        }

        // Split off a trailing action keyword (list | form) if present
        let (entity_part, action) = match rest.rsplit_once('/') {
            Some((e, a)) if a == "list" || a == "form" => (e, a),
            _ => (rest, "list"),
        };

        // Lossless mapping, mirroring the Angular router's
        // `logicalToUrlPath` (entity-url.utils.ts): an `xrm_{module}_{entity}`
        // name maps `_` to `/`; any other name (`trd_*`, unprefixed vertical
        // entities, 3-letter project prefixes such as `bmd_*`) and any
        // `entity_*` name keeps the verbatim `xrm/entity/{logicalname}`
        // shape. Not every logical name starts with `xrm_`.
        let url_path = if entity_part.starts_with("xrm_") && !entity_part.starts_with("entity_") {
            entity_part.replace('_', "/")
        } else {
            format!("xrm/entity/{entity_part}")
        };
        format!("/{url_path}/{action}")
    }

    let mut roots: Vec<&RawNode> = node_map
        .values()
        .filter(|n| {
            n.parent_id
                .as_ref()
                .map(|pid| !node_map.contains_key(pid.as_str()))
                .unwrap_or(true)
        })
        .collect();

    roots.sort_by(|a, b| {
        a.display_order
            .cmp(&b.display_order)
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut result: Vec<SidebarItem> = roots
        .iter()
        .map(|n| {
            build(
                &n.id,
                &node_map,
                &child_map,
                &[],
                &labels,
                requested_locale,
                &dep_locale,
            )
        })
        .collect();
    prune_empty_groups(&mut result);
    append_contributions(
        &mut result,
        contributions.as_ref().map(|Extension(c)| c),
        ctx.is_admin,
    );

    Ok(Json(result))
}

pub fn routes() -> Router<EngineState> {
    // The pre-2026-07-13 unprefixed `/api/sidebar/get` alias (ex-audit-finding
    // #20) was retired C-25 — its sunset date
    // (`attome_server::middleware::deprecation::DEPRECATED_PATHS`) passed
    // 2026-08-29, and this is the release after the one that carried the
    // deprecation headers. Do not re-add it: a caller still depending on the
    // unprefixed path now gets a 404, which is the documented end state of a
    // sunset alias, not a regression.
    Router::new()
        .route("/api/v1/sidebar/get", get(get_sidebar))
        .route(
            "/api/v1/sidebar/admin",
            get(list_sidebar_admin).post(create_sidebar_item),
        )
        .route(
            "/api/v1/sidebar/admin/privileges",
            get(list_sidebar_privileges),
        )
        .route(
            "/api/v1/sidebar/admin/{id}",
            patch(update_sidebar_item).delete(deactivate_sidebar_item),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_sidebar_admin,
    list_sidebar_privileges,
    create_sidebar_item,
    update_sidebar_item,
    deactivate_sidebar_item,
    get_sidebar
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod contributor_tests {
    use super::*;

    struct AdminOnlyGroup;

    impl SidebarContributor for AdminOnlyGroup {
        fn contribute(&self, is_admin: bool) -> Vec<SidebarItem> {
            if !is_admin {
                return Vec::new();
            }
            vec![SidebarItem {
                id: "fleet".into(),
                name: "Fleet".into(),
                icon: "la-network-wired".into(),
                color: String::new(),
                route: String::new(),
                is_disabled: false,
                child: Vec::new(),
            }]
        }
    }

    fn stored() -> Vec<SidebarItem> {
        vec![SidebarItem {
            id: "stored".into(),
            name: "Stored".into(),
            icon: String::new(),
            color: String::new(),
            route: "/xrm".into(),
            is_disabled: false,
            child: Vec::new(),
        }]
    }

    #[test]
    fn without_a_contributor_the_menu_is_exactly_the_stored_one() {
        let mut items = stored();
        append_contributions(&mut items, None, true);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "stored");
    }

    #[test]
    fn a_contributor_appends_after_the_stored_menu_for_whom_it_chooses() {
        let contributions = SidebarContributions(Arc::new(AdminOnlyGroup));
        let mut admin = stored();
        append_contributions(&mut admin, Some(&contributions), true);
        assert_eq!(
            admin.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["stored", "fleet"]
        );
        let mut user = stored();
        append_contributions(&mut user, Some(&contributions), false);
        assert_eq!(user.len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_gate_reads_the_page_behind_an_item() {
        assert_eq!(
            route_gate("/xrm/entity/account/list"),
            RouteGate::Entity("account".into())
        );
        assert_eq!(
            route_gate("/xrm/admin/entities"),
            RouteGate::Area(AdminArea::DataModel)
        );
        assert_eq!(
            route_gate("/xrm/admin/security/users/42"),
            RouteGate::Area(AdminArea::Users)
        );
        assert_eq!(
            route_gate("/xrm/admin/security/role-entity-access"),
            RouteGate::Area(AdminArea::Roles)
        );
        assert_eq!(route_gate("/xrm/admin/security/whoami"), RouteGate::Open);
        assert_eq!(route_gate("/xrm/admin/metadata/bundles"), RouteGate::Admin);
        assert_eq!(route_gate("/xrm/admin/entitiesx"), RouteGate::Admin);
        assert_eq!(route_gate("/xrm/dashboard"), RouteGate::Open);
    }

    #[test]
    fn route_visible_follows_areas_and_entity_reads() {
        let mut ctx = SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: ["admin.data_model", "account.read"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            field_grants: Default::default(),
            field_write_grants: Default::default(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: Default::default(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        };
        assert!(route_visible(&ctx, "/xrm/admin/views"));
        assert!(!route_visible(&ctx, "/xrm/admin/secrets"));
        assert!(route_visible(&ctx, "/xrm/entity/account/list"));
        assert!(!route_visible(&ctx, "/xrm/entity/contact/list"));
        assert!(!route_visible(&ctx, "/xrm/admin/metadata/bundles"));
        ctx.is_admin = true;
        assert!(route_visible(&ctx, "/xrm/admin/metadata/bundles"));
    }
}
