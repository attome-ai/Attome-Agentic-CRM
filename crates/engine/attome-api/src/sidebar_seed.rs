//! Ensures built-in sidebar items are wired to the correct routes.
//! Idempotent — upserts by name+parent, updates stale routes in place.
//! Called once at startup from EngineSystemBuilder::build().
//!
//! Ownership (P-environment-promotion §4 "Ownership is one boolean", §5
//! step 6): every helper here that would UPDATE an existing `sidebar`
//! row — the presentation-field refresh in `upsert_sidebar_item`, the
//! `rename_group` key rename, and the `deactivate*` retirements — leaves a
//! row whose `is_customized = true` alone and logs the skip at `info` with
//! the row's name. An admin write through `/api/v1/sidebar/admin` sets that
//! flag; this seed never does. Before this rule the seed was the one
//! over-applying seed in the platform (every boot clobbered every admin
//! edit); now it is the same reconcile-or-skip as `ensure_entity`.
//!
//! Convention: one top-level category per backend module (Security, S2S,
//! License, Audit, Entity Manager, Query Builder each get their own — never
//! folded into a shared "Administration" catch-all). Sales Suite is the one
//! deliberate exception: it groups real business data, not a single module.

use attome_db::DbPool;
use attome_security::context::ADMIN_PRIVILEGE_KEY;
use attome_types::AppError;
use uuid::Uuid;

/// Looks up a sidebar item by name + optional parent.
/// Updates its route/icon if the row exists with a stale value.
/// Inserts a new row otherwise. Returns the id.
///
/// `module_key` names a `attome_modules::MODULE_MAP` entry this item belongs
/// to, or `None` if it isn't tied to a toggleable license module (an
/// always-on admin tool, or a page like Dashboard/Security that must stay
/// reachable regardless of module state — see `seed()`'s own per-item
/// comments for which is which). `GET /api/v1/sidebar/get` hides an item
/// (and everything under it, since every child of a module-owned group is
/// tagged with the same key) once its module is disabled via
/// `/api/v1/admin/license/modules`.
#[allow(clippy::too_many_arguments)]
async fn upsert_sidebar(
    db: &DbPool,
    name: &str,
    route: Option<&str>,
    icon: &str,
    color: &str,
    parent_id: Option<Uuid>,
    display_order: i32,
    module_key: Option<&str>,
) -> Result<Uuid, AppError> {
    upsert_sidebar_item(
        db,
        name,
        route,
        icon,
        color,
        parent_id,
        display_order,
        module_key,
        false,
    )
    .await
}

/// Same as `upsert_sidebar`, with an explicit `is_disabled` — used by the
/// "Coming Soon" placeholders (`is_disabled: true`, greyed out but still
/// listed) so a module with no engine crate/route yet doesn't have to fake
/// one just to appear in the sidebar. See migration 0077's own comment for
/// why this is a separate axis from `is_active`/the module-visibility gate.
#[allow(clippy::too_many_arguments)]
async fn upsert_sidebar_item(
    db: &DbPool,
    name: &str,
    route: Option<&str>,
    icon: &str,
    color: &str,
    parent_id: Option<Uuid>,
    display_order: i32,
    module_key: Option<&str>,
    is_disabled: bool,
) -> Result<Uuid, AppError> {
    let existing: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, is_customized FROM sidebar \
         WHERE name = $1 AND (($2::uuid IS NULL AND parent_ref IS NULL) OR parent_ref = $2) \
         LIMIT 1",
    )
    .bind(name)
    .bind(parent_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    if let Some((id, is_customized)) = existing {
        if is_customized {
            // An admin edited this row through the sidebar admin API. The
            // seed owns the *name*, not the customer's presentation choices —
            // leave it exactly as they left it (route, icon, colour, order,
            // module_key, is_disabled AND is_active) and say so.
            tracing::info!(
                sidebar_item = %name,
                "sidebar seed: skipped a customized sidebar row (is_customized = true)"
            );
            return Ok(id);
        }
        // Older seeds may have retired a built-in item. Re-seeding restores it
        // and keeps every presentation field current. `IS DISTINCT FROM`
        // guards make the steady-state boot write nothing when the row
        // already matches.
        sqlx::query(
            "UPDATE sidebar
             SET route = $1, icon = $2, color = $3, display_order = $4, is_active = true,
                 module_key = $5, is_disabled = $6
             WHERE id = $7
               AND (route IS DISTINCT FROM $1 OR icon IS DISTINCT FROM $2
                    OR color IS DISTINCT FROM $3 OR display_order IS DISTINCT FROM $4
                    OR is_active IS DISTINCT FROM true OR module_key IS DISTINCT FROM $5
                    OR is_disabled IS DISTINCT FROM $6)",
        )
        .bind(route)
        .bind(icon)
        .bind(color)
        .bind(display_order)
        .bind(module_key)
        .bind(is_disabled)
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        return Ok(id);
    }

    // Solution 7 (D-785): the built-in sidebar is a platform definition; a
    // new row is stamped `platform` (an existing row keeps its layer).
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO sidebar \
             (id, name, route, icon, color, parent_ref, display_order, is_active, module_key, is_disabled, \
              owner_layer) \
         VALUES (uuidv7(), $1, $2, $3, $4, $5, $6, true, $7, $8, 'platform') \
         RETURNING id",
    )
    .bind(name)
    .bind(route)
    .bind(icon)
    .bind(color)
    .bind(parent_id)
    .bind(display_order)
    .bind(module_key)
    .bind(is_disabled)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Renames a top-level sidebar group from `old_name` to `new_name`.
/// No-op if the old name is not found (already renamed or never existed).
/// A customized row keeps its name (logged): the name is the row's key, and
/// an admin who deliberately set it gets to keep it — the seed then upserts
/// `new_name` as its own row, which is visible (two groups) rather than
/// silently undone.
async fn rename_group(db: &DbPool, old_name: &str, new_name: &str) -> Result<(), AppError> {
    log_customized_skips(db, old_name, None, "rename").await?;
    sqlx::query(
        "UPDATE sidebar SET name = $1 \
         WHERE name = $2 AND parent_ref IS NULL AND is_customized = false",
    )
    .bind(new_name)
    .bind(old_name)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Re-parents an existing built-in row, keeping its identity.
///
/// `upsert_sidebar` keys on `(name, parent_ref)`, so it cannot express a move:
/// calling it with a new parent would insert a *second* row with the same name
/// and leave the old one live — two links, one dead. [`deactivate`] is the
/// retire half of that problem; this is the move half, and unlike
/// deactivate-then-recreate it keeps the row's id, so a privilege link or any
/// admin reference attached to it survives.
///
/// Matches on `(name, old_parent)` rather than name alone: a same-named row
/// elsewhere is a different item, and moving the wrong one would be invisible.
/// A customized row is left where the admin put it (logged), same rule as every
/// other helper here. Returns `true` when a row actually moved.
async fn move_sidebar_item(
    db: &DbPool,
    name: &str,
    old_parent: Option<Uuid>,
    new_parent: Option<Uuid>,
    display_order: i32,
) -> Result<bool, AppError> {
    log_customized_skips(db, name, old_parent, "move").await?;
    let moved = sqlx::query(
        "UPDATE sidebar
         SET parent_ref = $1, display_order = $2, is_active = true
         WHERE name = $3
           AND (($4::uuid IS NULL AND parent_ref IS NULL) OR parent_ref = $4)
           AND is_customized = false
           AND (parent_ref IS DISTINCT FROM $1 OR display_order IS DISTINCT FROM $2
                OR is_active IS DISTINCT FROM true)",
    )
    .bind(new_parent)
    .bind(display_order)
    .bind(name)
    .bind(old_parent)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(moved > 0)
}

/// Logs, at `info`, every live `is_customized` row at `(name, parent)` that a
/// seed helper is about to leave alone. Shared by the rename/retire helpers
/// so the skip is always reported, never silent.
async fn log_customized_skips(
    db: &DbPool,
    name: &str,
    parent_id: Option<Uuid>,
    operation: &'static str,
) -> Result<(), AppError> {
    let skipped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sidebar \
         WHERE name = $1 AND (($2::uuid IS NULL AND parent_ref IS NULL) OR parent_ref = $2) \
           AND is_active = true AND is_customized = true",
    )
    .bind(name)
    .bind(parent_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if skipped > 0 {
        tracing::info!(
            sidebar_item = %name,
            operation,
            "sidebar seed: skipped a customized sidebar row (is_customized = true)"
        );
    }
    Ok(())
}

/// Retires a sidebar row that moved to a different parent — `upsert_sidebar`
/// keys on (name, parent) so it can't "move" a row; the item gets recreated
/// at its new parent and the old location is deactivated here. Idempotent:
/// re-running finds the already-deactivated row and leaves it alone (route
/// unchanged → no UPDATE fires). A customized row is left active (logged):
/// an admin who re-pointed or re-enabled a retired item keeps it.
async fn deactivate(db: &DbPool, name: &str, parent_id: Option<Uuid>) -> Result<(), AppError> {
    log_customized_skips(db, name, parent_id, "deactivate").await?;
    sqlx::query(
        "UPDATE sidebar SET is_active = false \
         WHERE name = $1 AND (($2::uuid IS NULL AND parent_ref IS NULL) OR parent_ref = $2) \
           AND is_customized = false",
    )
    .bind(name)
    .bind(parent_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Deactivates a top-level group by name AND every descendant beneath it,
/// recursively — `deactivate()` above only ever touches the exact
/// `(name, parent)` row it's given, so moving a whole group to a new parent
/// (as this restructure does for Access & Identity/Security, folded under
/// the new "core" group) requires this instead: leaving a child active with
/// its parent deactivated makes `get_sidebar()`'s orphan-promotion rule
/// resurface it as a bogus new top-level item — an item's own `is_active`
/// gates whether it renders, not its parent's. No-op if the named top-level
/// group doesn't exist (already retired, or never existed on this
/// database).
///
/// Customized rows anywhere in the subtree are left active and logged. That
/// is deliberate even though it can surface such a child as an orphan
/// top-level item (the rule the previous paragraph describes): the
/// alternative — retiring it and then having `upsert_sidebar_item` skip it
/// because it is customized — would make an admin's edited item vanish from
/// the sidebar for good. Visible and recoverable beats silently gone.
async fn deactivate_subtree(db: &DbPool, name: &str) -> Result<(), AppError> {
    let group_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM sidebar WHERE name = $1 AND parent_ref IS NULL")
            .bind(name)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(group_id) = group_id else {
        return Ok(());
    };
    let skipped: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE subtree AS (
             SELECT id FROM sidebar WHERE id = $1
             UNION ALL
             SELECT s.id FROM sidebar s JOIN subtree t ON s.parent_ref = t.id
         )
         SELECT name FROM sidebar
         WHERE id IN (SELECT id FROM subtree) AND is_active = true AND is_customized = true",
    )
    .bind(group_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for item in &skipped {
        tracing::info!(
            sidebar_item = %item,
            group = %name,
            operation = "deactivate_subtree",
            "sidebar seed: skipped a customized sidebar row (is_customized = true)"
        );
    }
    sqlx::query(
        "WITH RECURSIVE subtree AS (
             SELECT id FROM sidebar WHERE id = $1
             UNION ALL
             SELECT s.id FROM sidebar s JOIN subtree t ON s.parent_ref = t.id
         )
         UPDATE sidebar SET is_active = false
         WHERE id IN (SELECT id FROM subtree) AND is_customized = false",
    )
    .bind(group_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Adds an idempotent visibility mapping from a sidebar item to a privilege.
async fn ensure_sidebar_privilege(
    db: &DbPool,
    sidebar_id: Uuid,
    privilege_key: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO sidebar_mm_privilege (sidebar_ref, privilege_ref)
         SELECT $1, id FROM privilege WHERE key = $2 AND is_active = true
         ON CONFLICT (sidebar_ref, privilege_ref) DO UPDATE SET is_deleted = false",
    )
    .bind(sidebar_id)
    .bind(privilege_key)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Ensures built-in sidebar groups and items are correct.
// D-479 (M26 R-09) — bumped 1 -> 2: "Dashboards" retagged from module
// "report" to "dashboard", which only takes effect on an already-deployed
// database once this stamp is stale.
// Bumped 2 -> 3: Seed Trading module group and Terminal & Lab page.
// Bumped 4 -> 5: seed the Knowledge Base gap queue row (D-489). Adding a row
// inside `seed_body` is invisible on an existing database without this bump:
// `run_if_stale` returns before the body runs, so the row is never inserted.
// Bumped 5 -> 6: move Web Crawling/Website out of Knowledge Base into the new
// top-level Acquisition group (D-489 follow-up).
// Bumped 6 -> 7: swapped every icon string that wasn't in the committed Line
// Awesome subset (angular/src/styles/line-awesome-subset.css) for one that
// is. This file is never scanned by `generate:icons` (it only reads Angular
// .ts/.html/.css source), so an icon class with no other Angular-side use
// silently rendered nothing in the sidebar. Existing rows keep their stale
// icon until this stamp is bumped, same as every other in-place field fix
// here (`upsert_sidebar_item`'s own `IS DISTINCT FROM` guard only fires
// when `seed_body` actually runs).
// Bumped 7 -> 8: promoted "ai" out of Coming Soon in place (same pattern as
// "document"/"search") — real icon, plus enabled "Agents"/"Models" children
// for `ai_agent`/`ai_model`, both already-provisioned MODULE_AI
// entities with no bespoke Angular components. `la-user-astronaut`/`la-brain`
// are already used elsewhere in Angular source and are in the committed Line
// Awesome subset, so no `generate:icons` run is needed for this bump.
// Bumped 8 -> 9: added a "Providers" child under "ai" for the new
// `ai_provider` entity, and a new top-level "Master List" group (order
// 49, no `module_key` — reusable core reference data, not AI-specific) with
// an "Authentication Types" child for `authentication_type`. Both
// entities are metadata-seeded by their own `platform-bundles/*.json`, no
// bespoke Angular components. Icons (`la-server`, `la-list-ul`, `la-key`)
// already exist elsewhere in Angular source and the committed Line Awesome
// subset.
// Bumped 9 -> 10: added "Personalities"/"Tones" children under "ai" for the
// new `ai_personality`/`ai_tone` entities (`ai_agent`'s
// many-to-many persona/tone relationships, D-455 join tables). Both entities
// are metadata-seeded by their own `platform-bundles/*.json`, no bespoke
// Angular components. Icons (`la-user-friends`, `la-comments`) already exist
// elsewhere in Angular source and the committed Line Awesome subset.
// Bumped 10 -> 11: `ai_model` was renamed to `ai_model_approval`
// (the plain name now belongs to a separate AI Model catalog entity —
// provider/context-window/per-token-cost metadata, see
// `attome_ai::model_registry.rs`'s module doc) — the existing "Models" child
// keeps its `/xrm/ai/model/list` path and `la-brain` icon unchanged (D-222's
// route is derived from the logicalname, so the new catalog entity resolves
// to the identical path the old registry entity used), and a new "Model
// Approvals" child is added for the renamed governance entity at its own
// D-222-derived path, reusing `la-clipboard-check` — already present
// elsewhere in Angular source and the committed Line Awesome subset, so no
// `generate:icons` run is needed for this bump.
// Bumped 11 -> 12: D-491 removed `ai_model_approval` — model approval is
// now `ai_model.approval_status`, a field on the AI Model catalog
// entity, not a separate governance entity — so the "Model Approvals" child
// this comment previously added is deactivated (not deleted: `deactivate`
// preserves an admin's re-point/re-enable of a retired item, same posture
// every other retirement in this file takes). The "Models" child is
// unchanged.
// Bumped 12 -> 13: added the "Live Sessions" child under "ai" (C6/D-556) for
// the new agent-session supervisor screen. A new row inside `seed_body` is
// invisible on an already-deployed database without this bump
// (`run_if_stale` returns before the body runs).
// Bumped 13 -> 14: Basic Units P1 follow-up — sidebar rows for the U19
// governance screens (Data Quality, Data Catalog, Change Feed), U8's State
// Models editor and U15's My Approvals inbox. The first four sit behind
// `system.admin`-only routes, so each is linked to that privilege (the live
// tree shows it to admins via `ctx.is_admin`, and to nobody else); My
// Approvals is every signed-in user's own inbox and carries no gate. Icons
// are all already in the committed Line Awesome subset.
// Bumped 14 -> 15: the "Web Portals" group and its "Portals" child for the
// web portal admin screen (`/xrm/admin/portals`), tagged "portal" and linked
// to `system.admin` like its routes. `la-globe` is already in the subset.
// Bumped 15 -> 16 (D-778): licensing removed. The "License" group and its
// list, import and usage items are retired; a new admin-only "Modules" group
// holds Module Management and Feature Flags, tied to no module.
// Bumped 16 -> 17 (Topic 15 #9): an admin-only "Relationships" group listing
// the junction-table entities (User Teams, User Privileges).
const SEED_VERSION: &str = "17";

pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_core::seed_gate::run_if_stale(db, "sidebar", SEED_VERSION, || seed_body(db)).await
}

async fn seed_body(db: &DbPool) -> Result<(), AppError> {
    // ── Renames ───────────────────────────────────────────────────────────────
    rename_group(db, "Core Admin", "Access & Identity").await?;
    rename_group(db, "S2S", "System API").await?;
    rename_group(db, "Content", "Content Management").await?;

    // ── Dashboard: a top-level group, not a bare leaf. Used to be two
    // disconnected top-level items — a static welcome leaf named "Dashboard"
    // (reachable only via a hardcoded post-login successRoute, with nothing
    // in the sidebar itself to get back to it) and a separate "Report"
    // module group whose only real child was the legacy `dashboard` entity
    // list, "Dashboards". Folded into one parent with both nested inside,
    // matching this file's "one top-level category per module, entities
    // nested inside" convention (see header comment) instead of being the
    // one exception to it. "Overview" is untagged, same as the old bare leaf
    // always was, so it stays reachable regardless of module state.
    //
    // D-479 (M26 R-09) retagged "Dashboards" from "report" to "dashboard":
    // `/xrm/dashboard/list` resolves through `urlPathToLogical` to
    // `attome_dashboard` (the real, current dashboard module), not the retired
    // legacy `dashboard` entity, so gating it on `MODULE_REPORT` was gating
    // the wrong feature's licence bit — the leaf now belongs to the module
    // whose data it actually lists, same as every sibling below it. ──
    let dashboard_group = upsert_sidebar(
        db,
        "Dashboard",
        None,
        "las la-home",
        "#3b82f6",
        None,
        5,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Overview",
        Some("/xrm/dashboard"),
        "las la-home",
        "#3b82f6",
        Some(dashboard_group),
        10,
        None,
    )
    .await?;
    // Basic Units U15 — the approver's own inbox. Any signed-in user
    // (`/api/v1/my-work/approvals` is self-service), so no privilege gate,
    // and untagged like "Overview" so no module state hides it.
    upsert_sidebar(
        db,
        "My Approvals",
        Some("/xrm/my-work/approvals"),
        "las la-user-check",
        "#f59e0b",
        Some(dashboard_group),
        15,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Dashboards",
        Some("/xrm/dashboard/list"),
        "las la-th-large",
        "#8b5cf6",
        Some(dashboard_group),
        20,
        Some("dashboard"),
    )
    .await?;
    // M28 Phase 1 (Decision Intelligence) — `dashboard_decision` is a single-
    // segment logicalname, so `logicalToUrlPath`/`entityListRoute` (Angular's
    // `entity-url.utils.ts`) resolve it to `/xrm/decision/list` and
    // `/xrm/decision/form` through the generic entity dispatcher
    // (`EntityRouterComponent`) with no bespoke component needed — same
    // "single-segment logicalname -> single-segment URL" convention
    // `attome_project`'s own entry documents elsewhere in this file. Tagged
    // "dashboard" (MODULE_DASHBOARD, `attome_modules::modules::MODULE_MAP`),
    // same tag "Dashboards" above now carries (D-479 retagged it off
    // "report" — the legacy `attome-report`-owned `dashboard` entity that tag
    // used to name is retired).
    upsert_sidebar(
        db,
        "Decisions",
        Some("/xrm/decision/list"),
        "las la-gavel",
        "#f59e0b",
        Some(dashboard_group),
        30,
        Some("dashboard"),
    )
    .await?;
    // M26 gap-fill — the template gallery, a hand-built card grid (not a
    // generic entity list, so a bespoke route like "Decisions"'s own
    // `/xrm/decision/list` would be, but this one resolves to a hand-built
    // component instead — see `xrm-shell.routes.ts`'s
    // `'dashboard-templates'` entry). Tagged "dashboard" for the same reason
    // "Decisions" is: it lists `attome_dashboard` rows, the new module, not
    // attome-report's legacy entity.
    upsert_sidebar(
        db,
        "Templates",
        Some("/xrm/dashboard-templates"),
        "las la-columns",
        "#10b981",
        Some(dashboard_group),
        40,
        Some("dashboard"),
    )
    .await?;
    // M27 Phase 1 (KPI & Metrics, D-407) — the scorecard admin page
    // (`metric/scorecard`, `MetricListComponent`) already exists and is
    // routable (`xrm-shell.routes.ts`) but had no sidebar entry at all,
    // making it unreachable outside a typed-in URL. `dashboard_metric_definition`
    // itself is a registered entity with a generic list/form, but the
    // scorecard view (live status + trend + on-demand compute) is the more
    // useful landing page for this module, same reasoning as "Templates"
    // above pointing at the gallery instead of the bare `attome_dashboard` list.
    upsert_sidebar(
        db,
        "Scorecards",
        Some("/xrm/metric/scorecard"),
        "las la-tachometer-alt",
        "#ef4444",
        Some(dashboard_group),
        50,
        Some("dashboard"),
    )
    .await?;
    // M48 Phase 1 scaffolding (D-453) — `dashboard_scenario` is a registered
    // entity with a generic list/form (no bespoke component built yet, see
    // that module's own master plan); like "Decisions" above it had no
    // sidebar entry, making the whole scenario/simulation surface
    // unreachable without a typed-in URL despite the routes existing.
    upsert_sidebar(
        db,
        "Scenarios",
        Some("/xrm/scenario/list"),
        "las la-code-branch",
        "#06b6d4",
        Some(dashboard_group),
        60,
        Some("dashboard"),
    )
    .await?;
    // `dashboard_page` (M26 Phase 2) is a registered entity with a
    // generic list/form (`attome-dashboard::seed::seed_page`) but, like
    // "Decisions"/"Scenarios" above before their own entries were added, had
    // no sidebar row — unreachable outside the in-context "Pages" tab on
    // `DashboardEditorComponent` or a typed-in URL. Tagged "dashboard" for
    // the same reason those siblings are: it belongs to the new module, not
    // attome-report's legacy `dashboard` entity.
    upsert_sidebar(
        db,
        "Pages",
        Some("/xrm/dashboard/page/list"),
        "las la-file-alt",
        "#14b8a6",
        Some(dashboard_group),
        65,
        Some("dashboard"),
    )
    .await?;
    // Retires the old standalone "Report" top-level group (and its own
    // "Overview"/"Dashboards" children, now superseded by the ones above) —
    // upsert_sidebar keys on (name, parent_ref), so a different parent means
    // a different row; the old one needs its own explicit deactivation.
    deactivate_subtree(db, "Report").await?;

    // ── core: everything foundational — not tied to one specific licensable
    // engine — shares the "core" module_key across three separate top-level
    // categories (Access & Identity, Security, Management), so toggling
    // "core" off in Module Management hides all three together even though
    // none of them nest inside a visible "Core" parent. The sidebar UI
    // (ShellComponent) only ever renders two levels — top-level category and
    // its direct children — so a category can never itself have a parent
    // category; "core" is purely a shared tag, never a group row. There is
    // no separate "entity"/"security" module anymore (folded in, per
    // explicit product decision — this repo's D-010/D-011-era ruling that
    // Security's admin surface must stay reachable regardless of any
    // module's on/off state still holds, and does, since "core" is not
    // meant to ever be safely disabled in practice — Module Management does
    // not special-case that, so this is a product-level convention, not an
    // enforced one).
    //
    // Old top-level "Access & Identity"/"Security" groups (pre-restructure,
    // untagged) are deactivated (subtree, since their children were also
    // untagged) and recreated top-level again with the "core" tag —
    // upsert_sidebar keys on (name, parent), so a same-name/same-parent row
    // just gets its module_key updated in place, but deactivate_subtree
    // still runs first in case an intermediate session (this one) had
    // nested them under a since-removed "Core" wrapper group instead.
    deactivate_subtree(db, "Access & Identity").await?;
    deactivate_subtree(db, "Security").await?;
    deactivate_subtree(db, "Core").await?;

    // ── Access & Identity: user_account / organization /
    // api_key. Privilege grants live under Security below (one
    // category per concern, not per module now that both share "core").
    let access_group = upsert_sidebar(
        db,
        "Access & Identity",
        None,
        "las la-users-cog",
        "#64748b",
        None,
        10,
        Some("core"),
    )
    .await?;
    deactivate(db, "Privilege Grants", Some(access_group)).await?;
    deactivate(db, "Job Privileges", Some(access_group)).await?;
    // User, team, and organization metadata/default queries are registered
    // by attome-security, so all three use the generic list/form router.
    upsert_sidebar(
        db,
        "Users",
        Some("/xrm/core/systemuser/list"),
        "las la-user",
        "#64748b",
        Some(access_group),
        10,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Teams",
        Some("/xrm/core/team/list"),
        "las la-users",
        "#64748b",
        Some(access_group),
        20,
        Some("core"),
    )
    .await?;

    // "Jobs" (-> /xrm/core/job/list, core_job) is a stale leftover: D-133
    // (migration 0051) physically dropped core_job/core_job_mm_privilege/
    // core_systemuser_mm_job in favor of role, so it was never
    // re-registered in entity_info and the generic entity engine 404s
    // resolving it ("No entity found for path \"job\""). Don't re-add this
    // link — core_job is intentionally retired, not a routing bug.
    deactivate(db, "Jobs", Some(access_group)).await?;

    // Organization records use the generic entity list. Membership and
    // effective-access administration remains under Security -> User Access.
    upsert_sidebar(
        db,
        "Organizations",
        Some("/xrm/core/organization/list"),
        "las la-sitemap",
        "#64748b",
        Some(access_group),
        30,
        Some("core"),
    )
    .await?;
    deactivate(db, "Organization", Some(access_group)).await?;
    // Privileges remain on the dedicated Security administration pages.
    deactivate(db, "Privileges", Some(access_group)).await?;
    upsert_sidebar(
        db,
        "API Keys",
        Some("/xrm/core/api_key/list"),
        "las la-key",
        "#64748b",
        Some(access_group),
        40,
        Some("core"),
    )
    .await?;

    // ── core / Security (attome-security). Tagged "core" like the rest of this
    // module — see the top-of-block comment above for why "core" being
    // disabled is a product convention, not something Module Management
    // enforces as safe. `SecurityModel` itself (attome-security/src/model.rs,
    // D-010) still mounts zero routes through the license-gated
    // ModelRegistry, unrelated to this sidebar tag. ─────────────────────────
    let security_group = upsert_sidebar(
        db,
        "Security",
        None,
        "las la-shield-alt",
        "#a855f7",
        None,
        20,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "My Access",
        Some("/xrm/admin/security/whoami"),
        "las la-id-card",
        "#a855f7",
        Some(security_group),
        10,
        Some("core"),
    )
    .await?;

    // Self-service MFA enrollment/status (D-069/D-072) — grouped next to "My
    // Access" since both are "about me" pages, ahead of the admin-facing
    // privilege/role/team pages below.
    upsert_sidebar(
        db,
        "MFA Settings",
        Some("/xrm/admin/security/mfa"),
        "las la-user-shield",
        "#a855f7",
        Some(security_group),
        15,
        Some("core"),
    )
    .await?;

    // Privilege catalog — now a registered entity (privilege,
    // attome-security/src/seed.rs::register_readonly_entities), so this links to
    // the generic entity list/form pages instead of a hand-built one, same
    // convention as Users/Organizations/Teams. Was only reachable as an
    // autocomplete datalist inside the (since-removed) flat Privilege
    // Grants/Role Privileges pages before those moved onto the User/Role
    // forms' own tabs.
    upsert_sidebar(
        db,
        "Privileges",
        Some("/xrm/core/privilege/list"),
        "las la-list-ul",
        "#a855f7",
        Some(security_group),
        18,
        Some("core"),
    )
    .await?;

    // Removed 2026-08-19: the direct-user-grants page was retired in favor
    // of the User form's own "Privileges" tab (scoped to the one user it
    // grants to, not a flat cross-user list) — see
    // angular/projects/xrm/security/public-api.ts's comment. No replacement
    // sidebar entry: the tab is reached from a user record, not top-level
    // navigation.
    deactivate(db, "Privilege Grants", Some(security_group)).await?;

    // `/xrm/admin/security/job-grants` was never wired to any Angular route
    // (xrm-shell.routes.ts has no such path) — this link 404'd/errored for
    // every click. Retired; a real "Job Privileges" concept, if one is
    // reintroduced, needs its own routed page first.
    deactivate(db, "Job Privileges", Some(security_group)).await?;

    // Roles — role is a registered entity (D-372,
    // attome-security/src/seed.rs::register_readonly_entities), so this is the
    // generic entity list; the tabbed create/edit form
    // (RoleFormComponent) stays a literal-route override at
    // `core/role/form`, xrm-shell.routes.ts. Ordered ahead of Role Entity
    // Access below since it assigns onto a role this page is where you
    // create.
    upsert_sidebar(
        db,
        "Roles",
        Some("/xrm/core/role/list"),
        "las la-users-cog",
        "#a855f7",
        Some(security_group),
        25,
        Some("core"),
    )
    .await?;

    // Removed 2026-08-19: the flat role-privileges page was retired in favor
    // of the Role form's own Privilege Grants tab (same API, no cross-role
    // view worth keeping) — see angular/projects/xrm/security/public-api.ts's
    // comment.
    deactivate(db, "Role Privileges", Some(security_group)).await?;

    upsert_sidebar(
        db,
        "Role Entity Access",
        Some("/xrm/admin/security/role-entity-access"),
        "las la-th-list",
        "#a855f7",
        Some(security_group),
        40,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Field Security Profiles",
        Some("/xrm/admin/security/field-profiles"),
        "las la-user-lock",
        "#a855f7",
        Some(security_group),
        50,
        Some("core"),
    )
    .await?;

    // The Teams list lives under Access & Identity; retire the former copy
    // here so existing databases do not show it twice.
    deactivate(db, "Teams", Some(security_group)).await?;

    upsert_sidebar(
        db,
        "User Access",
        Some("/xrm/admin/security/users"),
        "las la-user-friends",
        "#a855f7",
        Some(security_group),
        70,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Record Shares",
        Some("/xrm/admin/security/record-shares"),
        "las la-share-alt",
        "#a855f7",
        Some(security_group),
        80,
        Some("core"),
    )
    .await?;

    // ── Management: platform admin tools with no single owning module —
    // Entity Manager, Query Builder, Sidebar Manager, System Settings. Was
    // four separate top-level items; now grouped under one top-level
    // "Management" category (still top-level, not nested under anything),
    // tagged "core" like Access & Identity/Security above, renamed from
    // "Platform Tools" per product decision. ────────────────────────────────
    deactivate(db, "Entity Manager", None).await?;
    deactivate(db, "Query Builder", None).await?;
    deactivate(db, "Sidebar Manager", None).await?;
    deactivate(db, "System Settings", None).await?;

    // ── Relationships (SYSTEM-CHANGES Topic 15 #9) ──────────────────────────
    // Junction-table entities have their own forms (Topic 14) and are listed
    // in their own group, apart from the entities they join. Admin-only, like
    // the security screens they relate to.
    let relationships_group = upsert_sidebar(
        db,
        "Relationships",
        None,
        "las la-project-diagram",
        "#0ea5e9",
        None,
        25,
        Some("core"),
    )
    .await?;
    let user_teams = upsert_sidebar(
        db,
        "User Teams",
        Some("/xrm/core/systemuser/mm/team/list"),
        "las la-users",
        "#0ea5e9",
        Some(relationships_group),
        10,
        Some("core"),
    )
    .await?;
    let user_privileges = upsert_sidebar(
        db,
        "User Privileges",
        Some("/xrm/core/systemuser/mm/privilege/list"),
        "las la-key",
        "#0ea5e9",
        Some(relationships_group),
        20,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, relationships_group, ADMIN_PRIVILEGE_KEY).await?;
    ensure_sidebar_privilege(db, user_teams, ADMIN_PRIVILEGE_KEY).await?;
    ensure_sidebar_privilege(db, user_privileges, ADMIN_PRIVILEGE_KEY).await?;

    let management_group = upsert_sidebar(
        db,
        "Management",
        None,
        "las la-cogs",
        "#94a3b8",
        None,
        30,
        Some("core"),
    )
    .await?;

    // Retire the old nested name after the Query/View concept split.
    deactivate(db, "Query Builder", Some(management_group)).await?;

    upsert_sidebar(
        db,
        "Entity Manager",
        Some("/xrm/admin/entities"),
        "las la-project-diagram",
        "#38bdf8",
        Some(management_group),
        10,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "SQL Queries",
        Some("/xrm/admin/queries"),
        "las la-database",
        "#22c55e",
        Some(management_group),
        20,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Views",
        Some("/xrm/admin/views"),
        "las la-table",
        "#14b8a6",
        Some(management_group),
        25,
        Some("core"),
    )
    .await?;

    // M45 Phase 2 (D-472; business rules D-789/D-790) — the rules admin page,
    // backed by the `/api/v1/admin/business-rules` family.
    upsert_sidebar(
        db,
        "Rules",
        Some("/xrm/admin/rules"),
        "las la-code",
        "#f59e0b",
        Some(management_group),
        27,
        Some("core"),
    )
    .await?;

    let sidebar_manager = upsert_sidebar(
        db,
        "Sidebar Manager",
        Some("/xrm/admin/sidebar"),
        "las la-stream",
        "#8b5cf6",
        Some(management_group),
        30,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, sidebar_manager, "sidebar.manage").await?;

    // Auto Value rules (`attome_metadata::autovalue`) — admin-configured
    // autonumber formats. Browsed through the generic entity list/form
    // rather than a bespoke admin page, same as Workflow: the rule table is
    // a registered entity, so `/xrm/core/autovalue/list` and `.../form` come
    // from the metadata-driven pages for free.
    upsert_sidebar(
        db,
        "Auto Value",
        Some("/xrm/core/autovalue/list"),
        "las la-hashtag",
        "#0ea5e9",
        Some(management_group),
        35,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "System Settings",
        Some("/xrm/admin/settings"),
        "las la-cog",
        "#64748b",
        Some(management_group),
        40,
        Some("core"),
    )
    .await?;

    // D-404 / M83 Phase 1.
    upsert_sidebar(
        db,
        "Calendars",
        Some("/xrm/admin/calendars"),
        "las la-calendar-alt",
        "#0d9488",
        Some(management_group),
        45,
        Some("core"),
    )
    .await?;

    // Basic Units U8 — the state-model editor. Its routes are
    // `Authorized<Admin>`, so the row is linked to `system.admin`
    // (declared by `platform-bundles/attome-security.json`, applied before
    // this seed) and hidden from everyone else.
    let state_models = upsert_sidebar(
        db,
        "State Models",
        Some("/xrm/admin/state-models"),
        "las la-code-branch",
        "#6366f1",
        Some(management_group),
        47,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, state_models, ADMIN_PRIVILEGE_KEY).await?;

    // Basic Units U19 — the M89 change feed, admin-only like its route.
    let change_feed = upsert_sidebar(
        db,
        "Change Feed",
        Some("/xrm/admin/changes"),
        "las la-history",
        "#64748b",
        Some(management_group),
        48,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, change_feed, ADMIN_PRIVILEGE_KEY).await?;

    // D-195/P-four-eyes-approval §5 step 10's own UI, built (`ApprovalQueueListComponent`,
    // `xrm-shell.routes.ts`'s `admin/approvals` route) but never linked from the
    // sidebar until now — an admin could reach it only by typing the URL.
    upsert_sidebar(
        db,
        "Approval Queue",
        Some("/xrm/admin/approvals"),
        "las la-gavel",
        "#f59e0b",
        Some(management_group),
        50,
        Some("core"),
    )
    .await?;

    // M92 Extension Management Phase 1 — the bundle ledger's lifecycle UI
    // (installed named bundles, pending plans, drift, rollback). Same
    // "own standalone admin page under Management" shape as Approval Queue
    // just above. `la-cube` (not `la-boxes`) deliberately — the icon-subset
    // scanner (`angular/scripts/line-awesome-subset.mjs`) only scans Angular
    // `.ts`/`.html`/`.css` source, never this Rust file, so a sidebar icon
    // string has to already be in the committed subset to render at all;
    // `la-cube` already is (used elsewhere), `la-boxes` is not.
    upsert_sidebar(
        db,
        "Bundle Lifecycle",
        Some("/xrm/admin/metadata/bundles"),
        "las la-cube",
        "#a855f7",
        Some(management_group),
        55,
        Some("core"),
    )
    .await?;

    // ── Data Protection (P-data-protection-governance, D-269): DSR request
    // tracking/fulfillment and per-record legal hold place/release. Both
    // admin surfaces existed with no sidebar entry before D-269 — same gap
    // "Approval Queue" above just closed. Tagged "core", same reasoning as
    // Security/Management above: neither route is wrapped in `license_gate`
    // in `system.rs`, so this is not a separately licensed module. ─────────
    let data_protection_group = upsert_sidebar(
        db,
        "Data Protection",
        None,
        "las la-clipboard-check",
        "#ec4899",
        None,
        35,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "DSR Requests",
        Some("/xrm/admin/data-protection/dsr"),
        "las la-paper-plane",
        "#ec4899",
        Some(data_protection_group),
        10,
        Some("core"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Legal Holds",
        Some("/xrm/admin/data-protection/legal-holds"),
        "las la-lock",
        "#ec4899",
        Some(data_protection_group),
        20,
        Some("core"),
    )
    .await?;

    // M15 (Data Governance, D-413) — the accountability register: named data
    // domains, their steward/deputy, and the report answering "who owns this
    // data and what's touching it". Same "core" tagging as the two entries
    // above (governance_admin.rs's routes are not wrapped in `license_gate`).
    upsert_sidebar(
        db,
        "Data Domains",
        Some("/xrm/admin/data-protection/domains"),
        "las la-sitemap",
        "#ec4899",
        Some(data_protection_group),
        5,
        Some("core"),
    )
    .await?;

    // Basic Units U19 — M14 data quality and M18 data catalog screens.
    // Both routes are `Authorized<Admin>`; same `system.admin` link as the
    // Management rows above.
    let data_quality = upsert_sidebar(
        db,
        "Data Quality",
        Some("/xrm/admin/data/quality"),
        "las la-check-circle",
        "#ec4899",
        Some(data_protection_group),
        30,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, data_quality, ADMIN_PRIVILEGE_KEY).await?;

    let data_catalog = upsert_sidebar(
        db,
        "Data Catalog",
        Some("/xrm/admin/data/catalog"),
        "las la-book-open",
        "#ec4899",
        Some(data_protection_group),
        40,
        Some("core"),
    )
    .await?;
    ensure_sidebar_privilege(db, data_catalog, ADMIN_PRIVILEGE_KEY).await?;

    // ── Sales Suite: retired from the base seed — this is a *vertical*
    // (verticals skill), not a generic-platform module. Its ss_* entities are
    // never auto-provisioned; per the verticals skill's "Standing up a
    // vertical today (manual procedure)", they only exist on a deployment
    // where someone has manually run the ss_* metadata setup against the
    // admin API. Hardcoding these 11 links into the base sidebar_seed (which
    // runs unconditionally on every deployment via EngineSystemBuilder::build())
    // guarantees "No entity found" on every deployment that hasn't — which is
    // this dev DB right now (entity_info has no ss_* rows). Route
    // construction itself (prefix-stripped logicalname + "/list", matching
    // `entity-url.utils.ts::entityMatchesUrlPath`) was already fixed in the
    // same session these links were relabeled from raw logicalnames, but that
    // fix papered over the deeper problem: these rows don't belong in the
    // unconditional base seed at all. A vertical's sidebar rows belong in its
    // own provisioning step (step 2 of the manual procedure — "entities ->
    // fields -> queries -> sidebar"), applied only to deployments that
    // actually run it, not baked into every deployment's platform seed.
    deactivate(db, "Sales Suite", None).await?;
    let sales_group_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM sidebar WHERE name = $1 AND parent_ref IS NULL")
            .bind("Sales Suite")
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if let Some(sales_group) = sales_group_id {
        for name in [
            "Customers",
            "Customer Contacts",
            "Leads",
            "Quotes",
            "Quote Lines",
            "Invoices",
            "Payment Requests",
            "Activities",
            "Messages",
            "Message Threads",
            "Seller Profiles",
        ] {
            deactivate(db, name, Some(sales_group)).await?;
        }
    }

    // ── System API (attome-s2s): "Clients" points at the dedicated admin page.
    // Tagged "s2s" — a real MODULE_MAP entry now used consistently, matching
    // the every-module-gets-a-category convention below. `s2s_client`/
    // `s2s_permission`/`s2s_access_log` are all registered
    // generic entities (attome-s2s's own seed) with no sidebar link at all until
    // now — added below as generic list links alongside the dedicated
    // "Clients" admin page (which stays; the two are complementary, not a
    // replacement for each other — the dedicated page edits a client and its
    // scoped permissions/access-log together, the generic lists are the
    // plain per-entity views). The standalone "Permissions"/"Access Log"
    // top-level items from an earlier layout are retired (both are per-client
    // and now live inside the client editor). ──────────────────────────────
    let system_api_group = upsert_sidebar(
        db,
        "System API",
        None,
        "las la-plug",
        "#6366f1",
        None,
        200,
        Some("s2s"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Clients",
        Some("/xrm/admin/s2s/clients"),
        "las la-server",
        "#6366f1",
        Some(system_api_group),
        10,
        Some("s2s"),
    )
    .await?;

    deactivate(db, "Permissions", Some(system_api_group)).await?;
    deactivate(db, "Access Log", Some(system_api_group)).await?;

    upsert_sidebar(
        db,
        "S2S Clients (list)",
        Some("/xrm/core/s2s/client/list"),
        "las la-list",
        "#6366f1",
        Some(system_api_group),
        20,
        Some("s2s"),
    )
    .await?;

    upsert_sidebar(
        db,
        "S2S Permissions",
        Some("/xrm/core/s2s/permission/list"),
        "las la-key",
        "#6366f1",
        Some(system_api_group),
        30,
        Some("s2s"),
    )
    .await?;

    upsert_sidebar(
        db,
        "S2S Access Log",
        Some("/xrm/core/s2s/access/log/list"),
        "las la-history",
        "#6366f1",
        Some(system_api_group),
        40,
        Some("s2s"),
    )
    .await?;

    // ── Web Portals (attome-portal, D-576): the staff-side portal admin screen
    // (`PortalAdminComponent`, `xrm-shell.routes.ts`'s `admin/portals`
    // route — web portal plan Phase 13 step 6). Its own top-level category
    // per this file's one-category-per-module convention, tagged "portal"
    // (`MODULE_PORTAL`) so an unlicensed portal module hides it. Every
    // `/api/v1/admin/webportals` route is `system.admin`-only, so both rows
    // are linked to that privilege: admins see them, nobody else does. ──
    let web_portals_group = upsert_sidebar(
        db,
        "Web Portals",
        None,
        "las la-globe",
        "#0ea5e9",
        None,
        202,
        Some("portal"),
    )
    .await?;
    ensure_sidebar_privilege(db, web_portals_group, ADMIN_PRIVILEGE_KEY).await?;
    let portals = upsert_sidebar(
        db,
        "Portals",
        Some("/xrm/admin/portals"),
        "las la-globe",
        "#0ea5e9",
        Some(web_portals_group),
        10,
        Some("portal"),
    )
    .await?;
    ensure_sidebar_privilege(db, portals, ADMIN_PRIVILEGE_KEY).await?;

    // ── Modules (D-778): no licence is checked, so the old "License" group's
    // list, import and usage pages are gone. Module Management is the one
    // switch that hides a module's entities and sidebar items. No module key:
    // switching modules off must never hide the page that switches them back.
    deactivate_subtree(db, "License").await?;
    let modules_group = upsert_sidebar(
        db,
        "Modules",
        None,
        "las la-sliders-h",
        "#f59e0b",
        None,
        210,
        None,
    )
    .await?;
    ensure_sidebar_privilege(db, modules_group, ADMIN_PRIVILEGE_KEY).await?;

    upsert_sidebar(
        db,
        "Module Management",
        Some("/xrm/admin/license/modules"),
        "las la-sliders-h",
        "#f59e0b",
        Some(modules_group),
        10,
        None,
    )
    .await?;

    // M95/D-430 — Feature Flags, alongside Module Management.
    upsert_sidebar(
        db,
        "Feature Flags",
        Some("/xrm/admin/license/features"),
        "las la-flag",
        "#f59e0b",
        Some(modules_group),
        20,
        None,
    )
    .await?;

    // ── Audit (attome-audit): fix the stale route migration 0007 seeded
    // directly into the DB before the current URL convention existed
    // (`/xrm/entity/audit_header`, no `/list` suffix, full logicalname —
    // same bug class as the Sales Suite/Templates fixes above). D-222 then
    // changed the URL convention itself to a pure, lossless `_` -> `/` split
    // with no `entity` segment, so `audit_header` maps to
    // `/xrm/core/audit/header/list`, not `/xrm/entity/audit/header/list`.
    // Migrations are immutable once applied (guidelines §4), so this
    // idempotent seed is the correct place to correct it, same as it already
    // does for "Users"/"Privilege Grants"/etc. `audit_header`
    // genuinely is a registered generic entity (attome-audit's own seed) —
    // unlike Jobs/Organization/Privileges above, this one just needs the
    // route fixed, not deactivating. `audit_config`/
    // `audit_detail`/`audit_snapshot` previously had no
    // top-level link at all (0007's own comment called Detail/Snapshot
    // "drill-down-only") — added below as generic list links per explicit
    // product decision, alongside Audit Log rather than instead of it.
    let audit_group = upsert_sidebar(
        db,
        "Audit",
        None,
        "las la-history",
        "#10b981",
        None,
        205,
        Some("audit"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Audit Log",
        Some("/xrm/core/audit/header/list"),
        "las la-history",
        "#10b981",
        Some(audit_group),
        10,
        Some("audit"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Audit Config",
        Some("/xrm/core/audit/config/list"),
        "las la-cog",
        "#10b981",
        Some(audit_group),
        20,
        Some("audit"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Audit Detail",
        Some("/xrm/core/audit/detail/list"),
        "las la-list-ul",
        "#10b981",
        Some(audit_group),
        30,
        Some("audit"),
    )
    .await?;

    upsert_sidebar(
        db,
        "Audit Snapshot",
        Some("/xrm/core/audit/snapshot/list"),
        "las la-camera",
        "#10b981",
        Some(audit_group),
        40,
        Some("audit"),
    )
    .await?;

    // M19 gap list — the dedicated search surface
    // (`GET /api/v1/admin/audit/search`/`/export`, `AuditSearchComponent`),
    // distinct from "Audit Log" above (the generic entity list over
    // `audit_header`): this one has the entity/record/user/operation/
    // date/field filter form and the streamed jsonl/cef/csv export the
    // generic list page doesn't.
    upsert_sidebar(
        db,
        "Audit Search",
        Some("/xrm/admin/audit/search"),
        "las la-search",
        "#10b981",
        Some(audit_group),
        5,
        Some("audit"),
    )
    .await?;

    // ── Notifications (attome-notification, P2.11): template admin, its own
    // top-level category (one category per module). Tagged "notification" —
    // `NotificationModel` genuinely gates `/api/v1/notification/dispatch` on
    // this module bit (attome-notification/src/engine.rs), though the
    // Templates list below reads through query/execute like every other
    // entity, so (same caveat as "entity"/"audit" above) this tag controls
    // sidebar visibility, not the Templates list's own data reachability. ──
    let notification_group = upsert_sidebar(
        db,
        "Notifications",
        None,
        "las la-bell",
        "#eab308",
        None,
        220,
        Some("notification"),
    )
    .await?;

    // Route is a pure `_` -> `/` split of the logicalname (D-222), no
    // `entity` segment: `notification_template` -> `/xrm/notification/template/list`.
    upsert_sidebar(
        db,
        "Templates",
        Some("/xrm/notification/template/list"),
        "las la-envelope",
        "#eab308",
        Some(notification_group),
        10,
        Some("notification"),
    )
    .await?;

    // ── Cleanup: "Administration" was an old shared group (a stale leftover
    // from before Entity Manager/Query Builder each got their own top-level
    // category) — deactivate it and its direct children if they still exist
    // at that parent, since Entity Manager/Query Builder/Sidebar Manager/
    // System Settings now live under core / Management instead. The
    // top-level (parent: None) copies of all four are separately deactivated
    // earlier in this function, right before core_group's "Management"
    // category is created.
    let old_admin_group_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM sidebar WHERE name = $1 AND parent_ref IS NULL")
            .bind("Administration")
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if let Some(old_admin_group) = old_admin_group_id {
        deactivate(db, "Entity Manager", Some(old_admin_group)).await?;
        deactivate(db, "Query Builder", Some(old_admin_group)).await?;
        deactivate(db, "Administration", None).await?;
    }

    // ── Profiler: own top-level category (no engine crate/licence gate
    // exists for it — it's a plain `config.observability.profiler_enabled`
    // opt-in, same footing as metrics_port/distributed tracing, not a
    // licensable module — so no module_key here either) grouping the live
    // call-stats dashboard and the generic `profiler_finding` entity
    // list (PROFILER-2026-09-09.md group G's "top expensive configuration
    // objects" panel, #80). Both used to be flat top-level items; "Findings"
    // moves under this new group, so its old top-level location is
    // deactivated first — `upsert_sidebar` keys on (name, parent) and can't
    // "move" a row itself (same pattern as the Entity Manager/Query Builder
    // moves above).
    deactivate(db, "Profiler Findings", None).await?;

    let profiler_group = upsert_sidebar(
        db,
        "Profiler",
        None,
        "las la-tachometer-alt",
        "#0ea5e9",
        None,
        320,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Dashboard",
        Some("/xrm/admin/profiler"),
        "las la-tachometer-alt",
        "#0ea5e9",
        Some(profiler_group),
        10,
        None,
    )
    .await?;
    // `la-chart-bar` (not `la-search-dollar`, which isn't in the committed
    // Line Awesome subset and has no other literal use for
    // `generate:icons`'s scanner to pick up) — same "reuse a subset icon"
    // convention the Tag Items entry above documents.
    upsert_sidebar(
        db,
        "Findings",
        Some("/xrm/profiler/finding/list"),
        "las la-chart-bar",
        "#0ea5e9",
        Some(profiler_group),
        20,
        None,
    )
    .await?;

    upsert_sidebar(
        db,
        "Failed Jobs",
        Some("/xrm/admin/jobs/failed"),
        "las la-exclamation-triangle",
        "#ef4444",
        None,
        330,
        None,
    )
    .await?;

    // ── Workflow Engine (P2.9, P-workflow-engine.md) — admin CRUD, execution
    // engine, and node-canvas editor all shipped; Definitions links to the
    // list/graph-editor UI, Instances to the run monitoring UI. Reuses the
    // "Workflow" name
    // at the same top level + display_order the "Coming Soon" loop below
    // used to seed for this module_key, so this upsert replaces that
    // placeholder row in place rather than creating a duplicate — keyed on
    // (name, parent_ref), same as every other module category in this file.
    // "workflow" is therefore removed from that loop's tuple list just
    // below (it now has a real crate/route, so a "coming soon" entry for
    // it would be a lie, same reasoning the loop's own comment already
    // gives for excluding "field"/"form").
    let workflow_group = upsert_sidebar(
        db,
        "Workflow",
        None,
        "las la-project-diagram",
        "#6366f1",
        None,
        400,
        Some("workflow"),
    )
    .await?;
    // Points at the *generic* entity list for workflow_definition
    // (registered by `platform-bundles/attome-workflow.json`), not a bespoke admin screen —
    // workflows browse and edit through the same metadata-driven list/form
    // pages as every other entity. Creating one still needs the node canvas,
    // so that list's "New" navigates to /xrm/admin/workflow/definitions/new
    // (the custom create page) instead of the generic form.
    upsert_sidebar(
        db,
        "Definitions",
        Some("/xrm/workflow/definition/list"),
        "las la-sitemap",
        "#6366f1",
        Some(workflow_group),
        10,
        Some("workflow"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Instances",
        Some("/xrm/admin/workflow/instances"),
        "las la-tasks",
        "#6366f1",
        Some(workflow_group),
        20,
        Some("workflow"),
    )
    .await?;

    // ── Project Management (attome-project) — customer delivery projects, a
    // hierarchical work-item (WBS) tree, deliverables, issues/risks, change
    // requests, and two-way customer communication. Every child row here
    // points at the *generic* list for its entity (registered by
    // `attome_project::seed`), same "browse through the metadata-driven pages,
    // no bespoke admin screen" posture as Workflow's Definitions row above.
    // Team Members and Communications are deliberately NOT given their own
    // top-level row — both are always accessed scoped to one project (from
    // that project's own detail page), never browsed standalone. ──────────
    let project_group = upsert_sidebar(
        db,
        "Projects & Delivery",
        None,
        "las la-briefcase",
        "#8b5cf6",
        None,
        405,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Projects",
        Some("/xrm/project/list"),
        "las la-folder-open",
        "#8b5cf6",
        Some(project_group),
        10,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Customers",
        Some("/xrm/project/customer/list"),
        "las la-building",
        "#8b5cf6",
        Some(project_group),
        20,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Contacts",
        Some("/xrm/project/customer/contact/list"),
        "las la-id-card",
        "#8b5cf6",
        Some(project_group),
        30,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Tasks",
        Some("/xrm/project/work/item/list"),
        "las la-tasks",
        "#8b5cf6",
        Some(project_group),
        40,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Deliverables",
        Some("/xrm/project/deliverable/list"),
        "las la-cube",
        "#8b5cf6",
        Some(project_group),
        50,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Change Requests",
        Some("/xrm/project/change/request/list"),
        "las la-redo",
        "#8b5cf6",
        Some(project_group),
        60,
        Some("project"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Issues & Risks",
        Some("/xrm/project/issue/list"),
        "las la-exclamation-triangle",
        "#8b5cf6",
        Some(project_group),
        70,
        Some("project"),
    )
    .await?;
    // Points at the bespoke Submit/Approve/Reject list
    // (`ProjectTimesheetListComponent`, `crates/engine/attome-project/src/
    // timesheet.rs`'s M07 state model + D-195/D-421 four-eyes gate) rather
    // than the entity's own generic list/form — a raw generic grid over
    // `project_timesheet` can browse rows but cannot call those
    // decision routes. Not project-scoped (the entity carries no
    // `project_id`, only `user_id`/`week_start_date` — see that component's
    // own doc comment), so it sits at this group's top level like every
    // other row here, not nested under a specific project.
    upsert_sidebar(
        db,
        "Timesheets",
        Some("/xrm/project/timesheet/list"),
        "las la-history",
        "#8b5cf6",
        Some(project_group),
        80,
        Some("project"),
    )
    .await?;

    // ── Acquisition (D-489 follow-up) — the crawler that feeds Knowledge
    // Base gets its own top-level group instead of sitting inside the corpus
    // it fills. D-365 hung "Web Crawling"/"Website" under Knowledge Base
    // because crawling was scoped as an extension of it and had no module to
    // own a group; that is an implementation lineage, not a navigation one.
    // The screens are acquisition plumbing, and they are the only rows this
    // file seeds whose visibility the `config.webcrawl.enabled` kill switch
    // does not affect. Sits at 44, immediately before Knowledge Base. Still no
    // `module_key`: crawling has no licence bit (D-365). ─────────────────────
    let acquisition_group = upsert_sidebar(
        db,
        "Acquisition",
        None,
        "las la-download",
        "#0ea5e9",
        None,
        44,
        None,
    )
    .await?;

    // ── Knowledge Base (D-363) — the corpus. A top-level group, not nested
    // under Search (see D-363's rationale). No `module_key`: the Data Source /
    // Data Item entities are ungated (D-363 built them so), and only the gap
    // queue below carries one. Idempotent against the (name, parent) row
    // D-363's one-off admin API call already created on this database — this
    // seed makes the group reproducible on a fresh deployment too, the same
    // gap the module doc on `attome_webcrawl::seed` explains. ──────────────────
    let knowledge_base_group = upsert_sidebar(
        db,
        "Knowledge Base",
        None,
        "las la-layer-group",
        "#0ea5e9",
        None,
        45,
        None,
    )
    .await?;
    // Pure logicalname->URL mapping (entity-url.utils.ts's `logicalToUrlPath`):
    // every underscore becomes a '/' — knowledge_data_source ->
    // xrm/knowledge/data/source, not .../knowledge/data_source.
    upsert_sidebar(
        db,
        "Data Sources",
        Some("/xrm/knowledge/data/source/list"),
        "las la-database",
        "#0ea5e9",
        Some(knowledge_base_group),
        10,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Data Items",
        Some("/xrm/knowledge/data/item/list"),
        "las la-file-alt",
        "#0ea5e9",
        Some(knowledge_base_group),
        20,
        None,
    )
    .await?;
    // D-489 follow-up — the crawler rows moved out of this group.
    // `move_sidebar_item` re-parents the row D-365's seed created here (on an
    // existing database it is still a child of Knowledge Base); the
    // `upsert_sidebar` calls after it create the row under Acquisition on a
    // fresh database and keep its fields current everywhere. The old-parent
    // upserts are deliberately gone: leaving them would recreate a duplicate
    // under Knowledge Base on the next boot.
    move_sidebar_item(
        db,
        "Web Crawling",
        Some(knowledge_base_group),
        Some(acquisition_group),
        10,
    )
    .await?;
    move_sidebar_item(
        db,
        "Website",
        Some(knowledge_base_group),
        Some(acquisition_group),
        20,
    )
    .await?;
    upsert_sidebar(
        db,
        "Web Crawling",
        Some("/xrm/admin/webcrawl/targets"),
        "las la-globe",
        "#0ea5e9",
        Some(acquisition_group),
        10,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Website",
        Some("/xrm/admin/webcrawl/website"),
        "las la-sitemap",
        "#0ea5e9",
        Some(acquisition_group),
        20,
        None,
    )
    .await?;
    // D-489 — the authors' gap queue. `module_key` IS set here, unlike every
    // sibling above: the route is mounted through `SearchModel`, so a
    // deployment without MODULE_SEARCH must not be shown a link that 403s.
    upsert_sidebar(
        db,
        "Knowledge Gaps",
        Some("/xrm/admin/knowledge/gaps"),
        "las la-question-circle",
        "#0ea5e9",
        Some(knowledge_base_group),
        50,
        Some("search"),
    )
    .await?;
    // Chatbot plan C8 — the draft review queue reads and writes
    // `knowledge_data_item` through the generic entity API, which is
    // ungated like the Data Items row above, so no `module_key`.
    upsert_sidebar(
        db,
        "Knowledge Drafts",
        Some("/xrm/admin/knowledge/drafts"),
        "las la-clipboard-check",
        "#0ea5e9",
        Some(knowledge_base_group),
        30,
        None,
    )
    .await?;
    // Chatbot plan C8 — per-collection coverage. Mounted through
    // `SearchModel`, like the gap queue, so it carries the same `module_key`.
    upsert_sidebar(
        db,
        "Knowledge Coverage",
        Some("/xrm/admin/knowledge/coverage"),
        "las la-chart-bar",
        "#0ea5e9",
        Some(knowledge_base_group),
        55,
        Some("search"),
    )
    .await?;

    // ── Content Management (D-367) — page-builder CMS: custom pages,
    // infinite editorial hierarchy, a block-based editor, and published
    // pages servable under their own custom URL. A real licensed module
    // (`MODULE_CONTENT`), same pattern as Workflow above — a top-level
    // group carrying `module_key`, not a "Coming Soon" placeholder, since
    // the admin CRUD + editor UI ship alongside this seed.
    let content_group = upsert_sidebar(
        db,
        "Content Management",
        None,
        "las la-file-code",
        "#f59e0b",
        None,
        46,
        Some("content"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Pages",
        Some("/xrm/admin/content/pages"),
        "las la-file-alt",
        "#f59e0b",
        Some(content_group),
        10,
        Some("content"),
    )
    .await?;

    // M59 Phase 1 (D-424/D-425) — external-system registry + inbound
    // webhook. Same pattern as Workflow/Content above: a top-level group
    // carrying `module_key = "integration"` (shared with attome-events'
    // MODULE_INTEGRATION, D-403), not a "Coming Soon" placeholder, since the
    // entity + generic CRUD UI ship alongside this seed — so "integration"
    // is removed from that loop's tuple list just below (same reasoning
    // "workflow"/"content" were).
    let integration_group = upsert_sidebar(
        db,
        "Integrations",
        None,
        "las la-plug",
        "#0ea5e9",
        None,
        47,
        Some("integration"),
    )
    .await?;
    // Points at the generic entity list for integration_system —
    // systems are created through this crate's bespoke
    // `/api/v1/admin/integrations/systems` endpoint (SSRF screening +
    // credential provisioning, see `attome-integration/src/admin.rs`), not the
    // generic form's own POST, but browse/edit/deactivate reuse the same
    // metadata-driven list/form pages as every other entity.
    upsert_sidebar(
        db,
        "Systems",
        Some("/xrm/integration/system/list"),
        "las la-server",
        "#0ea5e9",
        Some(integration_group),
        10,
        Some("integration"),
    )
    .await?;

    // M20 Phase 1 (D-427) — Governance, Risk & Compliance. Same pattern as
    // Content/Integration above: a top-level group carrying
    // `module_key = "grc"`, not a "Coming Soon" placeholder, since the
    // entities + generic CRUD UI (plus the bespoke Control Matrix/Policy
    // List views) ship alongside this seed. `risk_dependency` and
    // `policy_ack` are deliberately NOT given their own top-level row — same
    // "accessed scoped to its parent record, never browsed standalone"
    // reasoning Project Management's own Team Members/Communications rows
    // document above.
    let grc_group = upsert_sidebar(
        db,
        "Governance, Risk & Compliance",
        None,
        "las la-shield-alt",
        "#0d9488",
        None,
        48,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Regulations",
        Some("/xrm/grc/regulation/list"),
        "las la-gavel",
        "#0d9488",
        Some(grc_group),
        10,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Requirements",
        Some("/xrm/grc/requirement/list"),
        "las la-list-ol",
        "#0d9488",
        Some(grc_group),
        20,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Controls",
        Some("/xrm/grc/control/list"),
        "las la-check-circle",
        "#0d9488",
        Some(grc_group),
        30,
        Some("grc"),
    )
    .await?;
    // Points at the generic list route for grc_control_requirement, but
    // the Angular entry point (@attome/xrm/grc) overrides that route's
    // `listComponent` with a real control-x-requirement matrix — the M:M
    // mapping is not meaningfully browsable as a flat list.
    upsert_sidebar(
        db,
        "Control Matrix",
        Some("/xrm/grc/control/requirement/list"),
        "las la-th-large",
        "#0d9488",
        Some(grc_group),
        40,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Assessments",
        Some("/xrm/grc/assessment/list"),
        "las la-clipboard-check",
        "#0d9488",
        Some(grc_group),
        50,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Findings",
        Some("/xrm/grc/finding/list"),
        "las la-search",
        "#0d9488",
        Some(grc_group),
        60,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Evidence",
        Some("/xrm/grc/evidence/list"),
        "las la-folder-open",
        "#0d9488",
        Some(grc_group),
        70,
        Some("grc"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Risks",
        Some("/xrm/grc/risk/list"),
        "las la-exclamation-triangle",
        "#0d9488",
        Some(grc_group),
        80,
        Some("grc"),
    )
    .await?;
    // Points at the generic list route for grc_policy, but the Angular
    // entry point overrides its `listComponent` with a status/expiry-aware
    // Policy List view (M20-grc.md's Phase 1 checklist).
    upsert_sidebar(
        db,
        "Policies",
        Some("/xrm/grc/policy/list"),
        "las la-file-alt",
        "#0d9488",
        Some(grc_group),
        90,
        Some("grc"),
    )
    .await?;

    // ── Master List — reusable core reference data (Value/Purpose lookup
    // tables), not owned by any single engine. No `module_key`: same
    // ungated-by-design posture as `tag_category`/`glossary_term`
    // (entity_module_gate.rs). `authentication_type` is the first
    // entry; a future reusable lookup list belongs here too rather than
    // growing its own top-level group. ─────────────────────────────────────
    let master_list_group = upsert_sidebar(
        db,
        "Master List",
        None,
        "las la-list-ul",
        "#64748b",
        None,
        49,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Authentication Types",
        Some("/xrm/core/authentication/type/list"),
        "las la-key",
        "#64748b",
        Some(master_list_group),
        10,
        None,
    )
    .await?;

    // ── Tags (attome-api's own `tag_seed`) — platform-wide tagging. No
    // `module_key`: ungated core feature, same posture as Knowledge Base
    // above. "Tag Categories" is the primary admin surface (defines the
    // reusable tag vocabulary a record can be tagged with); "Tag Items" is
    // the flat list of every application, kept reachable for completeness
    // and bulk cleanup even though the normal way to create one is the
    // per-record "Tags" panel embedded on every entity form
    // (`tags-panel.component.ts`), not this list's own "+ New".
    let tags_group =
        upsert_sidebar(db, "Tags", None, "las la-tags", "#f472b6", None, 49, None).await?;
    upsert_sidebar(
        db,
        "Tag Categories",
        Some("/xrm/tag/category/list"),
        "las la-list-ul",
        "#f472b6",
        Some(tags_group),
        10,
        None,
    )
    .await?;
    upsert_sidebar(
        db,
        "Tag Items",
        Some("/xrm/tag/item/list"),
        // `la-tag` (singular) isn't in the committed Line Awesome subset and
        // has no other literal use in Angular source for
        // `generate:icons`'s scanner to pick up (unlike `la-tags`/`la-list-ul`
        // above, both already used elsewhere) — `la-th-list` instead, already
        // in the subset for the same reason.
        "las la-th-list",
        "#f472b6",
        Some(tags_group),
        20,
        None,
    )
    .await?;

    // ── Trading Engine (trade) ─────────────────────────────────────────────
    let trade_group = upsert_sidebar(
        db,
        "Trading",
        None,
        "las la-chart-line",
        "#10b981",
        None,
        50,
        Some("trd"),
    )
    .await?;
    upsert_sidebar(
        db,
        "Terminal & Lab",
        Some("/xrm/trade"),
        "las la-chart-bar",
        "#10b981",
        Some(trade_group),
        10,
        Some("trd"),
    )
    .await?;

    deactivate_subtree(db, "Coming Soon").await?;
    for (order, module_key, label) in [
        (401, "state", "State"),
        (402, "search", "Search"),
        (404, "document", "Document"),
        (405, "ai", "AI"),
        (407, "localization", "Localization"),
        (408, "view", "View"),
        (409, "config", "Config"),
        (410, "bot", "Bot"),
        (411, "automation", "Automation"),
        // "generator" (412) was removed here by D-457 (M66): its module bit
        // was retired (attome-modules/src/modules.rs), so this placeholder row
        // is no longer re-upserted on boot — `deactivate_subtree(db, "Coming
        // Soon")` above already deactivated it before this loop runs, and
        // dropping the tuple leaves it deactivated rather than reactivating
        // a "coming soon" promise for a module id that no longer exists.
    ] {
        // `document` is promoted out of Coming Soon (D-364): the entity, the
        // grouped read endpoint, and the folder-browser UI all ship. It keeps
        // its slot and `module_key` here rather than becoming a second,
        // competing top-level entry — the same promote-in-place pattern D-363
        // used for Knowledge Base — but it gets a real icon instead of the
        // greyed spinner, plus the enabled child added below. The disabled
        // "Overview" placeholder underneath it is left alone, exactly as
        // D-364 recorded.
        // `ai` is promoted the same way: `ai_agent`/`ai_model` are
        // real, provisioned entities (attome-ai, MODULE_AI) with no bespoke
        // Angular components, so they render through the generic
        // metadata-driven list/form pages the wildcard route already
        // resolves — same as `service_offering` (D-398).
        // `report` is NOT in this loop's tuple list above — its entity, CRUD,
        // and builder/viewer UI all ship (attome-report), but rather than being
        // promoted in place here it was folded into the top-level "Dashboard"
        // group instead (see that block earlier in this function), since the
        // two were the same product concept split across two disconnected
        // top-level items.
        let (group_icon, group_color) = if module_key == "document" {
            ("las la-folder-open", "#0ea5e9")
        } else if module_key == "ai" {
            ("las la-robot", "#8b5cf6")
        } else {
            ("las la-spinner", "#94a3b8")
        };
        // upsert_sidebar keys on (name, parent) and always sets route/icon/
        // etc. to whatever is passed here (including route: None), so this
        // also correctly clears the leftover route field on any row an
        // earlier session created as a flat leaf item under this same name.
        let module_group = upsert_sidebar(
            db,
            label,
            None,
            group_icon,
            group_color,
            None,
            order,
            Some(module_key),
        )
        .await?;
        upsert_sidebar_item(
            db,
            "Overview",
            Some(&format!("/xrm/modules/{module_key}")),
            "las la-spinner",
            "#94a3b8",
            Some(module_group),
            10,
            Some(module_key),
            true,
        )
        .await?;

        // `search` is the one key in this list whose engine is actually built
        // and mounted (attome-search, `GET /api/v1/search`), with a real UI route
        // at /xrm/admin/search/lab. The group stays here — the rest of the
        // Search surface is still coming — but a fresh deployment should be
        // able to reach the lab and exercise the engine without hand-adding a
        // sidebar row through the admin API first. Enabled (is_disabled =
        // false), unlike the greyed "Overview" placeholder above it.
        if module_key == "search" {
            upsert_sidebar(
                db,
                "Search Lab",
                Some("/xrm/admin/search/lab"),
                "las la-flask",
                "#6366f1",
                Some(module_group),
                20,
                Some(module_key),
            )
            .await?;
        }

        // D-364's system-wide Documents page. `/documents` is a literal route
        // registered in `xrm-shell.routes.ts` ahead of the entity wildcard —
        // not an `/xrm/...` entity list path — so it is spelled out here
        // rather than derived from a logicalname. Enabled, unlike the greyed
        // "Overview" placeholder above it. Idempotent against the row D-364's
        // one-off admin API call already created on the authoring database.
        if module_key == "document" {
            upsert_sidebar(
                db,
                "Documents",
                Some("/documents"),
                "las la-folder-open",
                "#0ea5e9",
                Some(module_group),
                20,
                Some(module_key),
            )
            .await?;
        }

        // Enabled, unlike the greyed "Overview" placeholder above — every
        // entity below is real (attome-ai, MODULE_AI) and renders through the
        // generic entity list/form pages at its D-222-derived route
        // (`ai_agent` -> `/xrm/ai/agent`, `ai_model` (catalog,
        // carrying its own `approval_status`) -> `/xrm/ai/model`).
        if module_key == "ai" {
            upsert_sidebar(
                db,
                "Agents",
                Some("/xrm/ai/agent/list"),
                "las la-user-astronaut",
                "#8b5cf6",
                Some(module_group),
                20,
                Some(module_key),
            )
            .await?;
            upsert_sidebar(
                db,
                "Models",
                Some("/xrm/ai/model/list"),
                "las la-brain",
                "#8b5cf6",
                Some(module_group),
                30,
                Some(module_key),
            )
            .await?;
            upsert_sidebar(
                db,
                "Providers",
                Some("/xrm/ai/provider/list"),
                "las la-server",
                "#8b5cf6",
                Some(module_group),
                40,
                Some(module_key),
            )
            .await?;
            upsert_sidebar(
                db,
                "Personalities",
                Some("/xrm/ai/personality/list"),
                "las la-user-friends",
                "#8b5cf6",
                Some(module_group),
                50,
                Some(module_key),
            )
            .await?;
            upsert_sidebar(
                db,
                "Tones",
                Some("/xrm/ai/tone/list"),
                "las la-comments",
                "#8b5cf6",
                Some(module_group),
                60,
                Some(module_key),
            )
            .await?;
            // The AI Playground (`agent.playground_complete` — send one
            // message to an agent's persona and see the reply, no session).
            // Not an `ai_agent`-family entity route: a bespoke Angular
            // page (`@attome/xrm/ai`'s `AiPlaygroundComponent`), same
            // "own literal route ahead of the entity wildcard" shape
            // `xrm-shell.routes.ts`'s `search/lab` uses.
            upsert_sidebar(
                db,
                "Playground",
                Some("/xrm/ai/playground"),
                "las la-flask",
                "#8b5cf6",
                Some(module_group),
                70,
                Some(module_key),
            )
            .await?;
            // C6 (D-556) -- the live-session supervisor: the read
            // (`GET /api/v1/admin/agents/sessions`) and the three actions
            // (`agent.pause`/`agent.resume`/`agent.kill`) already existed; only
            // the screen was missing. This is where an admin removes a
            // capability from a session that is ALREADY RUNNING — a policy
            // edit only reaches the next session. Gated on
            // `ai_agent.supervise`, the same privilege as the read and
            // the actions, so a deployment that shows this page already lets
            // its viewers act on it. `la-heartbeat` is in the committed Line
            // Awesome subset, so no `generate:icons` run is needed.
            upsert_sidebar(
                db,
                "Live Sessions",
                Some("/xrm/ai/sessions"),
                "las la-heartbeat",
                "#8b5cf6",
                Some(module_group),
                80,
                Some(module_key),
            )
            .await?;
            // Removed 2026-09-11 (D-491): `ai_model_approval` no longer
            // exists — approval is now `ai_model.approval_status`,
            // reached from the "Models" entry above, at its unchanged
            // `/xrm/ai/model/list` path.
            deactivate(db, "Model Approvals", Some(module_group)).await?;
        }
    }

    tracing::info!("attome-api: sidebar seed complete");
    Ok(())
}
