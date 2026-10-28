//! Assembles a dashboard's page/section/breakpoint/widget tree as JSON for
//! `lifecycle::do_publish_dashboard`'s immutable version snapshot — the
//! Phase 2 spec's "Layout serialization/deserialization (stable JSON for
//! versioning)" requirement, and the reason `dashboard_version.
//! snapshot_json` can call itself a snapshot of the dashboard's whole
//! "definition" rather than just its own scalar fields. Widgets (Phase 3)
//! are included here too, not just pages/sections (Phase 2) — a published
//! version that silently dropped every widget on the dashboard would not be
//! a snapshot of the definition at all.
//!
//! Page/section/breakpoint/widget CRUD, reordering (`sequence`), nesting
//! (`parent_section_id`), move/resize (plain field updates), and page-level
//! permission are entirely generic entity CRUD (`model.rs`'s doc comment) —
//! reachable from HTTP that way, never through this module's own routes
//! (it has none).
//!
//! No "grid collision" logic here despite the spec's Phase 2 checklist
//! bullet — collision detection needs *widget* positions to actually
//! collide over, and nothing computes widget collisions yet (Phase 3 placed
//! widgets; nothing has needed collision detection since). `grid_config`/
//! `freeform_config`/widget `config` stay opaque JSON blobs this module
//! snapshots verbatim, same as everywhere else they appear.
//!
//! **Write path (2026-08-29, M26 Phase 2 backlog).** `apply_pages_snapshot`
//! is the inverse of `pages_snapshot` — it materializes a snapshot JSON tree
//! back into real rows. Two callers, two different [`IdPolicy`]s:
//! `lifecycle::do_restore_version` reuses every snapshot id (`ReuseIds`) so
//! restoring twice in a row is idempotent and nothing else that referenced
//! those ids (an `emits`/`listens` binding, a bookmark) breaks; `lifecycle::
//! do_clone` generates fresh ids for everything (`GenerateNewIds`) because
//! the source dashboard's own rows are still live under those exact ids —
//! reusing them into a second dashboard would violate the primary key. Found
//! while building this: `do_clone` previously copied only `attome_dashboard`'s
//! own scalar fields and left the clone with zero pages — despite `xrm-
//! dashboard`'s own Pass-1 documentation and this crate's checklist both
//! having claimed it deep-copied the tree. Fixed here, not documented as a
//! pre-existing feature.
use attome_audit::AuditOperation;
use attome_core::{AttrInfo, EngineState};
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::DashboardCreate;

#[derive(sqlx::FromRow)]
struct PageRow {
    id: Uuid,
    name: String,
    name_ar: Option<String>,
    slug: Option<String>,
    sequence: Option<f64>,
    is_visible: Option<bool>,
    icon: Option<String>,
    background_kind: Option<String>,
    background_value: Option<String>,
    padding: Option<String>,
    settings: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SectionRow {
    id: Uuid,
    parent_section_id: Option<Uuid>,
    section_type: String,
    layout_mode: String,
    name: Option<String>,
    sequence: Option<f64>,
    grid_config: Option<String>,
    freeform_config: Option<String>,
}

#[derive(sqlx::FromRow)]
struct BreakpointRow {
    section_id: Uuid,
    breakpoint: String,
    position_config: Option<String>,
    size_config: Option<String>,
    is_visible: Option<bool>,
    column_count: Option<f64>,
    font_scale: Option<f64>,
    sequence_override: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct WidgetRow {
    id: Uuid,
    section_id: Uuid,
    widget_type: String,
    name: Option<String>,
    name_ar: Option<String>,
    sequence: Option<f64>,
    grid_col: Option<f64>,
    grid_row: Option<f64>,
    grid_col_span: Option<f64>,
    grid_row_span: Option<f64>,
    freeform_x: Option<f64>,
    freeform_y: Option<f64>,
    freeform_width: Option<f64>,
    freeform_height: Option<f64>,
    freeform_z_index: Option<f64>,
    config: Option<String>,
    responsive_overrides: Option<String>,
    is_visible: Option<bool>,
    is_locked: Option<bool>,
    group_id: Option<String>,
    query_id: Option<String>,
    view_id: Option<String>,
    query_params: Option<String>,
    emits: Option<String>,
    listens: Option<String>,
}

fn breakpoint_json(b: &BreakpointRow) -> Value {
    serde_json::json!({
        "breakpoint": b.breakpoint,
        "position_config": b.position_config,
        "size_config": b.size_config,
        "is_visible": b.is_visible,
        "column_count": b.column_count,
        "font_scale": b.font_scale,
        "sequence_override": b.sequence_override,
    })
}

fn widget_json(w: &WidgetRow) -> Value {
    serde_json::json!({
        "id": w.id,
        "widget_type": w.widget_type,
        "name": w.name,
        "name_ar": w.name_ar,
        "sequence": w.sequence,
        "grid_col": w.grid_col,
        "grid_row": w.grid_row,
        "grid_col_span": w.grid_col_span,
        "grid_row_span": w.grid_row_span,
        "freeform_x": w.freeform_x,
        "freeform_y": w.freeform_y,
        "freeform_width": w.freeform_width,
        "freeform_height": w.freeform_height,
        "freeform_z_index": w.freeform_z_index,
        "config": w.config,
        "responsive_overrides": w.responsive_overrides,
        "is_visible": w.is_visible,
        "is_locked": w.is_locked,
        "group_id": w.group_id,
        "query_id": w.query_id,
        "view_id": w.view_id,
        "query_params": w.query_params,
        "emits": w.emits,
        "listens": w.listens,
    })
}

/// Builds the section forest under `parent`, depth-first. Trusts the
/// platform's self-referencing-lookup hierarchy engine to have already
/// refused a cycle on write (same trust `attome-project`'s own WBS tree
/// extends to `parent_work_item_id` — see `attome-project::seed`'s doc
/// comment) rather than re-guarding against one here.
fn section_tree(
    sections: &[SectionRow],
    breakpoints: &[BreakpointRow],
    widgets: &[WidgetRow],
    parent: Option<Uuid>,
) -> Vec<Value> {
    sections
        .iter()
        .filter(|s| s.parent_section_id == parent)
        .map(|s| {
            let bps: Vec<Value> = breakpoints
                .iter()
                .filter(|b| b.section_id == s.id)
                .map(breakpoint_json)
                .collect();
            let section_widgets: Vec<Value> = widgets
                .iter()
                .filter(|w| w.section_id == s.id)
                .map(widget_json)
                .collect();
            serde_json::json!({
                "id": s.id,
                "section_type": s.section_type,
                "layout_mode": s.layout_mode,
                "name": s.name,
                "sequence": s.sequence,
                "grid_config": s.grid_config,
                "freeform_config": s.freeform_config,
                "breakpoints": bps,
                "widgets": section_widgets,
                "children": section_tree(sections, breakpoints, widgets, Some(s.id)),
            })
        })
        .collect()
}

/// Every `"number"`-typed column read here (`sequence`, `column_count`,
/// `font_scale`, `sequence_override`, and every widget position column) is
/// cast to `::double precision` before binding — same reasoning as
/// `lifecycle::do_publish_dashboard`'s `version_number` fix: a `"number"`
/// attribute is a Postgres `NUMERIC` column, and this workspace has no
/// `bigdecimal`/`rust_decimal` sqlx feature to decode one directly (see
/// `attome-project`'s `work_plan.rs`/`summary.rs`/`portfolio_program.rs` for
/// the same cast convention).
pub async fn pages_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
) -> Result<Vec<Value>, AppError> {
    let pages: Vec<PageRow> = sqlx::query_as(
        "SELECT id, name, name_ar, slug, sequence::double precision, is_visible, icon, \
                background_kind, background_value, padding, settings \
         FROM dashboard_page \
         WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY sequence NULLS LAST, id",
    )
    .bind(dashboard_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let mut result = Vec::with_capacity(pages.len());
    for page in pages {
        result.push(page_snapshot_json(tx, page).await?);
    }
    Ok(result)
}

/// D-520 — one active page's snapshot by id, whatever its `dashboard_id`.
/// The page reconciliation clones pages that are reachable only through the
/// retired M:M `dashboard_pages` (their `dashboard_id` is null), so it cannot
/// find them through [`pages_snapshot`]. Same shape as one element of
/// `pages_snapshot`'s result; `None` when the page is missing or inactive.
pub async fn single_page_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    page_id: Uuid,
) -> Result<Option<Value>, AppError> {
    let page: Option<PageRow> = sqlx::query_as(
        "SELECT id, name, name_ar, slug, sequence::double precision, is_visible, icon, \
                background_kind, background_value, padding, settings \
         FROM dashboard_page \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(page_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    match page {
        Some(page) => Ok(Some(page_snapshot_json(tx, page).await?)),
        None => Ok(None),
    }
}

/// One page's snapshot JSON: its sections (as a tree), their breakpoints and
/// their widgets. Shared by [`pages_snapshot`] and [`single_page_snapshot`].
async fn page_snapshot_json(
    tx: &mut Transaction<'_, Postgres>,
    page: PageRow,
) -> Result<Value, AppError> {
    {
        let sections: Vec<SectionRow> = sqlx::query_as(
            "SELECT id, parent_section_id, section_type, layout_mode, name, \
                    sequence::double precision, grid_config, freeform_config \
             FROM dashboard_section \
             WHERE page_id = $1 AND (is_active IS NULL OR is_active = true) \
             ORDER BY sequence NULLS LAST, id",
        )
        .bind(page.id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        let section_ids: Vec<Uuid> = sections.iter().map(|s| s.id).collect();
        let (breakpoints, widgets): (Vec<BreakpointRow>, Vec<WidgetRow>) = if section_ids.is_empty()
        {
            (Vec::new(), Vec::new())
        } else {
            let breakpoints = sqlx::query_as(
                "SELECT section_id, breakpoint, position_config, size_config, is_visible, \
                        column_count::double precision, font_scale::double precision, \
                        sequence_override::double precision \
                 FROM dashboard_section_breakpoint \
                 WHERE section_id = ANY($1) AND (is_active IS NULL OR is_active = true)",
            )
            .bind(&section_ids)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            let widgets = sqlx::query_as(
                "SELECT id, section_id, widget_type, name, name_ar, \
                        sequence::double precision, \
                        grid_col::double precision, grid_row::double precision, \
                        grid_col_span::double precision, grid_row_span::double precision, \
                        freeform_x::double precision, freeform_y::double precision, \
                        freeform_width::double precision, freeform_height::double precision, \
                        freeform_z_index::double precision, \
                        config, responsive_overrides, is_visible, is_locked, group_id, \
                        query_id, view_id, query_params, emits, listens \
                 FROM dashboard_widget \
                 WHERE section_id = ANY($1) AND (is_active IS NULL OR is_active = true) \
                 ORDER BY sequence NULLS LAST, id",
            )
            .bind(&section_ids)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (breakpoints, widgets)
        };

        let tree = section_tree(&sections, &breakpoints, &widgets, None);
        Ok(serde_json::json!({
            "id": page.id,
            "name": page.name,
            "name_ar": page.name_ar,
            "slug": page.slug,
            "sequence": page.sequence,
            "is_visible": page.is_visible,
            "icon": page.icon,
            "background_kind": page.background_kind,
            "background_value": page.background_value,
            "padding": page.padding,
            "settings": page.settings,
            "sections": tree,
        }))
    }
}

// ── Write path: materializing a snapshot back into real rows ────────────────

/// See this module's doc comment for why `do_restore_version` and `do_clone`
/// each need a different policy here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdPolicy {
    /// Reuse every id the snapshot carries (pages, sections, widgets —
    /// breakpoints never had one, see `breakpoint_json`). Restoring the same
    /// version twice in a row is therefore idempotent.
    ReuseIds,
    /// Ignore every id the snapshot carries and generate a fresh one for
    /// every row. Required whenever the target is a *different* dashboard
    /// than the one the snapshot was taken from — the source rows are still
    /// live under those exact ids.
    GenerateNewIds,
}

/// `pub` (struct and fields) — besides this module's own snapshot
/// round-trip, `create_from_layout`'s request body and this crate's own
/// tests construct these directly (see this module's doc comment's
/// "Write path" section and `do_create_from_layout`, below).
#[derive(Default, Deserialize, Serialize, ToSchema)]
pub struct SnapshotWidget {
    pub id: Option<Uuid>,
    pub widget_type: String,
    pub name: Option<String>,
    pub name_ar: Option<String>,
    pub sequence: Option<f64>,
    pub grid_col: Option<f64>,
    pub grid_row: Option<f64>,
    pub grid_col_span: Option<f64>,
    pub grid_row_span: Option<f64>,
    pub freeform_x: Option<f64>,
    pub freeform_y: Option<f64>,
    pub freeform_width: Option<f64>,
    pub freeform_height: Option<f64>,
    pub freeform_z_index: Option<f64>,
    pub config: Option<String>,
    pub responsive_overrides: Option<String>,
    pub is_visible: Option<bool>,
    pub is_locked: Option<bool>,
    pub group_id: Option<String>,
    pub query_id: Option<String>,
    #[serde(default)]
    pub view_id: Option<String>,
    pub query_params: Option<String>,
    /// R-07 step 6 — same `#[serde(default)]` reasoning R-02 gave for
    /// `view_id`: a snapshot written before this field existed must still
    /// deserialize. Omitted here, publish/restore/clone silently dropped a
    /// widget's event wiring.
    #[serde(default)]
    pub emits: Option<String>,
    #[serde(default)]
    pub listens: Option<String>,
}

impl std::fmt::Debug for SnapshotWidget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotWidget").finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize, Serialize, ToSchema)]
pub struct SnapshotBreakpoint {
    pub breakpoint: String,
    pub position_config: Option<String>,
    pub size_config: Option<String>,
    pub is_visible: Option<bool>,
    pub column_count: Option<f64>,
    pub font_scale: Option<f64>,
    pub sequence_override: Option<f64>,
}

impl std::fmt::Debug for SnapshotBreakpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBreakpoint").finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize, Serialize, ToSchema)]
pub struct SnapshotSection {
    pub id: Option<Uuid>,
    pub section_type: String,
    pub layout_mode: String,
    pub name: Option<String>,
    pub sequence: Option<f64>,
    pub grid_config: Option<String>,
    pub freeform_config: Option<String>,
    #[serde(default)]
    pub breakpoints: Vec<SnapshotBreakpoint>,
    #[serde(default)]
    pub widgets: Vec<SnapshotWidget>,
    /// A section tree nests, so this type is recursive, and utoipa needs
    /// `no_recursion` to stop expanding it inline — without it, building the
    /// workspace OpenAPI document recurses until the stack overflows.
    /// `attome_api::sidebar::SidebarItem::child` carries the identical
    /// annotation for the identical reason; this one was missed, and the
    /// symptom was `server --print-openapi` aborting with 0xC00000FD despite
    /// `main.rs` already spawning a 64 MB stack for exactly this work.
    ///
    /// The emitted schema still carries the `$ref` back to `SnapshotSection`,
    /// so a generated client keeps the recursive type.
    #[serde(default)]
    #[schema(no_recursion)]
    pub children: Vec<SnapshotSection>,
}

impl std::fmt::Debug for SnapshotSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotSection").finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize, Serialize, ToSchema)]
pub struct SnapshotPage {
    pub id: Option<Uuid>,
    pub name: String,
    pub name_ar: Option<String>,
    pub slug: Option<String>,
    pub sequence: Option<f64>,
    pub is_visible: Option<bool>,
    pub icon: Option<String>,
    pub background_kind: Option<String>,
    pub background_value: Option<String>,
    pub padding: Option<String>,
    pub settings: Option<String>,
    #[serde(default)]
    pub sections: Vec<SnapshotSection>,
}

impl std::fmt::Debug for SnapshotPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotPage").finish_non_exhaustive()
    }
}

/// Soft-deactivates every currently-live page/section/widget under
/// `dashboard_id` (the "clear the board" half of applying a snapshot) and
/// physically deletes its breakpoints — R-07 step 5: breakpoints carry no id
/// in the snapshot (`breakpoint_json` never wrote one) and nothing else
/// references one by id (confirmed by grep: `grep -rn section_breakpoint
/// crates/ angular/projects` has no hit outside this crate and its own
/// tests), so the old soft-deactivate-then-reinsert left every restore with a
/// full duplicate set instead of the same rows back. A `DELETE` is the
/// correct inverse of "always a fresh insert, nothing to upsert against"
/// below. Harmless (and a no-op) against a freshly-created dashboard with
/// nothing to clear yet, so `apply_pages_snapshot` always runs this rather
/// than making callers opt in.
async fn deactivate_existing_tree(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE dashboard_widget SET is_active = false \
         WHERE section_id IN ( \
             SELECT s.id FROM dashboard_section s \
             JOIN dashboard_page p ON p.id = s.page_id \
             WHERE p.dashboard_id = $1 \
         )",
    )
    .bind(dashboard_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "DELETE FROM dashboard_section_breakpoint \
         WHERE section_id IN ( \
             SELECT s.id FROM dashboard_section s \
             JOIN dashboard_page p ON p.id = s.page_id \
             WHERE p.dashboard_id = $1 \
         )",
    )
    .bind(dashboard_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE dashboard_section SET is_active = false \
         WHERE page_id IN (SELECT id FROM dashboard_page WHERE dashboard_id = $1)",
    )
    .bind(dashboard_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("UPDATE dashboard_page SET is_active = false WHERE dashboard_id = $1")
        .bind(dashboard_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// The `AttrInfo` slice for each of the four tables `apply_pages_snapshot`
/// writes — resolved once per call (not once per node) and threaded through
/// the recursion, so a tree with hundreds of widgets pays four metadata
/// lookups total, not one per node. Same registry-backed resolution generic
/// CRUD itself uses (`attome_records::entity_crud::resolve_entity`), so a
/// hand-written row here is validated by the exact same rules — choice
/// values, required flags, lengths — a `POST`/`PATCH` through the generic
/// engine would apply to the same entity.
pub(crate) struct DashboardTreeAttrs {
    page: Vec<AttrInfo>,
    section: Vec<AttrInfo>,
    breakpoint: Vec<AttrInfo>,
    widget: Vec<AttrInfo>,
}

pub(crate) async fn resolve_tree_attrs(
    state: &EngineState,
) -> Result<DashboardTreeAttrs, AppError> {
    let (_, _, page, _) =
        attome_records::entity_crud::resolve_entity(state, "dashboard_page").await?;
    let (_, _, section, _) =
        attome_records::entity_crud::resolve_entity(state, "dashboard_section").await?;
    let (_, _, breakpoint, _) =
        attome_records::entity_crud::resolve_entity(state, "dashboard_section_breakpoint").await?;
    let (_, _, widget, _) =
        attome_records::entity_crud::resolve_entity(state, "dashboard_widget").await?;
    Ok(DashboardTreeAttrs {
        page,
        section,
        breakpoint,
        widget,
    })
}

/// Builds the `obj` map `validate_body` checks a written node against —
/// `serde_json::to_value` of the Snapshot* struct itself (every field name
/// already matches its entity's attribute logicalname 1:1, confirmed against
/// `platform-bundles/attome-dashboard.json`) with the system-managed/nested keys
/// stripped and the structural lookup value (the row's own parent id, not
/// part of the Snapshot* struct — it's supplied by the caller placing the
/// node in the tree) inserted under `lookup_field`.
fn validate_obj<T: Serialize>(
    node: &T,
    drop_keys: &[&str],
    lookup_field: &str,
    lookup_value: Option<Uuid>,
) -> serde_json::Map<String, Value> {
    let mut obj = match serde_json::to_value(node) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    for key in drop_keys {
        obj.remove(*key);
    }
    obj.insert(
        lookup_field.to_string(),
        lookup_value
            .map(|id| Value::String(id.to_string()))
            .unwrap_or(Value::Null),
    );
    obj
}

async fn apply_widget(
    tx: &mut Transaction<'_, Postgres>,
    attrs: &DashboardTreeAttrs,
    section_id: Uuid,
    w: SnapshotWidget,
    id_policy: IdPolicy,
    actor_id: Uuid,
) -> Result<(), AppError> {
    let obj = validate_obj(&w, &["id"], "section_id", Some(section_id));
    attome_records::entity_mutation::validate_body(&attrs.widget, &obj, true)?;

    let widget_id = match (id_policy, w.id) {
        (IdPolicy::ReuseIds, Some(id)) => id,
        _ => Uuid::now_v7(),
    };
    sqlx::query(
        "INSERT INTO dashboard_widget AS t \
             (id, section_id, widget_type, name, name_ar, sequence, \
              grid_col, grid_row, grid_col_span, grid_row_span, \
              freeform_x, freeform_y, freeform_width, freeform_height, freeform_z_index, \
              config, responsive_overrides, is_visible, is_locked, group_id, \
              query_id, view_id, query_params, emits, listens, \
              created_by, modified_by, is_active) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,\
                  $23,$24,$25,$26,$27,true) \
         ON CONFLICT (id) DO UPDATE SET \
             section_id = EXCLUDED.section_id, widget_type = EXCLUDED.widget_type, \
             name = EXCLUDED.name, name_ar = EXCLUDED.name_ar, sequence = EXCLUDED.sequence, \
             grid_col = EXCLUDED.grid_col, grid_row = EXCLUDED.grid_row, \
             grid_col_span = EXCLUDED.grid_col_span, grid_row_span = EXCLUDED.grid_row_span, \
             freeform_x = EXCLUDED.freeform_x, freeform_y = EXCLUDED.freeform_y, \
             freeform_width = EXCLUDED.freeform_width, freeform_height = EXCLUDED.freeform_height, \
             freeform_z_index = EXCLUDED.freeform_z_index, config = EXCLUDED.config, \
             responsive_overrides = EXCLUDED.responsive_overrides, is_visible = EXCLUDED.is_visible, \
             is_locked = EXCLUDED.is_locked, group_id = EXCLUDED.group_id, \
             query_id = EXCLUDED.query_id, view_id = EXCLUDED.view_id, \
             query_params = EXCLUDED.query_params, emits = EXCLUDED.emits, \
             listens = EXCLUDED.listens, \
             modified_at = NOW(), modified_by = EXCLUDED.modified_by, \
             row_version = t.row_version + 1, is_active = true",
    )
    .bind(widget_id)
    .bind(section_id)
    .bind(&w.widget_type)
    .bind(&w.name)
    .bind(&w.name_ar)
    .bind(w.sequence)
    .bind(w.grid_col)
    .bind(w.grid_row)
    .bind(w.grid_col_span)
    .bind(w.grid_row_span)
    .bind(w.freeform_x)
    .bind(w.freeform_y)
    .bind(w.freeform_width)
    .bind(w.freeform_height)
    .bind(w.freeform_z_index)
    .bind(&w.config)
    .bind(&w.responsive_overrides)
    .bind(w.is_visible)
    .bind(w.is_locked)
    .bind(&w.group_id)
    .bind(&w.query_id)
    .bind(&w.view_id)
    .bind(&w.query_params)
    .bind(&w.emits)
    .bind(&w.listens)
    .bind(actor_id)
    .bind(actor_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    attome_records::entity_mutation::write_entity_change_event(
        tx,
        "dashboard_widget",
        widget_id,
        change_event_operation(id_policy),
    )
    .await?;
    Ok(())
}

/// R-07 step 3: `write_entity_change_event`'s operation for a Tier 2 upsert.
/// `IdPolicy::GenerateNewIds` (`do_clone`/`do_create_from_layout`) always
/// writes a brand-new row, so `Create` is exact. `IdPolicy::ReuseIds`
/// (`do_restore_version`) reinserts under the snapshot's own ids every time —
/// genuinely a first-ever row the first time a version is restored, an
/// update to the same row on every restore after that — and telling those
/// apart would cost a second round trip (`xmax = 0`) this outbox row's
/// consumers (lineage, event subscriptions) don't need: either way, *a*
/// change to that record just committed, which is what they actually care
/// about. `Update` is the documented choice for `ReuseIds`.
fn change_event_operation(id_policy: IdPolicy) -> attome_core::ChangeOperation {
    match id_policy {
        IdPolicy::GenerateNewIds => attome_core::ChangeOperation::Create,
        IdPolicy::ReuseIds => attome_core::ChangeOperation::Update,
    }
}

/// Recursive (a section's `children` are the same shape) — boxed per the
/// usual async-fn-recursion workaround, same as every other recursive async
/// function in this workspace.
pub(crate) fn apply_section<'a>(
    tx: &'a mut Transaction<'_, Postgres>,
    attrs: &'a DashboardTreeAttrs,
    page_id: Uuid,
    parent_section_id: Option<Uuid>,
    s: SnapshotSection,
    id_policy: IdPolicy,
    actor_id: Uuid,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Uuid, AppError>> + Send + 'a>> {
    Box::pin(async move {
        let mut obj = validate_obj(
            &s,
            &["id", "breakpoints", "widgets", "children"],
            "page_id",
            Some(page_id),
        );
        obj.insert(
            "parent_section_id".to_string(),
            parent_section_id
                .map(|id| Value::String(id.to_string()))
                .unwrap_or(Value::Null),
        );
        attome_records::entity_mutation::validate_body(&attrs.section, &obj, true)?;

        let section_id = match (id_policy, s.id) {
            (IdPolicy::ReuseIds, Some(id)) => id,
            _ => Uuid::now_v7(),
        };
        sqlx::query(
            "INSERT INTO dashboard_section AS t \
                 (id, page_id, parent_section_id, section_type, layout_mode, name, sequence, \
                  grid_config, freeform_config, created_by, modified_by, is_active) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) \
             ON CONFLICT (id) DO UPDATE SET \
                 page_id = EXCLUDED.page_id, parent_section_id = EXCLUDED.parent_section_id, \
                 section_type = EXCLUDED.section_type, layout_mode = EXCLUDED.layout_mode, \
                 name = EXCLUDED.name, \
                 sequence = EXCLUDED.sequence, grid_config = EXCLUDED.grid_config, \
                 freeform_config = EXCLUDED.freeform_config, \
                 modified_at = NOW(), modified_by = EXCLUDED.modified_by, \
                 row_version = t.row_version + 1, is_active = true",
        )
        .bind(section_id)
        .bind(page_id)
        .bind(parent_section_id)
        .bind(&s.section_type)
        .bind(&s.layout_mode)
        .bind(&s.name)
        .bind(s.sequence)
        .bind(&s.grid_config)
        .bind(&s.freeform_config)
        .bind(actor_id)
        .bind(actor_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        attome_records::entity_mutation::write_entity_change_event(
            tx,
            "dashboard_section",
            section_id,
            change_event_operation(id_policy),
        )
        .await?;

        // Breakpoints carry no id in the snapshot (`breakpoint_json` never
        // wrote one) — always a fresh insert, nothing to upsert against; see
        // `deactivate_existing_tree`'s doc comment for why the DELETE half of
        // that lives there instead of an UPDATE here.
        for b in s.breakpoints {
            let bp_obj = validate_obj(&b, &[], "section_id", Some(section_id));
            attome_records::entity_mutation::validate_body(&attrs.breakpoint, &bp_obj, true)?;

            let breakpoint_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO dashboard_section_breakpoint \
                     (id, section_id, breakpoint, position_config, size_config, \
                      is_visible, column_count, font_scale, sequence_override, \
                      created_by, modified_by, is_active) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)",
            )
            .bind(breakpoint_id)
            .bind(section_id)
            .bind(&b.breakpoint)
            .bind(&b.position_config)
            .bind(&b.size_config)
            .bind(b.is_visible)
            .bind(b.column_count)
            .bind(b.font_scale)
            .bind(b.sequence_override)
            .bind(actor_id)
            .bind(actor_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;

            attome_records::entity_mutation::write_entity_change_event(
                tx,
                "dashboard_section_breakpoint",
                breakpoint_id,
                attome_core::ChangeOperation::Create,
            )
            .await?;
        }

        for w in s.widgets {
            apply_widget(tx, attrs, section_id, w, id_policy, actor_id).await?;
        }

        for child in s.children {
            apply_section(
                tx,
                attrs,
                page_id,
                Some(section_id),
                child,
                id_policy,
                actor_id,
            )
            .await?;
        }
        Ok(section_id)
    })
}

/// Materializes a `pages_snapshot`-shaped JSON tree into real rows under
/// `dashboard_id`, first soft-deactivating whatever tree is already live
/// there. Called inside the caller's own transaction (both current callers
/// already hold one for their own row-version/lock checks) so a failure
/// partway through leaves the dashboard's previous tree untouched rather than
/// half-applied.
///
/// R-07: takes `state` (to resolve each written entity's `AttrInfo` for
/// `validate_body`, once per call — see `resolve_tree_attrs`) and `actor_id`
/// (stamped as `created_by`/`modified_by` on every row this writes, and passed
/// to `write_entity_change_event` for the per-record outbox row) — the same
/// invariants generic CRUD's own `create_one`/`update_one` give every write
/// to these tables, applied here because the tree materialization has to
/// stay inside one transaction under the dashboard advisory lock and so
/// cannot route each node through a separate engine call.
pub async fn apply_pages_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    dashboard_id: Uuid,
    pages_json: &Value,
    id_policy: IdPolicy,
    actor_id: Uuid,
) -> Result<(), AppError> {
    let pages: Vec<SnapshotPage> = serde_json::from_value(pages_json.clone())
        .map_err(|e| AppError::internal(format!("corrupt dashboard snapshot: {e}")))?;
    // R-13 item 5: the count ceiling `create_from_layout` already enforces
    // (`count_pages_tree`) applies to restore too — a snapshot is trusted
    // data, but the ceiling is cheap and bounds the lock hold time.
    count_pages_tree(&pages)?;

    let attrs = resolve_tree_attrs(state).await?;
    deactivate_existing_tree(tx, dashboard_id).await?;

    for page in pages {
        insert_page_node(tx, &attrs, dashboard_id, page, id_policy, actor_id).await?;
    }
    Ok(())
}

/// D-520 — materializes one additional page (with its whole section subtree)
/// under `dashboard_id` inside the caller's transaction, without touching the
/// dashboard's existing pages. Always generates fresh ids. Used by the page
/// reconciliation to give each extra dashboard its own copy of a page that
/// was shared through the retired M:M. Returns the new page's id.
pub async fn apply_single_page(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    dashboard_id: Uuid,
    page_json: &Value,
    actor_id: Uuid,
) -> Result<Uuid, AppError> {
    let page: SnapshotPage = serde_json::from_value(page_json.clone())
        .map_err(|e| AppError::internal(format!("corrupt page snapshot: {e}")))?;
    count_pages_tree(std::slice::from_ref(&page))?;
    let attrs = resolve_tree_attrs(state).await?;
    let (page_id, _) = insert_page_node(
        tx,
        &attrs,
        dashboard_id,
        page,
        IdPolicy::GenerateNewIds,
        actor_id,
    )
    .await?;
    Ok(page_id)
}

/// Validates and writes one page row and its whole section subtree under
/// `dashboard_id`. Returns the page id and the ids of its top-level sections.
/// Shared by [`apply_pages_snapshot`], [`apply_single_page`] and
/// `pages::do_create_page`, so every page write goes through the same
/// metadata validation, change events and actor stamping.
pub(crate) async fn insert_page_node(
    tx: &mut Transaction<'_, Postgres>,
    attrs: &DashboardTreeAttrs,
    dashboard_id: Uuid,
    page: SnapshotPage,
    id_policy: IdPolicy,
    actor_id: Uuid,
) -> Result<(Uuid, Vec<Uuid>), AppError> {
    {
        let obj = validate_obj(
            &page,
            &["id", "sections"],
            "dashboard_id",
            Some(dashboard_id),
        );
        attome_records::entity_mutation::validate_body(&attrs.page, &obj, true)?;

        let page_id = match (id_policy, page.id) {
            (IdPolicy::ReuseIds, Some(id)) => id,
            _ => Uuid::now_v7(),
        };
        sqlx::query(
            "INSERT INTO dashboard_page AS t \
                 (id, dashboard_id, name, name_ar, slug, sequence, is_visible, icon, \
                  background_kind, background_value, padding, settings, \
                  created_by, modified_by, is_active) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,true) \
             ON CONFLICT (id) DO UPDATE SET \
                 dashboard_id = EXCLUDED.dashboard_id, name = EXCLUDED.name, \
                 name_ar = EXCLUDED.name_ar, slug = EXCLUDED.slug, sequence = EXCLUDED.sequence, \
                 is_visible = EXCLUDED.is_visible, icon = EXCLUDED.icon, \
                 background_kind = EXCLUDED.background_kind, \
                 background_value = EXCLUDED.background_value, padding = EXCLUDED.padding, \
                 settings = EXCLUDED.settings, \
                 modified_at = NOW(), modified_by = EXCLUDED.modified_by, \
                 row_version = t.row_version + 1, is_active = true",
        )
        .bind(page_id)
        .bind(dashboard_id)
        .bind(&page.name)
        .bind(&page.name_ar)
        .bind(&page.slug)
        .bind(page.sequence)
        .bind(page.is_visible)
        .bind(&page.icon)
        .bind(&page.background_kind)
        .bind(&page.background_value)
        .bind(&page.padding)
        .bind(&page.settings)
        .bind(actor_id)
        .bind(actor_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        attome_records::entity_mutation::write_entity_change_event(
            tx,
            "dashboard_page",
            page_id,
            change_event_operation(id_policy),
        )
        .await?;

        let mut top_sections = Vec::with_capacity(page.sections.len());
        for section in page.sections {
            top_sections
                .push(apply_section(tx, attrs, page_id, None, section, id_policy, actor_id).await?);
        }
        Ok((page_id, top_sections))
    }
}

// ── Single-call authoring: create a dashboard from one layout document ─────
//
// Built for a caller that already has a whole dashboard's shape decided up
// front — an AI-authoring flow, a template import — and would otherwise have
// to orchestrate dozens of sequential, id-linked generic-entity-CRUD calls
// (create the dashboard, create each page, create each section with the
// right `parent_section_id`, create each widget...) to build one dashboard.
// This reuses `apply_pages_snapshot`'s existing, already-tested tree-write
// path (`IdPolicy::GenerateNewIds`, the same policy `lifecycle::do_clone`
// uses) rather than adding a second way to write these tables — the wire
// format is exactly `pages_snapshot`'s own shape, so a caller building a
// layout can start from an existing dashboard's published snapshot as a
// worked example.

/// Safety bound on a single `create_from_layout` call — a runaway or
/// malformed generation should fail fast with a `422`, not silently create
/// an unbounded number of rows in one transaction. Deliberately generous for
/// a real hand-built dashboard; revisit if a legitimate use case needs more.
pub(crate) const MAX_PAGES: usize = 50;
pub(crate) const MAX_SECTIONS: usize = 500;
pub(crate) const MAX_WIDGETS: usize = 1000;

/// Recursively counts one section and everything under it (its own
/// breakpoints/widgets, then its children) against `MAX_SECTIONS`/
/// `MAX_WIDGETS`, and checks each widget's `widget_type` against the live
/// Rust registry — the one check `entity_mutation::validate_body` cannot make
/// on its own, since `widget_type`'s metadata choice list is only ever as
/// current as `seed.rs`'s last `resync_widget_type_choices` run (R-08), not a
/// hand-maintained constant here. R-07 deleted this function's former
/// section-type/layout-mode/breakpoint hand-maintained choice-list checks —
/// `apply_pages_snapshot`'s own `validate_body` call against each node now
/// enforces those from the same metadata generic CRUD itself is validated
/// against, so a hand-maintained duplicate of the choice list could no
/// longer drift from it.
fn count_section_tree(
    section: &SnapshotSection,
    section_count: &mut usize,
    widget_count: &mut usize,
) -> Result<(), AppError> {
    *section_count += 1;
    if *section_count > MAX_SECTIONS {
        return Err(AppError::Validation(format!(
            "layout exceeds the maximum of {MAX_SECTIONS} sections"
        )));
    }

    for widget in &section.widgets {
        *widget_count += 1;
        if *widget_count > MAX_WIDGETS {
            return Err(AppError::Validation(format!(
                "layout exceeds the maximum of {MAX_WIDGETS} widgets"
            )));
        }
        // Same source of truth `seed.rs::seed_widget` reads for the
        // `widget_type` choice list on the ordinary create path — see
        // `widget_registry.rs`'s own doc comment.
        if crate::widget_registry::registry()
            .get(&widget.widget_type)
            .is_none()
        {
            return Err(AppError::Validation(format!(
                "unknown widget_type '{}'",
                widget.widget_type
            )));
        }
    }

    for child in &section.children {
        count_section_tree(child, section_count, widget_count)?;
    }
    Ok(())
}

/// `MAX_PAGES` plus the whole tree's `count_section_tree` walk — shared by
/// `do_create_from_layout` (pre-write, on the caller's own body) and
/// `apply_pages_snapshot` (R-13 item 5: the same ceiling applied to a
/// restore/clone's snapshot, which is trusted data but still cheap to bound).
fn count_pages_tree(pages: &[SnapshotPage]) -> Result<(), AppError> {
    if pages.len() > MAX_PAGES {
        return Err(AppError::Validation(format!(
            "layout exceeds the maximum of {MAX_PAGES} pages"
        )));
    }
    let mut section_count = 0usize;
    let mut widget_count = 0usize;
    for page in pages {
        for section in &page.sections {
            count_section_tree(section, &mut section_count, &mut widget_count)?;
        }
    }
    Ok(())
}

/// The scalar `attome_dashboard` fields a `create_from_layout` caller supplies
/// — deliberately narrower than the full column set `lifecycle.rs`'s
/// `DashboardFieldsRow` snapshots (no `organization_id`/`thumbnail`/
/// `settings`/`is_template`/`template_category`/`template_version`): those
/// are either operator-scoped concerns an authoring caller has no basis to
/// set, or edited afterward through ordinary generic entity CRUD once the
/// dashboard exists.
#[derive(Deserialize, Serialize, ToSchema)]
pub struct NewDashboardFields {
    pub name: String,
    pub name_ar: Option<String>,
    pub description: Option<String>,
    pub description_ar: Option<String>,
    pub dashboard_type: String,
    pub visibility: Option<String>,
}

impl std::fmt::Debug for NewDashboardFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDashboardFields").finish_non_exhaustive()
    }
}

/// Creates a new `draft` `attome_dashboard` row and materializes `pages` as its
/// whole page/section/breakpoint/widget tree, in one transaction. `pub` for
/// the same test-ergonomics reason as `lifecycle.rs`'s `do_*` functions —
/// see `tests/dashboard_crud.rs`.
///
/// R-07: takes `state` (not a bare `db: &DbPool`) — `apply_pages_snapshot`
/// needs it to resolve `AttrInfo` for `validate_body`, and this function's
/// own `dashboard_type`/`visibility` check now goes through the same
/// validator against `attome_dashboard`'s live metadata rather than the deleted
/// hand-maintained dashboard-type/visibility choice-list constants — one
/// fewer hand-maintained copy of a choice list
/// `platform-bundles/attome-dashboard.json` already owns.
pub async fn do_create_from_layout(
    state: &EngineState,
    fields: NewDashboardFields,
    pages: Vec<SnapshotPage>,
    created_by: Uuid,
) -> Result<Uuid, AppError> {
    count_pages_tree(&pages)?;
    let (_, _, dashboard_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "attome_dashboard").await?;
    let obj = match serde_json::to_value(&fields) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    attome_records::entity_mutation::validate_body(&dashboard_attrs, &obj, false)?;

    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;

    let new_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_dashboard \
         (id, name, name_ar, description, description_ar, dashboard_type, owner_id, \
          lifecycle_status, visibility, created_by, modified_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'draft', $8, $9, $9)",
    )
    .bind(new_id)
    .bind(&fields.name)
    .bind(&fields.name_ar)
    .bind(&fields.description)
    .bind(&fields.description_ar)
    .bind(&fields.dashboard_type)
    .bind(created_by)
    .bind(&fields.visibility)
    .bind(created_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // Round-trips through `Value` rather than a bespoke `Vec<SnapshotPage>`
    // overload of `apply_pages_snapshot` — keeps exactly one tree-materializing
    // code path (this module's doc comment) instead of two that could drift.
    let pages_json = serde_json::to_value(&pages).map_err(AppError::internal)?;
    apply_pages_snapshot(
        &mut tx,
        state,
        new_id,
        &pages_json,
        IdPolicy::GenerateNewIds,
        created_by,
    )
    .await?;

    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            new_id,
            AuditOperation::Create,
            "dashboard.create_from_layout",
            created_by,
        )
        .comment(format!(
            "dashboard {new_id} created from a layout document ({} page(s))",
            pages.len()
        )),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_id)
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateFromLayoutBody {
    #[serde(flatten)]
    fields: NewDashboardFields,
    /// Same shape `pages_snapshot` produces — every `id` may be omitted, a
    /// fresh one is always generated (`IdPolicy::GenerateNewIds`).
    pages: Vec<SnapshotPage>,
}

#[derive(Serialize, ToSchema)]
struct CreateFromLayoutResponse {
    id: Uuid,
    pages_created: usize,
}

/// Create a dashboard from a layout
///
/// Creates a dashboard and its whole tree of pages, sections and widgets from one layout document in
/// one transaction, for a caller that has the layout decided already (an AI authoring flow, an
/// import). Editing an existing dashboard stays the record API's job. Needs the dashboard create
/// privilege. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/from-layout",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    request_body = CreateFromLayoutBody,
    responses(
        (status = 201, description = "Success", body = CreateFromLayoutResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Malformed or out-of-bound layout document", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_from_layout(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardCreate>>,
    Json(body): Json<CreateFromLayoutBody>,
) -> Result<(StatusCode, Json<CreateFromLayoutResponse>), AppError> {
    let page_count = body.pages.len();
    let new_id = do_create_from_layout(&state, body.fields, body.pages, ctx.user_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateFromLayoutResponse {
            id: new_id,
            pages_created: page_count,
        }),
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/attome-dashboard/from-layout",
        post(create_from_layout),
    )
}

/// P-api-contract Phase 1 — this module's slice of the workspace OpenAPI
/// document; merged in by `crate::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_from_layout))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
