//! Phases 3 and 6 — the widget registry: `WidgetDescriptor` + `WidgetRegistry`,
//! built-in registration at crate init (`WidgetRegistry::with_builtins`),
//! and a "custom widget slot" (`WidgetRegistry::register`) reserved for
//! Phase 21's SDK. `dashboard_widget.widget_type` (`seed.rs`) is a
//! `"choice"` attribute whose option list comes straight from
//! [`WidgetRegistry::type_ids`], so the generic entity engine's own
//! choice-field validation is what rejects an unknown `widget_type` on
//! create/update — no bespoke validation handler needed (guidelines §9).
//!
//! **The bar for registering a type: is it renderable with what this
//! workspace has today?** Everything registered below can get its data from
//! a widget's `query_id` (Phase 4's stored-query reference) — a chart type
//! is just a rendering hint over that same result set, so "waterfall chart"
//! costs nothing more to register than "line chart" did in Phase 3.
//! Anything that fails this bar is left out, same discipline Phase 3
//! applied to KPI widgets:
//!
//! - **KPI widgets** (Phase 3's own deferral): resolved by M27 Phase 1 —
//!   `scorecard` and `trendline` (both [`WidgetCategory::Kpi`]) are the two
//!   widget types whose data comes from `metric_snapshot`
//!   (`attome_metric::metric`'s `GET /api/v1/metrics/{id}/snapshots`) via a
//!   widget's `config.metric_ref`/`config.metric_refs`, not `query_id` — the
//!   "bar" above still holds, it's just a second renderable data source now
//!   that `attome-metric` exists (a separate `xrm-kpi` crate was never required
//!   and still doesn't exist; D-480 split `attome-metric` out of this crate for
//!   an unrelated reason — see that decision — not to become that crate).
//! - **Opportunity/lead pipeline** (Phase 6's spec list): no separate type
//!   registered — a funnel-shaped result (stage, count, total_value
//!   columns) is exactly what an admin-authored stored query already
//!   produces, so `funnel_chart` (registered below) already covers this;
//!   a dedicated `opportunity_pipeline` type would be the same widget
//!   twice.
//! - **System health / integration status widgets** (Phase 6's spec list):
//!   not registered. These need genuine in-process/Redis platform state
//!   (job queue depth, `attome-s2s` connector health) that may not be exposed
//!   through any queryable table — confirming that was out of scope here,
//!   and registering a type with no verified way to feed it would be the
//!   same "looks real, nothing behind it" problem as an unregistered KPI
//!   widget.
//! - **Account/Contact/Case/Invoice/Opportunity-health/Employee-performance
//!   widgets** (Phase 6's "XRM-native entity widgets" spec list): none of
//!   these entities exist in this platform under those names (checked —
//!   no `account`/`contact`/`support_case`/`invoice`/`opportunity`/
//!   `lead` anywhere). The spec's own list already names the correct
//!   answer for this: `custom_entity_widget` ("generic, configured by admin
//!   to any custom entity"), registered below, is the one XRM-native
//!   widget type this phase adds beyond the concretely-real
//!   `project_health_widget` (from `attome-project`, which does exist).
//! - **Statistical overlays** (Trendline/Moving average/Confidence
//!   interval/Control limits/Percentile lines): not separate widget types
//!   — they're modifiers *on* an existing chart, expressed as optional keys
//!   in that widget's own `config` (e.g. `{"overlay": "trendline"}`), not a
//!   placement of their own. Registering five more `type_id`s for these
//!   would be modeling them as things you place on a section, which they
//!   aren't.
//! - **Entity data grid's inline/bulk editing, row actions**: registered
//!   (`entity_data_grid`) as a read-only visualization for now — write-back
//!   from a grid cell is Phase 8's action-registry concern, not this one's.
//! - **`declarative_widget`** (M67 Phase 1 — `document/xrm/module/
//!   M67-component-platform/master-plan.md` Step 1): a JSON-schema-driven table/list
//!   over a widget's own `query_id`, whose columns/formatting/conditional
//!   colors/links/actions are declared in `config` rather than hardcoded per
//!   chart type. Registered in [`WidgetCategory::Operational`] — same "a
//!   filtered/sorted list of live records, backed by `query_id`" shape as
//!   `entity_data_grid` above, just admin-schema-driven instead of
//!   hardcoded. Its `config` is the one widget config on this entity that
//!   IS validated server-side, at `POST /api/v1/attome-dashboard/widget/
//!   validate-config` — see `declarative_widget.rs`'s doc comment for why
//!   it needed that and every other type here does not.
//!
//! Also out of scope: `WidgetDescriptor::schema` is a descriptive
//! `serde_json::Value`, not an enforced JSON-schema validator — this
//! platform has no JSON-schema-validation dependency, and `config` on every
//! widget-carrying entity elsewhere in this codebase (`attome_dashboard.
//! settings`, `dashboard_section.grid_config`, …) is likewise an
//! unvalidated, client-owned blob.
use attome_core::EngineState;
use axum::{Json, Router, routing::get};
use serde::Serialize;
use std::sync::OnceLock;
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidgetCategory {
    Chart,
    Text,
    /// Phase 6 — a filtered/sorted list of live records, always backed by
    /// `query_id` (never a computed/aggregated status with no queryable
    /// source — see this module's doc comment for what got left out on
    /// that basis).
    Operational,
    /// Phase 6 — a widget scoped to one XRM entity/record. Only
    /// `project_health_widget` (concrete) and `custom_entity_widget` (the
    /// spec's own generic fallback) are registered; see the doc comment for
    /// why the rest of the spec's list isn't.
    EngineNative,
    /// Phase 6 — location-based visualizations, still just a rendering
    /// hint over a `query_id` result with lat/long or region-code columns.
    Geospatial,
    /// Phase 21 SDK's extension point — not yet populated by any built-in
    /// descriptor, but a real, exercised registration path (see
    /// `WidgetRegistry::register` and this module's own test), not
    /// speculative dead code.
    Custom,
    /// M27 Phase 1 — sourced from `metric_snapshot` via
    /// `config.metric_ref`/`config.metric_refs` (`attome_metric::metric`), not
    /// `query_id`. `scorecard` (a metric list + weighted score) and
    /// `trendline` (a metric's snapshot history over time) are the two
    /// members.
    Kpi,
}

/// D-525 — how the viewer renders a widget type. Only types with a real
/// renderer carry anything but `unsupported`; the palette hides the rest and an
/// existing widget of such a type renders an explicit "unsupported widget type"
/// state (and is reported by health).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RenderKind {
    ChartBar,
    ChartLine,
    ChartArea,
    ChartDonut,
    ChartFunnel,
    /// One number (the first measure of an ungrouped definition).
    Scalar,
    /// Rows of a stored query or view.
    Table,
    /// `declarative_widget`'s schema-driven table.
    Declarative,
    KpiScorecard,
    KpiTrendline,
    /// Plain text from `config.content` (never HTML).
    Text,
    Divider,
    Unsupported,
}

/// D-525 — the data a widget type is built on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataContract {
    /// `config.data`, a structured definition (Class A).
    Structured,
    /// Governed metric snapshots (Class B).
    Kpi,
    /// A stored query or view (Class C).
    Query,
    None,
}

/// The renderer each supported built-in type uses. Anything absent is
/// `unsupported`.
const RENDERERS: &[(&str, RenderKind, DataContract)] = &[
    ("bar_chart", RenderKind::ChartBar, DataContract::Structured),
    (
        "column_chart",
        RenderKind::ChartBar,
        DataContract::Structured,
    ),
    (
        "line_chart",
        RenderKind::ChartLine,
        DataContract::Structured,
    ),
    (
        "area_chart",
        RenderKind::ChartArea,
        DataContract::Structured,
    ),
    (
        "pie_chart",
        RenderKind::ChartDonut,
        DataContract::Structured,
    ),
    (
        "donut_chart",
        RenderKind::ChartDonut,
        DataContract::Structured,
    ),
    (
        "funnel_chart",
        RenderKind::ChartFunnel,
        DataContract::Structured,
    ),
    ("metric", RenderKind::Scalar, DataContract::Structured),
    ("entity_data_grid", RenderKind::Table, DataContract::Query),
    ("table", RenderKind::Table, DataContract::Query),
    ("list", RenderKind::Table, DataContract::Query),
    ("task_queue", RenderKind::Table, DataContract::Query),
    ("approval_queue", RenderKind::Table, DataContract::Query),
    ("ticket_queue", RenderKind::Table, DataContract::Query),
    ("sla_monitor", RenderKind::Table, DataContract::Query),
    ("escalation_monitor", RenderKind::Table, DataContract::Query),
    (
        "recent_activities_feed",
        RenderKind::Table,
        DataContract::Query,
    ),
    ("calendar_deadlines", RenderKind::Table, DataContract::Query),
    ("notification_feed", RenderKind::Table, DataContract::Query),
    ("assignment_queue", RenderKind::Table, DataContract::Query),
    ("exception_queue", RenderKind::Table, DataContract::Query),
    ("work_queue_board", RenderKind::Table, DataContract::Query),
    (
        "declarative_widget",
        RenderKind::Declarative,
        DataContract::Query,
    ),
    ("scorecard", RenderKind::KpiScorecard, DataContract::Kpi),
    ("trendline", RenderKind::KpiTrendline, DataContract::Kpi),
    ("rich_text", RenderKind::Text, DataContract::None),
    ("divider", RenderKind::Divider, DataContract::None),
];

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct WidgetDescriptor {
    /// Matches one value in `dashboard_widget.widget_type`'s choice list
    /// (`seed.rs`) — the two must stay in sync, which is why `seed.rs` reads
    /// its choice list from [`WidgetRegistry::type_ids`] rather than
    /// duplicating this table.
    pub type_id: &'static str,
    pub display_name: &'static str,
    pub category: WidgetCategory,
    /// Descriptive only — see this module's doc comment for why no schema
    /// enforcement exists yet.
    pub schema: serde_json::Value,
    pub default_config: serde_json::Value,
    /// D-479 (M26 R-09) — set when `type_id` is a legacy id kept only so an
    /// already-migrated `dashboard_widget.widget_type` value (written by
    /// the now-deleted legacy dashboard-migration job, D-790) still resolves
    /// to a real descriptor.
    /// Names the modern `type_id` a viewer should actually render this
    /// widget with — the palette/builder should offer the modern id, not
    /// this one, for a brand-new widget. `None` for every non-legacy
    /// descriptor.
    pub deprecated_alias_of: Option<&'static str>,
    /// D-525 — filled in by [`WidgetRegistry::register`] from the renderer
    /// table (an alias inherits its target's), so no descriptor can claim a
    /// renderer the viewer does not have.
    pub render_kind: RenderKind,
    pub data_contract: DataContract,
}

#[derive(Default)]
pub struct WidgetRegistry {
    descriptors: Vec<WidgetDescriptor>,
}

impl std::fmt::Debug for WidgetRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetRegistry").finish_non_exhaustive()
    }
}

impl WidgetRegistry {
    fn chart(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Chart,
            schema: serde_json::json!({
                "series_field": "string", "category_field": "string", "aggregation": "string"
            }),
            default_config: serde_json::json!({ "series_field": null, "category_field": null }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    fn text(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Text,
            schema: serde_json::json!({ "content": "string" }),
            default_config: serde_json::json!({ "content": "" }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    /// A filtered/sorted record list — `query_id` is the whole data
    /// contract, so the schema hint just names the display columns.
    fn operational(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Operational,
            schema: serde_json::json!({ "columns": "array" }),
            default_config: serde_json::json!({ "columns": [] }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    fn native(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::EngineNative,
            schema: serde_json::json!({ "entity": "string", "record_id": "uuid" }),
            default_config: serde_json::json!({ "entity": null, "record_id": null }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    fn geospatial(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Geospatial,
            schema: serde_json::json!({ "location_field": "string", "value_field": "string" }),
            default_config: serde_json::json!({ "location_field": null, "value_field": null }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    /// M26 gap-fill — the retention-grid widget: a query with a cohort key
    /// column, a period column (bucket index/date relative to the cohort's
    /// start), and a value column (the retained metric, usually a count or
    /// rate) renders as a cohort-by-period heatmap grid, same `query_id`
    /// data contract as every other type here — only the three named
    /// columns plus `period_unit` (how the builder buckets/labels the
    /// period axis) differ from the generic `chart()` schema. Distinct from
    /// the pre-existing `cohort_chart` (registered above, Phase 6's generic
    /// chart placeholder with the bare `series_field`/`category_field`
    /// schema every other `chart()` entry shares): that one predates this
    /// widget and is kept for compatibility with whatever already
    /// references it, but carries no cohort-specific schema — a builder
    /// offering retention analysis should offer this type, not that one.
    /// `dataviz` skill: a retention grid is a **sequential** encoding
    /// (magnitude, not identity) — one hue, light-to-dark by retention rate,
    /// never the categorical palette; the Angular renderer is this crate's
    /// own concern, out of scope for a registry-only backend change.
    fn cohort(type_id: &'static str, display_name: &'static str) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Chart,
            schema: serde_json::json!({
                "cohort_key_field": "string",
                "period_field": "string",
                "value_field": "string",
                "period_unit": "string",
            }),
            default_config: serde_json::json!({
                "cohort_key_field": null,
                "period_field": null,
                "value_field": null,
                "period_unit": "week",
            }),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    /// M27 Phase 1 — sourced from `metric_snapshot`, not `query_id`; see
    /// this module's doc comment and [`WidgetCategory::Kpi`].
    fn kpi(
        type_id: &'static str,
        display_name: &'static str,
        schema: serde_json::Value,
        default_config: serde_json::Value,
    ) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: WidgetCategory::Kpi,
            schema,
            default_config,
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    /// D-479 (M26 R-09) — a thin alias descriptor: `type_id` is a legacy
    /// `attome-report` widget kind with no name change from its modern
    /// equivalent's own descriptor, just a different `type_id` string
    /// (`donut` vs `donut_chart`, `text` vs `rich_text`). Carries the exact
    /// same `schema`/`default_config` as `of` so a widget stored under the
    /// legacy id is configured identically to one stored under the modern
    /// id; `deprecated_alias_of` is what tells a viewer/palette the two are
    /// the same thing.
    fn legacy_alias(
        type_id: &'static str,
        display_name: &'static str,
        of: &WidgetDescriptor,
    ) -> WidgetDescriptor {
        WidgetDescriptor {
            type_id,
            display_name,
            category: of.category,
            schema: of.schema.clone(),
            default_config: of.default_config.clone(),
            deprecated_alias_of: Some(of.type_id),
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        }
    }

    /// Phase 3's 8 basic chart + 3 text/static types, plus Phase 6's 22
    /// advanced chart, 11 operational, 3 XRM-native, and 6 geospatial
    /// types — every one of them genuinely renderable via a widget's
    /// `query_id` with what this workspace has today (see this module's
    /// doc comment for the ones deliberately left out). Called once, at
    /// crate init (via [`registry`]'s `OnceLock`).
    #[expect(
        clippy::expect_used,
        reason = "each expect() here guards an invariant its message states"
    )]
    pub fn with_builtins() -> Self {
        let mut registry = Self::default();
        let mut builtins: Vec<WidgetDescriptor> = vec![
            // Phase 3 — basic charts.
            Self::chart("line_chart", "Line Chart"),
            Self::chart("area_chart", "Area Chart"),
            Self::chart("bar_chart", "Bar Chart"),
            Self::chart("column_chart", "Column Chart"),
            Self::chart("pie_chart", "Pie Chart"),
            Self::chart("donut_chart", "Donut Chart"),
            Self::chart("stacked_bar_chart", "Stacked Bar Chart"),
            Self::chart("combo_chart", "Combo Chart"),
            // Phase 6 — advanced charts.
            Self::chart("waterfall_chart", "Waterfall Chart"),
            Self::chart("funnel_chart", "Funnel Chart"),
            Self::chart("treemap", "Treemap"),
            Self::chart("sunburst_chart", "Sunburst Chart"),
            Self::chart("sankey_diagram", "Sankey Diagram"),
            Self::chart("radar_chart", "Radar / Spider Chart"),
            Self::chart("polar_chart", "Polar Chart"),
            Self::chart("histogram", "Histogram"),
            Self::chart("box_plot", "Box Plot"),
            Self::chart("scatter_plot", "Scatter Plot"),
            Self::chart("bubble_chart", "Bubble Chart"),
            Self::chart("heatmap", "Heatmap"),
            Self::chart("calendar_heatmap", "Calendar Heatmap"),
            Self::chart("pareto_chart", "Pareto Chart"),
            Self::chart("control_chart", "Control Chart"),
            Self::chart("gantt_chart", "Gantt Chart"),
            Self::chart("timeline", "Timeline"),
            Self::chart("candlestick_chart", "Candlestick / OHLC"),
            Self::chart("range_area_chart", "Range Area Chart"),
            Self::chart("distribution_chart", "Distribution Chart"),
            Self::chart("correlation_matrix", "Correlation Matrix"),
            Self::chart("cohort_chart", "Cohort Chart"),
            // Phase 3 — text/static.
            Self::text("rich_text", "Rich Text"),
            Self::text("image", "Image"),
            WidgetDescriptor {
                type_id: "divider",
                display_name: "Divider / Spacer",
                category: WidgetCategory::Text,
                schema: serde_json::json!({}),
                default_config: serde_json::json!({}),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
            // Phase 6 — operational.
            Self::operational("entity_data_grid", "Entity Data Grid"),
            // M67 Phase 1 — see this module's doc comment and
            // `declarative_widget.rs`.
            WidgetDescriptor {
                type_id: "declarative_widget",
                display_name: "Declarative Widget",
                category: WidgetCategory::Operational,
                schema: crate::declarative_widget::schema_hint(),
                default_config: crate::declarative_widget::default_config(),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
            Self::operational("task_queue", "Task Queue"),
            Self::operational("approval_queue", "Approval Queue"),
            Self::operational("ticket_queue", "Ticket Queue"),
            Self::operational("sla_monitor", "SLA Monitor"),
            Self::operational("escalation_monitor", "Escalation Monitor"),
            Self::operational("recent_activities_feed", "Recent Activities Feed"),
            Self::operational("calendar_deadlines", "Calendar / Upcoming Deadlines"),
            Self::operational("notification_feed", "Notification Feed"),
            Self::operational("assignment_queue", "Assignment Queue"),
            Self::operational("exception_queue", "Exception Queue"),
            // M84 Phase 1 (Queue Management, D-464) — a `service_work_queue`
            // board: backlog + per-member load for one queue, same
            // `query_id`-backed shape as `ticket_queue`/`assignment_queue`
            // above (a stored query the admin points at `service_ticket` filtered
            // by `work_queue_ref`). Distinct from those pre-existing generic
            // types the same way `cohort` is distinct from `cohort_chart`
            // (see that pair's own doc comment): this one exists so a
            // builder can offer "a work queue's board" as its own named
            // choice rather than reusing a same-shaped but differently-named
            // generic type.
            Self::operational("work_queue_board", "Work Queue Board"),
            // M27 metrics feed this queue's depth/wait/claim-to-resolve KPIs
            // (`queue_analytics_seed.rs`'s three seeded stored queries) into
            // the pre-existing `scorecard`/`trendline` KPI types below via
            // `config.metric_ref`/`metric_refs` — no new KPI-category type
            // needed (see this module's own doc comment's "bar for
            // registering a type").
            // Phase 6 — XRM-native.
            Self::native("project_health_widget", "Project Health"),
            Self::native("relationship_graph", "Relationship Graph"),
            Self::native("custom_entity_widget", "Custom Entity"),
            // M36 Phase 1 (Predictive Intelligence, D-473) — a record's live
            // predictions (score/label/explanation), same entity+record_id
            // config shape every other `native` type here uses, sourced
            // from `attome-predict`'s own `GET /api/v1/predictions?
            // regarding_entity=&regarding_id=` rather than `query_id`
            // (`prediction` is a migration-owned infrastructure table,
            // not queryable through `query/execute` at all — same reason
            // `outcome` isn't either). No bespoke Angular renderer
            // yet, same state `project_health_widget`/`relationship_graph`/
            // `custom_entity_widget` are already in today (this module's own
            // doc comment: "the bar for registering a type" is about a
            // verified *data source*, not a shipped renderer — of the 67
            // registered types (`builtins_cover_every_phase_3_and_phase_6_
            // type_with_no_duplicates` below is the count's source of truth;
            // it grew from 51 once D-479/M26 R-09 added 8 legacy-alias/
            // first-class types), only the 4 chart families
            // `CHART_KIND_BY_WIDGET_TYPE` (`dashboard-widget-view.
            // component.ts`) recognizes get bespoke rendering; everything
            // else still falls through to the dashboard viewer's generic
            // scalar/table fallback).
            Self::native("prediction_insight", "Prediction Insights"),
            // Phase 6 — geospatial.
            Self::geospatial("choropleth_map", "Choropleth Map"),
            Self::geospatial("bubble_map", "Bubble Map"),
            Self::geospatial("map_heatmap", "Heatmap Layer"),
            Self::geospatial("cluster_map", "Cluster Map"),
            Self::geospatial("territory_boundary_overlay", "Territory Boundary Overlay"),
            Self::geospatial("location_drilldown", "Location Drilldown"),
            // M27 Phase 1 — KPI (see WidgetCategory::Kpi's doc comment).
            Self::kpi(
                "scorecard",
                "Scorecard",
                serde_json::json!({ "metric_refs": "array", "weights": "object" }),
                serde_json::json!({ "metric_refs": [], "weights": {} }),
            ),
            Self::kpi(
                "trendline",
                "Trendline",
                serde_json::json!({ "metric_ref": "uuid" }),
                serde_json::json!({ "metric_ref": null }),
            ),
            // M26 gap-fill — the retention-grid widget (see `cohort`'s own
            // doc comment for why it's distinct from `cohort_chart` above).
            Self::cohort("cohort", "Cohort Retention Grid"),
        ];

        // D-479 (M26 R-09) — the 8 legacy `attome-report` widget kinds
        // (`attome-report/src/widget_catalog.rs`, deleted) that had no registry
        // equivalent by id: `donut`/`text` alias the modern `donut_chart`/
        // `rich_text` descriptors already built above (same schema, so a
        // widget configured under either id behaves identically); the rest
        // are first-class descriptors, registered directly rather than as
        // aliases, because no modern equivalent by that shape exists yet
        // (`list`/`table` are Operational, `metric`/`progress` are single-
        // scalar Operational placeholders — see `attome-api::dashboard_
        // migration::map_widget_kind`'s own doc comment for why the
        // migration job still degrades `metric`/`progress` to
        // `entity_data_grid` rather than mapping onto these directly;
        // `container`/`tabs` are layout-only, same `Text` category `divider`
        // above uses, no data source at all).
        let donut_chart = builtins
            .iter()
            .find(|d| d.type_id == "donut_chart")
            .expect("donut_chart is registered above")
            .clone();
        let rich_text = builtins
            .iter()
            .find(|d| d.type_id == "rich_text")
            .expect("rich_text is registered above")
            .clone();
        builtins.extend([
            Self::legacy_alias("donut", "Donut (legacy)", &donut_chart),
            Self::legacy_alias("text", "Text (legacy)", &rich_text),
            Self::operational("list", "List"),
            Self::operational("table", "Table"),
            WidgetDescriptor {
                type_id: "metric",
                display_name: "Metric",
                category: WidgetCategory::Operational,
                schema: serde_json::json!({ "metric_field": "string", "aggregation": "string" }),
                default_config: serde_json::json!({ "metric_field": null, "aggregation": "count" }),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
            WidgetDescriptor {
                type_id: "progress",
                display_name: "Progress",
                category: WidgetCategory::Operational,
                schema: serde_json::json!({ "metric_field": "string", "target_field": "string" }),
                default_config: serde_json::json!({ "metric_field": null, "target_field": null }),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
            WidgetDescriptor {
                type_id: "container",
                display_name: "Container",
                category: WidgetCategory::Text,
                schema: serde_json::json!({}),
                default_config: serde_json::json!({}),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
            WidgetDescriptor {
                type_id: "tabs",
                display_name: "Tabs",
                category: WidgetCategory::Text,
                schema: serde_json::json!({ "tabs": "array" }),
                default_config: serde_json::json!({ "tabs": [] }),
                deprecated_alias_of: None,
                render_kind: RenderKind::Unsupported,
                data_contract: DataContract::None,
            },
        ]);

        for descriptor in builtins {
            registry.register(descriptor);
        }
        registry
    }

    /// The Phase 21 SDK's "custom widget slot" — registers a descriptor not
    /// in the built-in set. Also how `with_builtins` populates itself, so
    /// there is exactly one insertion path to keep consistent.
    pub fn register(&mut self, mut descriptor: WidgetDescriptor) {
        let renderer_of = descriptor.deprecated_alias_of.unwrap_or(descriptor.type_id);
        let (render_kind, data_contract) = RENDERERS
            .iter()
            .find(|(type_id, ..)| *type_id == renderer_of)
            .map(|(_, render_kind, data_contract)| (*render_kind, *data_contract))
            .unwrap_or((RenderKind::Unsupported, DataContract::None));
        descriptor.render_kind = render_kind;
        descriptor.data_contract = data_contract;
        self.descriptors.push(descriptor);
    }

    /// D-525 — the renderer for `type_id`; `unsupported` for an unknown type.
    pub fn render_kind(&self, type_id: &str) -> RenderKind {
        self.get(type_id)
            .map_or(RenderKind::Unsupported, |descriptor| descriptor.render_kind)
    }

    pub fn get(&self, type_id: &str) -> Option<&WidgetDescriptor> {
        self.descriptors.iter().find(|d| d.type_id == type_id)
    }

    pub fn all(&self) -> &[WidgetDescriptor] {
        &self.descriptors
    }

    /// Feeds `seed.rs`'s `widget_type` choice list — the single source of
    /// truth this module's doc comment describes.
    pub fn type_ids(&self) -> Vec<&'static str> {
        self.descriptors.iter().map(|d| d.type_id).collect()
    }
}

static REGISTRY: OnceLock<WidgetRegistry> = OnceLock::new();

/// The process-wide registry, built once on first access. Read-only after
/// that — `register()` exists for the SDK slot's future caller, not for
/// mutating this shared instance at runtime (same read-mostly-after-init
/// shape as `attome-ai`'s capability registry).
pub fn registry() -> &'static WidgetRegistry {
    REGISTRY.get_or_init(WidgetRegistry::with_builtins)
}

/// List widget types
///
/// Every registered widget type with its descriptor, so a builder can fill its palette without a
/// hard-coded list. Any signed-in user: it is a list of capabilities, not data.
#[utoipa::path(
    get,
    path = "/api/v1/attome-dashboard/widget-types",
    tag = "dashboard",
    params(WidgetTypesQuery),
    responses(
        (status = 200, description = "Success", body = [WidgetDescriptor]),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_widget_types(
    _ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Query(query): axum::extract::Query<WidgetTypesQuery>,
) -> Json<Vec<WidgetDescriptor>> {
    Json(
        registry()
            .all()
            .iter()
            .filter(|d| query.include_unsupported || d.render_kind != RenderKind::Unsupported)
            .cloned()
            .collect(),
    )
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct WidgetTypesQuery {
    /// D-525 — include types the viewer cannot render (hidden by default so a
    /// palette only offers renderable widgets).
    #[serde(default)]
    include_unsupported: bool,
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/attome-dashboard/widget-types",
        get(list_widget_types),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_widget_types))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn builtins_cover_every_phase_3_and_phase_6_type_with_no_duplicates() {
        let ids = registry().type_ids();
        let expected = [
            // Phase 3.
            "line_chart",
            "area_chart",
            "bar_chart",
            "column_chart",
            "pie_chart",
            "donut_chart",
            "stacked_bar_chart",
            "combo_chart",
            "rich_text",
            "image",
            "divider",
            // Phase 6 — advanced charts.
            "waterfall_chart",
            "funnel_chart",
            "treemap",
            "sunburst_chart",
            "sankey_diagram",
            "radar_chart",
            "polar_chart",
            "histogram",
            "box_plot",
            "scatter_plot",
            "bubble_chart",
            "heatmap",
            "calendar_heatmap",
            "pareto_chart",
            "control_chart",
            "gantt_chart",
            "timeline",
            "candlestick_chart",
            "range_area_chart",
            "distribution_chart",
            "correlation_matrix",
            "cohort_chart",
            // Phase 6 — operational.
            "entity_data_grid",
            // M67 Phase 1.
            "declarative_widget",
            "task_queue",
            "approval_queue",
            "ticket_queue",
            "sla_monitor",
            "escalation_monitor",
            "recent_activities_feed",
            "calendar_deadlines",
            "notification_feed",
            "assignment_queue",
            "exception_queue",
            // M84 Phase 1 (Queue Management, D-464).
            "work_queue_board",
            // Phase 6 — XRM-native.
            "project_health_widget",
            "relationship_graph",
            "custom_entity_widget",
            // M36 Phase 1 (Predictive Intelligence, D-473).
            "prediction_insight",
            // Phase 6 — geospatial.
            "choropleth_map",
            "bubble_map",
            "map_heatmap",
            "cluster_map",
            "territory_boundary_overlay",
            "location_drilldown",
            // M27 Phase 1 — KPI.
            "scorecard",
            "trendline",
            // M26 gap-fill — cohort retention grid.
            "cohort",
            // D-479 (M26 R-09) — the 8 legacy `attome-report` widget kinds with
            // no prior registry equivalent (`donut`/`text` are aliases, the
            // rest are first-class).
            "donut",
            "text",
            "list",
            "table",
            "metric",
            "progress",
            "container",
            "tabs",
        ];
        for id in expected {
            assert!(ids.contains(&id), "missing built-in widget type {id}");
        }
        let unique: HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "a widget type_id is registered more than once"
        );
        assert_eq!(
            ids.len(),
            expected.len(),
            "unexpected extra or missing built-in widget type"
        );
    }

    #[test]
    fn no_kpi_or_unverified_operational_widget_types_are_registered() {
        // Documents the deliberate deferrals this module's doc comment
        // explains — fails loudly if someone adds one back without first
        // confirming its data source actually exists. M27 Phase 1's
        // `scorecard`/`trendline` (WidgetCategory::Kpi) are real, verified
        // exceptions to the old blanket "no kpi_* type" rule — they're
        // deliberately not spelled `kpi_*`, so this assertion still holds.
        for id in registry().type_ids() {
            assert!(
                !id.starts_with("kpi_"),
                "found a kpi_* widget type ({id}) registered without xrm-kpi existing — \
                 see this module's doc comment"
            );
            assert!(
                id != "system_health_widget" && id != "integration_status_widget",
                "found {id} registered without a verified queryable data source — \
                 see this module's doc comment"
            );
        }
    }

    #[test]
    fn the_custom_widget_slot_actually_registers_and_is_retrievable() {
        let mut custom = WidgetRegistry::with_builtins();
        custom.register(WidgetDescriptor {
            type_id: "sdk_example",
            display_name: "SDK Example",
            category: WidgetCategory::Custom,
            schema: serde_json::json!({}),
            default_config: serde_json::json!({}),
            deprecated_alias_of: None,
            render_kind: RenderKind::Unsupported,
            data_contract: DataContract::None,
        });
        let found = custom
            .get("sdk_example")
            .expect("custom descriptor must be retrievable");
        assert_eq!(found.category, WidgetCategory::Custom);
    }

    /// D-479 (M26 R-09) — `donut`/`text` are the two legacy report kinds
    /// registered as aliases rather than first-class descriptors: same
    /// schema/config as their modern target, `deprecated_alias_of` naming it.
    #[test]
    fn donut_and_text_are_registered_as_aliases_of_their_modern_equivalents() {
        let donut = registry().get("donut").expect("donut must be registered");
        assert_eq!(donut.deprecated_alias_of, Some("donut_chart"));
        let donut_chart = registry()
            .get("donut_chart")
            .expect("donut_chart must be registered");
        assert_eq!(donut.schema, donut_chart.schema);
        assert_eq!(donut.default_config, donut_chart.default_config);

        let text = registry().get("text").expect("text must be registered");
        assert_eq!(text.deprecated_alias_of, Some("rich_text"));
        let rich_text = registry()
            .get("rich_text")
            .expect("rich_text must be registered");
        assert_eq!(text.schema, rich_text.schema);
        assert_eq!(text.default_config, rich_text.default_config);
    }

    /// D-479 (M26 R-09) — every non-alias built-in, including the 6 new
    /// first-class legacy-kind descriptors, carries no
    /// `deprecated_alias_of`.
    #[test]
    fn only_donut_and_text_carry_a_deprecated_alias() {
        for d in registry().all() {
            if d.type_id == "donut" || d.type_id == "text" {
                continue;
            }
            assert!(
                d.deprecated_alias_of.is_none(),
                "{} unexpectedly carries deprecated_alias_of {:?}",
                d.type_id,
                d.deprecated_alias_of
            );
        }
    }

    #[test]
    fn every_descriptor_has_a_render_kind_and_renderers_name_real_types() {
        for (type_id, ..) in RENDERERS {
            assert!(
                registry().get(type_id).is_some(),
                "renderer table names unregistered type {type_id}"
            );
        }
        for d in registry().all() {
            let supported = d.render_kind != RenderKind::Unsupported;
            assert_eq!(
                supported,
                d.data_contract != DataContract::None
                    || matches!(d.render_kind, RenderKind::Text | RenderKind::Divider),
                "{} has an inconsistent render_kind/data_contract",
                d.type_id
            );
        }
        assert_eq!(registry().render_kind("donut"), RenderKind::ChartDonut);
        assert_eq!(registry().render_kind("text"), RenderKind::Text);
        assert_eq!(
            registry().render_kind("sankey_diagram"),
            RenderKind::Unsupported
        );
        assert_eq!(
            registry().render_kind("no_such_type"),
            RenderKind::Unsupported
        );
    }

    #[test]
    fn cohort_widget_is_registered_with_its_own_schema_distinct_from_cohort_chart() {
        let cohort = registry().get("cohort").expect("cohort must be registered");
        assert_eq!(cohort.category, WidgetCategory::Chart);
        for field in [
            "cohort_key_field",
            "period_field",
            "value_field",
            "period_unit",
        ] {
            assert!(
                cohort.schema.get(field).is_some(),
                "cohort widget schema is missing '{field}'"
            );
        }
        assert_eq!(cohort.default_config["period_unit"], "week");

        let cohort_chart = registry()
            .get("cohort_chart")
            .expect("pre-existing cohort_chart must still be registered");
        assert_ne!(
            cohort.schema, cohort_chart.schema,
            "cohort must carry its own cohort-specific schema, not reuse cohort_chart's \
             generic series_field/category_field shape"
        );
    }

    #[test]
    fn every_phase_6_category_has_at_least_one_descriptor() {
        for category in [
            WidgetCategory::Operational,
            WidgetCategory::EngineNative,
            WidgetCategory::Geospatial,
            WidgetCategory::Kpi,
        ] {
            assert!(
                registry().all().iter().any(|d| d.category == category),
                "no built-in descriptor uses category {category:?}"
            );
        }
    }
}
