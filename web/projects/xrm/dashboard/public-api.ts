// `@attome/xrm/dashboard` — M67 Phase 1 (`document/xrm/module/
// M67-component-platform/master-plan.md` Step 1). The Angular counterpart of the
// `attome-dashboard` crate's `declarative_widget` widget type: a renderer that
// reads a JSON-schema-driven widget config and renders it — table/list
// columns, formatting, conditional colors and links — with
// zero customer code execution (Step 2's sandboxed-component model is out of
// scope; see the crate's `declarative_widget.rs` doc comment).
export { DeclarativeWidgetRendererComponent } from './widget/declarative-widget-renderer/declarative-widget-renderer.component';
export type {
  DeclarativeWidgetConfig,
  DeclarativeWidgetColumn,
  ColumnFormat,
  ConditionalColorRule,
  Condition,
  ConditionOperator,
  LinkSpec,
} from './widget/declarative-widget-renderer/declarative-widget.types';
export {
  evaluateCondition,
  resolveConditionalColor,
  isSafeLinkTarget,
  substitutePlaceholders,
} from './widget/declarative-widget-renderer/declarative-widget.util';

// M26 Phase 2 backlog — the first dashboard-viewer slice (read-only
// rendering of a live page/section/widget tree at `/xrm/dashboard/view`, no
// chart library; see `DashboardWidgetViewComponent`'s own doc comment for
// the full scope decision).
export { DashboardViewerComponent } from './viewer/dashboard-viewer/dashboard-viewer.component';
export { DashboardSectionViewComponent } from './viewer/dashboard-section-view/dashboard-section-view.component';
export { DashboardWidgetViewComponent } from './viewer/dashboard-widget-view/dashboard-widget-view.component';
export type { ChartBucket } from './viewer/dashboard-widget-view/dashboard-widget-view.component';

// "dashboard component can also be used in normal forms" — embed a dashboard
// by id or by tag(s) inside any unrelated record's form.
export { DashboardEmbedComponent } from './viewer/dashboard-embed/dashboard-embed.component';

// P9-T15: the scorecard view, metric catalogue and target spread dialog.
export { MetricScorecardComponent } from './viewer/metric-scorecard/metric-scorecard.component';
export { MetricCatalogueComponent } from './viewer/metric-catalogue/metric-catalogue.component';
export { TargetSpreadDialogComponent } from './viewer/target-spread-dialog/target-spread-dialog.component';

// M26 (Dashboard) gap-fill — the template gallery (moved from
// `@attome/xrm/report`, R-10 step 1: new-module UI belongs in the module
// that owns it, not the legacy report entry point).
export { DashboardTemplateGalleryComponent } from './gallery/dashboard-template-gallery/dashboard-template-gallery.component';

// M26 Phase 2 backlog, completed — the visual drag-and-drop Page Editor
// (`/xrm/dashboard/page/editor?pageId=&dashboardId=`), replacing the old
// `<select>`-driven Sections/Widgets drill-down in `DashboardEditorComponent`.
// Moved under `@attome/xrm/dashboard/registration` (R-10 step 3): it *is* the
// `dashboard_page` form override, so registration is its rightful home —
// no longer exported from this entry point.
