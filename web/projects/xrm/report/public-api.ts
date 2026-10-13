export { MetricListComponent }               from './metric/list/metric-list/metric-list.component';
export { MetricService }                     from './services/metric.service';
export type {
  MetricDefinitionSummary, MetricSnapshot, SnapshotStatus,
  ComputeMetricRequest, ComputeMetricResponse,
} from './services/metric.service';
export { ReportDataService }                 from './services/report-data.service';
export { resolveDateRange, withDateRangeFilters } from './services/report-data.service';
export type { AggregateRequest, AggregateResponse, AggregateBucket } from './services/report-data.service';
// `DashboardTemplateGalleryComponent` moved to `@attome/xrm/dashboard` and
// `DashboardVariableBusService` (+ its types) to `@attome/xrm/dashboard/data`
// — R-10 step 1 (M26-dashboard-remediation): new-module UI/state belongs in
// the module that owns it, not this legacy report entry point.
//
// D-479 (M26 R-09) deleted `dashboard/{builder,page,tab,viewer}` and
// `widget/` (the legacy dashboard product's own builder/viewer/widget-render
// tree, and its `DashboardPageComponent`/`DashboardViewerComponent`/
// `DashboardBuilderComponent`/`WidgetRendererComponent`/
// `WidgetConfigPanelComponent`/`DashboardPermissionsTabComponent`/
// `DashboardVersionsTabComponent` exports) along with `WidgetType`/
// `WidgetDataShape` below — `attome-dashboard`'s own components/widget registry
// are the platform's one dashboard product now.
export type {
  DashboardWidget, WidgetDataSource,
  DateRangeConfig, DateRangePreset, MetricMode,
} from './types';

// Hand-coded forms (moving off the generic metadata-driven EntityFormComponent
// for the platform's own built-in entities — see xrm/audit and xrm/notification
// for the established pattern).
export { registerReportEntityForms } from './provide-report-entity-forms';
