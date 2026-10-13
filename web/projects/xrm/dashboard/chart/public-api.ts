// `@attome/xrm/dashboard/chart` — the dashboard's chart primitive
// (`DashboardChartComponent`, Dashboard 10/10 Phase 4.1) and the entity list
// page's `kind = chart` renderer built on it (Basic Units P1 follow-up).
// Its own small entry point so the list page can load it with a dynamic
// `import()` when a chart view is selected, without reaching into the
// dashboard viewer's component barrel (D-314).
export { DashboardChartComponent, SLICE_COLORS } from './dashboard-chart/dashboard-chart.component';
export type {
  ChartBucket, ChartCategory, ChartKind, ChartSeries,
} from './dashboard-chart/dashboard-chart.component';
export { ChartViewComponent, CHART_VIEW_MAX_ROWS, CHART_VIEW_PAGE_SIZE } from './chart-view/chart-view.component';
export {
  aggregate, buildChartViewData, chartKindFor, dateBucketKey, isChartConfigured,
} from './chart-view/chart-view-data';
export type { ChartViewData, ChartViewLabels } from './chart-view/chart-view-data';
