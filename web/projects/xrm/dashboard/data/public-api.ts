// `@attome/xrm/dashboard/data` — services and wire types only, no components
// (D-314). R-10 (M26-dashboard-remediation): the client-side owner of every
// `attome-dashboard` bespoke route (lifecycle transitions, clone, restore,
// health-check, widget-types, widget/duplicate, resolve-variables) plus the
// dashboard tree and published-snapshot reads (Dashboard 10/10 Phase 1), so a
// caller no longer hand-rolls its own copy of either.
export {
  DashboardService, draftTreeToDashboardTree, snapshotToDashboardTree, snapshotParameters,
} from './services/dashboard.service';
export type {
  DashboardTree, PageWidgetTree, PublishedView, PublishedState, DashboardLifecycleAction,
  HealthCheckResponse, BrokenWidgetRef,
  TransitionResponse, PublishResponse, CloneResponse, RestoreResponse,
  WidgetDescriptor, DuplicateResponse, ResolveVariablesResponse,
  DraftTreeResponse, TreeRecord, NewPageBody, CreatedPage, RepairedRootSection,
  PublishedDashboard, ActivateResponse,
  DashboardParameter, WidgetInputs, WidgetDataResponse, PageDataResponse, PageWidgetResult,
  StructuredBucket, BucketKey, KpiMetric, KpiPoint, RenderKind, MeasureFn, DateBucket,
  WidgetRecordsInputs, WidgetRecordsResponse, WidgetExplanation, MetricLineageNode, GateIssue,
  WidgetDrillDownInputs, WidgetDrillDownResponse, WidgetCompareInputs, WidgetCompareResponse,
} from './services/dashboard.service';

// M26 (Dashboard) gap-fill — cross-filtering (widget A's click sets a
// dashboard variable; other widgets bound to it re-query). Moved from
// `@attome/xrm/report` (R-10 step 1) — the backend contributes only
// `dashboard_widget.emits`/`.listens` metadata, this is the whole
// client-side bus.
export {
  DashboardVariableBusService, resolveReQueryChain, widgetsListeningOn, MAX_PROPAGATION_HOPS,
  substituteVariableValues,
} from './services/dashboard-variable-bus.service';
export type {
  WidgetCrossFilterBinding, VariableChangeEvent, ReQueryNotification, VariableBoundFilter,
} from './services/dashboard-variable-bus.service';
