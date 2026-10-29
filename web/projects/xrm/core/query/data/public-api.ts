// Services and wire types only — no components (D-314).
//
// This is the edge that mattered most. `@attome/xrm/entity` — the wildcard route
// behind every record list and form in the product — needs `QueryService` and
// `ViewAdminService` to run a view, and importing them from `@attome/xrm/query`
// pulled the query and view *editors* onto the hottest route in the app, which
// in turn pulled `@attome/xrm/admin` (view-editor -> AdminService) and then
// `@attome/xrm/license` (sidebar-manager -> LicenseAdminService). Four entry
// points' components downloaded by a user opening a contact record.
export { QueryService } from './services/query.service';
export { QueryAdminService } from './services/query-admin.service';
export type {
  QueryMeta, QueryDetail, CreateQueryBody, UpdateQueryBody,
} from './services/query-admin.service';
export { ViewAdminService } from './services/view-admin.service';
export type {
  AvailableView, ViewBody, ViewDetail, ViewKind,
  KanbanViewMetadata, CalendarViewMetadata, MapViewMetadata,
  ChartViewMetadata, ChartSeries, ChartType, ChartAggregation, ChartDateBucket, ChartSort,
  CreatePersonalViewBody, UpdatePersonalViewBody,
} from './services/view-admin.service';
export type {
  QueryColumnDef, QueryExecParams, QueryExecResponse,
} from './services/types';
