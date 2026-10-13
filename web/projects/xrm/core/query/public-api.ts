// The services and their wire types now live in `@attome/xrm/core/query/data` and are
// re-exported here so this entry point's public API is unchanged (D-314).
// Consumers outside `query/` — `@attome/xrm/entity` above all — should import
// `@attome/xrm/core/query/data`; importing them from here still pulls all four
// query/view editor components in.
export { QueryService, QueryAdminService, ViewAdminService } from '@attome/xrm/core/query/data';
export type {
  QueryMeta, QueryDetail, CreateQueryBody, UpdateQueryBody,
  AvailableView, ViewBody, ViewDetail,
  QueryColumnDef, QueryExecParams, QueryExecResponse,
} from '@attome/xrm/core/query/data';
export { QueryListComponent }         from './list/query-list/query-list.component';
export { QueryEditorComponent }       from './editor/query-editor/query-editor.component';
export { ViewListComponent }          from './view/list/view-list/view-list.component';
export { ViewEditorComponent }        from './view/editor/view-editor/view-editor.component';
