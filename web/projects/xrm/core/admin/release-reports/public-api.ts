// Solution 7 Phase 2 (D-788, D-791; `SOLUTION-7-PHASE-2-DESIGN.md` §10) — the
// release report pages: the list (`/xrm/admin/release-reports`) and one report
// with its items and decisions (`/xrm/admin/release-reports/{id}`, the page the
// post-apply notification links to).
//
// Its own secondary entry point, like `governance`, so every route that loads
// the `@attome/xrm/core/admin` barrel does not download these pages too
// (D-314). The service and wire types live in `@attome/xrm/core/admin/data`.
export { ReleaseReportListComponent }   from './report-list/release-report-list.component';
export { ReleaseReportDetailComponent } from './report-detail/release-report-detail.component';
export { ReportItemComponent }          from './report-item/report-item.component';
export { describeItem, formatValue }    from './report-text';
