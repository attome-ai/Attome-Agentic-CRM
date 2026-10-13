// Project Management (merry-splashing-whistle.md) — the bespoke tabbed
// Project detail page. Everything else (Project Team/Tasks/Deliverables/
// Change Requests/Issues & Risks lists, and the Project list itself) is the
// generic metadata-driven pages seeded by `attome-project`; only what the
// generic pages cannot express lives here.
export { ProjectDetailPageComponent }   from './detail/project-detail-page/project-detail-page.component';
export { ProjectOverviewTabComponent }  from './tab/project-overview-tab/project-overview-tab.component';
export { ProjectWorkPlanTabComponent }  from './tab/project-work-plan-tab/project-work-plan-tab.component';
export { ProjectChangeRequestsTabComponent } from './tab/project-change-requests-tab/project-change-requests-tab.component';
export { ProjectService }               from './services/project.service';
export type {
  ProjectSummary,
  WorkItemRollupRow,
  CaptureBaselineRequest,
  CaptureBaselineResponse,
  ChangeRequestDecisionResponse,
  TimesheetDecisionResponse,
} from './services/project.service';

// Timesheets (M69 §4) — submit/approve/reject against `attome-project`'s M07
// state model + D-195/D-421 four-eyes gate. Not scoped to one project (see
// the component's own doc comment), so it is its own top-level page rather
// than a Project detail tab, same posture as Resource Capacity below.
export { ProjectTimesheetListComponent } from './timesheet/list/project-timesheet-list/project-timesheet-list.component';

// M72 Resource Management — the capacity heat grid (`GET
// /api/v1/resources/capacity`). Its own component/service pair, not part of
// the Project detail tabbed console above: it isn't scoped to one project.
export { ResourceCapacityPageComponent } from './capacity/resource-capacity-page/resource-capacity-page.component';
export { ResourceCapacityService }        from './services/resource-capacity.service';
export type { CapacityRow, CapacityQuery } from './services/resource-capacity.service';

// ProjectListComponent and registerProjectEntityForms live in
// `@attome/xrm/project/registration` instead of here — a separate, lighter
// entry point so registering the `attome_project` list override doesn't force
// this entry's heavier tabbed console page into the same eager chunk. See
// that entry's public-api.ts doc comment.
