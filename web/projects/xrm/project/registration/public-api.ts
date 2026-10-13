// Split out from `@attome/xrm/project` (D-314 packaging: xrm barrel
// splitting) — this entry holds only the thin `attome_project` list override
// that `EntityRouteRegistry` needs, kept separate from the parent entry's
// heavier tabbed console page (ProjectDetailPageComponent,
// ProjectOverviewTabComponent, ProjectWorkPlanTabComponent).
// The app's composition root (`src/app/attome-metadata-form-loaders.ts`) lazily
// `import()`s this entry and calls `registerProjectEntityForms` only once an
// entity that needs it is actually routed to — see EntityRouteRegistry's
// doc comment for why (a static import here would force the console page
// into the same eager chunk — ng-packagr bundles one entry point as one
// unit, so importing anything from the parent entry pulls all of it in —
// same reasoning as `core/admin/data`'s own doc comment).
export { ProjectListComponent }         from './list/project-list/project-list.component';
export { ProjectWorkItemFormComponent }        from './work-item/form/work-item-form/work-item-form.component';
export { ProjectDeliverableFormComponent }     from './deliverable/form/deliverable-form/deliverable-form.component';
export { ProjectIssueFormComponent }           from './issue/form/issue-form/issue-form.component';
export { ProjectChangeRequestFormComponent }   from './change-request/form/change-request-form/change-request-form.component';
export { ProjectPortfolioFormComponent }              from './forms/project-portfolio-form/project-portfolio-form.component';
export { ProjectProgramFormComponent }                from './forms/project-program-form/project-program-form.component';
export { ProjectWorkItemDependencyFormComponent }     from './forms/project-work-item-dependency-form/project-work-item-dependency-form.component';
export { ProjectBaselineFormComponent }               from './forms/project-baseline-form/project-baseline-form.component';
export { ProjectBaselineItemFormComponent }           from './forms/project-baseline-item-form/project-baseline-item-form.component';
export { ProjectResourceRateFormComponent }           from './forms/project-resource-rate-form/project-resource-rate-form.component';
export { ProjectTimesheetFormComponent }              from './forms/project-timesheet-form/project-timesheet-form.component';
export { ProjectTimeEntryFormComponent }              from './forms/project-time-entry-form/project-time-entry-form.component';
export { ProjectTeamFormComponent }                   from './forms/project-team-form/project-team-form.component';
export { ResourceAllocationFormComponent }            from './forms/resource-allocation-form/resource-allocation-form.component';
export { ProjectTemplateFormComponent }               from './forms/project-template-form/project-template-form.component';
export { ProjectMeetingFormComponent }                from './forms/project-meeting-form/project-meeting-form.component';
export { ProjectLessonFormComponent }                 from './forms/project-lesson-form/project-lesson-form.component';
export { registerProjectEntityForms }   from './provide-project-entity-forms';
