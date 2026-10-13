// `@attome/xrm/dashboard/registration` — the `attome_dashboard` form override
// (M26 Phase 2 backlog: "no drag-and-drop builder consumes the widget-types/
// duplicate/group/align routes yet"). Split into its own entry, same
// reasoning as `@attome/xrm/workflow/registration`'s own doc comment: the
// app's composition root (`src/app/attome-metadata-form-loaders.ts`) lazily
// `import()`s this entry and calls `registerDashboardEntityForms` only once
// `attome_dashboard` is actually routed to, so this component's code never
// lands in another module's chunk.
export { DashboardEditorComponent }      from './dashboard/form/dashboard-editor/dashboard-editor.component';
export { registerDashboardEntityForms }  from './provide-dashboard-entity-forms';
// M26 Phase 2 backlog, completed — the visual drag-and-drop Page Editor
// (`/xrm/dashboard/page/editor?pageId=&dashboardId=`). It *is* the
// `dashboard_page` form override (see `provide-dashboard-entity-forms.ts`),
// so it lives under this entry point (R-10 step 3) rather than
// `@attome/xrm/dashboard`'s own barrel.
export { PageEditorComponent }           from './page-editor/page-editor.component';
export { PAGE_EDITOR_ROUTES }            from './page-editor/page-editor.routes';
// The fifteen scaffolded layout-tree and decision/scenario/metric forms
// moved to `@attome/xrm/dashboard/layout-forms` and
// `@attome/xrm/dashboard/modeling-forms`, so the Page Editor's route chunk
// (this entry point) stays under the lazy-chunk cap.
