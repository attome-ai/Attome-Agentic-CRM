// `@attome/xrm/dashboard/layout-forms` — the hand-coded forms for the
// dashboard layout-tree entities (version, section, breakpoint, widget,
// variable, parameter), scaffolded by scripts/bundle-to-form-component.mjs
// from platform-bundles/xrm-dashboard.json. Split out of
// `@attome/xrm/dashboard/registration` (Basic Units P1 follow-up) so the
// Page Editor's route chunk no longer carries fifteen record forms it never
// renders: that chunk was 447 kB against the 360 kB lazy-chunk cap
// (scripts/chunk-budget.mjs). The app's composition root
// (`src/app/xrm-entity-form-loaders.ts`) imports this entry lazily, only
// when one of these entities is first routed to.
export { DashboardVersionFormComponent } from './dashboard-version-form/dashboard-version-form.component';
export { DashboardSectionFormComponent } from './dashboard-section-form/dashboard-section-form.component';
export { DashboardSectionBreakpointFormComponent } from './dashboard-section-breakpoint-form/dashboard-section-breakpoint-form.component';
export { DashboardWidgetFormComponent } from './dashboard-widget-form/dashboard-widget-form.component';
export { DashboardVariableFormComponent } from './dashboard-variable-form/dashboard-variable-form.component';
export { DashboardParameterFormComponent } from './dashboard-parameter-form/dashboard-parameter-form.component';
export { registerDashboardLayoutForms } from './register';
