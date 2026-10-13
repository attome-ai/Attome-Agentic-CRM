// `@attome/xrm/dashboard/modeling-forms` — the hand-coded forms for the
// decision/scenario-modeling entities and the `xrm_dashboard_metric_*`
// entities (authored in platform-bundles/xrm-metric.json), scaffolded by
// scripts/bundle-to-form-component.mjs. Split out of
// `@attome/xrm/dashboard/registration` for the same reason as
// `@attome/xrm/dashboard/layout-forms` (the 360 kB lazy-chunk cap); loaded
// lazily by `src/app/xrm-entity-form-loaders.ts`.
export { DashboardDecisionFormComponent } from './dashboard-decision-form/dashboard-decision-form.component';
export { DashboardDecisionOptionFormComponent } from './dashboard-decision-option-form/dashboard-decision-option-form.component';
export { DashboardDecisionDependencyFormComponent } from './dashboard-decision-dependency-form/dashboard-decision-dependency-form.component';
export { DashboardScenarioFormComponent } from './dashboard-scenario-form/dashboard-scenario-form.component';
export { DashboardScenarioAssumptionFormComponent } from './dashboard-scenario-assumption-form/dashboard-scenario-assumption-form.component';
export { DashboardScenarioMetricFormComponent } from './dashboard-scenario-metric-form/dashboard-scenario-metric-form.component';
export { DashboardScenarioResultFormComponent } from './dashboard-scenario-result-form/dashboard-scenario-result-form.component';
export { DashboardMetricDefinitionFormComponent } from './dashboard-metric-definition-form/dashboard-metric-definition-form.component';
export { DashboardMetricTargetFormComponent } from './dashboard-metric-target-form/dashboard-metric-target-form.component';
export { registerDashboardModelingForms } from './register';
