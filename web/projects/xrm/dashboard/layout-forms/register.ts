import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { DashboardVersionFormComponent } from './dashboard-version-form/dashboard-version-form.component';
import { DashboardSectionFormComponent } from './dashboard-section-form/dashboard-section-form.component';
import { DashboardSectionBreakpointFormComponent } from './dashboard-section-breakpoint-form/dashboard-section-breakpoint-form.component';
import { DashboardWidgetFormComponent } from './dashboard-widget-form/dashboard-widget-form.component';
import { DashboardVariableFormComponent } from './dashboard-variable-form/dashboard-variable-form.component';
import { DashboardParameterFormComponent } from './dashboard-parameter-form/dashboard-parameter-form.component';

/** Registers the layout-tree entities' form overrides. Called from
 * `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, never eagerly. */
export function registerDashboardLayoutForms(registry: EntityRouteRegistry): void {
  registry.register('dashboard_version', { formComponent: DashboardVersionFormComponent });
  registry.register('dashboard_section', { formComponent: DashboardSectionFormComponent });
  registry.register('dashboard_section_breakpoint', { formComponent: DashboardSectionBreakpointFormComponent });
  registry.register('dashboard_widget', { formComponent: DashboardWidgetFormComponent });
  registry.register('dashboard_variable', { formComponent: DashboardVariableFormComponent });
  registry.register('dashboard_parameter', { formComponent: DashboardParameterFormComponent });
}
