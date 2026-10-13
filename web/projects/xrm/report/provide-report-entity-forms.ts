import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { ReportFormComponent } from './forms/report-form/report-form.component';
import { ReportScheduleFormComponent } from './forms/report-schedule-form/report-schedule-form.component';

// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerReportEntityForms(registry: EntityRouteRegistry): void {
  registry.register('attome_report', { formComponent: ReportFormComponent });
  registry.register('report_schedule', { formComponent: ReportScheduleFormComponent });
}
