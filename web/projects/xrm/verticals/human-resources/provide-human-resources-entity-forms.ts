import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AttendanceFormComponent } from './forms/attendance-form/attendance-form.component';
import { EmployeeFormComponent } from './forms/employee-form/employee-form.component';
import { LeaveRequestFormComponent } from './forms/leave-request-form/leave-request-form.component';
import { PerformanceReviewFormComponent } from './forms/performance-review-form/performance-review-form.component';

// The human-resources vertical's entity forms (verticals/human-resources/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerHumanResourcesEntityForms(registry: EntityRouteRegistry): void {
  registry.register('attendance', { formComponent: AttendanceFormComponent });
  registry.register('employee', { formComponent: EmployeeFormComponent });
  registry.register('leave_request', { formComponent: LeaveRequestFormComponent });
  registry.register('performance_review', { formComponent: PerformanceReviewFormComponent });
}
