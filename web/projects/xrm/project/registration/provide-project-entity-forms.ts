import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { ProjectListComponent } from './list/project-list/project-list.component';
import { ProjectWorkItemFormComponent } from './work-item/form/work-item-form/work-item-form.component';
import { ProjectDeliverableFormComponent } from './deliverable/form/deliverable-form/deliverable-form.component';
import { ProjectIssueFormComponent } from './issue/form/issue-form/issue-form.component';
import { ProjectChangeRequestFormComponent } from './change-request/form/change-request-form/change-request-form.component';
import { ProjectPortfolioFormComponent } from './forms/project-portfolio-form/project-portfolio-form.component';
import { ProjectProgramFormComponent } from './forms/project-program-form/project-program-form.component';
import { ProjectWorkItemDependencyFormComponent } from './forms/project-work-item-dependency-form/project-work-item-dependency-form.component';
import { ProjectBaselineFormComponent } from './forms/project-baseline-form/project-baseline-form.component';
import { ProjectBaselineItemFormComponent } from './forms/project-baseline-item-form/project-baseline-item-form.component';
import { ProjectResourceRateFormComponent } from './forms/project-resource-rate-form/project-resource-rate-form.component';
import { ProjectTimesheetFormComponent } from './forms/project-timesheet-form/project-timesheet-form.component';
import { ProjectTimeEntryFormComponent } from './forms/project-time-entry-form/project-time-entry-form.component';
import { ProjectTeamFormComponent } from './forms/project-team-form/project-team-form.component';
import { ResourceAllocationFormComponent } from './forms/resource-allocation-form/resource-allocation-form.component';
import { ProjectTemplateFormComponent } from './forms/project-template-form/project-template-form.component';
import { ProjectMeetingFormComponent } from './forms/project-meeting-form/project-meeting-form.component';
import { ProjectLessonFormComponent } from './forms/project-lesson-form/project-lesson-form.component';
import { ProjectFormComponent } from './forms/project-form/project-form.component';

// 'attome_project' -> a bespoke list: opening a row goes to the tabbed
// Project detail page (`/xrm/admin/project/console/:id`, `@attome/xrm/project`)
// — see ProjectListComponent's doc comment. It also has its own form
// (SYSTEM-CHANGES.md Topic 14: every entity has one), a bundle scaffold to be
// designed by hand (D-773). Every other Project Management entity below gets its own
// dedicated form, including `project_team` (previously left on the
// generic dispatcher as a thin project<->team join with "nothing bespoke to
// show" — that reasoning is superseded by the platform-wide move to
// hand-coded forms for every built-in xrm/base entity, so it's registered
// below too). `project_communication` was retired in favor of the
// platform-wide `communication` entity, owned by a different module.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerProjectEntityForms(registry: EntityRouteRegistry): void {
  registry.register('attome_project', {
    listComponent: ProjectListComponent,
    formComponent: ProjectFormComponent,
  });
  registry.register('project_work_item', { formComponent: ProjectWorkItemFormComponent });
  registry.register('project_deliverable', { formComponent: ProjectDeliverableFormComponent });
  registry.register('project_issue', { formComponent: ProjectIssueFormComponent });
  registry.register('project_change_request', { formComponent: ProjectChangeRequestFormComponent });
  registry.register('project_portfolio', { formComponent: ProjectPortfolioFormComponent });
  registry.register('project_program', { formComponent: ProjectProgramFormComponent });
  registry.register('project_work_item_dependency', { formComponent: ProjectWorkItemDependencyFormComponent });
  registry.register('project_baseline', { formComponent: ProjectBaselineFormComponent });
  registry.register('project_baseline_item', { formComponent: ProjectBaselineItemFormComponent });
  registry.register('project_resource_rate', { formComponent: ProjectResourceRateFormComponent });
  registry.register('project_timesheet', { formComponent: ProjectTimesheetFormComponent });
  registry.register('project_time_entry', { formComponent: ProjectTimeEntryFormComponent });
  registry.register('project_team', { formComponent: ProjectTeamFormComponent });
  registry.register('resource_allocation', { formComponent: ResourceAllocationFormComponent });
  registry.register('project_template', { formComponent: ProjectTemplateFormComponent });
  registry.register('project_meeting', { formComponent: ProjectMeetingFormComponent });
  registry.register('project_lesson', { formComponent: ProjectLessonFormComponent });
}
