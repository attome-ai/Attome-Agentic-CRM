import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import { EntityListComponent, entityFormRoute } from '@attome/xrm/core/entity';
import type { EntityRecord } from '@attome/xrm';

/**
 * List override for `attome_project`.
 *
 * Identical to the generic EntityListPageComponent — same metadata-driven
 * grid, views, filters, and paging — with exactly one behaviour changed:
 * opening a row goes to the bespoke tabbed Project detail page
 * (`/xrm/admin/project/console/:id`, `@attome/xrm/project` — nested under
 * the `admin` route bucket for the same reason
 * `/xrm/admin/workflow/instances/:id` is, and with the extra `console`
 * segment because a two-segment `project/:id` would collide with the
 * generic entity list/form's own `/xrm/project/list` and `/xrm/project/form`
 * URLs — see the route's own comment in xrm-shell.routes.ts) instead of the
 * generic field-editing form, because a project needs its work plan,
 * deliverables, risks, change requests, communications, and team — not a
 * flat field list. "New" stays the generic create form (`attome_project` has
 * no bespoke create flow, unlike workflow definitions).
 *
 * Kept in this entry point rather than `@attome/xrm/project` on purpose,
 * mirroring `WorkflowDefinitionListComponent`'s own reasoning:
 * provide-xrm-forms.ts imports its registered components eagerly, so pulling
 * one from the project entry would drag the work-plan tree and control-center
 * tiles into the shell's eager chunk. This file depends only on
 * `@attome/xrm/entity`, which that entry already needs, and reaches the
 * detail page by route string so it stays lazily loaded.
 */
@Component({
  selector:   'attome-project-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [EntityListComponent],
  templateUrl: './project-list.component.html',
})
export class ProjectListComponent {
  private readonly router = inject(Router);

  readonly name = input('');

  onCreate(): void {
    void this.router.navigate(entityFormRoute(this.name()));
  }

  onEdit(record: EntityRecord): void {
    void this.router.navigate(['/xrm/admin/project/console', record.id]);
  }
}
