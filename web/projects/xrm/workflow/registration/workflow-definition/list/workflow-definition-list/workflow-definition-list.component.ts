import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import { EntityListComponent } from '@attome/xrm/core/entity';
import type { EntityRecord } from '@attome/xrm';
import { entityFormRoute } from '@attome/xrm/core/entity';

/**
 * List override for `workflow_definition`.
 *
 * Identical to the generic EntityListPageComponent — same metadata-driven
 * grid, views, filters, and paging — with exactly one behaviour changed:
 * "New" goes to the custom create page instead of the generic form, because
 * creating a workflow means authoring a graph, not filling in two text
 * fields (see WorkflowCreatePageComponent). Editing an existing workflow's
 * name still opens the ordinary entity form.
 *
 * Kept in this entry point rather than `@attome/xrm/workflow` on purpose:
 * provide-xrm-forms.ts imports its registered components eagerly, so pulling
 * one from the workflow entry would drag the graph editor and its canvas
 * into the shell's chunk. This file depends only on `@attome/xrm/entity`,
 * which that entry already needs, and reaches the create page by route
 * string so it stays lazily loaded.
 */
@Component({
  selector:   'attome-workflow-definition-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [EntityListComponent],
  templateUrl: './workflow-definition-list.component.html',
})
export class WorkflowDefinitionListComponent {
  private readonly router = inject(Router);

  readonly name = input('');

  onCreate(): void {
    void this.router.navigate(['/xrm/admin/workflow/definitions/new']);
  }

  onEdit(record: EntityRecord): void {
    void this.router.navigate(entityFormRoute(this.name()), {
      queryParams: { id: record.id },
    });
  }
}
