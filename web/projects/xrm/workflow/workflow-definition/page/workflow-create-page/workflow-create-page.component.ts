import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { entityFormRoute } from '@attome/xrm/core/entity';

import { WorkflowAdminService } from '../../../services/workflow-admin.service';

/**
 * Custom "New Workflow" page — the create half of the workflow UI, reached
 * from the generic entity list's New button (registered as a list override
 * for `workflow_definition`, see provide-xrm-forms.ts).
 *
 * A workflow is not creatable through the generic entity form: the record
 * that matters is the *graph*, which lives on `workflow_definition_version`
 * and is authored on the node canvas. So this page owns the two-step create
 * the engine's own admin API requires — POST the definition, POST its first
 * draft version — and then hands straight off to the graph editor. Editing
 * an existing workflow's name/logicalname stays on the generic entity form.
 *
 * Styles are shared with the entity form pages (xrm-form.css) so the custom
 * page reads as part of the same UI rather than a detour.
 */
@Component({
  selector:   'attome-workflow-create-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, TranslatePipe],
  styleUrls:  ['../../../../styles/xrm-form.css', './workflow-create-page.component.css'],
  templateUrl: './workflow-create-page.component.html',
})
export class WorkflowCreatePageComponent {
  private readonly svc    = inject(WorkflowAdminService);
  private readonly router = inject(Router);

  readonly creating = signal(false);
  readonly error    = signal<string | null>(null);

  name        = '';
  logicalname = '';
  /** Stops the auto-slug from overwriting a logical name typed by hand. */
  slugTouched = false;

  onNameChange(value: string): void {
    if (!this.slugTouched) this.logicalname = slugify(value);
  }

  create(): void {
    const name        = this.name.trim();
    const logicalname = this.logicalname.trim().toLowerCase();

    if (!name)        { this.error.set('Name is required.'); return; }
    if (!logicalname) { this.error.set('Logical name is required.'); return; }
    if (!/^[a-z0-9_-]+$/.test(logicalname)) {
      this.error.set('Logical name must be lowercase letters, digits, hyphens, or underscores.');
      return;
    }

    this.creating.set(true);
    this.error.set(null);

    this.svc.createDefinition({ logicalname, name }).subscribe({
      next: def => {
        // Second leg of the create: the definition alone has no graph to
        // edit, so a draft version is minted here rather than leaving the
        // user on an empty definition. If only this leg fails the workflow
        // still exists — fall back to its form, whose Versions section has
        // "New Draft Version" one click away, instead of stranding the user
        // on this page.
        this.svc.createVersion(def.id).subscribe({
          next: version => {
            this.creating.set(false);
            void this.router.navigate(
              ['/xrm/admin/workflow/definitions', def.id, 'versions', version.id],
            );
          },
          error: () => {
            this.creating.set(false);
            void this.router.navigate(entityFormRoute('workflow_definition'), {
              queryParams: { id: def.id },
            });
          },
        });
      },
      error: (e: ApiError) => {
        this.creating.set(false);
        this.error.set(e.message);
      },
    });
  }

  cancel(): void {
    void this.router.navigate(['/xrm', 'workflow', 'definition', 'list']);
  }
}

/** 'Lead Approval' → 'lead-approval'. Matches admin.rs's `valid_logicalname`. */
function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 100);
}
