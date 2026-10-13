import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, RelatedGridComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/**
 * Dedicated form for `organization`. Same field-rendering approach
 * as the generic dispatcher (`<attome-field-input>` per schema field — a
 * metadata-driven entity's editable surface is exactly its schema, so
 * hand-writing a duplicate `<input>` per field here would only drift from
 * it), but its own component, its own registration, its own tab set —
 * including the Teams/Users related grids that only make sense for this one
 * entity.
 */
@Component({
  selector:   'xrm-organization-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent, RelatedGridComponent],
  styleUrls:  ['../../../../../../styles/xrm-form.css', './organization-form.component.css'],
  templateUrl: './organization-form.component.html',
})
export class OrganizationFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      { id: 'teams', label: 'Teams', icon: 'las la-users' },
      { id: 'users', label: 'Users', icon: 'las la-user' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /**
   * The self-referencing "Parent Organization" lookup drives BusinessUnit-tier
   * record-level security and the generic ancestors/descendants hierarchy
   * engine — it stays a real, writable field in metadata and the API, but
   * this form hides the picker: setting an org's parent from the UI isn't a
   * supported workflow. Everything downstream of it (RLS, admin tooling,
   * direct API calls) is untouched. Same behavior as the generic dispatcher
   * this form replaces.
   */
  protected override filterFields(fields: FieldSchema[]): FieldSchema[] {
    return fields.filter(f => f.name !== 'organization_ref');
  }
}
