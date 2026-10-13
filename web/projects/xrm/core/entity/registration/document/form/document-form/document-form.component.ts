import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/**
 * Dedicated form for `attome_document` — a single document's own metadata
 * (name, the polymorphic `entity_name`/`record_id` it's attached to, folder,
 * the file itself). No Documents tab on itself, matching the generic
 * dispatcher this form replaces. The primary way documents get created and
 * browsed remains `DocumentFolderBrowserComponent` (the per-record Documents
 * tab and the system-wide Documents page); this form exists for the same
 * reason every entity gets one — direct admin access to one record's raw
 * fields.
 */
@Component({
  selector:   'attome-document-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent],
  styleUrls:  ['../../../../../../styles/xrm-form.css', './document-form.component.css'],
  templateUrl: './document-form.component.html',
})
export class DocumentFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
