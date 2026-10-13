import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/**
 * Dedicated form for `note` — a single note's own fields (title, text,
 * the polymorphic `entity_name`/`record_id` it's attached to, its
 * attachments/replies). No Notes tab on itself — a note doesn't take notes
 * on itself, matching the generic dispatcher this form replaces. The
 * primary way notes get created and browsed remains `NotesPanelComponent`
 * (embedded in every other entity's own form).
 */
@Component({
  selector:   'xrm-note-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent],
  styleUrls:  ['../../../../../../styles/xrm-form.css', './note-form.component.css'],
  templateUrl: './note-form.component.html',
})
export class NoteFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
