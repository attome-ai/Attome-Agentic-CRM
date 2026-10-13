import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/**
 * Dedicated form for `privilege` — the static privilege catalog
 * (`key`/`name`/`description`). No Communications tab: a privilege is a
 * catalog entry, not a record anything sends a message about, same
 * exclusion the generic dispatcher this form replaces already made.
 */
@Component({
  selector:   'xrm-privilege-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent],
  styleUrls:  ['../../../../../../styles/xrm-form.css', './privilege-form.component.css'],
  templateUrl: './privilege-form.component.html',
})
export class PrivilegeFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
