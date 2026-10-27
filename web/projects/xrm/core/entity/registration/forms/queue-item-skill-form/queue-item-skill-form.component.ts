import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/**
 * Hand-coded form for `queue_item_skill` (platform-bundles/attome-service-queue-skills.json), on the shared base
 * form (D-773). One details section with the entity's fields in the bundle's order;
 * the bundle stays the source of truth for the fields themselves.
 */
@Component({
  selector:   'attome-queue-item-skill-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../../../styles/xrm-form.css', './queue-item-skill-form.component.css'],
  templateUrl: './queue-item-skill-form.component.html',
})
export class QueueItemSkillFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: this.lang.translate('xrmForm.tabs.details'), icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }
}
