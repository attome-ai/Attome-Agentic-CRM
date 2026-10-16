import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/**
 * Hand-coded form for `ai_collection_rule` (platform-bundles/attome-ai-collections.json), on the shared base
 * form (D-773). One details section with the entity's fields in the bundle's order;
 * the bundle stays the source of truth for the fields themselves.
 */
@Component({
  selector:   'attome-ai-collection-rule-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './ai-collection-rule-form.component.css'],
  templateUrl: './ai-collection-rule-form.component.html',
})
export class AiCollectionRuleFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
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
