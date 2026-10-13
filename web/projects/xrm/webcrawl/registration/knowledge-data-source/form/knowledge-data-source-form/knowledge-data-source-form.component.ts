import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, RelatedGridComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/** Dedicated form for `knowledge_data_source`. Keeps the Knowledge Items
 * related grid the generic dispatcher gave this one entity. */
@Component({
  selector:   'xrm-knowledge-data-source-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent, RelatedGridComponent],
  styleUrls:  ['../../../../../styles/xrm-form.css', './knowledge-data-source-form.component.css'],
  templateUrl: './knowledge-data-source-form.component.html',
})
export class KnowledgeDataSourceFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      { id: 'knowledge', label: 'Knowledge items', icon: 'las la-table' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
