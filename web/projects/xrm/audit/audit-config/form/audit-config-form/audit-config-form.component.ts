import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/** Dedicated form for `audit_config` — the mutable per-entity/field audit
 * rule config (not the append-only `audit_header`/`detail`/`snapshot`
 * ledger, which stays on the generic dispatcher's read-only-in-practice path
 * since nothing writes to it through a form). */
@Component({
  selector:   'attome-audit-config-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent],
  styleUrls:  ['../../../../styles/xrm-form.css', './audit-config-form.component.css'],
  templateUrl: './audit-config-form.component.html',
})
export class AuditConfigFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
