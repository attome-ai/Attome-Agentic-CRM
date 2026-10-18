import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/**
 * The form for `invoice_line` (roadmap F4-T15): what is sold, then its tax and
 * amounts. The tax engine sets the rate, VAT and total when the draft is
 * recomputed; an issued invoice's lines are locked by the billing pack.
 */
@Component({
  selector:   'xrm-invoice-line-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, TranslatePipe],
  styleUrls:  ['../../../../styles/xrm-form.css', './invoice-line-form.component.css'],
  templateUrl: './invoice-line-form.component.html',
})
export class InvoiceLineFormComponent extends EngineFormBase {
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
