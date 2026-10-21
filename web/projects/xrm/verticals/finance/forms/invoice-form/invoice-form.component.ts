import { NgComponentOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

type EinvoiceStatusModule = typeof import('@attome/xrm/verticals/billing/einvoice-status');
type AiModule = typeof import('@attome/xrm/ai');

/**
 * F4-T15: the billing pack extends `invoice` (kind, buyer, amounts, notes,
 * document); its sections show only when those fields exist, so the finance
 * pack alone keeps its short form.
 *
 * Hand-coded form for `invoice`, scaffolded from verticals/finance/bundle.json's
 * "synthesized (no authored layout)" layout by scripts/bundle-to-form-component.mjs. Same
 * field-rendering approach as the generic dispatcher (<attome-field-input> per
 * schema field), but its own component/template — edit freely; re-running
 * the generator only overwrites this file with --force.
 *
 * Tab/section/field grouping below mirrors the bundle's layout at
 * generation time. The bundle JSON remains the source of truth for the
 * entity/fields themselves (schema, validation, choices) — only the form's
 * *presentation* moved to hand-written code.
 */
@Component({
  selector:   'xrm-invoice-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgComponentOutlet, ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, TranslatePipe],
  styleUrls:  ['../../../../styles/xrm-form.css', './invoice-form.component.css'],
  templateUrl: './invoice-form.component.html',
})
export class InvoiceFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  /** The e-invoice compliance panel (AG2-T4), loaded on its own; it hides
   *  itself when the invoice has no e-invoice. */
  protected readonly einvoicePanel = signal<EinvoiceStatusModule | null>(null);
  /** AI5-T7: the collections panel (reminders and payment promises),
   *  loaded on its own; it shows nothing where AI is not licensed. */
  protected readonly collectionsPanel = signal<AiModule | null>(null);

  constructor() {
    super();
    import('@attome/xrm/verticals/billing/einvoice-status').then(
      m => this.einvoicePanel.set(m),
      () => this.einvoicePanel.set(null),
    );
    import('@attome/xrm/ai').then(
      m => this.collectionsPanel.set(m),
      () => this.collectionsPanel.set(null),
    );
  }

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
