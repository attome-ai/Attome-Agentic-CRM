import { NgComponentOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, effect, inject, signal, untracked } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

type CompetitorsModule = typeof import('@attome/xrm/verticals/sales/competitors');
type PlaybooksModule = typeof import('@attome/xrm/verticals/sales/playbooks');

/**
 * Hand-coded form for `opportunity`, scaffolded from verticals/crm/bundle.json's
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
  selector:   'xrm-opportunity-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgComponentOutlet, ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, TranslatePipe],
  styleUrls:  ['../../../../styles/xrm-form.css', './opportunity-form.component.css'],
  templateUrl: './opportunity-form.component.html',
})
export class OpportunityFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  /** The sales pack's battle card panel (D25-T9), loaded on its own so a
   *  deployment without sales never fetches it; it hides itself when the deal
   *  has no competitor. */
  protected readonly competitorsPanel = signal<CompetitorsModule | null>(null);
  /** The sales pack's plays panel (D26-T2), loaded the same way; it hides
   *  itself when no play applies to the deal. */
  protected readonly playsPanel = signal<PlaybooksModule | null>(null);
  /** The deal's stage as last saved: the plays follow the saved deal, so an
   *  unsaved stage change does not reload them. */
  protected readonly savedStage = signal<string | null>(null);

  constructor() {
    super();
    import('@attome/xrm/verticals/sales/competitors').then(
      m => this.competitorsPanel.set(m),
      () => this.competitorsPanel.set(null),
    );
    import('@attome/xrm/verticals/sales/playbooks').then(
      m => this.playsPanel.set(m),
      () => this.playsPanel.set(null),
    );
    effect(() => {
      if (this.dirty()) return;
      const stage = this.recordValue()['stage'];
      untracked(() => this.savedStage.set(typeof stage === 'string' ? stage : null));
    });
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
