import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';
import { AiAgentAutonomyComponent } from '../../autonomy/agent-autonomy.component';
import { AiAgentTrialComponent } from '../../autonomy/agent-trial.component';

/**
 * Hand-coded form for `ai_agent`, scaffolded from platform-bundles/attome-ai-agent.json's
 * "Agent Form" layout by scripts/bundle-to-form-component.mjs. Same
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
  selector:   'attome-ai-agent-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, TranslatePipe, AiAgentAutonomyComponent, AiAgentTrialComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './ai-agent-form.component.css'],
  templateUrl: './ai-agent-form.component.html',
})
export class AiAgentFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // AH8: per-action autonomy levels.
      { id: 'autonomy', label: this.lang.translate('aiAutonomy.tab'), icon: 'las la-user-shield' },
      // AH6: the trial report and go-live.
      { id: 'trial', label: this.lang.translate('aiTrial.tab'), icon: 'las la-vial' },
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
