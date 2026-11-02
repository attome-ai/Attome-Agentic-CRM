import { ChangeDetectionStrategy, Component, effect, inject, signal } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { TemplatePreviewComponent } from '@attome/xrm/core/admin';
import type { FieldSchema } from '@attome/xrm';

/**
 * Hand-coded form for `docgen_template`, scaffolded from platform-bundles/attome-docgen.json's
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
  selector:   'attome-docgen-template-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, TemplatePreviewComponent],
  styleUrls:  ['../../../../../styles/xrm-form.css', './docgen-template-form.component.css'],
  templateUrl: './docgen-template-form.component.html',
})
export class DocgenTemplateFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);
  /** Z13-T9: the template as typed, for the preview. */
  protected readonly draft = signal({ body: '', entity: '' });

  constructor() {
    super();
    effect(onCleanup => {
      const form = this.form();
      const read = (): void => this.draft.set({
        body: String(form.get('body')?.value ?? ''),
        entity: String(form.get('entity')?.value ?? ''),
      });
      read();
      const changes = form.valueChanges.subscribe(read);
      onCleanup(() => changes.unsubscribe());
    });
  }

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
