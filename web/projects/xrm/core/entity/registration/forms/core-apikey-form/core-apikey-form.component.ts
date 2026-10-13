import { ChangeDetectionStrategy, Component, computed } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TranslatePipe } from '@attome/base';
import { FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { EntitySchema, FieldSchema } from '@attome/xrm';

/**
 * D-535: the generic entity engine refuses create, update and restore of
 * `api_key` (422), admins included — a key is minted only through
 * `POST /api/v1/auth/api-keys`, behind the D-510 `api_key_create` step-up.
 * This form is therefore read-only: no save in either mode, every control
 * disabled, no create form at all, and `secret_hash` is never rendered.
 * Revocation stays the generic delete from the list.
 *
 * (Original scaffold note follows.)
 *
 * Hand-coded form for `api_key`, scaffolded from platform-bundles/xrm-core-api_key.json's
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
  selector:   'xrm-core-api_key-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../../../styles/xrm-form.css', './core-api_key-form.component.css'],
  templateUrl: './core-api_key-form.component.html',
})
export class CoreApikeyFormComponent extends EngineFormBase {
  /** Never saveable: `EngineFormBase.save()` returns early on this. */
  override readonly canSave = computed(() => false);

  /** The fields shown, in order. `secret_hash` is deliberately absent. */
  readonly detailFields = ['user_ref', 'name', 'public_key', 'created_at', 'last_used_at', 'is_active'];

  protected override buildFormGroup(schema: EntitySchema): FormGroup {
    const fg = super.buildFormGroup(schema);
    fg.disable({ emitEvent: false });
    return fg;
  }

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }
}
