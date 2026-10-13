import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, signal, untracked,
} from '@angular/core';
import { ReactiveFormsModule, type FormGroup } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';
import { CapabilityPickerComponent } from '../../components/capability-picker/capability-picker.component';
import { AiActionsService, type ActionSummary } from '../../services/ai-actions.service';
import { parseJsonIdArray } from '../../services/admin-ai.service';

/**
 * Hand-written form for `ai_capability_pack` (C6, D-556) — a named,
 * versioned set of action ids an agent policy may reference.
 *
 * The entity's `action_ids` is a `text` column holding a JSON array, so its
 * picker reads the live catalogue (`GET /api/v1/actions` through
 * `AiActionsService`) and writes `JSON.stringify(selected)` back into the
 * control. The picker is the shared `<xrm-capability-picker>` the agent-policy
 * form also uses; only the value it writes differs, and that decision lives in
 * this class.
 *
 * **A pack is configuration, never authorization.** This form edits metadata
 * through the ordinary entity save path: it grants nothing itself, and the
 * notice in the template says so where the operator is editing.
 */
@Component({
  selector: 'attome-ai-capability-pack-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent, CapabilityPickerComponent],
  styleUrls: ['../../../styles/xrm-form.css', './ai-capability-pack-form.component.css'],
  templateUrl: './ai-capability-pack-form.component.html',
})
export class AiCapabilityPackFormComponent extends EngineFormBase {
  private readonly actionsSvc = inject(AiActionsService);
  private readonly viewDestroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  /** The live action catalogue, exactly as the route returned it. */
  readonly actions = signal<ActionSummary[]>([]);
  /** False until the catalogue read settles, so an empty list is never a flash. */
  readonly catalogueLoaded = signal(false);
  /** The ids the picker shows ticked — mirrors the `action_ids` control. */
  readonly selectedIds = signal<string[]>([]);

  constructor() {
    super();
    // The control only exists once the schema has landed (the base class
    // builds the real FormGroup in `ngOnInit`) and the record is patched into
    // it asynchronously, so the picker follows the control's own value rather
    // than a one-shot read taken before the record arrived. Reading
    // `ctrl.value` in the same pass covers the case where the patch already
    // happened before this ran.
    effect(() => {
      const fg = this.form();
      untracked(() => this.bindActionIds(fg));
    });

    this.actionsSvc.listActions().pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe({
      // An empty catalogue is the expected answer on a deployment that has not
      // licensed AI, has the kill switch off, or where this caller holds no
      // action privileges. It is not an error: the picker renders its own
      // empty state, and no rows are invented to fill it.
      next: (actions) => {
        this.actions.set(actions);
        this.catalogueLoaded.set(true);
      },
      error: () => this.catalogueLoaded.set(true),
    });
  }

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }

  /** Writes the picker's next selection into the `action_ids` control. */
  onSelectionChange(ids: string[]): void {
    const ctrl = this.form().get('action_ids');
    if (!ctrl) return;
    // `markAsDirty()` first: the base class refreshes its `dirty` signal from the
    // `valueChanges` emission, so the flag has to be set before the write emits
    // — otherwise an edit that touched only this picker would leave Update
    // disabled on the record it just changed.
    ctrl.markAsDirty();
    // A pack's list is not tri-state. An empty selection is written as `[]`,
    // which pack resolution reads as "this pack contributes nothing" — there is
    // no "unrestricted pack" meaning for `null` to carry here. (The field
    // where `null` and `[]` differ is the policy's `allowed_action_ids`, and it
    // never passes through this form.)
    ctrl.setValue(JSON.stringify(ids));
  }

  private bindActionIds(fg: FormGroup): void {
    const ctrl = fg.get('action_ids');
    if (!ctrl) return;
    // `?? []` is deliberate *here* and only here: a pack's `action_ids` has no
    // readable-versus-unrestricted distinction — `null` and `[]` both mean
    // "contributes no ids" to resolution — so collapsing them for display
    // loses nothing. It would be the I-16 bug on the policy form.
    this.selectedIds.set(parseJsonIdArray(ctrl.value) ?? []);
    ctrl.valueChanges.pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe((value) => {
      this.selectedIds.set(parseJsonIdArray(value) ?? []);
    });
  }
}
