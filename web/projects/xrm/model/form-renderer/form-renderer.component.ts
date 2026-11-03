import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, LangService, RulesEvaluatorService, SdkService, TranslatePipe } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import {
  computeFieldPolicies, fieldKindResolver, ruleExpressions, rulesTypesOf,
} from '@attome/xrm/core/entity';

import { LiveService } from '../live.service';
import { FormPlan, FormPlanField, ModelService, RecordView, tabSections } from '../model.service';
import { CHANGE_DEBOUNCE_MS, FormHookAnswer, FormHookEvent, rejectionText, withChanges } from './form-hooks';

/** How a field is edited, from its attribute's field type number. */
export type FieldControl = 'text' | 'number' | 'date' | 'checkbox' | 'readonly';

/**
 * The input a field type is edited with. Numbers and currency are numbers,
 * dates are dates, booleans are check boxes; formulas, lookups, files and
 * images are shown but not edited here (their own editors come with Y14).
 */
export function controlFor(fieldType: number): FieldControl {
  switch (fieldType) {
    case 1: case 2: case 4: case 9: case 10: return 'number';
    case 5:  return 'date';
    case 6:  return 'checkbox';
    case 11: case 12: case 13: case 16: case 18: return 'readonly';
    default: return 'text';
  }
}

/**
 * The generic form renderer (roadmap Y14, first step): draws a published
 * form's render plan (`GET /api/v1/model/forms/{id}/plan`) as sections of
 * labelled fields, fills them from a record, and saves the fields that
 * changed with the record's row version. Layout uses logical CSS
 * properties only, so Arabic (right to left) needs nothing extra.
 *
 * A12-T2: the plan's tabs and each section's columns; the caller's business
 * rules from the entity's schema applied live (a hidden field is not drawn,
 * a disabled one is read-only, a firing error shows under its field, a
 * firing `required` makes it required; expression conditions answered by
 * the rules evaluator, A11-T3); a field the server marks read-only (no
 * write grant, or seen masked) is drawn disabled. A field the caller may not
 * read is never in the plan. The server decides every write.
 */
@Component({
  selector:        'xrm-form-renderer',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './form-renderer.component.html',
  styleUrls:       ['./form-renderer.component.css'],
})
export class FormRendererComponent {
  private readonly model = inject(ModelService);
  private readonly sdk = inject(SdkService);
  /** The AI field a suggestion is being fetched for. */
  readonly suggesting = signal<string | null>(null);

  /** The published form to draw. */
  readonly formId   = input<string>('');
  /**
   * A12-T3: a plan to draw instead of a published form's (a designer's
   * unsaved draft), with no record.
   */
  readonly previewPlan = input<FormPlan | null>(null);
  /** The record to show and edit; without it the form is drawn empty. */
  readonly recordId = input<string | null>(null);

  readonly plan    = signal<FormPlan | null>(null);
  readonly schema  = signal<EntitySchema | null>(null);
  readonly record  = signal<RecordView | null>(null);
  /** A12-T2: the tab shown, by index. */
  readonly activeTab = signal(0);
  /** The sections of the tab shown (all of them without tabs). */
  readonly sections = computed(() => {
    const plan = this.plan();
    return plan ? tabSections(plan, this.activeTab()) : [];
  });
  readonly values  = signal<Record<string, unknown>>({});
  readonly loading = signal(true);
  readonly saving  = signal(false);
  readonly saved   = signal(false);
  readonly error   = signal<string | null>(null);

  // ── A12-T2: business rules, live ──────────────────────────────────────
  private readonly rules = computed(() => this.schema()?.business_rules ?? []);
  private readonly kinds = computed(() => fieldKindResolver(this.schema()?.fields ?? []));
  private readonly expressions = computed(() => ruleExpressions(this.rules()), {
    equal: (a, b) => a.length === b.length && a.every((x, i) => x === b[i]),
  });
  readonly expressionResults = signal<ReadonlyMap<string, boolean>>(new Map());
  private expressionRun = 0;
  readonly outcome = computed(() =>
    computeFieldPolicies(this.rules(), this.values(), this.kinds(), this.expressionResults()));

  /** The fields whose value differs from the loaded record. */
  readonly changed = computed(() => {
    const original = this.record()?.data ?? {};
    const current = this.values();
    return Object.keys(current).filter(key => current[key] !== original[key]);
  });

  constructor() {
    // Y14-T3: a published change drops the cached plans.
    inject(LiveService).connect();
    effect(() => {
      const preview = this.previewPlan();
      const formId = this.formId();
      const recordId = this.recordId();
      untracked(() => {
        if (preview) this.showPreview(preview);
        else if (formId) this.load(formId, recordId);
      });
    });
    // A11-T3: the rules' expressions, answered again on every change.
    effect(() => {
      if (!this.expressions().length) {
        untracked(() => { if (this.expressionResults().size) this.expressionResults.set(new Map()); });
        return;
      }
      const values = this.values();
      untracked(() => void this.evaluateExpressions(values));
    });
  }

  private async evaluateExpressions(values: Readonly<Record<string, unknown>>): Promise<void> {
    const expressions = this.expressions();
    const run = ++this.expressionRun;
    const schema = this.schema();
    if (!expressions.length || !schema) {
      if (this.expressionResults().size) this.expressionResults.set(new Map());
      return;
    }
    const evaluator = this.evaluator;
    const types = rulesTypesOf(schema.fields ?? []);
    const context = { now: new Date().toISOString(), fields: { ...values } };
    const results = new Map<string, boolean>();
    try {
      for (const expression of expressions) {
        const answer = await evaluator.evaluate(expression, types, context);
        if (answer.ok && typeof answer.value === 'boolean') results.set(expression, answer.value);
      }
    } catch {
      return; // No evaluator: those rules stay unknown and do not fire.
    }
    if (run === this.expressionRun) this.expressionResults.set(results);
  }

  private readonly evaluator = inject(RulesEvaluatorService);

  /** A rule hides the field. */
  hidden(field: FormPlanField): boolean {
    return this.outcome().locks.get(field.attribute)?.effect === 'hidden';
  }

  /** Not editable here: read-only to the caller, locked by a rule, or a read-only type. */
  disabled(field: FormPlanField): boolean {
    return field.read_only === true
      || this.outcome().locks.get(field.attribute)?.effect === 'disabled';
  }

  /** Required by the field, or by a firing `required` rule. */
  required(field: FormPlanField): boolean {
    return field.required || this.outcome().required.has(field.attribute);
  }

  /** The firing `error` rules' messages on the field. */
  messages(field: FormPlanField): string[] {
    return (this.outcome().errors.get(field.attribute) ?? []).map(m => m.message);
  }

  /** A required field left empty: shown under it. */
  missing(field: FormPlanField): boolean {
    const value = this.value(field);
    return this.required(field) && (value === null || value === undefined || value === '');
  }

  pickTab(index: number): void {
    this.activeTab.set(index);
  }

  // ── A12-T4: form hooks ─────────────────────────────────────────────────
  private readonly lang = inject(LangService);
  /** The form events with an extension on this entity (from the last answer). */
  readonly hookEvents = signal<readonly FormHookEvent[]>([]);
  /** The extensions' last refusal, in the person's language. */
  readonly hookMessage = signal<string | null>(null);
  private changeTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Asks the server to run the entity's extensions for `event` on the
   * form's values; fills in what they set and shows a refusal. Resolves to
   * the answer, or `null` when the call failed (the form carries on: the
   * save runs the write hooks itself).
   */
  runHooks(event: FormHookEvent): Promise<FormHookAnswer | null> {
    const plan = this.plan();
    if (!plan) return Promise.resolve(null);
    const record = this.record();
    return new Promise(resolve => {
      this.model.formHooks(plan.entity, {
        event,
        record_id: record?.id ?? null,
        values: this.values(),
        previous: record?.data ?? null,
      }).subscribe({
        next: answer => {
          this.hookEvents.set(answer.events);
          if (Object.keys(answer.changes).length) this.values.set(withChanges(this.values(), answer));
          this.hookMessage.set(rejectionText(answer, this.lang.current()));
          resolve(answer);
        },
        error: () => resolve(null),
      });
    });
  }

  /** After a change, once typing pauses, when an extension listens. */
  private scheduleChangeHooks(): void {
    if (!this.hookEvents().includes('change')) return;
    if (this.changeTimer) clearTimeout(this.changeTimer);
    this.changeTimer = setTimeout(() => {
      this.changeTimer = null;
      void this.runHooks('change');
    }, CHANGE_DEBOUNCE_MS);
  }

  /**
   * A12-T5: whether a form without a record creates one on save (a record
   * page's new-record form); a designer's preview does not.
   */
  readonly creates = input(false);

  /** Saves a new record from the form's values (A12-T5), then shows it. */
  private async create(plan: FormPlan): Promise<void> {
    const values = this.values();
    if (!Object.keys(values).length) return;
    if (this.hookEvents().includes('before_save')) {
      const answer = await this.runHooks('before_save');
      if (answer?.rejection) return;
    }
    this.saving.set(true);
    this.error.set(null);
    this.model.createRecord(plan.entity, this.values()).subscribe({
      next: created => {
        this.record.set(created);
        this.values.set({ ...created.data });
        this.saving.set(false);
        this.saved.set(true);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.saving.set(false); },
    });
  }

  /** A12-T3: draws `plan` empty, with the entity's live rules. */
  private showPreview(plan: FormPlan): void {
    const entityChanged = this.plan()?.entity !== plan.entity;
    this.plan.set(plan);
    this.record.set(null);
    this.error.set(null);
    this.loading.set(false);
    if (this.activeTab() >= Math.max(plan.tabs?.length ?? 0, 1)) this.activeTab.set(0);
    if (entityChanged) {
      this.values.set({});
      this.schema.set(null);
      this.model.schema(plan.entity).subscribe({
        next: schema => this.schema.set(schema),
        error: () => this.schema.set(null),
      });
    }
  }

  private load(formId: string, recordId: string | null): void {
    this.loading.set(true);
    this.error.set(null);
    this.saved.set(false);
    this.model.formPlan(formId).subscribe({
      next: plan => {
        this.plan.set(plan);
        this.activeTab.set(0);
        // A12-T2: the caller's rules for the entity; without them the form
        // still draws, with no live rules.
        this.schema.set(null);
        this.model.schema(plan.entity).subscribe({
          next: schema => this.schema.set(schema),
          error: () => this.schema.set(null),
        });
        if (!recordId) {
          this.record.set(null);
          this.values.set({});
          this.loading.set(false);
          void this.runHooks('load');
          return;
        }
        this.model.record(plan.entity, recordId).subscribe({
          next: record => {
            this.record.set(record);
            this.values.set({ ...record.data });
            this.loading.set(false);
            void this.runHooks('load');
          },
          error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
        });
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  control(field: FormPlanField): FieldControl {
    return controlFor(field.field_type);
  }

  value(field: FormPlanField): unknown {
    return this.values()[field.attribute] ?? null;
  }

  /** The text an input shows for a value. */
  text(field: FormPlanField): string {
    const value = this.value(field);
    if (value === null || value === undefined) return '';
    if (this.control(field) === 'date') return String(value).slice(0, 10);
    return String(value);
  }

  set(field: FormPlanField, raw: string | boolean): void {
    let value: unknown = raw;
    const control = this.control(field);
    if (control === 'number') value = raw === '' ? null : Number(raw);
    if (control === 'text' && raw === '') value = null;
    if (control === 'date' && raw === '') value = null;
    this.values.update(values => ({ ...values, [field.attribute]: value }));
    this.saved.set(false);
    this.scheduleChangeHooks();
  }

  /**
   * Saves the changed fields. A12-T4: when an extension listens before a
   * save, it runs first; a refusal stops the save and shows its message,
   * and the values it sets are saved with the rest.
   */
  async save(): Promise<void> {
    const plan = this.plan();
    const record = this.record();
    if (plan && !record && this.creates()) {
      await this.create(plan);
      return;
    }
    if (!plan || !record || this.changed().length === 0) return;
    if (this.hookEvents().includes('before_save')) {
      const answer = await this.runHooks('before_save');
      if (answer?.rejection) return;
    }
    const values = this.values();
    const patch: Record<string, unknown> = {};
    for (const key of this.changed()) patch[key] = values[key];
    this.saving.set(true);
    this.error.set(null);
    this.model.updateRecord(plan.entity, record.id, patch, record.row_version).subscribe({
      next: updated => {
        this.record.set(updated);
        this.values.set({ ...updated.data });
        this.saving.set(false);
        this.saved.set(true);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.saving.set(false); },
    });
  }

  /**
   * Asks `record.ai_field` for the field's value (N11-T1) and puts the
   * suggestion in the field as an unsaved change for the person to review.
   */
  suggest(field: FormPlanField): void {
    const plan = this.plan();
    const record = this.record();
    if (!plan || !record) return;
    this.suggesting.set(field.attribute);
    this.sdk.post<{ status: string; result?: { suggestion?: string } }>(
      '/api/v1/actions/record.ai_field/invoke',
      { body: { args: { entity: plan.entity, record_id: record.id, field: field.attribute } } },
    ).subscribe({
      next: outcome => {
        this.suggesting.set(null);
        const suggestion = outcome.status === 'completed' ? outcome.result?.suggestion : undefined;
        if (typeof suggestion === 'string') this.set(field, suggestion);
      },
      error: () => this.suggesting.set(null),
    });
  }
}
