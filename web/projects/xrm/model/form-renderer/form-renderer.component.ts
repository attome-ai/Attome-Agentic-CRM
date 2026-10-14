import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';

import { LiveService } from '../live.service';
import { FormPlan, FormPlanField, ModelService, RecordView } from '../model.service';

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

  /** The published form to draw. */
  readonly formId   = input.required<string>();
  /** The record to show and edit; without it the form is drawn empty. */
  readonly recordId = input<string | null>(null);

  readonly plan    = signal<FormPlan | null>(null);
  readonly record  = signal<RecordView | null>(null);
  readonly values  = signal<Record<string, unknown>>({});
  readonly loading = signal(true);
  readonly saving  = signal(false);
  readonly saved   = signal(false);
  readonly error   = signal<string | null>(null);

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
      const formId = this.formId();
      const recordId = this.recordId();
      untracked(() => this.load(formId, recordId));
    });
  }

  private load(formId: string, recordId: string | null): void {
    this.loading.set(true);
    this.error.set(null);
    this.saved.set(false);
    this.model.formPlan(formId).subscribe({
      next: plan => {
        this.plan.set(plan);
        if (!recordId) {
          this.record.set(null);
          this.values.set({});
          this.loading.set(false);
          return;
        }
        this.model.record(plan.entity, recordId).subscribe({
          next: record => {
            this.record.set(record);
            this.values.set({ ...record.data });
            this.loading.set(false);
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
  }

  save(): void {
    const plan = this.plan();
    const record = this.record();
    if (!plan || !record || this.changed().length === 0) return;
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
}
