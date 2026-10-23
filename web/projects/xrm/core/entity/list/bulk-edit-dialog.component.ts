import {
  ChangeDetectionStrategy, Component, computed, inject, input, output, signal,
} from '@angular/core';
import { FormControl, FormRecord, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { ChoiceOptions, FieldSchema } from '@attome/xrm';
import { EntityService } from '../services/entity.service';
import type {
  BulkEditFilter, BulkEditOp, BulkEditOperation, BulkEditPreview, BulkEditRequest, BulkEditSubmitted,
  BulkOperationStatus, BulkRecordEnvelope,
} from '../services/entity.service';
import { FieldInputComponent } from '../field/field-input/field-input.component';
import { BulkJobRunner, isBulkTerminal } from './bulk-job-runner.service';

// ── Bulk edit (PROD-12, B5-T4) — pure helpers ──

/**
 * The schema fields a grid-level bulk edit may set, in form order.
 *
 * `file` is out because the upload-session routes are scoped to one existing
 * record, so one value cannot be shared by a selection. `is_active` is out
 * because the platform's soft-delete flag already has its own sanctioned
 * grid actions (Deactivate/Activate) with their own confirm copy and, on
 * `user_account`, revocation side effects a plain field write would
 * bypass.
 */
const NOT_BULK_EDITABLE: ReadonlySet<string> = new Set(['file', 'image', 'formula']);

export function bulkEditableFields(fields: readonly FieldSchema[]): FieldSchema[] {
  return fields
    // U9: an `image` is a file field; a `formula` is computed and refused on write.
    .filter(f => !NOT_BULK_EDITABLE.has(f.field_type) && f.name !== 'is_active')
    .sort((a, b) => a.sort_order - b.sort_order);
}

/**
 * One `POST /api/v1/{entity}/bulk` envelope per selected record, each pinned
 * to the `row_version` just read for it — the engine's update path requires
 * both `id` and `expected_row_version`, so a record edited by someone else
 * between the read and the job fails that item alone instead of overwriting.
 */
export function buildBulkUpdateEnvelopes(
  versions: readonly { id: string; row_version: number }[],
  fieldName: string,
  value: unknown,
): BulkRecordEnvelope[] {
  return versions.map(v => ({
    id: v.id,
    expected_row_version: v.row_version,
    data: { [fieldName]: value },
  }));
}

/**
 * First human-readable message in a bulk operation's `errors` value, which
 * `bulk.rs` writes as `[{ index, error }, …]`. Tolerant of anything else so a
 * future shape change degrades to "no reason" rather than a render error.
 */
export function firstBulkError(errors: unknown): string | null {
  if (!Array.isArray(errors)) return null;
  for (const entry of errors) {
    if (!entry || typeof entry !== 'object') continue;
    const message = (entry as Record<string, unknown>)['error'];
    if (typeof message === 'string' && message.trim()) return message;
  }
  return null;
}

// Lives beside the job runner so the list can use it without importing this
// (deferred) file; re-exported here for existing callers.
export { isBulkTerminal } from './bulk-job-runner.service';

/** Whether a field is a multi-select choice. */
export function isMultiChoice(field: FieldSchema): boolean {
  return field.field_type === 'choice' && !!(field.options as ChoiceOptions | null)?.multi;
}

/** The operations a field accepts, as the server checks them (`bulk_edit::check_operation`). */
export function opsFor(field: FieldSchema): BulkEditOp[] {
  const ops: BulkEditOp[] = ['set'];
  if (!field.is_required) ops.push('clear');
  if (isMultiChoice(field)) ops.push('add', 'remove');
  if (field.field_type === 'number' || field.field_type === 'currency') ops.push('increment');
  return ops;
}

/** One change being drafted: the attribute, its operation, and (unless clearing) its value. */
export interface DraftOperation { attribute: string; op: BulkEditOp; value?: unknown }

/**
 * The bulk-edit request: the selection's ids, or the view's filters, and the
 * operations in order. `clear` carries no value; `increment` a number.
 */
export function buildEditRequest(
  mode: 'selection' | 'filters',
  ids: readonly string[],
  filters: readonly BulkEditFilter[],
  drafts: readonly DraftOperation[],
  quiet: boolean,
): BulkEditRequest {
  const operations: BulkEditOperation[] = drafts.map(d => {
    if (d.op === 'clear') return { attribute: d.attribute, op: d.op };
    const value = d.op === 'increment' ? Number(d.value) : d.value ?? null;
    return { attribute: d.attribute, op: d.op, value };
  });
  const scope = mode === 'selection' ? { ids: [...ids] } : { filters: [...filters] };
  return quiet ? { ...scope, operations, quiet } : { ...scope, operations };
}

/** One record a bulk edit did not change, and why. */
export interface BulkFailure {
  index: number;
  recordId: string | null;
  /** `conflict`: changed by someone after it was read; `failed`: refused. */
  reason: 'conflict' | 'failed';
  message: string;
}

interface ItemResultLike { index?: unknown; problem?: { code?: unknown; message?: unknown } | null }
interface ErrorEntryLike { index?: unknown; error?: unknown }

/**
 * The records an edit did not change, from the status's item results (with
 * `include_items`) or, failing those, its `errors` list; `recordIds` (the
 * edit's `record_ids`) names each item's record by its index.
 */
export function bulkFailures(status: unknown, recordIds: readonly string[]): BulkFailure[] {
  if (!status || typeof status !== 'object') return [];
  const record = (index: number) => recordIds[index] ?? null;
  const items = (status as { items?: unknown }).items;
  if (Array.isArray(items)) {
    return (items as ItemResultLike[]).flatMap(item => {
      if (!item?.problem || typeof item.index !== 'number') return [];
      const reason: BulkFailure['reason'] = item.problem.code === 'version_conflict' ? 'conflict' : 'failed';
      const message = typeof item.problem.message === 'string' ? item.problem.message : '';
      return [{ index: item.index, recordId: record(item.index), reason, message }];
    });
  }
  const errors = (status as { errors?: unknown }).errors;
  if (!Array.isArray(errors)) return [];
  return (errors as ErrorEntryLike[]).flatMap(entry => {
    if (typeof entry?.index !== 'number') return [];
    const message = typeof entry.error === 'string' ? entry.error : '';
    return [{ index: entry.index, recordId: record(entry.index), reason: 'failed' as const, message }];
  });
}

/** The per-user setting holding saved bulk edits, by entity. */
export const BULK_ACTIONS_SETTING = 'records.bulk_actions';
/** Most saved bulk edits per entity (the setting's schema). */
export const MAX_SAVED_ACTIONS = 50;

/** A saved, rerunnable bulk edit. */
export interface SavedBulkAction { name: string; operations: BulkEditOperation[] }

/** The saved bulk edits for `entity` in the setting's value, ignoring anything malformed. */
export function savedActionsFor(value: unknown, entity: string): SavedBulkAction[] {
  if (!value || typeof value !== 'object') return [];
  const list = (value as Record<string, unknown>)[entity];
  if (!Array.isArray(list)) return [];
  return list.filter((a): a is SavedBulkAction =>
    !!a && typeof a === 'object' && typeof (a as SavedBulkAction).name === 'string'
    && Array.isArray((a as SavedBulkAction).operations));
}

/** The setting's value with `action` saved for `entity`, replacing one of the same name. */
export function withSavedAction(
  value: unknown,
  entity: string,
  action: SavedBulkAction,
): Record<string, SavedBulkAction[]> {
  const all = value && typeof value === 'object' ? { ...(value as Record<string, SavedBulkAction[]>) } : {};
  const kept = savedActionsFor(value, entity).filter(a => a.name !== action.name);
  all[entity] = [action, ...kept].slice(0, MAX_SAVED_ACTIONS);
  return all;
}

/**
 * Grid-level bulk edit dialog (PROD-12, B5-T4), driven by the bulk-edit
 * routes (`attome_records::bulk_edit`). The person picks the selection or
 * every record matching the view's filters, drafts one or more operations
 * (set, clear, add or remove an option, increase a number), previews the
 * change, runs it, reads which records were not changed and why (each a link
 * to the record), and can undo it: the undo puts back only records nobody
 * changed since. An edit can be saved by name in the person's own settings
 * and run again later.
 *
 * Opened imperatively via `openDialog()` through a template reference
 * variable — this tag is always present in `entity-list.component.html` (not
 * behind an `@if`), so the reference stays valid whether or not the dialog is
 * currently visible.
 */
@Component({
  selector:    'xrm-bulk-edit-dialog',
  standalone:  true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:     [FormsModule, ReactiveFormsModule, RouterLink, TranslatePipe, FieldInputComponent],
  templateUrl: './bulk-edit-dialog.component.html',
  // Its own stylesheet, not `entity-list.component.css` — see that file's
  // sibling `bulk-edit-dialog.component.css` doc comment for why sharing it
  // directly is unsafe here (its `:host` rule).
  styleUrl:    './bulk-edit-dialog.component.css',
})
export class BulkEditDialogComponent {
  readonly entityName = input.required<string>();
  /** Live view of the grid's current selection, read at open and at each run. */
  readonly recordIds = input<readonly string[]>([]);
  /** The view's current filters, for "every record matching the filters". */
  readonly filters = input<readonly BulkEditFilter[]>([]);

  /** Mirrors `applying()` so the host grid can hold its other selection
   * actions disabled while an edit or its undo runs. */
  readonly busyChange = output<boolean>();
  /** Fired once an edit or its undo has run — the host clears its selection and reloads. */
  readonly applied = output<void>();

  private readonly entitySvc = inject(EntityService);
  private readonly api       = inject(ApiService);
  private readonly lang      = inject(LangService);
  private readonly dialogSvc = inject(DialogService);
  private readonly bulkJobs  = inject(BulkJobRunner);

  readonly open      = signal(false);
  readonly loading   = signal(false);
  readonly applying  = signal(false);
  readonly fields    = signal<FieldSchema[]>([]);
  readonly mode      = signal<'selection' | 'filters'>('selection');
  readonly step      = signal<'edit' | 'preview' | 'result'>('edit');
  /** The drafted changes, one per attribute; each value lives in `form` under the attribute's name. */
  readonly drafts    = signal<{ attribute: string; op: BulkEditOp }[]>([]);
  /** B5-T3: run without flows, agents or follower notifications (needs `records.bulk_quiet`). */
  readonly quiet     = signal(false);
  readonly preview   = signal<BulkEditPreview | null>(null);
  readonly submitted = signal<BulkEditSubmitted | null>(null);
  readonly status    = signal<BulkOperationStatus | null>(null);
  readonly undone    = signal(false);
  readonly saved     = signal<SavedBulkAction[]>([]);
  readonly saveName  = signal('');
  /** The selection's size when the dialog opened. */
  readonly selectionCount = signal(0);

  readonly fieldByName = computed(() => new Map(this.fields().map(f => [f.name, f])));
  /** Fields not yet drafted, for the "add a field" picker. */
  readonly addable = computed(() => {
    const used = new Set(this.drafts().map(d => d.attribute));
    return this.fields().filter(f => !used.has(f.name));
  });
  readonly failures = computed(() => bulkFailures(this.status(), this.submitted()?.record_ids ?? []));

  /** The setting's whole value as last read, so a save keeps other entities' actions. */
  private savedValue: unknown = {};

  form = new FormRecord<FormControl<unknown>>({});

  openDialog(): void {
    if (this.applying()) return;
    const ids = this.recordIds();
    if (!ids.length && !this.filters().length) return;
    this.open.set(true);
    this.loading.set(true);
    this.mode.set(ids.length ? 'selection' : 'filters');
    this.selectionCount.set(ids.length);
    this.resetRun();
    this.drafts.set([]);
    this.quiet.set(false);
    this.form = new FormRecord<FormControl<unknown>>({});
    this.fields.set([]);
    this.loadSaved();
    this.entitySvc.getSchema(this.entityName()).subscribe({
      next: schema => {
        const fields = bulkEditableFields(schema.fields);
        this.fields.set(fields);
        if (fields[0]) this.addOperation(fields[0].name);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        this.open.set(false);
        this.loading.set(false);
        void this.dialogSvc.error({ title: 'Action Failed', message: err.message });
      },
    });
  }

  close(): void {
    if (this.applying()) return;
    this.open.set(false);
  }

  setMode(mode: 'selection' | 'filters'): void {
    this.mode.set(mode);
    this.resetRun();
  }

  /** Drafts a change to one more field, starting with `op` when it fits, else its first operation. */
  addOperation(name: string | null, op?: BulkEditOp, value?: unknown): void {
    const field = name ? this.fieldByName().get(name) : undefined;
    if (!field || this.drafts().some(d => d.attribute === field.name)) return;
    const first = op && opsFor(field).includes(op) ? op : opsFor(field)[0];
    const empty = isMultiChoice(field) ? [] : null;
    this.form.addControl(field.name, new FormControl<unknown>(
      value ?? empty,
      field.is_required ? [Validators.required] : [],
    ));
    this.drafts.update(list => [...list, { attribute: field.name, op: first }]);
    this.resetRun();
  }

  removeOperation(attribute: string): void {
    this.drafts.update(list => list.filter(d => d.attribute !== attribute));
    this.form.removeControl(attribute);
    this.resetRun();
  }

  setOp(attribute: string, op: BulkEditOp): void {
    this.drafts.update(list => list.map(d => (d.attribute === attribute ? { ...d, op } : d)));
    this.resetRun();
  }

  /** The request for the current draft, or null when a needed value is missing. */
  private request(): BulkEditRequest | null {
    const drafts = this.drafts();
    if (!drafts.length) return null;
    let valid = true;
    const withValues = drafts.map(d => {
      const ctrl = this.form.get(d.attribute);
      if (d.op !== 'clear' && ctrl?.invalid) { ctrl.markAsTouched(); valid = false; }
      return { ...d, value: ctrl?.value };
    });
    if (!valid) return null;
    return buildEditRequest(this.mode(), this.recordIds(), this.filters(), withValues, this.quiet());
  }

  /** Shows what the edit would change, writing nothing. */
  async runPreview(): Promise<void> {
    const body = this.request();
    if (!body || this.applying()) return;
    this.setApplying(true);
    try {
      this.preview.set(await firstValueFrom(this.entitySvc.bulkEditPreview(this.entityName(), body)));
      this.step.set('preview');
    } catch (err) {
      await this.reportError(err);
    } finally {
      this.setApplying(false);
    }
  }

  /** Runs the previewed edit and follows its job to the end. */
  async apply(): Promise<void> {
    const body = this.request();
    if (!body || this.applying()) return;
    const entity = this.entityName();
    this.setApplying(true);
    try {
      const submitted = await firstValueFrom(this.entitySvc.bulkEdit(entity, body));
      this.submitted.set(submitted);
      this.undone.set(false);
      if (submitted.id) this.status.set(await this.follow(submitted.id));
      this.step.set('result');
      this.applied.emit();
    } catch (err) {
      await this.reportError(err);
    } finally {
      this.setApplying(false);
    }
  }

  /** Puts the edit back; a record changed since the edit is reported and left as it is. */
  async undo(): Promise<void> {
    const submitted = this.submitted();
    if (!submitted?.undo.length || this.applying() || this.undone()) return;
    const entity = this.entityName();
    this.setApplying(true);
    try {
      const reverted = await firstValueFrom(this.entitySvc.bulkEditUndo(entity, submitted.undo, this.quiet()));
      this.submitted.set({ ...reverted, undo: [] });
      this.status.set(reverted.id ? await this.follow(reverted.id) : null);
      this.undone.set(true);
      this.applied.emit();
    } catch (err) {
      await this.reportError(err);
    } finally {
      this.setApplying(false);
    }
  }

  /** Saves the drafted operations under a name in the person's settings. */
  async saveAction(): Promise<void> {
    const name = this.saveName().trim();
    const body = this.request();
    if (!name || !body) return;
    const value = withSavedAction(this.savedValue, this.entityName(), { name, operations: body.operations });
    try {
      await firstValueFrom(this.api.put(`/api/v1/settings/me/${BULK_ACTIONS_SETTING}`, { value }));
      this.savedValue = value;
      this.saved.set(value[this.entityName()] ?? []);
      this.saveName.set('');
    } catch (err) {
      await this.reportError(err);
    }
  }

  /** Loads a saved edit's operations into the draft and previews it. */
  useSaved(action: SavedBulkAction): void {
    for (const d of this.drafts()) this.form.removeControl(d.attribute);
    this.drafts.set([]);
    for (const op of action.operations) this.addOperation(op.attribute, op.op, op.value);
    void this.runPreview();
  }

  /** The "add a field" picker: drafts the chosen field and resets the picker. */
  onAddField(event: Event): void {
    const select = event.target as HTMLSelectElement;
    this.addOperation(select.value || null);
    select.value = '';
  }

  /** The drafted attributes a preview sample changes, in draft order. */
  changedNames(sample: { after: Record<string, unknown> }): string[] {
    return this.drafts().map(d => d.attribute).filter(name => name in sample.after);
  }

  /** Back from the preview to the draft. */
  back(): void {
    this.step.set('edit');
  }

  fieldLabel(name: string): string {
    return this.fieldByName().get(name)?.display_name || name;
  }

  fieldOf(name: string): FieldSchema | null {
    return this.fieldByName().get(name) ?? null;
  }

  opsOf(name: string): BulkEditOp[] {
    const field = this.fieldByName().get(name);
    return field ? opsFor(field) : ['set'];
  }

  /** A preview value as text: lists joined, empty as a dash. */
  shown(value: unknown): string {
    if (value === null || value === undefined || value === '') return '—';
    if (Array.isArray(value)) return value.join(', ');
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }

  /** Whether the job is still running past the poll budget. */
  stillRunning(): boolean {
    const status = this.status();
    return !!status && !isBulkTerminal(status.status);
  }

  private resetRun(): void {
    this.step.set('edit');
    this.preview.set(null);
    this.submitted.set(null);
    this.status.set(null);
    this.undone.set(false);
  }

  private follow(operationId: string): Promise<BulkOperationStatus> {
    const entity = this.entityName();
    return firstValueFrom(this.bulkJobs.poll(
      () => this.entitySvc.bulkStatus(entity, operationId, true),
      s => isBulkTerminal(s.status),
    ));
  }

  private loadSaved(): void {
    this.saved.set([]);
    this.api.get<{ items?: { key: string; value: unknown }[] }>('/api/v1/settings/me').subscribe({
      next: settings => {
        this.savedValue = settings.items?.find(s => s.key === BULK_ACTIONS_SETTING)?.value ?? {};
        this.saved.set(savedActionsFor(this.savedValue, this.entityName()));
      },
      // Saved edits are a convenience: without them the dialog still works.
      error: () => this.saved.set([]),
    });
  }

  private setApplying(value: boolean): void {
    this.applying.set(value);
    this.busyChange.emit(value);
  }

  private async reportError(err: unknown): Promise<void> {
    const message = (err as Partial<ApiError> | null)?.message
      ?? (err instanceof Error ? err.message : String(err));
    await this.dialogSvc.error({ title: this.lang.translate('entityList.bulkEdit'), message });
  }
}
