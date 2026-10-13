import {
  ChangeDetectionStrategy, Component, computed, inject, input, output, signal,
} from '@angular/core';
import { FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { firstValueFrom, from } from 'rxjs';
import { map, mergeMap, toArray } from 'rxjs/operators';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { ChoiceOptions, FieldSchema } from '@attome/xrm';
import { EntityService } from '../services/entity.service';
import type { BulkRecordEnvelope } from '../services/entity.service';
import { FieldInputComponent } from '../field/field-input/field-input.component';
import { BulkJobRunner, isBulkTerminal } from './bulk-job-runner.service';

// ── Bulk edit (PROD-12) — pure helpers, extracted from `entity-list` (C-28) ──

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

/** In-flight `GET /api/v1/{entity}/{id}` reads while gathering row versions — bounded fan-out, not one burst per selection. */
const BULK_EDIT_READ_CONCURRENCY = 4;

/**
 * Grid-level bulk edit dialog (PROD-12), extracted out of `EntityListComponent`
 * (C-28). Owns its own visibility, schema load, and field-selection form;
 * `EntityListComponent` only supplies the entity name and the record ids to
 * operate on (a live view of its selection), and reacts to `busyChange` (so
 * its own other selection actions stay disabled for the duration of an apply,
 * the same as before extraction) and `applied` (clear selection + reload).
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
  imports:     [FormsModule, ReactiveFormsModule, TranslatePipe, FieldInputComponent],
  templateUrl: './bulk-edit-dialog.component.html',
  // Its own stylesheet, not `entity-list.component.css` — see that file's
  // sibling `bulk-edit-dialog.component.css` doc comment for why sharing it
  // directly is unsafe here (its `:host` rule).
  styleUrl:    './bulk-edit-dialog.component.css',
})
export class BulkEditDialogComponent {
  readonly entityName = input.required<string>();
  /** Live view of the grid's current selection — read fresh at open and at
   * apply time, not snapshotted once. */
  readonly recordIds = input<readonly string[]>([]);

  /** Mirrors `applying()` so the host grid can hold its other selection
   * actions disabled for the same duration `bulkActionRunning` did before
   * this dialog was its own component. */
  readonly busyChange = output<boolean>();
  /** Fired once a bulk edit completes (terminal or not) — the host clears its
   * selection and reloads, same as `applyBulkEdit` always did inline. */
  readonly applied = output<void>();

  private readonly entitySvc = inject(EntityService);
  private readonly lang      = inject(LangService);
  private readonly dialogSvc = inject(DialogService);
  private readonly bulkJobs  = inject(BulkJobRunner);

  readonly open      = signal(false);
  readonly loading   = signal(false);
  readonly fields    = signal<FieldSchema[]>([]);
  readonly fieldName = signal<string | null>(null);
  /** "Clear this field" — sends `null` instead of the editor's value; offered only for optional fields. */
  readonly clear     = signal(false);
  readonly field     = computed(() => this.fields().find(f => f.name === this.fieldName()) ?? null);
  readonly applying  = signal(false);

  /**
   * One control, keyed by the chosen field's name, so `attome-field-input` (which
   * binds `formControlName` to `field().name`) can be reused unchanged.
   * Rebuilt on every field change rather than mutated, so a stale value from
   * the previous field never leaks into the next one's payload.
   */
  form = new FormGroup<Record<string, FormControl<unknown>>>({});

  openDialog(): void {
    if (this.applying() || !this.recordIds().length) return;
    this.open.set(true);
    this.loading.set(true);
    this.fields.set([]);
    this.selectField(null);
    this.entitySvc.getSchema(this.entityName()).subscribe({
      next: schema => {
        const fields = bulkEditableFields(schema.fields);
        this.fields.set(fields);
        this.selectField(fields[0]?.name ?? null);
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

  selectField(name: string | null): void {
    this.fieldName.set(name);
    this.clear.set(false);
    const field = this.fields().find(f => f.name === name);
    const controls: Record<string, FormControl<unknown>> = {};
    if (field) {
      // Same defaults as EngineFormBase.buildFormGroup: a multi-choice control
      // starts as `[]` so the checkbox group has an array to toggle into.
      const multi = field.field_type === 'choice' && !!(field.options as ChoiceOptions | null)?.multi;
      controls[field.name] = new FormControl<unknown>(
        multi ? [] : null,
        field.is_required ? [Validators.required] : [],
      );
    }
    this.form = new FormGroup(controls);
  }

  private setApplying(value: boolean): void {
    this.applying.set(value);
    this.busyChange.emit(value);
  }

  /**
   * Applies one field value to every selected record through the engine's
   * durable bulk job (`POST /api/v1/{entity}/bulk`, operation `update`), then
   * polls its status until the worker reports a terminal state.
   *
   * Reads each record first: the job's update path needs
   * `expected_row_version`, and the grid's rows come from `query/execute`,
   * which only projects the stored query's columns. Bounded fan-out, one
   * enqueue, one refresh — failures are reported once at the end.
   */
  async apply(): Promise<void> {
    const field = this.field();
    const ids = [...this.recordIds()];
    if (!field || !ids.length || this.applying()) return;

    const doClear = this.clear() && !field.is_required;
    const ctrl = this.form.get(field.name);
    if (!doClear && ctrl?.invalid) { ctrl.markAsTouched(); return; }
    const value: unknown = doClear ? null : ctrl?.value ?? null;

    const confirmed = await this.dialogSvc.confirm({
      message: this.lang.translate('entityList.bulkEditConfirm', {
        count: ids.length,
        field: field.display_name || field.name,
      }),
      variant: 'primary',
      confirmText: this.lang.translate('entityList.bulkEditApply'),
    });
    if (!confirmed) return;

    const entityName = this.entityName();
    this.setApplying(true);
    try {
      const versions = await firstValueFrom(from(ids).pipe(
        mergeMap(
          id => this.entitySvc.get(entityName, id).pipe(map(r => ({ id, row_version: r.row_version }))),
          BULK_EDIT_READ_CONCURRENCY,
        ),
        toArray(),
      ));
      const enqueued = await firstValueFrom(
        this.entitySvc.bulkUpdate(entityName, buildBulkUpdateEnvelopes(versions, field.name, value)),
      );
      const status = await firstValueFrom(this.bulkJobs.poll(
        () => this.entitySvc.bulkStatus(entityName, enqueued.id),
        s => isBulkTerminal(s.status),
      ));

      this.open.set(false);
      this.applied.emit();

      if (!isBulkTerminal(status.status)) {
        await this.dialogSvc.error({
          title: this.lang.translate('entityList.bulkEdit'),
          message: this.lang.translate('entityList.bulkEditStillRunning'),
        });
      } else if (status.failed + status.rejected > 0 || status.status === 'failed') {
        const count = status.failed + status.rejected || status.total;
        await this.dialogSvc.error({
          title: 'Action Failed',
          message: this.lang.translate('entityList.bulkActionPartialFailure', {
            count,
            reason: firstBulkError(status.errors) ?? status.status,
          }),
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.dialogSvc.error({ title: 'Action Failed', message });
    } finally {
      this.setApplying(false);
    }
  }
}
