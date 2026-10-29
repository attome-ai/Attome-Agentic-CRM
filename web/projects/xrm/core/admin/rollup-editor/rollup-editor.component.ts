import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { AdminService, EntityMeta } from '@attome/xrm/core/admin/data';
import { QueryService } from '@attome/xrm/core/query/data';

export type RollupFunction = 'count' | 'distinct_count' | 'sum' | 'avg' | 'min' | 'max' | 'first' | 'last';
export const ROLLUP_FUNCTIONS: RollupFunction[] = ['count', 'distinct_count', 'sum', 'avg', 'min', 'max', 'first', 'last'];
/** Parents one backfill run fills (`attome_records::rollup_heal::BACKFILL_BATCH`). */
export const BACKFILL_BATCH = 1000;

const NUMERIC = ['number', 'currency'];
const ORDERED = ['number', 'currency', 'date', 'date_time'];
const DISTINCT = ['text', 'number', 'currency', 'date', 'date_time', 'bool', 'choice', 'lookup', 'icon', 'color'];

/** Whether `fn` can aggregate a field of `fieldType` (the server's `fits`). Pure. */
export function fits(fn: RollupFunction, fieldType: string): boolean {
  if (fn === 'count') return true;
  if (fn === 'distinct_count') return DISTINCT.includes(fieldType);
  if (fn === 'sum' || fn === 'avg') return NUMERIC.includes(fieldType);
  return ORDERED.includes(fieldType);
}

/** The result type the server requires (`expected_result_type`). Pure. */
export function resultType(fn: RollupFunction, fieldType: string | null): string {
  if (fn === 'count' || fn === 'distinct_count' || !fieldType) return 'number';
  return fieldType;
}

/** Whether exact mode is allowed: a count or sum with no filter or window. Pure. */
export function exactAllowed(fn: RollupFunction, filter: string, windowDays: number | null): boolean {
  return (fn === 'count' || fn === 'sum') && !filter.trim() && !windowDays;
}

/** How many backfill runs fill `parents`. Pure. */
export function backfillRuns(parents: number): number {
  return Math.max(1, Math.ceil(parents / BACKFILL_BATCH));
}

/** A field of the related entity, as the schema lists it. */
interface ChildField { name: string; label: string; type: string; target: string | null; }

/**
 * A10-T6: defines a rollup field on `entity`: the function, the related
 * entity and its lookup back to this one (one step; a longer path is
 * written through the API), the field aggregated, a filter, a window and
 * the mode. It previews how many records the backfill fills and in how many
 * runs, and saves through `POST /api/v1/admin/entities/{id}/fields`, where
 * the server checks the definition again.
 */
@Component({
  selector: 'xrm-rollup-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="re" data-testid="rollup-editor" [attr.aria-label]="'rollupEditor.title' | translate">
      <div class="re-grid">
        <label>{{ 'rollupEditor.name' | translate }}
          <input type="text" dir="ltr" data-testid="rollup-name" [value]="name()" (input)="name.set($any($event.target).value)" />
        </label>
        <label>{{ 'rollupEditor.function' | translate }}
          <select data-testid="rollup-function" (change)="setFunction($any($event.target).value)">
            @for (f of functions; track f) {
              <option [value]="f" [selected]="f === fn()">{{ 'rollupEditor.functions.' + f | translate }}</option>
            }
          </select>
        </label>
        <label>{{ 'rollupEditor.related' | translate }}
          <select data-testid="rollup-child" (change)="setChild($any($event.target).value)">
            <option value="">—</option>
            @for (e of entities(); track e.logicalname) {
              <option [value]="e.logicalname" [selected]="e.logicalname === child()">{{ e.name || e.logicalname }}</option>
            }
          </select>
        </label>
        <label>{{ 'rollupEditor.via' | translate }}
          <select data-testid="rollup-via" [disabled]="lookups().length === 0" (change)="via.set($any($event.target).value)">
            @for (l of lookups(); track l.name) {
              <option [value]="l.name" [selected]="l.name === via()">{{ l.label }}</option>
            }
          </select>
        </label>
        @if (fn() !== 'count') {
          <label>{{ 'rollupEditor.field' | translate }}
            <select data-testid="rollup-field" (change)="field.set($any($event.target).value)">
              <option value="">—</option>
              @for (f of fittingFields(); track f.name) {
                <option [value]="f.name" [selected]="f.name === field()">{{ f.label }}</option>
              }
            </select>
          </label>
        }
        <label>{{ 'rollupEditor.filter' | translate }}
          <input type="text" dir="ltr" data-testid="rollup-filter" [value]="filter()" (input)="filter.set($any($event.target).value)"
                 [placeholder]="'rollupEditor.filterHint' | translate" />
        </label>
        <label>{{ 'rollupEditor.windowDays' | translate }}
          <input type="number" min="1" max="3660" data-testid="rollup-window" [value]="windowDays() ?? ''"
                 (input)="setWindow($any($event.target).value)" />
        </label>
        @if (windowDays()) {
          <label>{{ 'rollupEditor.windowField' | translate }}
            <select data-testid="rollup-window-field" (change)="windowField.set($any($event.target).value)">
              <option value="">—</option>
              @for (f of dateFields(); track f.name) {
                <option [value]="f.name" [selected]="f.name === windowField()">{{ f.label }}</option>
              }
            </select>
          </label>
        }
        <label>{{ 'rollupEditor.mode' | translate }}
          <select data-testid="rollup-mode" (change)="mode.set($any($event.target).value)">
            <option value="fast" [selected]="mode() === 'fast'">{{ 'rollupEditor.fast' | translate }}</option>
            <option value="exact" [selected]="mode() === 'exact'" [disabled]="!canBeExact()">{{ 'rollupEditor.exact' | translate }}</option>
          </select>
        </label>
      </div>
      @if (parents() !== null) {
        <p class="re-hint" data-testid="rollup-impact">
          {{ 'rollupEditor.impact' | translate: { parents: parents(), runs: runs() } }}
        </p>
      }
      @if (error(); as message) {
        <p class="re-error" role="alert" data-testid="rollup-error">{{ message }}</p>
      }
      <div class="re-actions">
        <button type="button" class="btn btn-primary" data-testid="rollup-save" [disabled]="!ready() || saving()" (click)="save()">
          {{ 'rollupEditor.save' | translate }}
        </button>
        <button type="button" class="btn btn-secondary" (click)="cancelled.emit()">{{ 'rollupEditor.cancel' | translate }}</button>
      </div>
    </section>
  `,
  styles: [`
    .re { display: flex; flex-direction: column; gap: .75rem; padding-block: .75rem; }
    .re-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr)); gap: .5rem 1rem; }
    .re-grid label { display: flex; flex-direction: column; gap: .25rem; font-size: .8125rem; }
    .re-hint { color: var(--color-text-secondary); margin: 0; font-size: .8125rem; }
    .re-error { color: var(--color-danger); margin: 0; }
    .re-actions { display: flex; gap: .5rem; }
  `],
})
export class RollupEditorComponent {
  private readonly admin = inject(AdminService);
  private readonly api = inject(ApiService);
  private readonly query = inject(QueryService);
  private readonly lang = inject(LangService);

  /** The entity's id, for the save route. */
  readonly entityId = input.required<string>();
  /** The entity's logical name, the rollup's own. */
  readonly entity = input.required<string>();
  readonly saved = output<string>();
  readonly cancelled = output<void>();

  protected readonly functions = ROLLUP_FUNCTIONS;
  readonly name = signal('');
  readonly fn = signal<RollupFunction>('sum');
  readonly child = signal('');
  readonly via = signal('');
  readonly field = signal('');
  readonly filter = signal('');
  readonly windowDays = signal<number | null>(null);
  readonly windowField = signal('');
  readonly mode = signal<'fast' | 'exact'>('fast');
  readonly entities = signal<EntityMeta[]>([]);
  readonly childFields = signal<ChildField[]>([]);
  readonly parents = signal<number | null>(null);
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);

  /** The related entity's lookups to this entity. */
  readonly lookups = computed(() => this.childFields().filter(f => f.type === 'lookup' && f.target === this.entity()));
  readonly fittingFields = computed(() => this.childFields().filter(f => fits(this.fn(), f.type)));
  readonly dateFields = computed(() => this.childFields().filter(f => f.type === 'date' || f.type === 'date_time'));
  readonly canBeExact = computed(() => exactAllowed(this.fn(), this.filter(), this.windowDays()));
  readonly runs = computed(() => backfillRuns(this.parents() ?? 0));
  readonly ready = computed(() =>
    /^[a-z][a-z0-9_]*$/.test(this.name().trim()) && !!this.child() && !!this.via()
    && (this.fn() === 'count' || !!this.field())
    && (!this.windowDays() || !!this.windowField()));

  constructor() {
    effect(() => {
      const entity = this.entity();
      untracked(() => {
        this.admin.listEntities().subscribe({ next: list => this.entities.set(list), error: () => this.entities.set([]) });
        // The impact preview: the records the backfill fills.
        this.query.execute({ entity, page: 1, page_size: 1, include_total: true }).subscribe({
          next: res => this.parents.set(res.data.total ?? res.data.records.length),
          error: () => this.parents.set(null),
        });
      });
    });
    effect(() => {
      if (!this.canBeExact() && this.mode() === 'exact') untracked(() => this.mode.set('fast'));
    });
  }

  setFunction(value: string): void {
    this.fn.set(value as RollupFunction);
    if (!this.fittingFields().some(f => f.name === this.field())) this.field.set('');
  }

  setWindow(value: string): void {
    const n = Number(value);
    this.windowDays.set(value && Number.isFinite(n) && n > 0 ? Math.floor(n) : null);
  }

  setChild(logicalname: string): void {
    this.child.set(logicalname);
    this.via.set('');
    this.field.set('');
    this.childFields.set([]);
    if (!logicalname) return;
    this.api.get<EntitySchema>(`/api/v1/schema/${encodeURIComponent(logicalname)}`).subscribe({
      next: schema => {
        const fields = (schema.fields ?? []).map(f => ({
          name: f.name,
          label: f.display_name || f.name,
          type: f.field_type === 'formula'
            ? ((f.options as { result_type?: string } | null)?.result_type ?? 'text')
            : f.field_type,
          target: f.field_type === 'lookup'
            ? ((f.options as { target_entity_name?: string | null } | null)?.target_entity_name ?? null)
            : null,
        }));
        this.childFields.set(fields);
        const first = this.lookups()[0];
        if (first) this.via.set(first.name);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  /** The `options` the field is saved with. */
  options(): Record<string, unknown> {
    const field = this.fn() === 'count' ? null : this.field();
    const type = field ? this.childFields().find(f => f.name === field)?.type ?? null : null;
    const options: Record<string, unknown> = {
      function: this.fn(),
      path: [{ entity: this.child(), via: this.via() }],
      mode: this.mode(),
      result_type: resultType(this.fn(), type),
    };
    if (field) options['attribute'] = field;
    if (this.filter().trim()) options['filter'] = this.filter().trim();
    if (this.windowDays()) options['window'] = { days: this.windowDays(), date_attribute: this.windowField() };
    return options;
  }

  save(): void {
    const logicalname = this.name().trim();
    this.saving.set(true);
    this.error.set(null);
    this.admin.createAttribute(this.entityId(), {
      logicalname, name: logicalname, field_type: 'rollup', options: this.options(),
    }).subscribe({
      next: () => { this.saving.set(false); this.saved.emit(logicalname); },
      error: (e: ApiError) => { this.saving.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
