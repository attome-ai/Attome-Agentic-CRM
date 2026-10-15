import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import type { Subscription } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import type { FieldSchema } from '@attome/xrm';
import { EntityService } from '../services/entity.service';
import { FieldInputComponent } from '../field/field-input/field-input.component';
import type { ColumnFilterDraft, FilterKind, QueryFilter } from './column-filters';
import {
  AdvancedCondition, MAX_ADVANCED_CONDITIONS, advancedFindFields, choiceOptions, conditionKind,
  conditionOperators, conditionsToFilters, filtersToConditions, newCondition,
} from './advanced-find';

/** i18n key for each operator the builder offers — the grid popover's own labels. */
const OPERATOR_LABELS: Record<string, string> = {
  contains: 'entityList.filterOpContains', equals: 'entityList.filterOpEquals',
  eq: 'entityList.filterOpEquals', neq: 'entityList.filterOpNotEquals',
  starts_with: 'entityList.filterOpStartsWith', ends_with: 'entityList.filterOpEndsWith',
  gt: 'entityList.filterOpGreaterThan', gte: 'entityList.filterOpGreaterThanOrEqual',
  lt: 'entityList.filterOpLessThan', lte: 'entityList.filterOpLessThanOrEqual',
  between: 'entityList.filterOpBetween', is_null: 'entityList.filterOpIsEmpty',
  is_not_null: 'entityList.filterOpIsNotEmpty', today: 'entityList.dateToday',
  past_7_days: 'entityList.datePast7Days', past_month: 'entityList.datePastMonth',
  past_year: 'entityList.datePastYear', on: 'entityList.dateOn', after: 'entityList.dateAfter',
  before: 'entityList.dateBefore',
};

/**
 * Advanced find (U12 Phase A, D-607): a condition builder over the list's
 * entity. Rows are ANDed — the one flat filter grammar `query/execute`
 * accepts. `Apply` hands the wire filters to the list; `Save as view` hands
 * them over to be stored in a personal view's `view_metadata.filters`.
 *
 * Loaded on demand (`@defer` in `entity-list.component.html`), so its code
 * and `FieldInputComponent`'s lookup picker stay out of the shared entity
 * chunk. The server validates and enforces every filter; this component only
 * composes them (D-429).
 */
@Component({
  selector:    'xrm-advanced-find-panel',
  standalone:  true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:     [ReactiveFormsModule, TranslatePipe, FieldInputComponent],
  templateUrl: './advanced-find-panel.component.html',
  styleUrl:    './advanced-find-panel.component.css',
})
export class AdvancedFindPanelComponent {
  readonly entityName = input.required<string>();
  /** The advanced filters the list currently applies (from the builder or the open view). */
  readonly filters    = input<readonly QueryFilter[]>([]);
  /** The columns the list's query returns (hidden ones included), or `null`
   * for no restriction. `query/execute` can only filter on a column its query
   * returns, so the picker offers only those attributes. */
  readonly columnNames = input<readonly string[] | null>(null);
  /** Whether "Save as view" is offered (the list knows the query to bind it to). */
  readonly canSave    = input(false);

  readonly applied    = output<QueryFilter[]>();
  readonly saveAsView = output<QueryFilter[]>();
  readonly closed     = output<void>();

  private readonly entitySvc = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly loading    = signal(true);
  readonly error      = signal<string | null>(null);
  readonly fields     = signal<FieldSchema[]>([]);
  readonly conditions = signal<AdvancedCondition[]>([]);
  /** Saved filters no builder row reproduces — still applied, shown read-only. */
  readonly kept       = signal<QueryFilter[]>([]);

  readonly maxConditions = MAX_ADVANCED_CONDITIONS;
  readonly canAdd = computed(() =>
    this.fields().length > 0 && this.conditions().length + this.kept().length < MAX_ADVANCED_CONDITIONS);

  /** Lookup rows edit their value through `attome-field-input`'s lookup picker,
   * which binds a control named after its field — one control per row. */
  lookupForm = new FormGroup<Record<string, FormControl<unknown>>>({});
  private lookupSubs = new Map<number, Subscription>();
  private nextKey = 1;
  private schemaSub: Subscription | null = null;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      untracked(() => this.loadSchema(entity));
    });
  }

  private loadSchema(entity: string): void {
    this.schemaSub?.unsubscribe();
    this.loading.set(true);
    this.error.set(null);
    this.schemaSub = this.entitySvc.getSchema(entity).subscribe({
      next: schema => {
        const columns = this.columnNames();
        const fields = advancedFindFields(schema.fields, this.lang.intlLocale())
          .filter(f => !columns?.length || columns.includes(f.name));
        this.fields.set(fields);
        const { conditions, kept } = filtersToConditions(this.filters(), fields, this.nextKey);
        this.nextKey += conditions.length;
        this.kept.set(kept);
        this.setConditions(conditions);
        if (!conditions.length && !kept.length && fields.length) this.addCondition();
        this.loading.set(false);
      },
      error: (err: ApiError) => { this.loading.set(false); this.error.set(err.message); },
    });
  }

  // ── Rows ──────────────────────────────────────────────────────────────────

  field(name: string): FieldSchema | undefined {
    return this.fields().find(f => f.name === name);
  }

  kind(condition: AdvancedCondition): FilterKind | null {
    const field = this.field(condition.field);
    return field ? conditionKind(field) : null;
  }

  operators(condition: AdvancedCondition): readonly string[] {
    const field = this.field(condition.field);
    return field ? conditionOperators(field) : [];
  }

  operatorLabel(op: string): string { return OPERATOR_LABELS[op] ?? op; }

  choices(condition: AdvancedCondition): { value: string; label: string }[] {
    const field = this.field(condition.field);
    return field ? choiceOptions(field) : [];
  }

  needsValue(condition: AdvancedCondition): boolean {
    const op = String(condition.draft.operator ?? '');
    if (['is_null', 'is_not_null', 'today', 'past_7_days', 'past_month', 'past_year'].includes(op)) return false;
    return this.kind(condition) !== 'boolean';
  }

  isRange(condition: AdvancedCondition): boolean { return condition.draft.operator === 'between'; }

  addCondition(): void {
    const first = this.fields()[0];
    if (!first || !this.canAdd()) return;
    this.setConditions([...this.conditions(), newCondition(this.nextKey++, first)]);
  }

  removeCondition(key: number): void {
    this.setConditions(this.conditions().filter(c => c.key !== key));
  }

  removeKept(index: number): void {
    this.kept.update(list => list.filter((_, i) => i !== index));
  }

  setField(key: number, name: string): void {
    const field = this.field(name);
    if (!field) return;
    this.setConditions(this.conditions().map(c => (c.key === key ? newCondition(key, field) : c)));
  }

  setOperator(key: number, operator: string): void {
    this.patch(key, { operator });
  }

  setValue(key: number, value: string): void { this.patch(key, { value }); }
  setValueTo(key: number, valueTo: string): void { this.patch(key, { valueTo }); }
  setBoolean(key: number, value: string): void {
    this.patch(key, { operator: 'eq', value: value === '' ? null : value === 'true' });
  }

  valueOf(condition: AdvancedCondition): string {
    const v = condition.draft.value;
    return v === null || v === undefined ? '' : String(v);
  }

  valueToOf(condition: AdvancedCondition): string {
    const v = condition.draft.valueTo;
    return v === null || v === undefined ? '' : String(v);
  }

  /** The schema `attome-field-input` renders a lookup row with: the field's own
   * lookup options, under a per-row control name. */
  lookupField(condition: AdvancedCondition): FieldSchema | null {
    const field = this.field(condition.field);
    return field ? { ...field, name: this.lookupControlName(condition.key), is_required: false } : null;
  }

  lookupControlName(key: number): string { return `c${key}`; }

  // ── Actions ───────────────────────────────────────────────────────────────

  /** The wire filters of every complete row, plus the kept ones. */
  currentFilters(): QueryFilter[] {
    return [...conditionsToFilters(this.conditions(), this.fields()), ...this.kept()];
  }

  apply(): void { this.applied.emit(this.currentFilters()); }

  clear(): void {
    this.kept.set([]);
    this.setConditions([]);
    this.applied.emit([]);
  }

  save(): void {
    const filters = this.currentFilters();
    if (!filters.length) return;
    this.saveAsView.emit(filters);
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  private patch(key: number, patch: Partial<ColumnFilterDraft>): void {
    this.conditions.update(list =>
      list.map(c => (c.key === key ? { ...c, draft: { ...c.draft, ...patch } } : c)));
  }

  /** Replaces the rows and rebuilds the lookup rows' controls, seeding each
   * from its draft so an opened view shows its saved record. */
  private setConditions(conditions: AdvancedCondition[]): void {
    for (const sub of this.lookupSubs.values()) sub.unsubscribe();
    this.lookupSubs.clear();
    const controls: Record<string, FormControl<unknown>> = {};
    for (const c of conditions) {
      if (this.kind(c) !== 'lookup') continue;
      const control = new FormControl<unknown>(c.draft.value ?? null);
      controls[this.lookupControlName(c.key)] = control;
      this.lookupSubs.set(c.key, control.valueChanges.subscribe(value =>
        this.patch(c.key, { value: value === null || value === undefined ? null : String(value) })));
    }
    this.lookupForm = new FormGroup(controls);
    this.conditions.set(conditions);
  }
}
