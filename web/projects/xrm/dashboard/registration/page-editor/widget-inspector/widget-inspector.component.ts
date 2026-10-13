import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { ApiComponents, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import type { DateBucket, MeasureFn } from '@attome/xrm/dashboard/data';

/** A pickable field of the structured definition's source entity. */
export interface ChartFieldOption {
  name:    string;
  label:   string;
  is_date: boolean;
  /** Number or currency — the only fields sum/avg/min/max/median accept. */
  is_numeric?: boolean;
}

/** `GET /api/v1/admin/views` item shape. */
export type ViewSummary = ApiComponents['schemas']['ViewDetail'];

export interface ViewGroup {
  entity_name: string;
  views:       ViewSummary[];
}

export interface WidgetFieldChange {
  key:   string;
  value: unknown;
}

type SortOrder = 'value_desc' | 'value_asc' | 'key_asc' | 'key_desc';

/** `attome_core::filter::Filter`'s operator set (filter.rs:60-67) — a
 * static filter clause of a Class A definition. `is_null` takes no value;
 * `in`/`contains_any`/`contains_all` take a comma-separated list the UI
 * splits into a JSON array; everything else takes one scalar string. */
export type StructuredFilterOp =
  | 'eq' | 'gt' | 'gte' | 'lt' | 'lte'
  | 'contains' | 'contains_any' | 'contains_all' | 'in' | 'is_null';

export interface StructuredFilter {
  field: string;
  op:    StructuredFilterOp;
  value?: string | string[];
}

/** `attome_core::data_definition::BindingSource`/`BindingOp`
 * (data_definition.rs:164-186) — `#[serde(rename_all = "snake_case")]`. */
export type BindingSource = 'parameter' | 'variable' | 'builtin';
export type BindingOp = 'eq' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'in' | 'range';

export interface StructuredBinding {
  source: BindingSource;
  name:   string;
  field:  string;
  op:     BindingOp;
}

/** `attome_core::data_definition::BUILTIN_NAMES` (data_definition.rs:48-55) —
 * kept in lockstep by hand; the server is the source of truth and rejects
 * anything else with a 422 the inspector surfaces via `configErrors`. */
export const BUILTIN_NAMES = [
  '@current_user', '@current_date', '@current_user_bu',
  '@current_user_team', '@current_record_id', '@current_entity',
];

/** The client's view of `attome_core::data_definition::DataDefinition` —
 * the structured `config.data` a Class A widget stores (D-528). The server
 * validates it on every save; this panel only builds it. */
export interface StructuredDefinition {
  source: string;
  measures: { aggregation: MeasureFn; field?: string; label?: string }[];
  group?: { field: string; bucket?: DateBucket };
  series?: string;
  filters?: StructuredFilter[];
  bindings?: StructuredBinding[];
  presentation?: {
    sort?: SortOrder;
    limit?: number;
    other_bucket?: boolean;
    cumulative?: boolean;
    percent_of_total?: boolean;
    moving_average_window?: number;
    threshold?: number;
  };
}

/** Widget types rendered from a structured definition (`data_contract:
 * structured` in the registry, D-525). */
const STRUCTURED_WIDGET_TYPES = new Set([
  'bar_chart', 'column_chart', 'line_chart', 'area_chart', 'pie_chart', 'donut_chart', 'funnel_chart', 'metric',
]);
const SERIES_WIDGET_TYPES = new Set(['line_chart', 'area_chart']);

export const MEASURE_FNS: MeasureFn[] = ['count', 'count_distinct', 'sum', 'avg', 'min', 'max', 'median'];
export const DATE_BUCKETS: DateBucket[] = ['day', 'week', 'month', 'quarter', 'year'];
export const SORT_ORDERS: SortOrder[] = ['value_desc', 'value_asc', 'key_asc', 'key_desc'];
const NUMERIC_FNS = new Set<MeasureFn>(['sum', 'avg', 'min', 'max', 'median']);
export const FILTER_OPS: StructuredFilterOp[] =
  ['eq', 'gt', 'gte', 'lt', 'lte', 'contains', 'contains_any', 'contains_all', 'in', 'is_null'];
export const BINDING_SOURCES: BindingSource[] = ['parameter', 'variable', 'builtin'];
export const BINDING_OPS: BindingOp[] = ['eq', 'gt', 'gte', 'lt', 'lte', 'contains', 'in', 'range'];
/** Operators whose `value` is a list rather than one scalar. */
const LIST_FILTER_OPS = new Set<StructuredFilterOp>(['contains_any', 'contains_all', 'in']);

function parseConfig(raw: unknown): Record<string, unknown> {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

/** Drops unset optional parts so the stored definition stays minimal and
 * passes the server's `deny_unknown_fields` validation. */
function clean(definition: StructuredDefinition): StructuredDefinition {
  const out: StructuredDefinition = { source: definition.source, measures: definition.measures };
  if (definition.group?.field) {
    out.group = definition.group.bucket
      ? { field: definition.group.field, bucket: definition.group.bucket }
      : { field: definition.group.field };
  }
  if (definition.series && out.group) out.series = definition.series;
  if (definition.filters?.length) out.filters = definition.filters;
  if (definition.bindings?.length) out.bindings = definition.bindings;
  const p = definition.presentation ?? {};
  const presentation = Object.fromEntries(
    Object.entries(p).filter(([, value]) => value !== undefined && value !== null && value !== false),
  );
  if (Object.keys(presentation).length) out.presentation = presentation;
  return out;
}

/**
 * The selected widget's inspector — name, data source, a `declarative_widget`'s
 * raw config, and duplicate/delete. Signal inputs/outputs only, no service
 * injection (R-11): every edit is reported upward through `fieldChange`, and
 * `PageEditorComponent` applies it to the draft, validates it with the server
 * and saves it. `configErrors` is that validation read back down.
 *
 * **Data (Dashboard 10/10 Phase 2.1).** A chart or metric widget is built from
 * a structured definition — an entity, a measure, an optional group (a field
 * or a time bucket), an optional series — stored in the widget's
 * `config.data` and computed entirely on the server over every live row the
 * viewer may see. The editor never writes a shared view or query for it, so
 * editing a draft never changes a published dashboard (D-543). Table-shaped
 * widgets keep the view picker (Class C: the view's rows are the result).
 */
@Component({
  selector:   'xrm-widget-inspector',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  styleUrls:  ['./widget-inspector.component.css'],
  templateUrl: './widget-inspector.component.html',
})
export class WidgetInspectorComponent {
  readonly widget       = input.required<EntityRecord>();
  readonly viewGroups   = input<ViewGroup[]>([]);
  /** The last server validation of this widget's config; `[]` when valid. */
  readonly configErrors = input<string[]>([]);
  /** Fields of the definition's source entity, fetched by the editor. */
  readonly fieldOptions = input<ChartFieldOption[]>([]);
  /** Names of the dashboard's declared `dashboard_parameter` rows — a
   * `source: 'parameter'` binding's `name` must be one of these (server
   * rejects anything else with a 422). */
  readonly declaredParameters = input<string[]>([]);

  readonly fieldChange     = output<WidgetFieldChange>();
  readonly duplicateWidget = output<void>();
  readonly deleteWidget    = output<void>();
  readonly deselect        = output<void>();

  readonly measureFns     = MEASURE_FNS;
  readonly dateBuckets    = DATE_BUCKETS;
  readonly sortOrders     = SORT_ORDERS;
  readonly filterOps      = FILTER_OPS;
  readonly bindingSources = BINDING_SOURCES;
  readonly bindingOps     = BINDING_OPS;
  readonly builtinNames   = BUILTIN_NAMES;

  private readonly widgetType = computed(() => String(this.widget().data['widget_type'] ?? ''));
  readonly isDeclarativeWidget = computed(() => this.widgetType() === 'declarative_widget');
  readonly isStructuredWidget  = computed(() => STRUCTURED_WIDGET_TYPES.has(this.widgetType()));
  readonly isMetricWidget      = computed(() => this.widgetType() === 'metric');
  readonly allowsSeries        = computed(() => SERIES_WIDGET_TYPES.has(this.widgetType()));

  /** Every entity with at least one view — every provisioned entity has a
   * system view, so this is the deployment's entity list without another
   * request. */
  readonly availableEntities = computed(() => this.viewGroups().map(group => group.entity_name));

  private readonly config = computed(() => parseConfig(this.widget().data['config']));

  readonly definition = computed<StructuredDefinition>(() => {
    const data = this.config()['data'];
    if (data && typeof data === 'object') {
      const d = data as StructuredDefinition;
      return {
        ...d,
        source: d.source ?? '',
        measures: Array.isArray(d.measures) && d.measures.length ? d.measures : [{ aggregation: 'count' }],
      };
    }
    return { source: '', measures: [{ aggregation: 'count' }] };
  });

  readonly measure = computed(() => this.definition().measures[0]);
  readonly measureFieldOptions = computed(() =>
    NUMERIC_FNS.has(this.measure().aggregation)
      ? this.fieldOptions().filter(f => f.is_numeric)
      : this.fieldOptions());
  readonly groupFieldIsDate = computed(() => {
    const field = this.definition().group?.field;
    return !!field && !!this.fieldOptions().find(f => f.name === field)?.is_date;
  });

  readonly filters  = computed(() => this.definition().filters ?? []);
  readonly bindings = computed(() => this.definition().bindings ?? []);

  isListFilterOp(op: StructuredFilterOp): boolean {
    return LIST_FILTER_OPS.has(op);
  }

  filterValueDisplay(filter: StructuredFilter): string {
    return Array.isArray(filter.value) ? filter.value.join(', ') : (filter.value ?? '');
  }

  /** `parameter`/`builtin` bindings pick `name` from a closed list; `variable`
   * is free text (a cross-filter variable name the widget declares it
   * `listens` to — not modeled in this panel yet, same as today). */
  bindingNameOptions(source: BindingSource): string[] {
    return source === 'parameter' ? this.declaredParameters()
         : source === 'builtin'   ? this.builtinNames
         : [];
  }

  onNameBlur(value: string): void {
    this.fieldChange.emit({ key: 'name', value: value || null });
  }

  onViewChange(value: string): void {
    this.fieldChange.emit({ key: 'view_id', value: value || null });
  }

  onConfigBlur(value: string): void {
    this.fieldChange.emit({ key: 'config', value });
  }

  private commit(next: StructuredDefinition): void {
    const config = { ...this.config(), data: clean(next) };
    this.fieldChange.emit({ key: 'config', value: JSON.stringify(config) });
  }

  private patchPresentation(patch: NonNullable<StructuredDefinition['presentation']>): void {
    const d = this.definition();
    this.commit({ ...d, presentation: { ...d.presentation, ...patch } });
  }

  /** A new source entity invalidates every field chosen for the old one. */
  onSourceChange(source: string): void {
    this.commit({ source, measures: [{ aggregation: 'count' }] });
  }

  onMeasureFnChange(aggregation: MeasureFn): void {
    const field = aggregation === 'count' ? undefined : this.measure().field;
    this.commit({ ...this.definition(), measures: [{ ...this.measure(), aggregation, field }] });
  }

  onMeasureFieldChange(field: string): void {
    this.commit({ ...this.definition(), measures: [{ ...this.measure(), field: field || undefined }] });
  }

  onGroupFieldChange(field: string): void {
    const d = this.definition();
    this.commit({ ...d, group: field ? { field } : undefined, series: field ? d.series : undefined });
  }

  onBucketChange(bucket: string): void {
    const d = this.definition();
    if (!d.group) return;
    this.commit({ ...d, group: { field: d.group.field, bucket: (bucket || undefined) as DateBucket | undefined } });
  }

  onSeriesChange(series: string): void {
    const d = this.definition();
    // `limit` and `other_bucket` cannot combine with a series (server rule).
    const presentation = series ? { ...d.presentation, limit: undefined, other_bucket: undefined } : d.presentation;
    this.commit({ ...d, series: series || undefined, presentation });
  }

  onSortChange(sort: string): void {
    this.patchPresentation({ sort: (sort || undefined) as SortOrder | undefined });
  }

  onLimitChange(value: string): void {
    const n = Number(value);
    this.patchPresentation({ limit: value && Number.isInteger(n) ? n : undefined });
  }

  onOtherBucketChange(checked: boolean): void {
    this.patchPresentation({ other_bucket: checked });
  }

  onCumulativeChange(checked: boolean): void {
    this.patchPresentation({ cumulative: checked });
  }

  onPercentOfTotalChange(checked: boolean): void {
    this.patchPresentation({ percent_of_total: checked });
  }

  onMovingAverageChange(value: string): void {
    const n = Number(value);
    this.patchPresentation({ moving_average_window: value && Number.isInteger(n) ? n : undefined });
  }

  onThresholdChange(value: string): void {
    const n = Number(value);
    this.patchPresentation({ threshold: value && !Number.isNaN(n) ? n : undefined });
  }

  // ── Filters (Dashboard 10/10 Phase 5.A) ──────────────────────────────────

  addFilter(): void {
    const field = this.fieldOptions()[0]?.name ?? '';
    this.commit({ ...this.definition(), filters: [...this.filters(), { field, op: 'eq', value: '' }] });
  }

  removeFilter(index: number): void {
    this.commit({ ...this.definition(), filters: this.filters().filter((_, i) => i !== index) });
  }

  onFilterFieldChange(index: number, field: string): void {
    this.patchFilter(index, { field });
  }

  onFilterOpChange(index: number, op: StructuredFilterOp): void {
    // `is_null` carries no value; switching into or out of a list op resets
    // the value rather than leaving a stale scalar/array mismatch.
    const value = op === 'is_null' ? undefined : this.isListFilterOp(op) ? [] : '';
    this.patchFilter(index, { op, value });
  }

  onFilterValueChange(index: number, raw: string): void {
    const filter = this.filters()[index];
    if (!filter) return;
    const value = this.isListFilterOp(filter.op)
      ? raw.split(',').map(v => v.trim()).filter(v => v.length > 0)
      : raw;
    this.patchFilter(index, { value });
  }

  private patchFilter(index: number, patch: Partial<StructuredFilter>): void {
    const filters = this.filters().map((f, i) => (i === index ? { ...f, ...patch } : f));
    this.commit({ ...this.definition(), filters });
  }

  // ── Bindings (Dashboard 10/10 Phase 5.A) ─────────────────────────────────

  addBinding(): void {
    const field = this.fieldOptions()[0]?.name ?? '';
    const source: BindingSource = 'parameter';
    const name = this.bindingNameOptions(source)[0] ?? '';
    this.commit({ ...this.definition(), bindings: [...this.bindings(), { source, name, field, op: 'eq' }] });
  }

  removeBinding(index: number): void {
    this.commit({ ...this.definition(), bindings: this.bindings().filter((_, i) => i !== index) });
  }

  onBindingSourceChange(index: number, source: BindingSource): void {
    // A new source invalidates the previous `name` choice (parameter and
    // builtin names come from disjoint closed lists; variable is free text).
    const name = this.bindingNameOptions(source)[0] ?? '';
    this.patchBinding(index, { source, name });
  }

  onBindingNameChange(index: number, name: string): void {
    this.patchBinding(index, { name });
  }

  onBindingFieldChange(index: number, field: string): void {
    this.patchBinding(index, { field });
  }

  onBindingOpChange(index: number, op: BindingOp): void {
    this.patchBinding(index, { op });
  }

  private patchBinding(index: number, patch: Partial<StructuredBinding>): void {
    const bindings = this.bindings().map((b, i) => (i === index ? { ...b, ...patch } : b));
    this.commit({ ...this.definition(), bindings });
  }
}
