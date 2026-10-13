import {
  ChangeDetectionStrategy, Component, DestroyRef, OnChanges, OnDestroy, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router, RouterLink, UrlTree } from '@angular/router';
import { Subject, Subscription, catchError, map, of, switchMap } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { logicalToUrlPath, resolveRouteTemplate } from '@attome/xrm/core/entity';
import { QueryColumnDef, QueryExecResponse } from '@attome/xrm/core/query/data';
import {
  BucketKey, DashboardService, DashboardVariableBusService, KpiMetric, PageWidgetResult, RenderKind,
  StructuredBucket, WidgetDataResponse, WidgetInputs,
} from '@attome/xrm/dashboard/data';
import {
  ChartBucket, ChartCategory, ChartKind, ChartSeries, DashboardChartComponent, SLICE_COLORS,
} from '@attome/xrm/dashboard/chart';
import { DeclarativeWidgetRendererComponent } from '../../widget/declarative-widget-renderer/declarative-widget-renderer.component';
import { WidgetExplainPanelComponent } from '../widget-explain-panel/widget-explain-panel.component';
import { WidgetRecordsDrawerComponent } from '../widget-records-drawer/widget-records-drawer.component';
import { DeclarativeWidgetConfig } from '../../widget/declarative-widget-renderer/declarative-widget.types';

/** A column plus its resolved click-to-navigate route template — same
 * precedence `EntityListComponent` computes from the identical wire shape
 * (`QueryColumnDef`): an explicit `route_template` wins, then a lookup
 * column defaults to its own target record, then (if the query is
 * single-entity) the first column defaults to the row's own record. */
interface ClickableColumn extends QueryColumnDef {
  resolvedRouteTemplate: string;
}

export type { ChartBucket } from '@attome/xrm/dashboard/chart';

const COLORS = SLICE_COLORS;

/** Parses an `emits`/`listens` column (a JSON array of variable names).
 * Absent or malformed degrades to `[]`. */
function parseVariableList(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string' && v.length > 0) : [];
  } catch {
    return [];
  }
}

function parseConfig(raw: unknown): Record<string, unknown> | null {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

const keyIdentity = (key: BucketKey | null | undefined): string => key ? JSON.stringify(key) : '';

/**
 * Renders one dashboard widget from data the **server** computed (Dashboard
 * 10/10 Phase 2.4, D-522). This component never aggregates, buckets, sorts or
 * sums: a chart's buckets, a KPI's values and a table's rows all arrive
 * finished from `POST .../widgets/{id}/data` (or the viewer's page batch), and
 * rendering dispatches on the server's `render_kind`, never on a client-side
 * table of widget types.
 *
 * Two ways to get data:
 * - **Page batch** — the viewer passes `result` (one request per page load).
 * - **Self-fetch** — `result` left `undefined` (the editor canvas): the widget
 *   asks for its own data, with `preview` for the draft.
 *
 * Every request goes through one `switchMap`, so a newer request (a changed
 * parameter, a sibling's cross-filter) cancels an older one and a slow stale
 * response can never overwrite a newer number.
 */
@Component({
  selector:   'attome-dashboard-widget-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DashboardChartComponent, DeclarativeWidgetRendererComponent, RouterLink, TranslatePipe, WidgetRecordsDrawerComponent, WidgetExplainPanelComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './dashboard-widget-view.component.css'],
  templateUrl: './dashboard-widget-view.component.html',
})
export class DashboardWidgetViewComponent implements OnChanges, OnInit, OnDestroy {
  private readonly dashboardApi = inject(DashboardService);
  private readonly router       = inject(Router);
  private readonly lang         = inject(LangService);
  private readonly destroyRef   = inject(DestroyRef);
  /** Provided by the dashboard viewer / page editor; absent elsewhere. */
  private readonly bus          = inject(DashboardVariableBusService, { optional: true });

  readonly widget      = input.required<EntityRecord>();
  readonly dashboardId = input<string | null>(null);
  /** Execute the editor's draft (needs record Update on the dashboard). */
  readonly preview     = input(false);
  /** Page-batch result from the viewer. `undefined` = fetch it myself;
   * `null` = the page request is still in flight. */
  readonly result      = input<PageWidgetResult | null | undefined>(undefined);
  /** Parameter values for a self-fetch (the viewer sends them in the batch). */
  readonly parameters  = input<Record<string, unknown>>({});

  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  readonly data    = signal<WidgetDataResponse | null>(null);

  private readonly requests = new Subject<WidgetInputs>();
  private busSub?: Subscription;
  private registeredWidgetId: string | null = null;
  private lastKey: string | null = null;

  readonly renderKind = computed<RenderKind | null>(() => this.data()?.render_kind ?? null);
  readonly config = computed(() => parseConfig(this.widget().data['config']));
  readonly emittedVariables  = computed(() => parseVariableList(this.widget().data['emits']));
  readonly listenedVariables = computed(() => parseVariableList(this.widget().data['listens']));
  readonly canCrossFilter    = computed(() => this.emittedVariables().length > 0);
  /** Phase 3.1: a structured widget's values open their records. */
  readonly canDrill = computed(() => this.data()?.drillability === 'exact' && !!this.dashboardId());
  /** Whether a value or bucket responds to click and keyboard at all. */
  readonly interactive = computed(() => this.canDrill() || this.canCrossFilter());
  /** Phase 3.2: every data widget can explain itself. */
  readonly canExplain = computed(() => !!this.dashboardId() && !!this.data() && this.data()!.data_class !== 'none');

  /** The bucket whose records drawer is open, if any. */
  readonly drill = signal<{ bucket: BucketKey | null; series: BucketKey | null; label: string } | null>(null);
  readonly explainOpen = signal(false);
  readonly widgetName = computed(() => String(this.widget().data['name'] || this.widget().data['widget_type'] || ''));

  readonly declarativeConfig = computed<DeclarativeWidgetConfig | null>(() =>
    this.widget().data['widget_type'] === 'declarative_widget'
      ? this.config() as unknown as DeclarativeWidgetConfig | null
      : null);

  readonly textContent = computed(() => {
    const content = this.config()?.['content'];
    return typeof content === 'string' ? content : '';
  });

  private readonly structured = computed(() => this.data()?.structured ?? null);
  private readonly query = computed(() => (this.data()?.query ?? null) as QueryExecResponse | null);

  readonly truncated = computed(() => {
    const s = this.structured();
    return !!s && s.truncated && !s.other;
  });

  readonly asOf = computed(() => {
    const value = this.data()?.as_of;
    if (!value) return '';
    return new Date(value).toLocaleString(this.lang.intlLocale(), { dateStyle: 'short', timeStyle: 'short' });
  });

  /** The first measure of every structured bucket (plus Other), in the
   * server's order. A series is shown in the label for single-series marks. */
  readonly buckets = computed<ChartBucket[]>(() => {
    const s = this.structured();
    if (s) {
      const all = s.other ? [...s.buckets, s.other] : s.buckets;
      return all.map(b => ({
        trackKey: keyIdentity(b.key) + '|' + keyIdentity(b.series_key),
        label: b.series_key ? `${this.keyLabel(b)} · ${this.seriesLabel(b)}` : this.keyLabel(b),
        value: b.values[0] ?? 0,
        key: b.key,
        seriesKey: b.series_key ?? null,
      }));
    }
    return this.rowBuckets();
  });

  /** A legacy chart bound to a stored query: the query's own rows, already
   * aggregated by its SQL, mapped label -> value with no arithmetic. */
  private readonly rowBuckets = computed<ChartBucket[]>(() => {
    const q = this.query();
    if (!q) return [];
    const numeric = q.data.columns.find(c => c.name !== 'id' && c.data_type === 'number');
    const label = q.data.columns.find(c => c.name !== 'id' && c.name !== numeric?.name);
    if (!numeric || !label) return [];
    return q.data.records.map((r, i) => ({
      trackKey: `row-${i}`,
      label: String(r[label.name] ?? ''),
      value: Number(r[numeric.name]) || 0,
      key: null,
    }));
  });

  /** Chart categories: the distinct group keys in the server's order, Other last. */
  readonly chartCategories = computed<ChartCategory[]>(() => {
    const s = this.structured();
    if (!s) return this.rowBuckets().map(b => ({ trackKey: b.trackKey, label: b.label }));
    const seen = new Map<string, ChartCategory>();
    for (const b of s.other ? [...s.buckets, s.other] : s.buckets) {
      const id = keyIdentity(b.key);
      if (!seen.has(id)) seen.set(id, { trackKey: id, label: this.keyLabel(b) });
    }
    return [...seen.values()];
  });

  /** Chart series: buckets grouped by series key, aligned to the categories
   * (`null` where a series has no bucket). No series key = one series named
   * after the measure. */
  readonly chartSeries = computed<ChartSeries[]>(() => {
    const s = this.structured();
    if (!s) {
      const points = this.rowBuckets();
      return points.length ? [{ trackKey: 'rows', name: '', color: COLORS[0], points }] : [];
    }
    const categories = this.chartCategories();
    const index = new Map(categories.map((c, i) => [c.trackKey, i]));
    const bySeries = new Map<string, ChartSeries>();
    for (const b of s.other ? [...s.buckets, s.other] : s.buckets) {
      const id = keyIdentity(b.series_key);
      let entry = bySeries.get(id);
      if (!entry) {
        const name = b.series_key ? this.seriesLabel(b) : '';
        entry = { trackKey: id || 'total', name, color: COLORS[bySeries.size % COLORS.length], points: categories.map(() => null) };
        bySeries.set(id, entry);
      }
      const position = index.get(keyIdentity(b.key));
      if (position === undefined) continue;
      entry.points[position] = {
        trackKey: keyIdentity(b.key) + '|' + id,
        label: this.keyLabel(b),
        value: b.values[0] ?? 0,
        key: b.key,
        seriesKey: b.series_key ?? null,
        seriesLabel: entry.name,
      };
    }
    return [...bySeries.values()];
  });

  readonly chartKind = computed<ChartKind | null>(() => {
    switch (this.renderKind()) {
      case 'chart_bar':    return 'bar';
      case 'chart_line':   return 'line';
      case 'chart_area':   return 'area';
      case 'chart_donut':  return 'donut';
      case 'chart_funnel': return 'funnel';
      default:             return null;
    }
  });

  readonly threshold = computed(() => this.structured()?.threshold ?? null);

  /** One number: the first measure of an ungrouped definition, or a one-row,
   * one-column query result. */
  readonly scalar = computed<number | string | null>(() => {
    const s = this.structured();
    if (s) return s.buckets[0]?.values[0] ?? null;
    const q = this.query();
    const cols = q?.data.columns.filter(c => c.name !== 'id') ?? [];
    if (q && q.data.records.length === 1 && cols.length === 1) {
      const value = q.data.records[0][cols[0].name];
      return typeof value === 'number' || typeof value === 'string' ? value : null;
    }
    return null;
  });

  readonly columns = computed<ClickableColumn[]>(() => {
    const q = this.query();
    if (!q) return [];
    const linkedEntityPath = q.metadata.entity_logical_name ? logicalToUrlPath(q.metadata.entity_logical_name) : null;
    return q.data.columns.map((c, index) => {
      const lookupPath = c.lookup_target_entity ? logicalToUrlPath(c.lookup_target_entity) : null;
      const template = c.route_template
        || (lookupPath ? `/${lookupPath}/form?id={{${c.name}}}` : '')
        || (index === 0 && linkedEntityPath ? `/${linkedEntityPath}/form?id={{id}}` : '');
      return { ...c, resolvedRouteTemplate: template };
    });
  });
  readonly rows = computed<Record<string, unknown>[]>(() => this.query()?.data.records ?? []);

  readonly kpiMetrics = computed<KpiMetric[]>(() => this.data()?.kpi?.metrics ?? []);

  constructor() {
    this.requests.pipe(
      switchMap(inputs => {
        const dashboardId = this.dashboardId();
        if (!dashboardId) return of({ ok: false as const, message: this.lang.translate('dashboard.viewer.noDataSource') });
        return this.dashboardApi.widgetData(dashboardId, this.widget().id, inputs).pipe(
          map(data => ({ ok: true as const, data })),
          catchError((e: ApiError) => of({
            ok: false as const,
            message: e.message || this.lang.translate('dashboard.viewer.widgetQueryFailed'),
          })),
        );
      }),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(outcome => {
      this.loading.set(false);
      if (outcome.ok) {
        this.error.set(null);
        this.data.set(outcome.data);
      } else {
        this.error.set(outcome.message);
        this.data.set(null);
      }
    });
  }

  ngOnInit(): void {
    const id = this.widget().id;
    const emits = this.emittedVariables();
    const listens = this.listenedVariables();
    if (!this.bus || (emits.length === 0 && listens.length === 0)) return;
    this.registeredWidgetId = id;
    this.bus.register({ widgetId: id, emits, listens });
    this.busSub = this.bus.changes$().subscribe(notification => {
      if (notification.widgetIds.includes(id)) this.fetch();
    });
  }

  ngOnDestroy(): void {
    if (this.registeredWidgetId) this.bus?.unregister(this.registeredWidgetId);
    this.busSub?.unsubscribe();
  }

  ngOnChanges(): void {
    const result = this.result();
    if (result !== undefined) {
      this.lastKey = null;
      this.applyResult(result);
      return;
    }
    const w = this.widget();
    const key = JSON.stringify([this.dashboardId(), w.id, w.row_version, w.data['config'], this.preview(), this.parameters()]);
    if (key === this.lastKey) return;
    this.lastKey = key;
    this.fetch();
  }

  private applyResult(result: PageWidgetResult | null): void {
    if (result === null) {
      this.loading.set(true);
      return;
    }
    this.loading.set(false);
    this.data.set(result.data ?? null);
    this.error.set(result.error ? result.error.message : null);
  }

  /** Asks the server again with this widget's current inputs — the self-fetch
   * path, and a cross-filter re-query in either mode. */
  private fetch(): void {
    this.loading.set(true);
    this.requests.next({
      parameters: this.parameters(),
      cross_filters: this.crossFilters(),
      preview: this.preview(),
    });
  }

  /** The bus values of the variables this widget listens to, as strings. */
  crossFilters(): Record<string, unknown> {
    const values = this.bus?.values();
    const out: Record<string, unknown> = {};
    if (!values) return out;
    for (const name of this.listenedVariables()) {
      const value = values.get(name);
      if (value !== undefined && value !== null) out[name] = String(value);
    }
    return out;
  }

  /** A click on a value: on an exactly drillable widget it opens the records
   * behind that value (the drawer offers "filter the dashboard by this" when
   * the widget emits a variable); otherwise it sets the widget's first emitted
   * variable to the bucket's stored value (never its display label). */
  onBucketClick(bucket: ChartBucket): void {
    if (this.canDrill() && bucket.key) {
      const label = [bucket.label, bucket.seriesLabel].filter(Boolean).join(' · ');
      this.drill.set({ bucket: bucket.key.kind === 'total' ? null : bucket.key, series: bucket.seriesKey ?? null, label });
      return;
    }
    this.emitBucket(bucket.key);
  }

  /** The scalar value's records (an ungrouped definition). */
  onScalarClick(): void {
    if (this.canDrill()) this.drill.set({ bucket: null, series: null, label: '' });
  }

  /** "Filter the dashboard by this" from the records drawer. */
  crossFilterFromDrill(): void {
    this.emitBucket(this.drill()?.bucket ?? null);
    this.drill.set(null);
  }

  private emitBucket(key: BucketKey | null): void {
    const variable = this.emittedVariables()[0];
    if (!variable || !this.bus || key?.kind !== 'value') return;
    this.bus.emit(variable, key.value, this.widget().id);
  }

  keyLabel(bucket: StructuredBucket): string {
    switch (bucket.key.kind) {
      case 'null':  return this.lang.translate('dashboard.viewer.emptyBucket');
      case 'other': return this.lang.translate('dashboard.viewer.chartOtherBucket');
      case 'total': return '';
      default:      return bucket.label ?? '';
    }
  }

  private seriesLabel(bucket: StructuredBucket): string {
    const key = bucket.series_key;
    if (!key) return '';
    return key.kind === 'value' ? (bucket.series_label ?? key.value) : this.lang.translate('dashboard.viewer.emptyBucket');
  }

  formatValue(value: number | string | null | undefined): string {
    if (value === null || value === undefined) return '—';
    if (typeof value === 'string') return value;
    return value.toLocaleString(this.lang.intlLocale(), { maximumFractionDigits: 2 });
  }

  kpiStatusKey(metric: KpiMetric): string | null {
    switch (metric.status) {
      case 'no_snapshot':        return 'dashboard.viewer.kpiNoSnapshot';
      case 'definition_changed': return 'dashboard.viewer.kpiDefinitionChanged';
      case 'missing':            return 'dashboard.viewer.kpiMissing';
      default:                   return null;
    }
  }

  /** Each trendline's chart input, computed once per response. */
  readonly kpiTrends = computed(() => new Map(this.kpiMetrics().map(m => [m.metric_id, this.kpiTrend(m)])));

  /** A trendline's history as chart input, oldest first. */
  private kpiTrend(metric: KpiMetric): { categories: ChartCategory[]; series: ChartSeries[] } {
    const history = [...metric.history].reverse();
    const categories = history.map(p => ({ trackKey: p.snapshot_id, label: this.periodLabel(p.period_start) }));
    const points = history.map((p, i) => ({ trackKey: p.snapshot_id, label: categories[i].label, value: p.actual ?? 0, key: null }));
    return { categories, series: [{ trackKey: metric.metric_id, name: metric.name || metric.key || '', color: COLORS[0], points }] };
  }

  private periodLabel(date: string): string {
    const parsed = new Date(`${date}T00:00:00Z`);
    return Number.isNaN(parsed.getTime())
      ? date
      : parsed.toLocaleDateString(this.lang.intlLocale(), { dateStyle: 'medium', timeZone: 'UTC' });
  }

  /** A cell's record link as a real anchor target (Phase 4: no `role="link"` spans). */
  cellLink(col: ClickableColumn, row: Record<string, unknown>): UrlTree | null {
    if (!col.resolvedRouteTemplate) return null;
    const path = resolveRouteTemplate(col.resolvedRouteTemplate, row);
    return path ? this.router.parseUrl(path) : null;
  }
}
