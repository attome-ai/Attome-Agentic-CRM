import {
  AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnInit, inject, input, output, signal, viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService, logicalToUrlPath } from '@attome/xrm/core/entity';
import {
  BucketKey, DashboardService, WidgetCompareResponse, WidgetDrillDownResponse, WidgetRecordsResponse,
} from '@attome/xrm/dashboard/data';

type Records = WidgetRecordsResponse['records'];

/** P7-T11: a period as two `YYYY-MM-DD` dates (`from` included, `to` not). */
export interface DatePeriod { from: string; to: string; }

/** P7-T11: a period as the compare route takes it, or `null` when either
 * date is missing or the period is empty. Pure. */
export function periodBody(p: DatePeriod): { from: string; to: string } | null {
  if (!p.from || !p.to || p.from >= p.to) return null;
  return { from: `${p.from}T00:00:00Z`, to: `${p.to}T00:00:00Z` };
}

/** P7-T11: the catalog key for a parity reason. Pure. */
export function parityKey(reason: string): string {
  return `dashboard.records.parity.${reason}`;
}

/**
 * Dashboard 10/10 Phase 3.1 — the records behind one widget value or bucket.
 *
 * Everything shown comes from `POST .../widgets/{id}/records`, which resolves
 * the same definition, parameters, bindings, timezone and record scope the
 * number used, so the drawer's exact `total` equals the value it was opened
 * from on static data. The context echo at the top (filters and their origins,
 * timezone, as-of time) is the server's, not a client reconstruction. "Export
 * these records" sends the drill's exact filters to the entity export
 * (Phase 3.4); the Other bucket has no filter form and offers no export.
 */
@Component({
  selector:   'xrm-widget-records-drawer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  styleUrls:  ['./widget-records-drawer.component.css'],
  templateUrl: './widget-records-drawer.component.html',
  host: { '(document:keydown.escape)': 'closed.emit()' },
})
export class WidgetRecordsDrawerComponent implements OnInit, AfterViewInit {
  private readonly dashboardApi = inject(DashboardService);
  private readonly entities     = inject(EntityService);
  private readonly router       = inject(Router);
  private readonly lang         = inject(LangService);

  readonly dashboardId  = input.required<string>();
  readonly widgetId     = input.required<string>();
  readonly widgetName   = input('');
  readonly bucketLabel  = input('');
  readonly bucketKey    = input<BucketKey | null>(null);
  readonly seriesKey    = input<BucketKey | null>(null);
  readonly parameters   = input<Record<string, unknown>>({});
  readonly crossFilters = input<Record<string, unknown>>({});
  readonly preview      = input(false);
  /** Offer "Filter the dashboard by this" (the widget emits a variable). */
  readonly canCrossFilter = input(false);
  /** P7-T11: the widget has `drill_levels`, so its buckets drill down. */
  readonly canDrillDown = input(false);
  /** P7-T11: the widget is grouped by a date, so two periods compare. */
  readonly canCompare = input(false);

  readonly closed      = output<void>();
  readonly crossFilter = output<void>();

  private readonly panel = viewChild<ElementRef<HTMLElement>>('panel');

  readonly loading  = signal(false);
  readonly error    = signal<string | null>(null);
  readonly response = signal<WidgetRecordsResponse | null>(null);
  readonly rows     = signal<Record<string, unknown>[]>([]);
  readonly exportMessage = signal<string | null>(null);
  readonly rtl = signal(false);
  /** P7-T11: which view the panel shows. */
  readonly tab = signal<'records' | 'compare'>('records');
  /** P7-T11: the buckets clicked so far and the level they opened. */
  readonly drillPath = signal<BucketKey[]>([]);
  readonly level = signal<WidgetDrillDownResponse | null>(null);
  readonly periodA = signal<DatePeriod>({ from: '', to: '' });
  readonly periodB = signal<DatePeriod>({ from: '', to: '' });
  readonly comparison = signal<WidgetCompareResponse | null>(null);

  ngOnInit(): void {
    this.rtl.set(this.lang.isRtl());
    this.load(null);
  }

  /** P7-T11: the parity banner's text, when the listed total and the number
   * differ. */
  parityText(): string | null {
    const parity = this.response()?.parity;
    if (!parity || parity.matches || parity.reason === 'not_comparable') return null;
    return this.lang.translate(parityKey(parity.reason), {
      value: parity.value ?? '', total: parity.listed_total,
    });
  }

  /** P7-T11: the agent session that last changed a listed record. */
  agentRun(row: Record<string, unknown>): string | null {
    // `trails` (P7-T9) is read loosely so the panel does not wait on that
    // field's generated type.
    const res = this.response() as unknown as { trails?: { record_id: string; agent_run_id?: string | null }[] } | null;
    const trail = (res?.trails ?? []).find(t => t.record_id === row['id']);
    return trail?.agent_run_id ?? null;
  }

  /** P7-T11: one level down under the clicked bucket, or (with `key`) under
   * one of the level's own buckets. */
  drillDown(key?: BucketKey): void {
    const first = this.bucketKey();
    const path = key ? [...this.drillPath(), key] : (first ? [first] : []);
    this.openLevel(path);
  }

  /** P7-T11: back to the level a breadcrumb names. */
  crumb(index: number): void {
    if (index <= 0) {
      this.drillPath.set([]);
      this.level.set(null);
      return;
    }
    this.openLevel(this.drillPath().slice(0, index));
  }

  private openLevel(path: BucketKey[]): void {
    this.error.set(null);
    this.dashboardApi.drillDown(this.dashboardId(), this.widgetId(), {
      parameters: this.parameters(),
      cross_filters: this.crossFilters(),
      preview: this.preview(),
      path,
    }).subscribe({
      next: res => { this.drillPath.set(path); this.level.set(res); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** P7-T11: open where the widget sends a click, with its values. */
  followThrough(): void {
    const target = this.response()?.drill_through;
    if (!target) return;
    const params = new URLSearchParams();
    for (const [name, value] of Object.entries(target.parameters ?? {})) {
      params.set(name, value === null || value === undefined ? '' : String(value));
    }
    if (target.target_kind === 'dashboard' && target.target_dashboard_id) {
      params.set('id', target.target_dashboard_id);
      if (target.target_page_id) params.set('page', target.target_page_id);
      void this.router.navigateByUrl(`/xrm/dashboard/view?${params.toString()}`);
    } else if (target.route) {
      const query = params.toString();
      void this.router.navigateByUrl(query ? `${target.route}?${query}` : target.route);
    }
  }

  /** P7-T11: compare the two periods entered. */
  runCompare(): void {
    const a = periodBody(this.periodA());
    const b = periodBody(this.periodB());
    if (!a || !b) {
      this.error.set(this.lang.translate('dashboard.records.compare.invalid'));
      return;
    }
    this.error.set(null);
    this.dashboardApi.compare(this.dashboardId(), this.widgetId(), {
      parameters: this.parameters(),
      cross_filters: this.crossFilters(),
      preview: this.preview(),
      period_a: a,
      period_b: b,
      page_size: 50,
    }).subscribe({
      next: res => this.comparison.set(res),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  setPeriod(which: 'a' | 'b', edge: 'from' | 'to', value: string): void {
    const target = which === 'a' ? this.periodA : this.periodB;
    target.update(p => ({ ...p, [edge]: value }));
  }

  openRecordId(id: string): void {
    this.openRecord({ id });
  }

  ngAfterViewInit(): void {
    this.panel()?.nativeElement.focus();
  }

  loadMore(): void {
    const cursor = this.response()?.records.next_cursor;
    if (cursor) this.load(cursor);
  }

  private load(afterId: string | null): void {
    this.loading.set(true);
    this.error.set(null);
    this.dashboardApi.widgetRecords(this.dashboardId(), this.widgetId(), {
      parameters: this.parameters(),
      cross_filters: this.crossFilters(),
      preview: this.preview(),
      bucket_key: this.bucketKey() ?? undefined,
      series_key: this.seriesKey() ?? undefined,
      after_id: afterId ?? undefined,
      page_size: 50,
    }).subscribe({
      next: res => {
        this.loading.set(false);
        this.response.set(res);
        const page = (res.records.rows ?? []) as Record<string, unknown>[];
        this.rows.update(existing => afterId ? [...existing, ...page] : page);
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.error.set(e.message);
      },
    });
  }

  records(): Records | null {
    return this.response()?.records ?? null;
  }

  asOf(): string {
    const value = this.records()?.as_of;
    return value
      ? new Date(value).toLocaleString(this.lang.intlLocale(), { dateStyle: 'short', timeStyle: 'short' })
      : '';
  }

  filterValue(value: unknown): string {
    if (value === null || value === undefined) return '';
    if (Array.isArray(value)) return value.map(v => String(v)).join(', ');
    return String(value);
  }

  cell(row: Record<string, unknown>, column: string): string {
    const value = row[column];
    return value === null || value === undefined ? '' : String(value);
  }

  openRecord(row: Record<string, unknown>): void {
    const entity = this.records()?.entity_logical_name;
    const id = row['id'];
    if (!entity || typeof id !== 'string') return;
    void this.router.navigateByUrl(`/${logicalToUrlPath(entity)}/form?id=${encodeURIComponent(id)}`);
  }

  exportRecords(format: 'csv' | 'xlsx' | 'json'): void {
    const records = this.records();
    if (!records?.drill_filters) return;
    this.exportMessage.set(null);
    this.entities.exportRecords(records.entity_logical_name, format, [], records.drill_filters).subscribe({
      next: res => this.exportMessage.set(this.lang.translate('dashboard.records.exportQueued', { rows: res.matching_rows })),
      error: (e: ApiError) => this.exportMessage.set(e.message),
    });
  }
}
