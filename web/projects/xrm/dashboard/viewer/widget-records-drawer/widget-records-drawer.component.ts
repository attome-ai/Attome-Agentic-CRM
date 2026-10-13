import {
  AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnInit, inject, input, output, signal, viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService, logicalToUrlPath } from '@attome/xrm/core/entity';
import {
  BucketKey, DashboardService, WidgetRecordsResponse,
} from '@attome/xrm/dashboard/data';

type Records = WidgetRecordsResponse['records'];

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

  readonly closed      = output<void>();
  readonly crossFilter = output<void>();

  private readonly panel = viewChild<ElementRef<HTMLElement>>('panel');

  readonly loading  = signal(false);
  readonly error    = signal<string | null>(null);
  readonly response = signal<WidgetRecordsResponse | null>(null);
  readonly rows     = signal<Record<string, unknown>[]>([]);
  readonly exportMessage = signal<string | null>(null);

  ngOnInit(): void {
    this.load(null);
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
