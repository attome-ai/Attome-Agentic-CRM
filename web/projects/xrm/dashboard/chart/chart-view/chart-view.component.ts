import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { Subscription } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { AvailableView, ChartViewMetadata, QueryService } from '@attome/xrm/core/query/data';
import { DashboardChartComponent } from '../dashboard-chart/dashboard-chart.component';
import { buildChartViewData, isChartConfigured } from './chart-view-data';

/** Rows per `query/execute` page — the platform's `MAX_PAGE_SIZE`. */
export const CHART_VIEW_PAGE_SIZE = 200;
/** The most rows a chart view reads before it stops and says so. */
export const CHART_VIEW_MAX_ROWS = 2000;

/**
 * `kind = chart` on the entity list page (Basic Units P1 follow-up): the
 * dashboard's own chart primitive drawn over the view's bound query.
 *
 * The rows come from `POST /api/v1/query/execute` with the view's id — the
 * same privilege- and record-security-gated feed the list, kanban, calendar
 * and timeline kinds use (D-429), so a chart can never count a row its viewer
 * could not list. The grouping the view's `ChartViewMetadata` asks for is
 * done over those rows (`buildChartViewData`); at most `CHART_VIEW_MAX_ROWS`
 * are read, and the chart says when it stopped short.
 *
 * Lives in `@attome/xrm/dashboard/chart` and is loaded by the list page with a
 * dynamic `import()` only when a chart view is selected, so neither the list
 * page nor the shared entity chunk carries the chart code.
 */
@Component({
  selector:   'xrm-chart-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DashboardChartComponent, TranslatePipe],
  templateUrl: './chart-view.component.html',
  styleUrl:    './chart-view.component.css',
})
export class ChartViewComponent {
  /** The selected `kind = chart` view (from `GET /api/v1/views?entity=`). */
  readonly view = input.required<AvailableView>();

  private readonly querySvc = inject(QueryService);
  private readonly lang     = inject(LangService);

  readonly loading   = signal(false);
  readonly error     = signal<string | null>(null);
  readonly rows      = signal<Record<string, unknown>[]>([]);
  /** The query's total, when more rows exist than were read. */
  readonly truncatedTotal = signal<number | null>(null);

  private loadSub: Subscription | null = null;

  readonly metadata = computed(() => (this.view().view_metadata ?? {}) as Partial<ChartViewMetadata>);
  readonly configured = computed(() => isChartConfigured(this.metadata()));

  readonly chart = computed(() => buildChartViewData(this.rows(), this.metadata(), {
    other:  this.lang.translate('entityViews.chart.other'),
    empty:  this.lang.translate('entityViews.chart.emptyValue'),
    arabic: this.lang.isRtl(),
  }));

  constructor() {
    effect(onCleanup => {
      const view = this.view();
      const configured = this.configured();
      untracked(() => {
        this.rows.set([]);
        this.truncatedTotal.set(null);
        this.error.set(null);
        if (configured) this.load(view.id, 1, []);
      });
      onCleanup(() => this.loadSub?.unsubscribe());
    });
  }

  private load(viewId: string, page: number, acc: Record<string, unknown>[]): void {
    this.loading.set(true);
    this.loadSub = this.querySvc.execute({
      view_id: viewId, page, page_size: CHART_VIEW_PAGE_SIZE, include_total: true,
    }).subscribe({
      next: res => {
        const rows = [...acc, ...res.data.records];
        const total = res.data.total ?? rows.length;
        const more = res.data.records.length === CHART_VIEW_PAGE_SIZE && rows.length < total;
        if (more && rows.length < CHART_VIEW_MAX_ROWS) {
          this.load(viewId, page + 1, rows);
          return;
        }
        this.rows.set(rows);
        this.truncatedTotal.set(more ? total : null);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }
}
