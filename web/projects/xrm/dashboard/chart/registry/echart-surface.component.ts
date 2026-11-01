import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, InjectionToken, afterNextRender, effect, inject, input, output,
  signal, viewChild,
} from '@angular/core';
import { TranslatePipe } from '@attome/base';
import type { ChartBucket } from '../dashboard-chart/dashboard-chart.component';
import type { ChartOption } from './chart-registry';

/** What this component uses of an ECharts instance. */
export interface EChartInstance {
  setOption(option: ChartOption, opts: { notMerge: boolean }): void;
  on(event: 'click', handler: (params: { data?: unknown }) => void): void;
  resize(): void;
  dispose(): void;
}

export type EChartInit = (element: HTMLElement, theme: null, options: { renderer: 'svg' }) => EChartInstance;

/** The library, loaded on first use (a chunk of its own). */
export const ECHART_LOADER = new InjectionToken<() => Promise<EChartInit>>('ECHART_LOADER', {
  factory: () => () => import('@attome/xrm/dashboard/echarts').then(m => m.init as unknown as EChartInit),
});

/**
 * Hosts one ECharts instance. A failed load (an offline chunk) says so; the
 * chart's table does not depend on the library and stays available.
 */
@Component({
  selector: 'attome-echart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (failed()) {
      <p class="xch-echart-status" role="status">{{ 'dashboard.chart.loadFailed' | translate }}</p>
    } @else {
      <div #host class="xch-echart" role="img" [attr.aria-label]="summary()"></div>
    }
  `,
  styles: [`
    :host { display: flex; flex: 1; min-height: 80px; min-width: 0; }
    .xch-echart { flex: 1; min-width: 0; }
    .xch-echart-status { margin: auto; font-size: 13px; opacity: 0.7; }
  `],
})
export class EChartSurfaceComponent {
  private readonly load = inject(ECHART_LOADER);

  readonly option      = input.required<ChartOption>();
  readonly summary     = input('');
  readonly interactive = input(false);

  /** A value was clicked. */
  readonly picked = output<ChartBucket>();

  readonly failed = signal(false);
  private readonly chart = signal<EChartInstance | null>(null);
  private readonly host = viewChild<ElementRef<HTMLElement>>('host');

  constructor() {
    let destroyed = false;
    let observer: ResizeObserver | null = null;

    afterNextRender(() => {
      void this.load().then(init => {
        const element = this.host()?.nativeElement;
        if (destroyed || !element) return;
        const chart = init(element, null, { renderer: 'svg' });
        chart.on('click', params => {
          const bucket = (params.data as { bucket?: ChartBucket } | undefined)?.bucket;
          if (bucket && this.interactive()) this.picked.emit(bucket);
        });
        if (typeof ResizeObserver !== 'undefined') {
          observer = new ResizeObserver(() => chart.resize());
          observer.observe(element);
        }
        this.chart.set(chart);
      }).catch(() => this.failed.set(true));
    });

    effect(() => {
      // `notMerge`: a series dropped from one option must not survive into the next.
      this.chart()?.setOption(this.option(), { notMerge: true });
    });

    inject(DestroyRef).onDestroy(() => {
      destroyed = true;
      observer?.disconnect();
      this.chart()?.dispose();
    });
  }
}
