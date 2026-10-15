import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

/** `system_health::MetricPoint`. */
export interface MetricPoint {
  at: string;
  value: number;
}

/** `metrics_catalogue::MetricInfo` (U4-T2). */
export interface MetricInfo {
  name: string;
  kind: string;
  unit: string;
  en: string;
  ar: string;
}

/** A time range and the seconds per point it is drawn at. */
export const RANGES = [
  { key: 'hour', hours: 1, step: 60 },
  { key: 'day', hours: 24, step: 600 },
  { key: 'week', hours: 24 * 7, step: 3600 },
  { key: 'month', hours: 24 * 30, step: 6 * 3600 },
] as const;
export type RangeKey = typeof RANGES[number]['key'];

const WIDTH = 640;
const HEIGHT = 200;

/**
 * Metrics (roadmap U4-T4): any sampled metric from the built-in metrics
 * store (U4-T1) over the last hour, day, week or month, drawn as a line.
 * Logical CSS only; the chart is plain SVG.
 */
@Component({
  selector: 'xrm-ops-metrics',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="om">
      <header class="om-head">
        <h2>{{ 'metricsPage.title' | translate }}</h2>
        <label>
          <span>{{ 'metricsPage.metric' | translate }}</span>
          <select #metric dir="ltr" (change)="choose(metric.value)">
            <option value="">{{ 'metricsPage.choose' | translate }}</option>
            @for (n of names(); track n) {
              <option [value]="n" [selected]="n === name()">{{ n }}</option>
            }
          </select>
        </label>
        <span class="om-ranges" role="group">
          @for (r of ranges; track r.key) {
            <button type="button" class="btn btn-text" [class.om-on]="r.key === range()" (click)="setRange(r.key)">
              {{ 'metricsPage.range.' + r.key | translate }}
            </button>
          }
        </span>
      </header>
      @if (meaning(); as m) { <p class="om-muted" data-meaning>{{ m }}</p> }
      @if (error(); as message) { <p class="om-error" role="alert">{{ message }}</p> }
      @if (names().length === 0 && !error()) {
        <p class="om-muted">{{ 'metricsPage.empty' | translate }}</p>
      }
      @if (points().length > 0) {
        <svg class="om-chart" [attr.viewBox]="'0 0 ' + width + ' ' + height" role="img"
             [attr.aria-label]="name() + ': ' + summary()" data-chart>
          <polyline [attr.points]="line()" fill="none" stroke="var(--color-primary)" stroke-width="2" />
        </svg>
        <p class="om-muted" dir="ltr" data-summary>{{ summary() }}</p>
      } @else if (name()) {
        <p class="om-muted">{{ 'metricsPage.noPoints' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .om { display: flex; flex-direction: column; gap: 0.75rem; }
    .om-head { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
    .om-head h2 { margin-block: 0; font-size: 1.25rem; margin-inline-end: auto; }
    .om-head label { display: flex; align-items: center; gap: 0.5rem; }
    .om-ranges { display: flex; gap: 0.25rem; }
    .om-on { font-weight: 600; text-decoration: underline; }
    .om-chart { inline-size: 100%; max-inline-size: 960px; block-size: auto; border: 1px solid var(--color-border); }
    .om-muted { color: var(--color-text-secondary); font-size: 0.875rem; }
    .om-error { color: var(--color-danger); }
  `],
})
export class OpsMetricsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly catalogue = signal<MetricInfo[]>([]);

  readonly ranges = RANGES;
  readonly width = WIDTH;
  readonly height = HEIGHT;
  readonly names = signal<string[]>([]);
  readonly name = signal('');
  readonly range = signal<RangeKey>('hour');
  readonly points = signal<MetricPoint[]>([]);
  readonly error = signal<string | null>(null);

  /** U4-T2: what the chosen metric means, with its unit, in the interface language. */
  readonly meaning = computed(() => {
    const info = this.catalogue().find(m => m.name === this.name());
    if (!info) return '';
    const text = this.lang.current() === 'ar' ? info.ar : info.en;
    return `${text} (${info.unit})`;
  });

  /** The SVG polyline: time across, value up, scaled to the box. */
  readonly line = computed(() => polyline(this.points(), WIDTH, HEIGHT));
  readonly summary = computed(() => {
    const values = this.points().map(p => p.value);
    if (!values.length) return '';
    const fmt = (v: number) => Number.isInteger(v) ? String(v) : v.toFixed(2);
    return `min ${fmt(Math.min(...values))} · max ${fmt(Math.max(...values))} · last ${fmt(values[values.length - 1])}`;
  });

  ngOnInit(): void {
    this.api.get<{ items: MetricInfo[] }>('/api/v1/admin/ops/metrics/catalogue').subscribe({
      next: page => this.catalogue.set(page.items),
      error: () => this.catalogue.set([]),
    });
    this.api.get<{ items: string[] }>('/api/v1/admin/ops/metrics/names').subscribe({
      next: page => this.names.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  choose(name: string): void {
    this.name.set(name);
    this.load();
  }

  setRange(range: RangeKey): void {
    this.range.set(range);
    this.load();
  }

  private load(): void {
    const name = this.name();
    if (!name) { this.points.set([]); return; }
    const r = RANGES.find(x => x.key === this.range()) ?? RANGES[0];
    const to = new Date();
    const from = new Date(to.getTime() - r.hours * 3_600_000);
    this.api.get<{ items: MetricPoint[] }>('/api/v1/admin/ops/metrics/query', {
      name, from: from.toISOString(), to: to.toISOString(), step: String(r.step),
    }).subscribe({
      next: page => { this.error.set(null); this.points.set(page.items); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}

/** Points scaled into a `width` x `height` box (y grows upwards). */
export function polyline(points: readonly MetricPoint[], width: number, height: number): string {
  if (points.length === 0) return '';
  const times = points.map(p => Date.parse(p.at));
  const values = points.map(p => p.value);
  const [t0, t1] = [Math.min(...times), Math.max(...times)];
  const [v0, v1] = [Math.min(...values), Math.max(...values)];
  const x = (t: number) => t1 === t0 ? width / 2 : ((t - t0) / (t1 - t0)) * width;
  const y = (v: number) => v1 === v0 ? height / 2 : height - ((v - v0) / (v1 - v0)) * height;
  return points.map((p, i) => `${x(times[i]).toFixed(1)},${y(p.value).toFixed(1)}`).join(' ');
}
