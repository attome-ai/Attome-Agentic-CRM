import {
  ChangeDetectionStrategy, Component, ElementRef, computed, effect, inject, input, output, signal, viewChild,
} from '@angular/core';
import { LangService, TranslatePipe } from '@attome/base';
import { BucketKey } from '@attome/xrm/dashboard/data';
import {
  BarRect, PlotArea, ValueAxis, areaAttr, bandCenter, barRects, donutPaths, plotArea, pointsAttr, scale, valueAxis,
} from './chart-geometry';

/** One drawable value. `trackKey` is the bucket's typed key (plus its series),
 * never its display label, so two groups that render the same text never
 * collide in an `@for` (the NG0955 duplicate-key warning). */
export interface ChartBucket {
  trackKey: string;
  label:    string;
  value:    number;
  /** The server's typed key; `null` for a row-mapped legacy query chart. */
  key:      BucketKey | null;
  /** The bucket's series key, when the definition has a series. */
  seriesKey?: BucketKey | null;
  /** The series' display name, for a drill's heading. */
  seriesLabel?: string;
}

/** A category on the x axis (or a slice, or a funnel stage). */
export interface ChartCategory { trackKey: string; label: string }

/** One series: a value (or `null` for no value) per category, in category order. */
export interface ChartSeries {
  trackKey: string;
  name:     string;
  color:    string;
  points:   (ChartBucket | null)[];
}

export type ChartKind = 'bar' | 'line' | 'area' | 'donut' | 'funnel';

interface Hover { bucket: ChartBucket; series: string; x: number; y: number }

export const SLICE_COLORS = ['#8b5cf6', '#22d3ee', '#f59e0b', '#34d399', '#f472b6', '#60a5fa', '#f87171', '#a3e635'];

const DEFAULT_WIDTH = 320;
const DEFAULT_HEIGHT = 180;
const LABEL_CHARS = 14;

/**
 * The dashboard's one chart primitive (Dashboard 10/10 Phase 4.1, R-28):
 * hand-drawn SVG with value axes, gridlines, category labels, tooltips on
 * hover and keyboard focus, and a table alternative behind a toggle.
 *
 * It draws numbers the server computed and nothing else (D-522) — see
 * `chart-geometry.ts` for the placement rules.
 *
 * **Accessibility.** A non-interactive chart is one `role="img"` whose label
 * summarises the data; its marks are hidden from assistive technology. An
 * interactive chart (its values drill or cross-filter) is a `role="group"`
 * whose marks are buttons with their own labels, operable with Enter and
 * Space. Either way the table toggle gives the same values as text, and in
 * an interactive chart the table's values are buttons too.
 *
 * **Size.** The SVG is drawn in pixels at the size of its container
 * (a `ResizeObserver`), so axis text is never stretched; without one it
 * falls back to 320×180.
 */
@Component({
  selector:   'attome-dashboard-chart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  styleUrls:  ['./dashboard-chart.component.css'],
  templateUrl: './dashboard-chart.component.html',
})
export class DashboardChartComponent {
  private readonly lang = inject(LangService);

  readonly kind        = input.required<ChartKind>();
  readonly title       = input('');
  readonly categories  = input.required<ChartCategory[]>();
  readonly series      = input.required<ChartSeries[]>();
  readonly threshold   = input<number | null>(null);
  /** Whether a value responds to click and keyboard (drill or cross-filter). */
  readonly interactive = input(false);

  /** A value was activated by click, Enter or Space. */
  readonly selected = output<ChartBucket>();

  readonly showTable = signal(false);
  readonly hover = signal<Hover | null>(null);
  readonly width  = signal(DEFAULT_WIDTH);
  readonly height = signal(DEFAULT_HEIGHT);

  private readonly surface = viewChild<ElementRef<HTMLElement>>('surface');

  constructor() {
    // Re-attached whenever the surface is recreated (the table toggle removes it).
    effect(onCleanup => {
      const element = this.surface()?.nativeElement;
      if (!element || typeof ResizeObserver === 'undefined') return;
      const observer = new ResizeObserver(entries => {
        const box = entries[0]?.contentRect;
        if (!box || box.width < 40 || box.height < 40) return;
        this.width.set(Math.round(box.width));
        this.height.set(Math.round(box.height));
      });
      observer.observe(element);
      onCleanup(() => observer.disconnect());
    });
  }

  readonly rtl = computed(() => this.lang.isRtl());

  /** Every drawn value, for the summary and the value axis. */
  private readonly allBuckets = computed(() =>
    this.series().flatMap(s => s.points.filter((p): p is ChartBucket => p !== null)));

  readonly empty = computed(() => this.allBuckets().length === 0);

  readonly axis = computed<ValueAxis>(() => {
    const values = this.allBuckets().map(b => b.value);
    const threshold = this.threshold();
    return valueAxis(threshold === null ? values : [...values, threshold]);
  });

  readonly tickLabels = computed(() => this.axis().ticks.map(t => ({ value: t, label: this.compact(t) })));

  readonly area = computed<PlotArea>(() => {
    const widest = Math.max(...this.tickLabels().map(t => t.label.length), 1);
    return plotArea(this.width(), this.height(), widest * 6.5, this.rtl());
  });

  /** The y of each tick and its label's anchor side. */
  readonly ticks = computed(() => {
    const area = this.area();
    const axis = this.axis();
    const rtl = this.rtl();
    return this.tickLabels().map(t => ({
      ...t,
      y: scale(t.value, axis, area.top + area.height, area.top),
      labelX: rtl ? area.left + area.width + 6 : area.left - 6,
    }));
  });

  readonly labelAnchor = computed(() => this.rtl() ? 'start' : 'end');
  readonly gridX2 = computed(() => this.area().left + this.area().width);

  /** Category labels under the plot, thinned to what fits. */
  readonly categoryLabels = computed(() => {
    const categories = this.categories();
    const area = this.area();
    const fit = Math.max(1, Math.floor(area.width / 64));
    const every = Math.max(1, Math.ceil(categories.length / fit));
    return categories
      .map((c, i) => ({
        trackKey: c.trackKey,
        full: c.label,
        text: c.label.length > LABEL_CHARS ? c.label.slice(0, LABEL_CHARS - 1) + '…' : c.label,
        x: bandCenter(i, categories.length, area, this.rtl()),
        index: i,
      }))
      .filter(l => l.index % every === 0);
  });

  readonly labelY = computed(() => this.area().top + this.area().height + 15);

  readonly zeroY = computed(() => scale(0, this.axis(), this.area().top + this.area().height, this.area().top));

  readonly thresholdY = computed(() => {
    const threshold = this.threshold();
    return threshold === null ? null : scale(threshold, this.axis(), this.area().top + this.area().height, this.area().top);
  });

  readonly bars = computed<(BarRect & { bucket: ChartBucket; color: string; seriesName: string })[]>(() => {
    const series = this.series();
    const values = series.map(s => s.points.map(p => p?.value ?? 0));
    return barRects(values, this.axis(), this.area(), this.rtl())
      .map(r => ({ ...r, bucket: series[r.series].points[r.category], color: series[r.series].color, seriesName: series[r.series].name }))
      .filter((r): r is BarRect & { bucket: ChartBucket; color: string; seriesName: string } => r.bucket !== null);
  });

  readonly lines = computed(() => {
    const categories = this.categories().length;
    const axis = this.axis();
    const area = this.area();
    return this.series().map(s => {
      const present = s.points
        .map((bucket, index) => ({ bucket, index }))
        .filter((p): p is { bucket: ChartBucket; index: number } => p.bucket !== null);
      const placed = present.map(p => ({
        x: bandCenter(p.index, categories, area, this.rtl()),
        y: scale(p.bucket.value, axis, area.top + area.height, area.top),
        bucket: p.bucket,
      }));
      return {
        trackKey: s.trackKey,
        name: s.name,
        color: s.color,
        points: pointsAttr(placed),
        area: areaAttr(placed, axis, area),
        marks: placed,
      };
    });
  });

  readonly donutSize = computed(() => Math.max(60, Math.min(this.height(), this.width() / 2) - 8));

  readonly slices = computed(() => {
    const first = this.series()[0];
    if (!first) return [];
    const size = this.donutSize();
    const values = first.points.map(p => p?.value ?? 0);
    const paths = donutPaths(values, size / 2, size / 2, size / 2, size / 2 * 0.6);
    const total = values.reduce((sum, v) => sum + (v > 0 ? v : 0), 0);
    return first.points.map((bucket, i) => ({
      bucket,
      path: paths[i],
      color: SLICE_COLORS[i % SLICE_COLORS.length],
      share: total > 0 && bucket && bucket.value > 0 ? bucket.value / total : 0,
    })).filter((s): s is { bucket: ChartBucket; path: string | null; color: string; share: number } => s.bucket !== null);
  });

  /** Funnel stages: the first series, widths relative to the largest stage. */
  readonly stages = computed(() => {
    const first = this.series()[0];
    if (!first) return [];
    const buckets = first.points.filter((p): p is ChartBucket => p !== null);
    const max = Math.max(1, ...buckets.map(b => Math.abs(b.value)));
    return buckets.map(b => ({ bucket: b, percent: (Math.abs(b.value) / max) * 100 }));
  });

  /** The text alternative's one-line summary (also the image's label). */
  readonly summary = computed(() => {
    const buckets = this.allBuckets();
    if (buckets.length === 0) return this.title();
    const max = buckets.reduce((a, b) => (b.value > a.value ? b : a));
    const min = buckets.reduce((a, b) => (b.value < a.value ? b : a));
    return this.lang.translate('dashboard.chart.summary', {
      title: this.title(),
      count: buckets.length,
      maxLabel: max.label || this.title(),
      maxValue: this.format(max.value),
      minLabel: min.label || this.title(),
      minValue: this.format(min.value),
    });
  });

  /** The table alternative: one row per category, one column per series. */
  readonly tableRows = computed(() => {
    const series = this.series();
    return this.categories().map((c, i) => ({ category: c, cells: series.map(s => ({ trackKey: s.trackKey, bucket: s.points[i] ?? null })) }));
  });

  readonly legend = computed(() => this.series().length > 1 && (this.kind() === 'bar' || this.kind() === 'line' || this.kind() === 'area'));

  toggleTable(): void {
    this.showTable.update(v => !v);
    this.hover.set(null);
  }

  activate(bucket: ChartBucket, event?: Event): void {
    event?.preventDefault();
    if (this.interactive()) this.selected.emit(bucket);
  }

  showHover(bucket: ChartBucket, series: string, x: number, y: number): void {
    this.hover.set({ bucket, series, x, y });
  }

  clearHover(): void {
    this.hover.set(null);
  }

  markLabel(bucket: ChartBucket, seriesName: string): string {
    const name = [bucket.label, seriesName].filter(Boolean).join(' · ');
    return `${name}: ${this.format(bucket.value)}`;
  }

  percent(share: number): string {
    return share.toLocaleString(this.lang.intlLocale(), { style: 'percent', maximumFractionDigits: 1 });
  }

  format(value: number | null | undefined): string {
    if (value === null || value === undefined) return '—';
    return value.toLocaleString(this.lang.intlLocale(), { maximumFractionDigits: 2 });
  }

  private compact(value: number): string {
    return value.toLocaleString(this.lang.intlLocale(), { notation: 'compact', maximumFractionDigits: 1 });
  }
}
