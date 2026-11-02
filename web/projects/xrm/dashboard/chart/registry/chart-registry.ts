import { ChartBucket, ChartCategory, ChartSeries, SLICE_COLORS } from '../dashboard-chart/dashboard-chart.component';

/**
 * One adapter per chart type drawn by ECharts (P6). An adapter turns the
 * primitive's categories and series into an ECharts option and nothing else:
 * no library import, so this file costs nothing on a page without such a
 * chart, and a spec can read an option without a browser.
 *
 * Every drawn value carries its `ChartBucket` as `bucket` on the data item, so
 * a click drills the same way a bar in the SVG primitive does. The numbers are
 * the server's (D-522). The share, running total and control limits an adapter
 * adds are arithmetic over those numbers, as the donut's percentages are.
 *
 * Tooltips are HTML: anything an adapter shows goes through `tip`, which
 * escapes it. Record names reach these charts as labels.
 */
export type EChartKind =
  | 'stacked_bar' | 'combo' | 'waterfall' | 'treemap' | 'sunburst' | 'sankey' | 'radar' | 'polar'
  | 'heatmap' | 'calendar_heatmap' | 'pareto' | 'control' | 'scatter' | 'bubble' | 'range_area' | 'box_plot' | 'candlestick'
  | 'correlation';

export type ChartOption = Record<string, unknown>;

export interface ChartLabels {
  cumulativeShare: string;
  mean: string;
  upperLimit: string;
  lowerLimit: string;
}

export interface ChartInput {
  categories: ChartCategory[];
  series: ChartSeries[];
  threshold: number | null;
  rtl: boolean;
  /** The chart's text colour. */
  textColor: string;
  locale: string;
  labels: ChartLabels;
  format: (value: number) => string;
  compact: (value: number) => string;
}

export interface ChartAdapter {
  /** The fewest series the chart can draw: a scatter needs an x and a y. */
  minSeries: number;
  /** Whether the series are named in a legend under the chart. */
  legend: boolean;
  option: (input: ChartInput) => ChartOption;
}

interface RenderApi {
  value: (dimension: number) => number;
  coord: (point: number[]) => number[];
  size: (span: number[]) => number[];
  visual: (name: 'color') => string;
}

const GRID_LINE = 'rgba(128, 128, 128, 0.25)';
const HEAT_LOW = 'rgba(139, 92, 246, 0.12)';
const HEAT_HIGH = '#8b5cf6';
const POSITIVE = '#34d399';
const NEGATIVE = '#f87171';
/** No correlation: the diverging scale's neutral middle. */
const NEUTRAL = 'rgba(128, 128, 128, 0.15)';
const BUBBLE_MIN = 6;
const BUBBLE_MAX = 40;

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
}

/** A tooltip's text, one escaped line per entry. */
export function tip(...lines: string[]): string {
  return lines.filter(Boolean).map(escapeHtml).join('<br/>');
}

function pointTip(input: ChartInput, bucket: ChartBucket, seriesName: string): string {
  return tip([bucket.label, seriesName].filter(Boolean).join(' · '), input.format(bucket.value));
}

/** Tooltips read each item's own `tip`. */
function base(input: ChartInput, rest: ChartOption): ChartOption {
  return {
    textStyle: { color: input.textColor, fontFamily: 'inherit' },
    tooltip: {
      trigger: 'item',
      confine: true,
      extraCssText: input.rtl ? 'direction: rtl;' : '',
      formatter: (item: { data?: { tip?: string } }) => item.data?.tip ?? '',
    },
    ...rest,
  };
}

function point(input: ChartInput, bucket: ChartBucket | null, seriesName: string): ChartOption | null {
  return bucket ? { value: bucket.value, bucket, tip: pointTip(input, bucket, seriesName) } : null;
}

function categoryAxis(input: ChartInput): ChartOption {
  return {
    type: 'category',
    data: input.categories.map(c => c.label),
    inverse: input.rtl,
    axisLabel: { hideOverlap: true, color: input.textColor },
  };
}

function valueAxis(input: ChartInput, side: 'start' | 'end' = 'start'): ChartOption {
  return {
    type: 'value',
    position: (side === 'start') !== input.rtl ? 'left' : 'right',
    axisLabel: { color: input.textColor, formatter: (v: number) => input.compact(v) },
    splitLine: { lineStyle: { color: GRID_LINE } },
  };
}

function plot(): ChartOption {
  return { top: 12, bottom: 24, left: 8, right: 8, containLabel: true };
}

function thresholdLine(input: ChartInput): ChartOption {
  return input.threshold === null ? {} : {
    markLine: {
      silent: true, symbol: 'none', label: { show: false }, lineStyle: { color: NEGATIVE, type: 'dashed' },
      data: [{ yAxis: input.threshold }],
    },
  };
}

function cartesian(input: ChartInput, series: ChartOption[]): ChartOption {
  return base(input, { grid: plot(), xAxis: categoryAxis(input), yAxis: valueAxis(input), series });
}

function stackedBar(input: ChartInput): ChartOption {
  return cartesian(input, input.series.map((s, i) => ({
    type: 'bar',
    name: s.name,
    stack: 'total',
    itemStyle: { color: s.color },
    data: s.points.map(p => point(input, p, s.name)),
    ...(i === 0 ? thresholdLine(input) : {}),
  })));
}

/** The first series as bars, every other as a line over them. */
function combo(input: ChartInput): ChartOption {
  return cartesian(input, input.series.map((s, i) => ({
    type: i === 0 ? 'bar' : 'line',
    name: s.name,
    itemStyle: { color: s.color },
    lineStyle: { color: s.color },
    data: s.points.map(p => point(input, p, s.name)),
    ...(i === 0 ? thresholdLine(input) : {}),
  })));
}

export interface WaterfallStep { index: number; from: number; to: number; bucket: ChartBucket | null }

/** Each step starts where the last one ended. */
export function waterfallSteps(series: ChartSeries): WaterfallStep[] {
  let running = 0;
  return series.points.map((bucket, index) => {
    const from = running;
    running += bucket?.value ?? 0;
    return { index, from, to: running, bucket };
  });
}

/** A rectangle from one value to another, which unlike a stacked bar can cross zero. */
function waterfallRect(_: unknown, api: RenderApi): ChartOption {
  const [x, top] = api.coord([api.value(0), api.value(2)]);
  const [, bottom] = api.coord([api.value(0), api.value(1)]);
  const width = api.size([1, 0])[0] * 0.6;
  return {
    type: 'rect',
    shape: { x: x - width / 2, y: Math.min(top, bottom), width, height: Math.abs(bottom - top) },
    style: { fill: api.visual('color') },
  };
}

function waterfall(input: ChartInput): ChartOption {
  const first = input.series[0];
  return cartesian(input, [{
    type: 'custom',
    renderItem: waterfallRect,
    encode: { x: 0, y: [1, 2] },
    data: waterfallSteps(first).map(step => ({
      value: [step.index, step.from, step.to],
      bucket: step.bucket,
      tip: step.bucket ? pointTip(input, step.bucket, first.name) : '',
      itemStyle: { color: step.to < step.from ? NEGATIVE : POSITIVE },
    })),
  }]);
}

/** Categories, each split into its series when there is more than one. A
 * treemap and a sunburst have no way to draw a value at or below zero. */
function tree(input: ChartInput): ChartOption[] {
  const leaf = (s: ChartSeries, i: number, name: string, color: string): ChartOption[] => {
    const bucket = s.points[i];
    if (!bucket || bucket.value <= 0) return [];
    return [{ name, value: bucket.value, bucket, tip: pointTip(input, bucket, s.name), itemStyle: { color } }];
  };
  if (input.series.length === 1) {
    // One series has one colour, which would make every part look alike.
    return input.categories.flatMap((c, i) => leaf(input.series[0], i, c.label, SLICE_COLORS[i % SLICE_COLORS.length]));
  }
  return input.categories.flatMap((c, i) => {
    const children = input.series.flatMap(s => leaf(s, i, s.name, s.color));
    return children.length ? [{ name: c.label, tip: tip(c.label), children }] : [];
  });
}

function treemap(input: ChartInput): ChartOption {
  return base(input, {
    series: [{
      type: 'treemap', roam: false, nodeClick: false, breadcrumb: { show: false },
      top: 0, bottom: 0, left: 0, right: 0, data: tree(input),
    }],
  });
}

function sunburst(input: ChartInput): ChartOption {
  return base(input, {
    series: [{
      type: 'sunburst', nodeClick: false, radius: ['12%', '92%'],
      label: { color: input.textColor, minAngle: 12 }, data: tree(input),
    }],
  });
}

/**
 * Categories flow into series. Nodes get an id of their own because a category
 * and a series may share a name, which ECharts refuses as a loop. It has no
 * mirrored layout, so right to left swaps each link's ends.
 */
function sankey(input: ChartInput): ChartOption {
  const from = (c: ChartCategory) => `c:${c.trackKey}`;
  const to = (s: ChartSeries) => `s:${s.trackKey}`;
  const links = input.series.flatMap(s => input.categories.flatMap((c, i) => {
    const bucket = s.points[i];
    if (!bucket || bucket.value <= 0) return [];
    return [{
      source: input.rtl ? to(s) : from(c),
      target: input.rtl ? from(c) : to(s),
      value: bucket.value,
      bucket,
      tip: pointTip(input, bucket, s.name),
    }];
  }));
  const used = new Set(links.flatMap(l => [l.source, l.target]));
  const node = (name: string, label: string) => ({ name, label: { formatter: () => label }, tip: tip(label) });
  const nodes = [
    ...input.categories.map(c => node(from(c), c.label)),
    ...input.series.map(s => node(to(s), s.name)),
  ].filter(n => used.has(n.name));
  return base(input, {
    series: [{
      type: 'sankey', top: 8, bottom: 8, left: 8, right: 8, data: nodes, links,
      label: { color: input.textColor, position: input.rtl ? 'left' : 'right' },
    }],
  });
}

/** ECharts reports only the whole polygon on a click, so a radar does not
 * drill from the mark; its table's values do. */
function radar(input: ChartInput): ChartOption {
  const max = Math.max(1, ...input.series.flatMap(s => s.points.map(p => p?.value ?? 0)));
  return base(input, {
    radar: {
      radius: '70%',
      indicator: input.categories.map(c => ({ name: c.label, max })),
      axisName: { color: input.textColor },
      splitLine: { lineStyle: { color: GRID_LINE } },
    },
    series: [{
      type: 'radar',
      data: input.series.map(s => ({
        name: s.name,
        value: s.points.map(p => p?.value ?? 0),
        itemStyle: { color: s.color },
        lineStyle: { color: s.color },
        areaStyle: { color: s.color, opacity: 0.15 },
        tip: tip(s.name, ...s.points.flatMap(p => p ? [`${p.label}: ${input.format(p.value)}`] : [])),
      })),
    }],
  });
}

function polar(input: ChartInput): ChartOption {
  return base(input, {
    polar: { radius: ['8%', '85%'] },
    angleAxis: {
      type: 'category', clockwise: !input.rtl, data: input.categories.map(c => c.label),
      axisLabel: { hideOverlap: true, color: input.textColor },
    },
    radiusAxis: { type: 'value', axisLabel: { show: false }, splitLine: { lineStyle: { color: GRID_LINE } } },
    series: input.series.map(s => ({
      type: 'bar', name: s.name, coordinateSystem: 'polar', stack: 'total',
      itemStyle: { color: s.color }, data: s.points.map(p => point(input, p, s.name)),
    })),
  });
}

function heatScale(input: ChartInput): ChartOption {
  const all = input.series.flatMap(s => s.points.flatMap(p => p ? [p.value] : []));
  return { show: false, min: Math.min(0, ...all), max: Math.max(1, ...all), inRange: { color: [HEAT_LOW, HEAT_HIGH] } };
}

/** One row per series, one column per category. */
function heatmap(input: ChartInput): ChartOption {
  return base(input, {
    grid: plot(),
    xAxis: categoryAxis(input),
    yAxis: {
      type: 'category', position: input.rtl ? 'right' : 'left',
      data: input.series.map(s => s.name), axisLabel: { color: input.textColor },
    },
    visualMap: heatScale(input),
    series: [{
      type: 'heatmap',
      data: input.series.flatMap((s, y) => s.points.flatMap((bucket, x) => bucket
        ? [{ value: [x, y, bucket.value], bucket, tip: pointTip(input, bucket, s.name) }] : [])),
    }],
  });
}

const DAY_RE = /^\d{4}-\d{2}-\d{2}/;

/** The dated values of the first series, oldest first; a category that is no
 * date has no cell. */
export function calendarDays(input: ChartInput): { day: string; bucket: ChartBucket }[] {
  return input.categories
    .flatMap((c, i) => {
      const bucket = input.series[0].points[i];
      const date = c.date ?? c.label;
      return bucket && DAY_RE.test(date) ? [{ day: date.slice(0, 10), bucket }] : [];
    })
    .sort((a, b) => a.day.localeCompare(b.day));
}

function monthNames(locale: string): string[] {
  const format = new Intl.DateTimeFormat(locale, { month: 'short', timeZone: 'UTC' });
  return Array.from({ length: 12 }, (_, m) => format.format(Date.UTC(2024, m, 15)));
}

function dayNames(locale: string): string[] {
  const format = new Intl.DateTimeFormat(locale, { weekday: 'narrow', timeZone: 'UTC' });
  // 7 January 2024 was a Sunday, the first name ECharts asks for.
  return Array.from({ length: 7 }, (_, d) => format.format(Date.UTC(2024, 0, 7 + d)));
}

/** ECharts has no mirrored calendar: weeks run left to right in both directions. */
function calendarHeatmap(input: ChartInput): ChartOption {
  const days = calendarDays(input);
  return base(input, {
    visualMap: heatScale(input),
    calendar: {
      top: 24, bottom: 8, left: 32, right: 8,
      range: days.length ? [days[0].day, days[days.length - 1].day] : undefined,
      cellSize: ['auto', 'auto'],
      itemStyle: { color: 'transparent', borderColor: GRID_LINE },
      splitLine: { show: false },
      yearLabel: { show: false },
      monthLabel: { color: input.textColor, nameMap: monthNames(input.locale) },
      dayLabel: { color: input.textColor, nameMap: dayNames(input.locale) },
    },
    series: [{
      type: 'heatmap',
      coordinateSystem: 'calendar',
      data: days.map(({ day, bucket }) => ({
        value: [day, bucket.value], bucket, tip: pointTip(input, bucket, input.series[0].name),
      })),
    }],
  });
}

/** Largest first, with the running share of the total. Only positive values
 * have a share. */
export function paretoRows(series: ChartSeries): { bucket: ChartBucket; share: number }[] {
  const sorted = series.points
    .filter((p): p is ChartBucket => p !== null && p.value > 0)
    .sort((a, b) => b.value - a.value);
  const total = sorted.reduce((sum, b) => sum + b.value, 0);
  let running = 0;
  return sorted.map(bucket => {
    running += bucket.value;
    return { bucket, share: (running / total) * 100 };
  });
}

function pareto(input: ChartInput): ChartOption {
  const first = input.series[0];
  const rows = paretoRows(first);
  const name = input.labels.cumulativeShare;
  return base(input, {
    grid: plot(),
    xAxis: { ...categoryAxis(input), data: rows.map(r => r.bucket.label) },
    yAxis: [
      valueAxis(input),
      {
        ...valueAxis(input, 'end'), min: 0, max: 100, splitLine: { show: false },
        axisLabel: { color: input.textColor, formatter: '{value}%' },
      },
    ],
    series: [
      {
        type: 'bar', name: first.name, itemStyle: { color: first.color },
        data: rows.map(r => point(input, r.bucket, first.name)),
        ...thresholdLine(input),
      },
      {
        type: 'line', name, yAxisIndex: 1, itemStyle: { color: POSITIVE }, lineStyle: { color: POSITIVE },
        data: rows.map(r => ({ value: r.share, tip: tip(name, `${input.format(r.share)}%`) })),
      },
    ],
  });
}

/** The mean and the three-sigma limits of the values shown. */
export function controlLimits(numbers: number[]): { mean: number; upper: number; lower: number } {
  const count = numbers.length || 1;
  const mean = numbers.reduce((sum, v) => sum + v, 0) / count;
  const variance = numbers.reduce((sum, v) => sum + (v - mean) ** 2, 0) / count;
  const spread = 3 * Math.sqrt(variance);
  return { mean, upper: mean + spread, lower: mean - spread };
}

function control(input: ChartInput): ChartOption {
  const first = input.series[0];
  const numbers = first.points.flatMap(p => p ? [p.value] : []);
  const limits = controlLimits(numbers);
  const line = (name: string, yAxis: number, type: string) => ({
    name,
    yAxis,
    lineStyle: { type, color: type === 'solid' ? input.textColor : NEGATIVE },
    label: { formatter: () => `${name} ${input.compact(yAxis)}` },
  });
  const chart = cartesian(input, [{
    type: 'line', name: first.name, itemStyle: { color: first.color }, lineStyle: { color: first.color },
    data: first.points.map(p => point(input, p, first.name)),
    markLine: {
      silent: true,
      symbol: 'none',
      label: { color: input.textColor, position: 'insideEndTop' },
      data: [
        line(input.labels.mean, limits.mean, 'solid'),
        line(input.labels.upperLimit, limits.upper, 'dashed'),
        line(input.labels.lowerLimit, limits.lower, 'dashed'),
      ],
    },
  }]);
  // An axis scales to the series alone, which would leave the limits off the chart.
  const span = limits.upper - limits.lower || 1;
  const margin = span * 0.05;
  return {
    ...chart,
    yAxis: {
      ...valueAxis(input),
      min: Math.floor(Math.min(limits.lower, ...numbers) - margin),
      max: Math.ceil(Math.max(limits.upper, ...numbers) + margin),
    },
  };
}

/** The categories where each of the first `count` series has a value. */
function aligned(input: ChartInput, count: number): { category: ChartCategory; buckets: ChartBucket[] }[] {
  return input.categories.flatMap((category, i) => {
    const buckets = input.series.slice(0, count).flatMap(s => s.points[i] ? [s.points[i]] : []);
    return buckets.length === count ? [{ category, buckets }] : [];
  });
}

function measureAxis(input: ChartInput, name: string): ChartOption {
  return {
    ...valueAxis(input), name, nameLocation: 'middle', nameTextStyle: { color: input.textColor }, scale: true,
  };
}

function scatterOption(input: ChartInput, count: number, size?: (buckets: ChartBucket[]) => number): ChartOption {
  const names = input.series.map(s => s.name);
  return base(input, {
    grid: { ...plot(), bottom: 36, left: 52, right: 52 },
    xAxis: { ...measureAxis(input, names[0]), inverse: input.rtl, position: 'bottom', nameGap: 24 },
    yAxis: { ...measureAxis(input, names[1]), nameGap: 40 },
    series: [{
      type: 'scatter',
      clip: false,
      itemStyle: { color: input.series[0].color },
      data: aligned(input, count).map(({ category, buckets }) => ({
        value: [buckets[0].value, buckets[1].value],
        bucket: buckets[0],
        symbolSize: size?.(buckets),
        tip: tip(category.label, ...buckets.map((b, i) => `${names[i]}: ${input.format(b.value)}`)),
      })),
    }],
  });
}

function scatter(input: ChartInput): ChartOption {
  return scatterOption(input, 2);
}

/** The area of a bubble, not its radius, follows the third value. */
function bubble(input: ChartInput): ChartOption {
  const largest = Math.max(1, ...aligned(input, 3).map(a => Math.abs(a.buckets[2].value)));
  return scatterOption(input, 3, buckets =>
    Math.max(BUBBLE_MIN, Math.sqrt(Math.abs(buckets[2].value) / largest) * BUBBLE_MAX));
}

export interface BandPoint { index: number; low: number; high: number }

/** The categories where both of the first two series have a value. */
export function rangeBand(input: ChartInput): BandPoint[] {
  const [low, high] = input.series;
  return input.categories.flatMap((_, index) => {
    const l = low.points[index];
    const h = high.points[index];
    return l && h ? [{ index, low: l.value, high: h.value }] : [];
  });
}

/** A band between the first two series, one slice between each neighbouring
 * pair of categories. A stacked area could not cross zero. */
function rangeArea(input: ChartInput): ChartOption {
  const band = rangeBand(input);
  const [low, high] = input.series;
  const slice = (params: { dataIndex: number }, api: RenderApi): ChartOption => {
    const here = band[params.dataIndex];
    const next = band[params.dataIndex + 1];
    if (!next) return { type: 'group', children: [] };
    return {
      type: 'polygon',
      shape: {
        points: [
          api.coord([here.index, here.low]), api.coord([here.index, here.high]),
          api.coord([next.index, next.high]), api.coord([next.index, next.low]),
        ],
      },
      style: { fill: high.color, opacity: 0.18 },
    };
  };
  const edge = (s: ChartSeries): ChartOption => ({
    type: 'line', name: s.name, itemStyle: { color: s.color }, lineStyle: { color: s.color },
    data: s.points.map(p => point(input, p, s.name)),
  });
  return cartesian(input, [
    { type: 'custom', silent: true, renderItem: slice, data: band.map(b => [b.index, b.low, b.high]) },
    edge(low),
    edge(high),
  ]);
}

export interface BoxRow { index: number; entries: { name: string; bucket: ChartBucket }[] }

/**
 * P6-T1: one box per category from the first five series (the `min`, `q1`,
 * `median`, `q3` and `max` measures), each box's five values in ascending
 * order, which is the order of genuine quartiles whatever order the measures
 * were listed in. A category missing any of the five has no box.
 */
export function boxRows(input: ChartInput): BoxRow[] {
  const five = input.series.slice(0, 5);
  if (five.length < 5) return [];
  return input.categories.flatMap((_, index) => {
    const entries = five.flatMap(s => s.points[index] ? [{ name: s.name, bucket: s.points[index]! }] : []);
    if (entries.length < 5) return [];
    entries.sort((a, b) => a.bucket.value - b.bucket.value);
    return [{ index, entries }];
  });
}

const NO_BOX = ['-', '-', '-', '-', '-'];

/** Boxes on the category axis; a click drills into the category through the
 * median's bucket. */
function boxPlot(input: ChartInput): ChartOption {
  const rows = new Map(boxRows(input).map(r => [r.index, r]));
  const color = input.series[2]?.color ?? input.series[0]?.color;
  return cartesian(input, [{
    type: 'boxplot',
    itemStyle: { color: 'transparent', borderColor: color },
    // A category with no box gets ECharts' empty values, fresh each time (ECharts
    // adds the category index to each array; a null item breaks the boxplot).
    data: input.categories.map((category, index) => {
      const row = rows.get(index);
      if (!row) return [...NO_BOX];
      return {
        value: row.entries.map(e => e.bucket.value),
        bucket: row.entries[2].bucket,
        tip: tip(category.label, ...row.entries.map(e => `${e.name}: ${input.format(e.bucket.value)}`)),
      };
    }),
  }]);
}

/**
 * P6-T1: a candle per category from the first four series in order: open
 * (the `first` measure), close (`last`), low (`min`) and high (`max`). Up
 * candles take the positive colour, down ones the negative. A category
 * missing any of the four has no candle.
 */
function candlestick(input: ChartInput): ChartOption {
  const four = input.series.slice(0, 4);
  return cartesian(input, [{
    type: 'candlestick',
    itemStyle: { color: POSITIVE, color0: NEGATIVE, borderColor: POSITIVE, borderColor0: NEGATIVE },
    data: input.categories.map((category, index) => {
      const points = four.map(s => s.points[index]);
      if (four.length < 4 || points.some(p => !p)) return ['-', '-', '-', '-'];
      const [open, close, low, high] = points as ChartBucket[];
      return {
        value: [open.value, close.value, low.value, high.value],
        bucket: close,
        tip: tip(category.label, ...four.map((s, k) => `${s.name}: ${input.format(points[k]!.value)}`)),
      };
    }),
  }]);
}

export interface CorrelationCell {
  /** Column and row, indexes into `fields`. */
  x: number;
  y: number;
  value: number;
  /** The measure's bucket, to drill through; none on the diagonal. */
  bucket: ChartBucket | null;
}

/**
 * P6-T1: a correlation matrix from `corr` measures side by side: one row and
 * one column per field the measures name, in the order they first appear.
 * Each measure fills its cell and the mirrored one from its first point; the
 * diagonal is 1; a pair no measure covers stays empty. Pure.
 */
export function correlationCells(series: ChartSeries[]): { fields: string[]; cells: CorrelationCell[] } {
  const fields: string[] = [];
  const indexOf = (field: string): number => {
    const found = fields.indexOf(field);
    if (found >= 0) return found;
    fields.push(field);
    return fields.length - 1;
  };
  const cells = new Map<string, CorrelationCell>();
  for (const s of series) {
    if (!s.pair) continue;
    const a = indexOf(s.pair[0]);
    const b = indexOf(s.pair[1]);
    const bucket = s.points[0];
    if (!bucket) continue;
    cells.set(`${a},${b}`, { x: a, y: b, value: bucket.value, bucket });
    cells.set(`${b},${a}`, { x: b, y: a, value: bucket.value, bucket });
  }
  fields.forEach((_, i) => {
    if (!cells.has(`${i},${i}`)) cells.set(`${i},${i}`, { x: i, y: i, value: 1, bucket: null });
  });
  return { fields, cells: [...cells.values()] };
}

/** The most fields whose cells show their numbers; past it only the colour. */
const CORRELATION_LABELS_UP_TO = 8;

/**
 * P6-T1: the correlation matrix on a diverging scale from -1 (negative) through
 * 0 (neutral) to 1 (positive), first field at the top; the columns mirror in
 * Arabic.
 */
function correlation(input: ChartInput): ChartOption {
  const { fields, cells } = correlationCells(input.series);
  const number = (value: number) =>
    value.toLocaleString(input.locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const labels = { color: input.textColor, hideOverlap: true };
  return base(input, {
    grid: plot(),
    xAxis: { type: 'category', data: fields, inverse: input.rtl, axisLabel: labels },
    yAxis: { type: 'category', data: fields, inverse: true, position: input.rtl ? 'right' : 'left', axisLabel: labels },
    visualMap: { show: false, min: -1, max: 1, inRange: { color: [NEGATIVE, NEUTRAL, POSITIVE] } },
    series: [{
      type: 'heatmap',
      label: {
        show: fields.length <= CORRELATION_LABELS_UP_TO,
        color: input.textColor,
        formatter: (item: { value?: number[] }) => number(item.value?.[2] ?? 0),
      },
      data: cells.map(c => ({
        value: [c.x, c.y, c.value],
        ...(c.bucket ? { bucket: c.bucket } : {}),
        tip: tip(`${fields[c.y]} · ${fields[c.x]}`, number(c.value)),
      })),
    }],
  });
}

export const CHART_REGISTRY: Record<EChartKind, ChartAdapter> = {
  stacked_bar:      { minSeries: 1, legend: true,  option: stackedBar },
  combo:            { minSeries: 1, legend: true,  option: combo },
  waterfall:        { minSeries: 1, legend: false, option: waterfall },
  treemap:          { minSeries: 1, legend: false, option: treemap },
  sunburst:         { minSeries: 1, legend: false, option: sunburst },
  sankey:           { minSeries: 1, legend: false, option: sankey },
  radar:            { minSeries: 1, legend: true,  option: radar },
  polar:            { minSeries: 1, legend: true,  option: polar },
  heatmap:          { minSeries: 1, legend: false, option: heatmap },
  calendar_heatmap: { minSeries: 1, legend: false, option: calendarHeatmap },
  pareto:           { minSeries: 1, legend: false, option: pareto },
  control:          { minSeries: 1, legend: false, option: control },
  scatter:          { minSeries: 2, legend: false, option: scatter },
  bubble:           { minSeries: 3, legend: false, option: bubble },
  range_area:       { minSeries: 2, legend: true,  option: rangeArea },
  box_plot:         { minSeries: 5, legend: false, option: boxPlot },
  candlestick:      { minSeries: 4, legend: false, option: candlestick },
  correlation:      { minSeries: 1, legend: false, option: correlation },
};

export function isEChartKind(kind: string): kind is EChartKind {
  return kind in CHART_REGISTRY;
}

/** Kinds whose series are measures side by side, not one measure split by a field. */
export const MEASURE_KINDS: ReadonlySet<string> = new Set([
  'combo', 'scatter', 'bubble', 'range_area', 'box_plot', 'candlestick', 'correlation',
]);
