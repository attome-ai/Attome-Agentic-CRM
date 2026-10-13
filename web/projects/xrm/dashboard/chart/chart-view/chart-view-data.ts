import type { ChartAggregation, ChartDateBucket, ChartViewMetadata } from '@attome/xrm/core/query/data';
import {
  ChartBucket, ChartCategory, ChartKind, ChartSeries, SLICE_COLORS,
} from '../dashboard-chart/dashboard-chart.component';

/**
 * Turns the rows a `kind = chart` view's own query returned
 * (`POST /api/v1/query/execute` with the view's id — the same privilege- and
 * record-security-gated feed every other view kind renders over, D-429) into
 * what `DashboardChartComponent` draws, following the view's
 * `ChartViewMetadata` (`chart_view_metadata.rs`).
 *
 * The chart view has no server-side aggregation route of its own: the view
 * is bound to a stored query, and only that query's rows are the rows the
 * view may show. So the grouping happens here, over the fetched rows. The
 * caller fetches a bounded number of rows and says so when it had to stop
 * (`ChartViewComponent.truncated`).
 *
 * `x_field`/`y_fields[].field` are shape-checked by the backend, never
 * checked against the query's columns: a field the rows do not carry reads
 * as empty, never as a crash (same posture as that module's doc comment).
 * `stacked`, `show_legend` and `number_format` are advisory presentation
 * hints the dashboard chart does not implement; they are kept on the view
 * and ignored here.
 */

/** The category key used for rows whose x value is empty. */
export const EMPTY_KEY = '';
/** The category key of the "Other" bucket (`other_bucket`). */
export const OTHER_KEY = '\u0000other';

export interface ChartViewData {
  kind:       ChartKind;
  categories: ChartCategory[];
  series:     ChartSeries[];
  threshold:  number | null;
}

export interface ChartViewLabels {
  /** Label for the `other_bucket` category. */
  other: string;
  /** Label for rows whose x (or group) value is empty. */
  empty: string;
  /** Use `label_ar` when a series has one. */
  arabic: boolean;
}

/** The view's metadata is configured enough to draw: an x field and at least one series. */
export function isChartConfigured(meta: Partial<ChartViewMetadata> | null | undefined): boolean {
  return !!meta && typeof meta.x_field === 'string' && meta.x_field !== ''
    && Array.isArray(meta.y_fields) && meta.y_fields.length > 0;
}

export function chartKindFor(type: ChartViewMetadata['chart_type'] | undefined): ChartKind {
  switch (type) {
    case 'area':   return 'area';
    case 'bar':
    case 'column': return 'bar';
    case 'donut':
    case 'pie':    return 'donut';
    case 'funnel': return 'funnel';
    default:       return 'line';
  }
}

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})/;

function pad(n: number): string { return String(n).padStart(2, '0'); }

/** The bucket key of a date value, or `null` when `raw` is not a date. Keys
 * sort chronologically as strings. Date-only values are taken literally (no
 * time zone shift); timestamps are bucketed in the viewer's local time. */
export function dateBucketKey(raw: unknown, bucket: ChartDateBucket): string | null {
  if (typeof raw !== 'string' || !DATE_RE.test(raw)) return null;
  let date: Date;
  if (raw.length === 10) {
    const [, y, m, d] = DATE_RE.exec(raw)!;
    date = new Date(Number(y), Number(m) - 1, Number(d));
  } else {
    date = new Date(raw);
    if (Number.isNaN(date.getTime())) return null;
  }
  const y = date.getFullYear();
  switch (bucket) {
    case 'day':     return `${y}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    case 'week': {
      // Weeks start on Monday; the key is that Monday's date.
      const monday = new Date(y, date.getMonth(), date.getDate() - ((date.getDay() + 6) % 7));
      return `${monday.getFullYear()}-${pad(monday.getMonth() + 1)}-${pad(monday.getDate())}`;
    }
    case 'month':   return `${y}-${pad(date.getMonth() + 1)}`;
    case 'quarter': return `${y}-Q${Math.floor(date.getMonth() / 3) + 1}`;
    case 'year':    return String(y);
  }
}

function lookupName(row: Record<string, unknown>, field: string): string | null {
  const lookups = row['__lookups'];
  if (!lookups || typeof lookups !== 'object') return null;
  const meta = (lookups as Record<string, { name?: unknown } | undefined>)[field];
  return meta && typeof meta.name === 'string' && meta.name !== '' ? meta.name : null;
}

interface Keyed { key: string; label: string }

function keyOf(row: Record<string, unknown>, field: string, bucket: ChartDateBucket | null | undefined, labels: ChartViewLabels): Keyed {
  const raw = row[field];
  if (raw === null || raw === undefined || raw === '') return { key: EMPTY_KEY, label: labels.empty };
  if (bucket) {
    const k = dateBucketKey(raw, bucket);
    if (k !== null) return { key: k, label: k };
  }
  const key = Array.isArray(raw) ? raw.map(String).join(', ') : String(raw);
  return { key, label: lookupName(row, field) ?? key };
}

function toNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

/** One aggregation over the values a (series, category) cell collected.
 * Mirrors SQL: `count` counts non-null values, the numeric functions ignore
 * values that are not numbers, and an empty set is `null` except for the
 * counts (0). */
export function aggregate(values: readonly unknown[], fn: ChartAggregation): number | null {
  const present = values.filter(v => v !== null && v !== undefined && v !== '');
  if (fn === 'count') return present.length;
  if (fn === 'count_distinct') return new Set(present.map(v => (typeof v === 'object' ? JSON.stringify(v) : String(v)))).size;
  const numbers = present.map(toNumber).filter((n): n is number => n !== null);
  if (numbers.length === 0) return null;
  switch (fn) {
    case 'sum': return numbers.reduce((a, b) => a + b, 0);
    case 'avg': return numbers.reduce((a, b) => a + b, 0) / numbers.length;
    case 'min': return Math.min(...numbers);
    case 'max': return Math.max(...numbers);
    case 'median': {
      const sorted = [...numbers].sort((a, b) => a - b);
      const mid = Math.floor(sorted.length / 2);
      return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }
  }
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

interface SeriesSpec { trackKey: string; name: string; color: string; field: string; fn: ChartAggregation; groupKey: string | null }

/**
 * Builds the chart for `rows` under `meta`. Returns `null` when the view is
 * not configured yet (no x field or no series).
 */
export function buildChartViewData(
  rows: readonly Record<string, unknown>[],
  meta: Partial<ChartViewMetadata>,
  labels: ChartViewLabels,
): ChartViewData | null {
  if (!isChartConfigured(meta)) return null;
  const xField = meta.x_field!;
  const yFields = meta.y_fields!;
  const groupField = meta.group_by_field || null;

  // Categories and group values, first-seen order.
  const categoryLabels = new Map<string, string>();
  const groups = new Map<string, string>();
  const rowCategory: string[] = [];
  const rowGroup: (string | null)[] = [];
  for (const row of rows) {
    const x = keyOf(row, xField, meta.x_bucket, labels);
    if (!categoryLabels.has(x.key)) categoryLabels.set(x.key, x.label);
    rowCategory.push(x.key);
    if (groupField) {
      const g = keyOf(row, groupField, null, labels);
      if (!groups.has(g.key)) groups.set(g.key, g.label);
      rowGroup.push(g.key);
    } else {
      rowGroup.push(null);
    }
  }

  // One series per y field, or per (y field, group value).
  const specs: SeriesSpec[] = [];
  yFields.forEach((y, yi) => {
    const yName = (labels.arabic && y.label_ar) ? y.label_ar : y.label;
    if (!groupField) {
      specs.push({ trackKey: `y${yi}`, name: yName, color: y.color || SLICE_COLORS[yi % SLICE_COLORS.length], field: y.field, fn: y.aggregation, groupKey: null });
      return;
    }
    for (const [gKey, gLabel] of groups) {
      const i = specs.length;
      specs.push({
        trackKey: `y${yi}|${gKey}`,
        name: yFields.length > 1 ? `${yName} · ${gLabel}` : gLabel,
        color: SLICE_COLORS[i % SLICE_COLORS.length],
        field: y.field, fn: y.aggregation, groupKey: gKey,
      });
    }
  });

  const compute = (categoryOf: (rowIndex: number) => string, categories: string[]): (number | null)[][] => {
    const index = new Map(categories.map((c, i) => [c, i]));
    return specs.map(spec => {
      const cells: unknown[][] = categories.map(() => []);
      rows.forEach((row, r) => {
        if (spec.groupKey !== null && rowGroup[r] !== spec.groupKey) return;
        const c = index.get(categoryOf(r));
        if (c !== undefined) cells[c].push(row[spec.field]);
      });
      return cells.map(values => aggregate(values, spec.fn));
    });
  };

  // Sort the categories.
  let categories = [...categoryLabels.keys()];
  let values = compute(r => rowCategory[r], categories);
  const sort = meta.sort ?? 'x_asc';
  const total = (i: number) => values.reduce((sum, s) => sum + (s[i] ?? 0), 0);
  const order = categories.map((key, i) => ({ key, i }));
  order.sort((a, b) => {
    switch (sort) {
      case 'x_desc':     return collator.compare(b.key, a.key);
      case 'value_asc':  return total(a.i) - total(b.i) || collator.compare(a.key, b.key);
      case 'value_desc': return total(b.i) - total(a.i) || collator.compare(a.key, b.key);
      default:           return collator.compare(a.key, b.key);
    }
  });
  categories = order.map(o => o.key);

  // `limit`, folding the rest into "Other" when asked.
  const limit = meta.limit ?? null;
  if (limit !== null && categories.length > limit) {
    const kept = categories.slice(0, limit);
    if (meta.other_bucket) {
      const keptSet = new Set(kept);
      categories = [...kept, OTHER_KEY];
      values = compute(r => (keptSet.has(rowCategory[r]) ? rowCategory[r] : OTHER_KEY), categories);
    } else {
      categories = kept;
      values = compute(r => rowCategory[r], categories);
    }
  } else {
    values = compute(r => rowCategory[r], categories);
  }

  // Calculation modifiers, in the order the chart settings name them.
  values = values.map(series => {
    let out = series;
    if (meta.percent_of_total) {
      const sum = out.reduce<number>((a, v) => a + (v ?? 0), 0);
      out = out.map(v => (v === null ? null : sum === 0 ? 0 : (v / sum) * 100));
    }
    if (meta.cumulative) {
      let running = 0;
      out = out.map(v => { if (v === null) return null; running += v; return running; });
    }
    const window = meta.moving_average_window ?? null;
    if (window !== null && window >= 2) {
      out = out.map((v, i) => {
        if (v === null) return null;
        const span = out.slice(Math.max(0, i - window + 1), i + 1).filter((p): p is number => p !== null);
        return span.reduce((a, b) => a + b, 0) / span.length;
      });
    }
    return out;
  });

  const chartCategories: ChartCategory[] = categories.map(key => ({
    trackKey: key === OTHER_KEY ? 'other' : `c:${key}`,
    label: key === OTHER_KEY ? labels.other : (categoryLabels.get(key) ?? key),
  }));
  const series: ChartSeries[] = specs.map((spec, s) => ({
    trackKey: spec.trackKey,
    name: spec.name,
    color: spec.color,
    points: values[s].map((value, c): ChartBucket | null => value === null ? null : {
      trackKey: `${chartCategories[c].trackKey}|${spec.trackKey}`,
      label: chartCategories[c].label,
      value,
      key: null,
      seriesLabel: spec.name,
    }),
  }));

  return {
    kind: chartKindFor(meta.chart_type),
    categories: chartCategories,
    series,
    threshold: typeof meta.threshold?.value === 'number' ? meta.threshold.value : null,
  };
}
