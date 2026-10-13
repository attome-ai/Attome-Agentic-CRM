import type {
  ChartAggregation, ChartDateBucket, ChartSort, ChartType,
} from '@attome/xrm/core/query/data';

/**
 * The view editor's chart settings (Basic Units P1 follow-up) and the
 * `view_metadata` they build. The checks mirror
 * `attome_core::chart_view_metadata::validate` exactly, so a save the
 * backend would reject is caught here with a named field first. The backend
 * still validates every write; this is the friendly half, not the guard.
 *
 * `number_format` has no editor yet and is carried through from the stored
 * metadata unchanged.
 */

export const CHART_TYPES: readonly ChartType[] = ['line', 'area', 'bar', 'column', 'donut', 'pie', 'funnel'];
export const CHART_AGGREGATIONS: readonly ChartAggregation[] =
  ['count', 'count_distinct', 'sum', 'avg', 'min', 'max', 'median'];
export const CHART_DATE_BUCKETS: readonly ChartDateBucket[] = ['day', 'week', 'month', 'quarter', 'year'];
export const CHART_SORTS: readonly ChartSort[] = ['x_asc', 'x_desc', 'value_asc', 'value_desc'];

/** Backend bounds (`chart_view_metadata.rs`). */
export const CHART_MAX_FIELD_LEN = 128;
export const CHART_MAX_LABEL_LEN = 200;
export const CHART_MAX_SERIES = 8;
export const CHART_LIMIT_RANGE = [1, 366] as const;
export const CHART_MOVING_AVERAGE_RANGE = [2, 90] as const;

export interface ChartSeriesDraft {
  field:       string;
  aggregation: ChartAggregation;
  label:       string;
  labelAr:     string;
  color:       string;
}

export interface ChartDraft {
  chartType:      ChartType;
  xField:         string;
  /** `''` = no date bucketing. */
  xBucket:        ChartDateBucket | '';
  groupByField:   string;
  /** `''` = the renderer's default order. */
  sort:           ChartSort | '';
  limit:          string;
  otherBucket:    boolean;
  stacked:        boolean;
  cumulative:     boolean;
  percentOfTotal: boolean;
  movingAverage:  string;
  thresholdValue: string;
  thresholdLabel: string;
  showLegend:     boolean;
  series:         ChartSeriesDraft[];
}

export const EMPTY_CHART_DRAFT: ChartDraft = {
  chartType: 'line', xField: '', xBucket: '', groupByField: '', sort: '', limit: '',
  otherBucket: false, stacked: false, cumulative: false, percentOfTotal: false,
  movingAverage: '', thresholdValue: '', thresholdLabel: '', showLegend: true, series: [],
};

export function emptySeries(): ChartSeriesDraft {
  return { field: '', aggregation: 'count', label: '', labelAr: '', color: '' };
}

const IDENTIFIER_RE = /^[a-z][a-z0-9_]*$/;
const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;
const INTEGER_RE = /^\d+$/;

/** `attribute_info.logicalname` shape, as the backend checks it. */
export function isChartIdentifier(value: string): boolean {
  return IDENTIFIER_RE.test(value) && value.length <= CHART_MAX_FIELD_LEN;
}

function oneOf<T extends string>(allowed: readonly T[], value: unknown, fallback: T): T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value) ? value as T : fallback;
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function numberText(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

/** Reads a stored chart view's metadata into the editor's draft. */
export function chartDraftFromMetadata(meta: Record<string, unknown>): ChartDraft {
  const threshold = meta['threshold'] && typeof meta['threshold'] === 'object'
    ? meta['threshold'] as Record<string, unknown> : null;
  const series = Array.isArray(meta['y_fields']) ? meta['y_fields'] as Record<string, unknown>[] : [];
  return {
    chartType:      oneOf(CHART_TYPES, meta['chart_type'], 'line'),
    xField:         text(meta['x_field']),
    xBucket:        oneOf<ChartDateBucket | ''>(CHART_DATE_BUCKETS, meta['x_bucket'], ''),
    groupByField:   text(meta['group_by_field']),
    sort:           oneOf<ChartSort | ''>(CHART_SORTS, meta['sort'], ''),
    limit:          numberText(meta['limit']),
    otherBucket:    meta['other_bucket'] === true,
    stacked:        meta['stacked'] === true,
    cumulative:     meta['cumulative'] === true,
    percentOfTotal: meta['percent_of_total'] === true,
    movingAverage:  numberText(meta['moving_average_window']),
    thresholdValue: threshold ? numberText(threshold['value']) : '',
    thresholdLabel: threshold ? text(threshold['label']) : '',
    showLegend:     meta['show_legend'] !== false,
    series: series.filter(s => s && typeof s === 'object').map(s => ({
      field:       text(s['field']),
      aggregation: oneOf(CHART_AGGREGATIONS, s['aggregation'], 'count'),
      label:       text(s['label']),
      labelAr:     text(s['label_ar']),
      color:       text(s['color']),
    })),
  };
}

export type ChartMetadataResult =
  | { ok: true; metadata: Record<string, unknown> }
  | { ok: false; errorKey: string };

function fail(key: string): ChartMetadataResult {
  return { ok: false, errorKey: `queryAdmin.viewKind.chartError.${key}` };
}

function integerIn(raw: string, [min, max]: readonly [number, number]): number | null {
  if (!INTEGER_RE.test(raw)) return null;
  const n = Number(raw);
  return n >= min && n <= max ? n : null;
}

/**
 * Builds a chart view's `view_metadata`. An empty x field or an empty series
 * list is valid — the backend stores a chart that is "not configured yet"
 * and the list page says so — but anything present must pass the backend's
 * checks. `existing` supplies the keys this editor does not edit.
 */
export function buildChartMetadata(draft: ChartDraft, existing: Record<string, unknown> = {}): ChartMetadataResult {
  const xField = draft.xField.trim();
  if (xField && !isChartIdentifier(xField)) return fail('xField');
  if (draft.series.length > CHART_MAX_SERIES) return fail('tooManySeries');

  const yFields: Record<string, unknown>[] = [];
  for (const s of draft.series) {
    const field = s.field.trim();
    const label = s.label.trim();
    const labelAr = s.labelAr.trim();
    const color = s.color.trim();
    if (!isChartIdentifier(field)) return fail('seriesField');
    if (!label || label.length > CHART_MAX_LABEL_LEN) return fail('seriesLabel');
    if (labelAr.length > CHART_MAX_LABEL_LEN) return fail('seriesLabel');
    if (color && !HEX_COLOR_RE.test(color)) return fail('seriesColor');
    const series: Record<string, unknown> = { field, aggregation: s.aggregation, label };
    if (labelAr) series['label_ar'] = labelAr;
    if (color) series['color'] = color;
    yFields.push(series);
  }

  const metadata: Record<string, unknown> = { chart_type: draft.chartType, x_field: xField, y_fields: yFields };
  if (draft.xBucket) metadata['x_bucket'] = draft.xBucket;

  const groupBy = draft.groupByField.trim();
  if (groupBy) {
    if (!isChartIdentifier(groupBy)) return fail('groupBy');
    metadata['group_by_field'] = groupBy;
  }
  if (draft.sort) metadata['sort'] = draft.sort;

  if (draft.limit.trim()) {
    const limit = integerIn(draft.limit.trim(), CHART_LIMIT_RANGE);
    if (limit === null) return fail('limit');
    metadata['limit'] = limit;
  }
  if (draft.movingAverage.trim()) {
    const window = integerIn(draft.movingAverage.trim(), CHART_MOVING_AVERAGE_RANGE);
    if (window === null) return fail('movingAverage');
    metadata['moving_average_window'] = window;
  }

  const thresholdLabel = draft.thresholdLabel.trim();
  if (draft.thresholdValue.trim()) {
    const value = Number(draft.thresholdValue.trim());
    if (!Number.isFinite(value)) return fail('threshold');
    if (thresholdLabel.length > CHART_MAX_LABEL_LEN) return fail('threshold');
    metadata['threshold'] = thresholdLabel ? { value, label: thresholdLabel } : { value };
  } else if (thresholdLabel) {
    return fail('threshold');
  }

  if (draft.otherBucket) metadata['other_bucket'] = true;
  if (draft.stacked) metadata['stacked'] = true;
  if (draft.cumulative) metadata['cumulative'] = true;
  if (draft.percentOfTotal) metadata['percent_of_total'] = true;
  if (!draft.showLegend) metadata['show_legend'] = false;
  if (existing['number_format'] && typeof existing['number_format'] === 'object') {
    metadata['number_format'] = existing['number_format'];
  }
  return { ok: true, metadata };
}
