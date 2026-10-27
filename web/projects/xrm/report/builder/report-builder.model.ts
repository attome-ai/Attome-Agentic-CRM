/**
 * P1-T1: the report builder's state and the QuerySpec it makes
 * (`attome_records::query_spec`, run through `POST /api/v1/query/run` under
 * the person's own access), and the pure shaping of the answer into the
 * three layouts. No SQL anywhere.
 */

export const REPORT_LAYOUTS = ['table', 'summary', 'matrix'] as const;
export type ReportLayout = (typeof REPORT_LAYOUTS)[number];

export const REPORT_OPERATORS = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'contains', 'is_null', 'is_not_null'] as const;
export type ReportOperator = (typeof REPORT_OPERATORS)[number];

export const REPORT_FUNCS = ['count', 'sum', 'avg', 'min', 'max'] as const;
export type ReportFunc = (typeof REPORT_FUNCS)[number];

export const REPORT_BUCKETS = ['day', 'week', 'month', 'quarter', 'year'] as const;
export type ReportBucket = (typeof REPORT_BUCKETS)[number];

/** Rows a preview shows. */
export const PREVIEW_ROWS = 50;
/** The alias the one measure carries in the answer. */
export const MEASURE = 'value';

export interface ReportCondition {
  field: string;
  op: ReportOperator;
  value: string;
}

/** A grouping: a field, and a date field's bucket (empty groups by the value). */
export interface ReportGroup {
  field: string;
  bucket: ReportBucket | '';
}

export interface ReportState {
  entity: string;
  layout: ReportLayout;
  /** The table's columns: fields, or related fields by path (`account.industry`). */
  columns: string[];
  conditions: ReportCondition[];
  /** Summary and matrix: what the rows are. */
  rows: ReportGroup;
  /** Matrix: what the columns are. */
  across: ReportGroup;
  /** Summary and matrix: what each cell holds. */
  func: ReportFunc;
  /** The measured field; empty for a count of records. */
  field: string;
}

export function emptyReport(entity = ''): ReportState {
  return {
    entity, layout: 'table', columns: [], conditions: [],
    rows: { field: '', bucket: '' }, across: { field: '', bucket: '' }, func: 'count', field: '',
  };
}

function typed(raw: string): string | number | boolean {
  const text = raw.trim();
  if (text === 'true' || text === 'false') return text === 'true';
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return text;
}

function where(conditions: readonly ReportCondition[]): Record<string, unknown> | null {
  const parts = conditions.filter(c => c.field).map(c => {
    const node: Record<string, unknown> = { kind: 'compare', field: c.field, op: c.op };
    if (c.op !== 'is_null' && c.op !== 'is_not_null') node['value'] = typed(c.value);
    return node;
  });
  if (!parts.length) return null;
  return parts.length === 1 ? parts[0] : { kind: 'and', all: parts };
}

function group(g: ReportGroup): Record<string, unknown> {
  return g.bucket ? { field: g.field, bucket: g.bucket } : { field: g.field };
}

/** Whether the state is complete enough to run. Pure. */
export function ready(state: ReportState): boolean {
  if (!state.entity.trim()) return false;
  if (state.layout === 'table') return state.columns.length > 0;
  if (!state.rows.field || (state.func !== 'count' && !state.field)) return false;
  return state.layout === 'summary' || (!!state.across.field && state.across.field !== state.rows.field);
}

/** The QuerySpec the state describes. Pure. */
export function reportSpec(state: ReportState): Record<string, unknown> {
  const spec: Record<string, unknown> = { entity: state.entity.trim() };
  const filter = where(state.conditions);
  if (filter) spec['where'] = filter;
  if (state.layout === 'table') {
    spec['select'] = [...state.columns];
    spec['page_size'] = PREVIEW_ROWS;
    return spec;
  }
  spec['group_by'] = state.layout === 'matrix' ? [group(state.rows), group(state.across)] : [group(state.rows)];
  spec['aggregates'] = [state.field && state.func !== 'count'
    ? { func: state.func, field: state.field, alias: MEASURE }
    : { func: 'count', alias: MEASURE }];
  return spec;
}

/** One group of the answer. */
export interface AnswerGroup {
  keys: Record<string, unknown>;
  values: Record<string, unknown>;
}

/** A key as the layouts show it; a missing value is empty. Pure. */
export function keyText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

/** A measure as a number (the server may send decimals as text); `null` when it is none. Pure. */
export function measure(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return null;
}

/** Whether totals of the measure are its sum (a count or a sum); an average or extreme has none. Pure. */
export function additive(func: ReportFunc): boolean {
  return func === 'count' || func === 'sum';
}

function add(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return a + b;
}

export interface SummaryLine {
  key: string;
  value: number | null;
}

/** The summary layout: one line per group in key order, and the total when it adds up. Pure. */
export function summarise(groups: readonly AnswerGroup[], rowField: string, func: ReportFunc): { lines: SummaryLine[]; total: number | null } {
  const lines = groups
    .map(g => ({ key: keyText(g.keys[rowField]), value: measure(g.values[MEASURE]) }))
    .sort((a, b) => a.key.localeCompare(b.key));
  const total = additive(func) ? lines.reduce<number | null>((t, l) => add(t, l.value), null) : null;
  return { lines, total };
}

export interface Matrix {
  rows: string[];
  cols: string[];
  cells: Record<string, Record<string, number | null>>;
  rowTotals: Record<string, number | null>;
  colTotals: Record<string, number | null>;
  total: number | null;
}

/** The matrix layout: rows by columns, with totals each way when the measure adds up. Pure. */
export function pivot(groups: readonly AnswerGroup[], rowField: string, colField: string, func: ReportFunc): Matrix {
  const rows = new Set<string>();
  const cols = new Set<string>();
  const cells: Record<string, Record<string, number | null>> = {};
  for (const g of groups) {
    const r = keyText(g.keys[rowField]);
    const c = keyText(g.keys[colField]);
    rows.add(r);
    cols.add(c);
    (cells[r] ??= {})[c] = measure(g.values[MEASURE]);
  }
  const sortedRows = [...rows].sort((a, b) => a.localeCompare(b));
  const sortedCols = [...cols].sort((a, b) => a.localeCompare(b));
  const sums = additive(func);
  const rowTotals: Record<string, number | null> = {};
  const colTotals: Record<string, number | null> = {};
  let total: number | null = null;
  for (const r of sortedRows) {
    for (const c of sortedCols) {
      const v = cells[r]?.[c] ?? null;
      if (!sums) continue;
      rowTotals[r] = add(rowTotals[r] ?? null, v);
      colTotals[c] = add(colTotals[c] ?? null, v);
      total = add(total, v);
    }
  }
  return { rows: sortedRows, cols: sortedCols, cells, rowTotals, colTotals, total: sums ? total : null };
}

/** The table layout's columns, in the order the person chose them. Pure. */
export function tableColumns(state: ReportState, rows: readonly Record<string, unknown>[]): string[] {
  if (state.columns.length) return [...state.columns];
  return rows.length ? Object.keys(rows[0]) : [];
}
