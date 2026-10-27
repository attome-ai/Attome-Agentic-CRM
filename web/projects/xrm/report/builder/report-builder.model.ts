/**
 * P1-T1: the report builder's state and the QuerySpec it makes
 * (`attome_records::query_spec`, run through `POST /api/v1/query/run` under
 * the person's own access), and the pure shaping of the answer into the
 * three layouts. No SQL anywhere. Totals are the server's (P1-T2: `rollup`
 * for a summary, `cube` for a matrix), so an average or an extreme has a
 * true total over all its records, not a sum of the cells.
 */

export const REPORT_LAYOUTS = ['table', 'summary', 'matrix'] as const;
export type ReportLayout = (typeof REPORT_LAYOUTS)[number];

export const REPORT_OPERATORS = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'contains', 'is_null', 'is_not_null'] as const;
export type ReportOperator = (typeof REPORT_OPERATORS)[number];

export const REPORT_FUNCS = ['count', 'sum', 'avg', 'min', 'max'] as const;
export type ReportFunc = (typeof REPORT_FUNCS)[number];

export const REPORT_BUCKETS = ['day', 'week', 'month', 'quarter', 'year'] as const;
export type ReportBucket = (typeof REPORT_BUCKETS)[number];

/** P1-T3: the types a prompt asks for (a subset of the saved query's `ParamType`). */
export const PROMPT_TYPES = ['text', 'number', 'date'] as const;
export type PromptType = (typeof PROMPT_TYPES)[number];

/** P1-T3: the chart kinds a grouped report draws (the dashboard's chart). */
export const REPORT_CHARTS = ['bar', 'line', 'area', 'donut', 'funnel'] as const;
export type ReportChart = (typeof REPORT_CHARTS)[number];

/** Rows a preview shows. */
export const PREVIEW_ROWS = 50;
/** The alias the one measure carries in the answer. */
export const MEASURE = 'value';

export interface ReportCondition {
  field: string;
  op: ReportOperator;
  value: string;
}

/**
 * P1-T3: a value the person running the report is asked for, an A14
 * parameter: `{kind: 'param', field, op, param: name}` in the spec, declared
 * with its type when the report is saved. `value` is the value for the
 * preview.
 */
export interface ReportPrompt {
  field: string;
  op: ReportOperator;
  name: string;
  type: PromptType;
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
  /** P1-T3: values asked for at run time. */
  prompts: ReportPrompt[];
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
    entity, layout: 'table', columns: [], conditions: [], prompts: [],
    rows: { field: '', bucket: '' }, across: { field: '', bucket: '' }, func: 'count', field: '',
  };
}

function typed(raw: string): string | number | boolean {
  const text = raw.trim();
  if (text === 'true' || text === 'false') return text === 'true';
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return text;
}

/** A prompt's parameter name, as the server takes it. Pure. */
export function promptNameOk(name: string): boolean {
  return /^[a-z][a-z0-9_]*$/.test(name);
}

function where(conditions: readonly ReportCondition[], prompts: readonly ReportPrompt[] = []): Record<string, unknown> | null {
  const parts = conditions.filter(c => c.field).map(c => {
    const node: Record<string, unknown> = { kind: 'compare', field: c.field, op: c.op };
    if (c.op !== 'is_null' && c.op !== 'is_not_null') node['value'] = typed(c.value);
    return node;
  });
  for (const p of prompts) {
    if (p.field && promptNameOk(p.name)) parts.push({ kind: 'param', field: p.field, op: p.op, param: p.name });
  }
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
  const filter = where(state.conditions, state.prompts ?? []);
  if (filter) spec['where'] = filter;
  if (state.layout === 'table') {
    spec['select'] = [...state.columns];
    spec['page_size'] = PREVIEW_ROWS;
    return spec;
  }
  spec['group_by'] = state.layout === 'matrix' ? [group(state.rows), group(state.across)] : [group(state.rows)];
  spec['totals'] = state.layout === 'matrix' ? 'cube' : 'rollup';
  spec['aggregates'] = [state.field && state.func !== 'count'
    ? { func: state.func, field: state.field, alias: MEASURE }
    : { func: 'count', alias: MEASURE }];
  return spec;
}

/** P1-T3: the prompts' values for a run, by parameter name, typed. Pure. */
export function promptValues(prompts: readonly ReportPrompt[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const p of prompts) {
    if (!p.field || !promptNameOk(p.name) || !p.value.trim()) continue;
    out[p.name] = p.type === 'number' ? Number(p.value) : p.value.trim();
  }
  return out;
}

/** P1-T3: the parameters a saved report declares, one per prompt. Pure. */
export function parameterDecls(prompts: readonly ReportPrompt[]): { name: string; type: PromptType; required: boolean }[] {
  return prompts
    .filter(p => p.field && promptNameOk(p.name))
    .map(p => ({ name: p.name, type: p.type, required: true }));
}

/** One group of the answer; a total row names the group fields it adds up (P1-T2). */
export interface AnswerGroup {
  keys: Record<string, unknown>;
  values: Record<string, unknown>;
  rolled_up?: string[];
}

function rolls(g: AnswerGroup, field: string): boolean {
  return (g.rolled_up ?? []).includes(field);
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


export interface SummaryLine {
  key: string;
  value: number | null;
}

/** The summary layout: one line per group in key order, and the server's grand total. Pure. */
export function summarise(groups: readonly AnswerGroup[], rowField: string): { lines: SummaryLine[]; total: number | null } {
  const lines = groups
    .filter(g => !rolls(g, rowField))
    .map(g => ({ key: keyText(g.keys[rowField]), value: measure(g.values[MEASURE]) }))
    .sort((a, b) => a.key.localeCompare(b.key));
  const grand = groups.find(g => rolls(g, rowField));
  return { lines, total: grand ? measure(grand.values[MEASURE]) : null };
}

export interface Matrix {
  rows: string[];
  cols: string[];
  cells: Record<string, Record<string, number | null>>;
  rowTotals: Record<string, number | null>;
  colTotals: Record<string, number | null>;
  total: number | null;
}

/** The matrix layout: rows by columns, with the server's row, column and grand totals. Pure. */
export function pivot(groups: readonly AnswerGroup[], rowField: string, colField: string): Matrix {
  const rows = new Set<string>();
  const cols = new Set<string>();
  const cells: Record<string, Record<string, number | null>> = {};
  const rowTotals: Record<string, number | null> = {};
  const colTotals: Record<string, number | null> = {};
  let total: number | null = null;
  for (const g of groups) {
    const r = keyText(g.keys[rowField]);
    const c = keyText(g.keys[colField]);
    const v = measure(g.values[MEASURE]);
    const rowsUp = rolls(g, rowField);
    const colsUp = rolls(g, colField);
    if (rowsUp && colsUp) total = v;
    else if (colsUp) rowTotals[r] = v;
    else if (rowsUp) colTotals[c] = v;
    else {
      rows.add(r);
      cols.add(c);
      (cells[r] ??= {})[c] = v;
    }
  }
  return {
    rows: [...rows].sort((a, b) => a.localeCompare(b)),
    cols: [...cols].sort((a, b) => a.localeCompare(b)),
    cells, rowTotals, colTotals, total,
  };
}

/** The table layout's columns, in the order the person chose them. Pure. */
export function tableColumns(state: ReportState, rows: readonly Record<string, unknown>[]): string[] {
  if (state.columns.length) return [...state.columns];
  return rows.length ? Object.keys(rows[0]) : [];
}
