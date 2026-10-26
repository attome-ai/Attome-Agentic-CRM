/**
 * A14-T3: the query builder's state and the QuerySpec it makes
 * (`attome_records::query_spec`, run through `POST /api/v1/query/run`). Pure.
 */

/** The operators a condition row offers. */
export const BUILDER_OPERATORS = [
  'eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'in', 'contains', 'starts_with', 'is_null', 'is_not_null',
] as const;
export type BuilderOperator = (typeof BUILDER_OPERATORS)[number];

/** The aggregate functions a summary row offers. */
export const BUILDER_FUNCS = ['count', 'sum', 'avg', 'min', 'max', 'count_distinct'] as const;
export type BuilderFunc = (typeof BUILDER_FUNCS)[number];

/** The date buckets a grouping by a date offers. */
export const DATE_BUCKETS = ['day', 'week', 'month', 'quarter', 'year'] as const;
export type DateBucket = (typeof DATE_BUCKETS)[number];

/** One condition: field, operator, value (a comma-separated list for `in`). */
export interface BuilderCondition {
  field: string;
  op: BuilderOperator;
  value: string;
}

export interface BuilderGroup {
  field: string;
  /** A date field's bucket; empty groups by the value itself. */
  bucket: DateBucket | '';
}

export interface BuilderAggregate {
  func: BuilderFunc;
  /** Empty for `count` of records. */
  field: string;
  alias: string;
}

export interface BuilderState {
  entity: string;
  /** Columns: fields of the entity, or related fields by path (`account.industry`). */
  select: string[];
  conditions: BuilderCondition[];
  /**
   * A condition tree the rows cannot show (from a sentence with `or` or
   * `not`), kept as it came and ANDed with the rows.
   */
  extraWhere: Record<string, unknown> | null;
  groups: BuilderGroup[];
  aggregates: BuilderAggregate[];
  sortField: string;
  sortDesc: boolean;
  pageSize: number;
}

export function emptyState(entity = ''): BuilderState {
  return {
    entity, select: [], conditions: [], extraWhere: null, groups: [], aggregates: [],
    sortField: '', sortDesc: false, pageSize: 50,
  };
}

/** A row's value as the spec carries it: a number when it reads as one. */
function typed(raw: string): string | number | boolean {
  const text = raw.trim();
  if (text === 'true' || text === 'false') return text === 'true';
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return text;
}

function compare(condition: BuilderCondition): Record<string, unknown> {
  const node: Record<string, unknown> = { kind: 'compare', field: condition.field, op: condition.op };
  if (condition.op === 'is_null' || condition.op === 'is_not_null') return node;
  node['value'] = condition.op === 'in'
    ? condition.value.split(',').map(v => v.trim()).filter(v => v).map(typed)
    : typed(condition.value);
  return node;
}

/** The QuerySpec the state describes. Rows with no field are left out. */
export function buildSpec(state: BuilderState): Record<string, unknown> {
  const spec: Record<string, unknown> = { entity: state.entity.trim() };
  const parts = state.conditions.filter(c => c.field).map(compare);
  if (state.extraWhere) parts.push(state.extraWhere);
  if (parts.length === 1) spec['where'] = parts[0];
  else if (parts.length > 1) spec['where'] = { kind: 'and', all: parts };
  const groups = state.groups.filter(g => g.field);
  const aggregates = state.aggregates.filter(a => a.alias.trim() && (a.field || a.func === 'count'));
  if (groups.length || aggregates.length) {
    spec['group_by'] = groups.map(g => (g.bucket ? { field: g.field, bucket: g.bucket } : { field: g.field }));
    spec['aggregates'] = aggregates.map(a => (a.field
      ? { func: a.func, field: a.field, alias: a.alias.trim() }
      : { func: a.func, alias: a.alias.trim() }));
  } else {
    if (state.select.length) spec['select'] = [...state.select];
    spec['page_size'] = state.pageSize;
  }
  if (state.sortField) spec['sort'] = [{ field: state.sortField, desc: state.sortDesc }];
  return spec;
}

/**
 * The state a parsed sentence's filter (`{entity, where}`, from
 * `search.parse_filter`) gives: a flat `and` of comparisons (or one) becomes
 * condition rows; anything else is kept whole as the extra condition.
 */
export function stateFromFilter(filter: { entity: string; where?: unknown }): BuilderState {
  const state = emptyState(filter.entity);
  const where = filter.where as Record<string, unknown> | null | undefined;
  if (!where) return state;
  const nodes = where['kind'] === 'and' && Array.isArray(where['all'])
    ? (where['all'] as Record<string, unknown>[])
    : [where];
  const rows: BuilderCondition[] = [];
  for (const node of nodes) {
    const op = node['op'] as BuilderOperator;
    if (node['kind'] !== 'compare' || !BUILDER_OPERATORS.includes(op) || typeof node['field'] !== 'string') {
      state.extraWhere = where;
      return state;
    }
    const value = node['value'];
    rows.push({
      field: node['field'] as string,
      op,
      value: Array.isArray(value) ? value.join(', ') : value === undefined || value === null ? '' : String(value),
    });
  }
  state.conditions = rows;
  return state;
}

/** The columns of result rows, in the order the first row has them. */
export function columnsOf(rows: readonly Record<string, unknown>[]): string[] {
  return rows.length ? Object.keys(rows[0]) : [];
}
