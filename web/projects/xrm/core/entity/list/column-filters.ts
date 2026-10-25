/**
 * Pure filter grammar for `attome-metadata-list` (C-28): the column-filter draft
 * shape, the operator sets per `FilterKind`, translation into
 * `query/execute` filters, and URL (de)serialization. Nothing here touches
 * Angular, a signal, or the DOM — every function is a plain, synchronously
 * testable transform, so `EntityListComponent` (and anything else that wants
 * the same filter grammar) can depend on it without dragging the component
 * along.
 */

// `lookup` (D-607): a lookup column's value is a record id, so it takes
// equality and emptiness only — never `contains`, which the server refuses on
// a uuid column.
export type FilterKind = 'text' | 'number' | 'date' | 'boolean' | 'optionset' | 'lookup';

// `equals` (not `eq`) on text is the pre-existing URL-parameter spelling —
// kept so a shared link written before the operator set grew still parses.
export type TextOperator  = 'contains' | 'equals' | 'starts_with' | 'ends_with' | 'neq' | 'is_null' | 'is_not_null';
export type NumberOperator = 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'between' | 'is_null' | 'is_not_null';
export type DateOperator  = '' | 'today' | 'past_7_days' | 'past_month' | 'past_year' | 'on' | 'after' | 'before'
  | 'between' | 'is_null' | 'is_not_null';

export type LookupOperator = 'eq' | 'neq' | 'is_null' | 'is_not_null';

export const TEXT_OPERATORS:   readonly TextOperator[]   = ['contains', 'equals', 'starts_with', 'ends_with', 'neq', 'is_null', 'is_not_null'];
export const LOOKUP_OPERATORS: readonly LookupOperator[] = ['eq', 'neq', 'is_null', 'is_not_null'];
export const NUMBER_OPERATORS: readonly NumberOperator[] = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'between', 'is_null', 'is_not_null'];
export const DATE_OPERATORS:   readonly DateOperator[]   = [
  'today', 'past_7_days', 'past_month', 'past_year', 'on', 'after', 'before', 'between', 'is_null', 'is_not_null',
];
/** Operators that carry no value: the draft is active on the operator alone. */
export const VALUELESS_OPERATORS: readonly string[] = ['is_null', 'is_not_null', 'today', 'past_7_days', 'past_month', 'past_year'];

export interface ColumnFilterDraft {
  operator?: TextOperator | NumberOperator | DateOperator | string;
  value?:    string | number | boolean | null;
  /** Upper bound of a `between` range; unused by every other operator. */
  valueTo?:  string | number | null;
}

/** One entry of `query/execute`'s `filters` array, as this grid sends it. */
export interface QueryFilter {
  field:  string;
  op:     string;
  value?: string;
}

function hasFilterValue(value: unknown): boolean {
  return value !== null && value !== undefined && String(value).trim() !== '';
}

/** Whether a draft carries enough to send — an operator that needs no value,
 * a single value, or both ends of a range. */
export function isColumnFilterDraftActive(draft: ColumnFilterDraft | undefined): boolean {
  if (!draft) return false;
  const op = String(draft.operator ?? '');
  if (VALUELESS_OPERATORS.includes(op)) return true;
  if (op === 'between') return hasFilterValue(draft.value) && hasFilterValue(draft.valueTo);
  return hasFilterValue(draft.value);
}

/** Whether `op` needs no value box in the filter popover at all (a relative
 * date preset or an `is_null`/`is_not_null` test). Shared by every kind's
 * `requires*Value` getter. */
export function isValuelessOperator(op: string): boolean {
  return VALUELESS_OPERATORS.includes(op);
}

/** Reads the operator out of a draft, validated against `valid` — the same
 * "unrecognized/absent operator falls back to the kind's default" rule every
 * `get*Operator` getter on the list component applies. */
export function draftOperator<T extends string>(
  draft: ColumnFilterDraft | undefined,
  valid: readonly T[],
  fallback: T,
): T {
  const op = draft?.operator;
  return valid.includes(op as T) ? op as T : fallback;
}

/** Reads a draft's scalar `value` as a string, `''` when absent — the shared
 * shape every `get*Value` getter renders into a plain `<input>`. */
export function draftValue(draft: ColumnFilterDraft | undefined): string {
  return String(draft?.value ?? '');
}

/** Reads a draft's `valueTo` (the upper bound of a `between` range) as a
 * string, `''` when absent. */
export function draftValueTo(draft: ColumnFilterDraft | undefined): string {
  return String(draft?.valueTo ?? '');
}

function startOfDay(d: Date): Date {
  const n = new Date(d); n.setHours(0, 0, 0, 0); return n;
}

function toDateStr(d: Date): string {
  const y   = d.getFullYear();
  const m   = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Translates one column's filter draft into the `query/execute` filters that
 * express it. Pure — `now` is injectable for the relative date presets.
 *
 * The operator names on the wire are the server's (`query_exec.rs`'s WHERE
 * loop): `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `contains`, `starts_with`,
 * `ends_with`, `is_null`, `is_not_null`. The UI's `between` is sent as an
 * inclusive `gte` + `lte` pair — same rows the server's own `between` selects,
 * without this grid needing an array-valued filter entry.
 */
export function columnFilterToQueryFilters(
  field: string,
  draft: ColumnFilterDraft,
  kind:  FilterKind,
  now:   Date = new Date(),
): QueryFilter[] {
  const op = String(draft.operator ?? '');
  if (op === 'is_null' || op === 'is_not_null') {
    // A boolean filter never offers these. The grid's optionset popover does
    // not either, but the advanced-find builder does (D-607).
    return kind === 'boolean' ? [] : [{ field, op }];
  }
  switch (kind) {
    case 'text': {
      const v = String(draft.value ?? '').trim();
      if (!v) return [];
      const opMap: Record<string, string> = {
        contains: 'contains', equals: 'eq', starts_with: 'starts_with', ends_with: 'ends_with', neq: 'neq',
      };
      return [{ field, op: opMap[op] ?? 'contains', value: v }];
    }
    case 'number': {
      if (op === 'between') {
        const low = Number(draft.value), high = Number(draft.valueTo);
        if (!Number.isFinite(low) || !Number.isFinite(high)) return [];
        return [{ field, op: 'gte', value: String(low) }, { field, op: 'lte', value: String(high) }];
      }
      const n = Number(draft.value);
      if (!Number.isFinite(n)) return [];
      const scalar = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte'];
      return [{ field, op: scalar.includes(op) ? op : 'eq', value: String(n) }];
    }
    case 'date': {
      const sinceDaysAgo = (days: number): QueryFilter[] => {
        const d = new Date(now); d.setDate(d.getDate() - days);
        return [{ field, op: 'gte', value: toDateStr(startOfDay(d)) }];
      };
      const v = String(draft.value ?? '').trim();
      switch (op as DateOperator) {
        case 'today':       return sinceDaysAgo(0);
        case 'past_7_days': return sinceDaysAgo(6);
        case 'past_month':  return sinceDaysAgo(29);
        case 'past_year':   return sinceDaysAgo(364);
        case 'on':          return v ? [{ field, op: 'eq',  value: v }] : [];
        case 'after':       return v ? [{ field, op: 'gte', value: v }] : [];
        case 'before':      return v ? [{ field, op: 'lte', value: v }] : [];
        case 'between': {
          const to = String(draft.valueTo ?? '').trim();
          return v && to ? [{ field, op: 'gte', value: v }, { field, op: 'lte', value: to }] : [];
        }
        default: return [];
      }
    }
    case 'boolean': {
      if (draft.value === null || draft.value === undefined) return [];
      return [{ field, op: 'eq', value: String(draft.value) }];
    }
    case 'optionset': {
      if (!draft.value && draft.value !== 0) return [];
      // `neq` is the advanced-find builder's "is not"; the grid popover only
      // ever sets `eq` (its `setOptionsetValue`).
      // `contains` tests one option of a multi-select choice.
      const choiceOp = op === 'neq' || op === 'contains' ? op : 'eq';
      return [{ field, op: choiceOp, value: String(draft.value) }];
    }
    case 'lookup': {
      const v = String(draft.value ?? '').trim();
      if (!v) return [];
      return [{ field, op: op === 'neq' ? 'neq' : 'eq', value: v }];
    }
  }
}

/**
 * The operators `POST /api/v1/{entity}/export` compiles
 * (`attome_core::filter::compile`). Since D-607 that is every operator this
 * grid sends — `neq`, `starts_with`, `ends_with` and `is_not_null` joined the
 * shared compiler, so `query/execute` and export accept the same flat set.
 * The split below stays for B-R10 Phase B's nested groups.
 */
export const EXPORT_FILTER_OPS: readonly string[] = [
  'contains', 'starts_with', 'ends_with', 'eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'is_null', 'is_not_null',
];

/**
 * Splits the grid's `query/execute` filters into those the export endpoint
 * expresses exactly and those it cannot. Nothing is approximated: a filter the
 * export grammar lacks is reported, so the caller can ask before exporting a
 * wider set of rows than the grid shows.
 */
export function splitExportFilters(filters: readonly QueryFilter[]): {
  exportable:  QueryFilter[];
  unsupported: QueryFilter[];
} {
  const exportable:  QueryFilter[] = [];
  const unsupported: QueryFilter[] = [];
  for (const f of filters) {
    (EXPORT_FILTER_OPS.includes(f.op) ? exportable : unsupported).push(f);
  }
  return { exportable, unsupported };
}

interface UrlColumnFilter extends ColumnFilterDraft {
  field: string;
}

/** Serializes active list filters into a stable, shareable query parameter. */
export function serializeColumnFilters(filters: Record<string, ColumnFilterDraft>): string | null {
  const entries: UrlColumnFilter[] = Object.entries(filters)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([field, draft]) => ({ field, ...draft }));
  return entries.length ? JSON.stringify(entries) : null;
}

/** Safely restores list filters from the URL. Invalid entries are ignored. */
export function deserializeColumnFilters(value: string | null): Record<string, ColumnFilterDraft> {
  if (!value) return {};
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return {};

    const filters: Record<string, ColumnFilterDraft> = {};
    for (const item of parsed) {
      if (!item || typeof item !== 'object') continue;
      const candidate = item as Record<string, unknown>;
      if (typeof candidate['field'] !== 'string' || !candidate['field'].trim()) continue;
      const operator = candidate['operator'];
      const filterValue = candidate['value'];
      const valueTo = candidate['valueTo'];
      if (operator !== undefined && typeof operator !== 'string') continue;
      if (filterValue !== undefined && filterValue !== null
          && typeof filterValue !== 'string' && typeof filterValue !== 'number'
          && typeof filterValue !== 'boolean') continue;
      if (valueTo !== undefined && valueTo !== null
          && typeof valueTo !== 'string' && typeof valueTo !== 'number') continue;
      filters[candidate['field']] = {
        ...(operator === undefined ? {} : { operator }),
        ...(filterValue === undefined ? {} : { value: filterValue }),
        ...(valueTo === undefined ? {} : { valueTo }),
      };
    }
    return filters;
  } catch {
    return {};
  }
}

/** Maps a field's declared type to the filter grammar it offers. Kept here
 * (not in `@attome/xrm`'s `FieldType`) because the mapping is this grid's own
 * UI decision, not a wire contract. */
export function fieldTypeToFilterKind(fieldType: string): FilterKind {
  switch (fieldType) {
    case 'number':   return 'number';
    case 'currency': return 'number';
    case 'date':     return 'date';
    case 'date_time': return 'date';
    case 'bool':     return 'boolean';
    case 'choice':   return 'optionset';
    case 'lookup':   return 'lookup';
    case 'icon':     return 'text';
    case 'color':    return 'text';
    // U9: a rich-text column filters on its (sanitized HTML) text; an image
    // on its object key. A formula column never reaches here as 'formula' —
    // the query engine reports it as its result type (number, date, ...).
    case 'rich_text': return 'text';
    case 'image':     return 'text';
    case 'formula':   return 'text';
    default:       return 'text';
  }
}
