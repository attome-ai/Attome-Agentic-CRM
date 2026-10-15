/**
 * Advanced find (U12 Phase A, D-607) — the pure half of the condition
 * builder: which fields it offers, which operators each field takes, and the
 * mapping between builder rows and `query/execute` filters.
 *
 * One translation, not two: a builder row is a `ColumnFilterDraft` on one
 * field, and it becomes wire filters through the grid's own
 * `columnFilterToQueryFilters`. The grammar is the server's flat AND list
 * (`attome_core::Filter`); `view_metadata.filters` stores exactly those
 * wire filters, and the server validates them on save (at most
 * {@link MAX_ADVANCED_CONDITIONS}, attributes of the view's entity only,
 * operators valid for the field's type) and again on every `query/execute`.
 * Nothing here decides access (D-429).
 */
import { compareText } from '@attome/base';
import type { ChoiceOptions, FieldSchema } from '@attome/xrm';
import {
  ColumnFilterDraft, DATE_OPERATORS, FilterKind, LOOKUP_OPERATORS, NUMBER_OPERATORS, QueryFilter,
  TEXT_OPERATORS, columnFilterToQueryFilters, fieldTypeToFilterKind, isColumnFilterDraftActive,
} from './column-filters';

/** The server's cap on `view_metadata.filters` (`view_admin::MAX_VIEW_FILTERS`). */
export const MAX_ADVANCED_CONDITIONS = 50;

/** One row of the builder. `key` is a stable identity for `@for`/form controls. */
export interface AdvancedCondition {
  key:   number;
  field: string;
  draft: ColumnFilterDraft;
}

/**
 * The fields the builder offers: every attribute whose type the filter
 * grammar compiles — all but `file` — in display-name order. `is_filterable`
 * is an index hint (an unindexed filter only logs a warning server-side), not
 * a permission, so it does not narrow this list. A field the caller cannot
 * read is refused by the server with "unknown filter field"; the builder does
 * not try to predict that. Names sort in the reader's `locale` (B21-T2).
 */
export function advancedFindFields(fields: readonly FieldSchema[], locale?: string): FieldSchema[] {
  return fields
    .filter(f => f.field_type !== 'file')
    .sort((a, b) => compareText(a.display_name || a.name, b.display_name || b.name, locale));
}

export function isMultiChoice(field: FieldSchema): boolean {
  return field.field_type === 'choice' && !!(field.options as ChoiceOptions | null)?.multi;
}

/** The filter kind a field's editor and translation use. */
export function conditionKind(field: FieldSchema): FilterKind {
  return fieldTypeToFilterKind(field.field_type);
}

/** The operators the builder offers for `field`, in menu order. */
export function conditionOperators(field: FieldSchema): readonly string[] {
  switch (conditionKind(field)) {
    case 'text':      return TEXT_OPERATORS;
    case 'number':    return NUMBER_OPERATORS;
    case 'date':      return DATE_OPERATORS;
    case 'boolean':   return ['eq'];
    case 'lookup':    return LOOKUP_OPERATORS;
    case 'optionset': return isMultiChoice(field)
      ? ['contains', 'is_null', 'is_not_null']
      : ['eq', 'neq', 'is_null', 'is_not_null'];
  }
}

/** A fresh row for `field`, on its first operator with no value. */
export function newCondition(key: number, field: FieldSchema): AdvancedCondition {
  return { key, field: field.name, draft: { operator: conditionOperators(field)[0] } };
}

/** The choice values offered for an option-set row, with their labels. */
export function choiceOptions(field: FieldSchema): { value: string; label: string }[] {
  const opts = field.options as ChoiceOptions | null;
  return (opts?.choices ?? []).map(value => ({ value, label: opts?.option_labels?.[value] ?? value }));
}

/** Whether a row carries enough to become at least one filter. */
export function isConditionComplete(condition: AdvancedCondition): boolean {
  return isColumnFilterDraftActive(condition.draft);
}

/**
 * The wire filters for `conditions`, through the grid's one translation. A
 * row whose field is gone from `fields`, or that is incomplete, contributes
 * nothing. `now` anchors the relative date presets: a saved "past 7 days"
 * is stored as the fixed date it resolved to on save (Phase A stores wire
 * filters, not presets).
 */
export function conditionsToFilters(
  conditions: readonly AdvancedCondition[],
  fields: readonly FieldSchema[],
  now: Date = new Date(),
): QueryFilter[] {
  const byName = new Map(fields.map(f => [f.name, f]));
  return conditions.flatMap(c => {
    const field = byName.get(c.field);
    if (!field || !isConditionComplete(c)) return [];
    return columnFilterToQueryFilters(c.field, c.draft, conditionKind(field), now);
  });
}

const VALUELESS = new Set(['is_null', 'is_not_null']);

/** The builder draft that `columnFilterToQueryFilters` turns back into
 * exactly `filter`, or `null` when no draft does. */
function draftFor(filter: QueryFilter, field: FieldSchema): ColumnFilterDraft | null {
  const { op } = filter;
  if (VALUELESS.has(op)) return conditionKind(field) === 'boolean' ? null : { operator: op };
  const value = filter.value;
  if (value === undefined || value === null) return null;
  switch (conditionKind(field)) {
    case 'text': {
      const textOp = op === 'eq' ? 'equals' : op;
      return (TEXT_OPERATORS as readonly string[]).includes(textOp) ? { operator: textOp, value } : null;
    }
    case 'number':
      return ['eq', 'neq', 'gt', 'gte', 'lt', 'lte'].includes(op) ? { operator: op, value } : null;
    case 'date': {
      const dateOp = ({ eq: 'on', gte: 'after', lte: 'before' } as Record<string, string>)[op];
      return dateOp ? { operator: dateOp, value } : null;
    }
    case 'boolean':
      return op === 'eq' && (value === 'true' || value === 'false')
        ? { operator: 'eq', value: value === 'true' }
        : null;
    case 'optionset':
      return conditionOperators(field).includes(op) ? { operator: op, value } : null;
    case 'lookup':
      return op === 'eq' || op === 'neq' ? { operator: op, value } : null;
  }
}

/**
 * Rebuilds builder rows from saved wire filters (opening a view). Each
 * filter becomes one row; a filter no row reproduces exactly (a field that is
 * no longer on the entity, or an operator only another client writes) is
 * returned in `kept` so the caller still applies it — it is never dropped,
 * which would silently widen the result.
 */
export function filtersToConditions(
  filters: readonly QueryFilter[],
  fields: readonly FieldSchema[],
  firstKey = 1,
): { conditions: AdvancedCondition[]; kept: QueryFilter[] } {
  const byName = new Map(fields.map(f => [f.name, f]));
  const conditions: AdvancedCondition[] = [];
  const kept: QueryFilter[] = [];
  let key = firstKey;
  for (const filter of filters) {
    const field = byName.get(filter.field);
    const draft = field ? draftFor(filter, field) : null;
    if (field && draft) {
      conditions.push({ key: key++, field: filter.field, draft });
    } else {
      kept.push(filter);
    }
  }
  return { conditions, kept };
}

/** `view_metadata.filters` read defensively: only well-formed entries. */
export function viewFilters(metadata: Record<string, unknown> | null | undefined): QueryFilter[] {
  const raw = metadata?.['filters'];
  if (!Array.isArray(raw)) return [];
  const out: QueryFilter[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const f = item as Record<string, unknown>;
    if (typeof f['field'] !== 'string' || typeof f['op'] !== 'string') continue;
    const value = f['value'];
    out.push(typeof value === 'string'
      ? { field: f['field'], op: f['op'], value }
      : { field: f['field'], op: f['op'] });
  }
  return out;
}
