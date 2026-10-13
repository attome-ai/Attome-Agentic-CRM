import { describe, expect, it } from 'vitest';
import type { FieldSchema } from '@attome/xrm';
import {
  MAX_ADVANCED_CONDITIONS, advancedFindFields, choiceOptions, conditionOperators, conditionsToFilters,
  filtersToConditions, newCondition, viewFilters,
} from './advanced-find';

const field = (
  name: string,
  field_type: FieldSchema['field_type'],
  options: FieldSchema['options'] = null,
): FieldSchema => ({
  id: `f-${name}`, entity_id: 'e-1', name, display_name: name.toUpperCase(), field_type,
  options, sort_order: 0, is_required: false,
});

const FIELDS: FieldSchema[] = [
  field('title', 'text'),
  field('amount', 'currency'),
  field('due', 'date'),
  field('done', 'bool'),
  field('status', 'choice', { choices: ['open', 'closed'], multi: false, option_labels: { open: 'Open' } }),
  field('tags', 'choice', { choices: ['a', 'b'], multi: true }),
  field('owner', 'lookup', { target_entity_id: 't', target_entity_name: 'user_account', display_field: 'email' }),
  field('attachment', 'file'),
];

describe('advanced find (U12 Phase A, D-607)', () => {
  it('caps conditions at the server limit', () => {
    expect(MAX_ADVANCED_CONDITIONS).toBe(50);
  });

  it('offers every field but file uploads, by display name', () => {
    const names = advancedFindFields(FIELDS).map(f => f.name);
    expect(names).not.toContain('attachment');
    expect(names).toEqual(['amount', 'done', 'due', 'owner', 'status', 'tags', 'title']);
  });

  it('offers operators by field type', () => {
    const byName = (n: string) => FIELDS.find(f => f.name === n)!;
    expect(conditionOperators(byName('title'))).toContain('starts_with');
    expect(conditionOperators(byName('amount'))).toContain('between');
    expect(conditionOperators(byName('owner'))).toEqual(['eq', 'neq', 'is_null', 'is_not_null']);
    expect(conditionOperators(byName('status'))).toEqual(['eq', 'neq', 'is_null', 'is_not_null']);
    // A multi-select choice tests membership; `eq`/`neq` are refused server-side.
    expect(conditionOperators(byName('tags'))).toEqual(['contains', 'is_null', 'is_not_null']);
    expect(conditionOperators(byName('done'))).toEqual(['eq']);
  });

  it('labels choice options with their translation, else the value', () => {
    expect(choiceOptions(FIELDS[4])).toEqual([{ value: 'open', label: 'Open' }, { value: 'closed', label: 'closed' }]);
  });

  it('translates rows through the grid translation, skipping incomplete ones', () => {
    const filters = conditionsToFilters([
      { key: 1, field: 'title', draft: { operator: 'starts_with', value: 'ac' } },
      { key: 2, field: 'amount', draft: { operator: 'between', value: '10', valueTo: '20' } },
      { key: 3, field: 'owner', draft: { operator: 'eq', value: 'u-1' } },
      { key: 4, field: 'tags', draft: { operator: 'contains', value: 'a' } },
      { key: 5, field: 'title', draft: { operator: 'equals', value: '' } },
      { key: 6, field: 'gone', draft: { operator: 'eq', value: 'x' } },
    ], FIELDS);
    expect(filters).toEqual([
      { field: 'title', op: 'starts_with', value: 'ac' },
      { field: 'amount', op: 'gte', value: '10' },
      { field: 'amount', op: 'lte', value: '20' },
      { field: 'owner', op: 'eq', value: 'u-1' },
      { field: 'tags', op: 'contains', value: 'a' },
    ]);
  });

  it('a new row starts on the field type first operator', () => {
    expect(newCondition(7, FIELDS[6])).toEqual({ key: 7, field: 'owner', draft: { operator: 'eq' } });
  });

  it('rebuilds rows from saved filters, and round-trips them unchanged', () => {
    const saved = [
      { field: 'title', op: 'eq', value: 'x' },
      { field: 'amount', op: 'gt', value: '5' },
      { field: 'due', op: 'gte', value: '2026-01-01' },
      { field: 'done', op: 'eq', value: 'true' },
      { field: 'status', op: 'neq', value: 'open' },
      { field: 'owner', op: 'is_null' },
    ];
    const { conditions, kept } = filtersToConditions(saved, FIELDS);
    expect(kept).toEqual([]);
    expect(conditions.map(c => c.draft.operator)).toEqual(['equals', 'gt', 'after', 'eq', 'neq', 'is_null']);
    expect(conditionsToFilters(conditions, FIELDS)).toEqual(saved);
  });

  it('keeps, never drops, a saved filter no row reproduces', () => {
    const { conditions, kept } = filtersToConditions([
      { field: 'gone', op: 'eq', value: 'x' },
      { field: 'due', op: 'gt', value: '2026-01-01' },
      { field: 'title', op: 'contains', value: 'a' },
    ], FIELDS);
    expect(conditions.map(c => c.field)).toEqual(['title']);
    expect(kept).toEqual([
      { field: 'gone', op: 'eq', value: 'x' },
      { field: 'due', op: 'gt', value: '2026-01-01' },
    ]);
  });

  it('reads view_metadata.filters defensively', () => {
    expect(viewFilters(null)).toEqual([]);
    expect(viewFilters({ filters: 'nope' })).toEqual([]);
    expect(viewFilters({ filters: [
      { field: 'a', op: 'eq', value: '1' },
      { field: 'b', op: 'is_null', value: null },
      { op: 'eq' },
      42,
    ] })).toEqual([{ field: 'a', op: 'eq', value: '1' }, { field: 'b', op: 'is_null' }]);
  });
});
