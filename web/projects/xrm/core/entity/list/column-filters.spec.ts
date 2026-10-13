import { describe, expect, it } from 'vitest';
import {
  columnFilterToQueryFilters, deserializeColumnFilters, draftOperator, draftValue, draftValueTo,
  fieldTypeToFilterKind, isColumnFilterDraftActive, isValuelessOperator, serializeColumnFilters,
  splitExportFilters,
} from './column-filters';

describe('entity-list URL filters', () => {
  it('round-trips filters and serializes fields deterministically', () => {
    const encoded = serializeColumnFilters({
      status: { operator: 'eq', value: 'active' },
      age: { operator: 'gte', value: 18 },
      enabled: { operator: 'eq', value: false },
    });

    expect(encoded).toBe('[{"field":"age","operator":"gte","value":18},{"field":"enabled","operator":"eq","value":false},{"field":"status","operator":"eq","value":"active"}]');
    expect(deserializeColumnFilters(encoded)).toEqual({
      age: { operator: 'gte', value: 18 },
      enabled: { operator: 'eq', value: false },
      status: { operator: 'eq', value: 'active' },
    });
  });

  it('removes the parameter for an empty filter set', () => {
    expect(serializeColumnFilters({})).toBeNull();
  });

  it('ignores malformed URL data instead of breaking the list', () => {
    expect(deserializeColumnFilters('not-json')).toEqual({});
    expect(deserializeColumnFilters('{"field":"name"}')).toEqual({});
    expect(deserializeColumnFilters('[{"field":"name","value":{"nested":true}}]')).toEqual({});
  });

  it('round-trips a between range and drops one whose upper bound is not scalar', () => {
    const encoded = serializeColumnFilters({ amount: { operator: 'between', value: 2, valueTo: 5 } });
    expect(deserializeColumnFilters(encoded)).toEqual({ amount: { operator: 'between', value: 2, valueTo: 5 } });
    expect(deserializeColumnFilters('[{"field":"amount","operator":"between","value":2,"valueTo":[5]}]'))
      .toEqual({});
  });
});

describe('entity-list column filter operators (T5-1)', () => {
  it('sends the text operator the user picked, not always contains', () => {
    expect(columnFilterToQueryFilters('name', { operator: 'contains', value: ' ab ' }, 'text'))
      .toEqual([{ field: 'name', op: 'contains', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { operator: 'equals', value: 'ab' }, 'text'))
      .toEqual([{ field: 'name', op: 'eq', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { operator: 'neq', value: 'ab' }, 'text'))
      .toEqual([{ field: 'name', op: 'neq', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { operator: 'starts_with', value: 'ab' }, 'text'))
      .toEqual([{ field: 'name', op: 'starts_with', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { operator: 'ends_with', value: 'ab' }, 'text'))
      .toEqual([{ field: 'name', op: 'ends_with', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { value: 'ab' }, 'text'))
      .toEqual([{ field: 'name', op: 'contains', value: 'ab' }]);
    expect(columnFilterToQueryFilters('name', { operator: 'equals', value: '  ' }, 'text')).toEqual([]);
  });

  it('sends is_null / is_not_null with no value, and treats them as active without one', () => {
    expect(columnFilterToQueryFilters('name', { operator: 'is_null' }, 'text'))
      .toEqual([{ field: 'name', op: 'is_null' }]);
    expect(columnFilterToQueryFilters('amount', { operator: 'is_not_null', value: '' }, 'number'))
      .toEqual([{ field: 'amount', op: 'is_not_null' }]);
    expect(columnFilterToQueryFilters('due', { operator: 'is_null' }, 'date'))
      .toEqual([{ field: 'due', op: 'is_null' }]);
    expect(isColumnFilterDraftActive({ operator: 'is_null' })).toBe(true);
    expect(isColumnFilterDraftActive({ operator: 'is_not_null', value: null })).toBe(true);
    expect(isColumnFilterDraftActive({ operator: 'equals', value: '' })).toBe(false);
    expect(isColumnFilterDraftActive(undefined)).toBe(false);
  });

  it('covers every number comparison and sends between as an inclusive gte/lte pair', () => {
    for (const op of ['eq', 'neq', 'gt', 'gte', 'lt', 'lte']) {
      expect(columnFilterToQueryFilters('amount', { operator: op, value: '7' }, 'number'))
        .toEqual([{ field: 'amount', op, value: '7' }]);
    }
    expect(columnFilterToQueryFilters('amount', { operator: 'between', value: '2', valueTo: 5 }, 'number'))
      .toEqual([
        { field: 'amount', op: 'gte', value: '2' },
        { field: 'amount', op: 'lte', value: '5' },
      ]);
    expect(columnFilterToQueryFilters('amount', { operator: 'between', value: '2' }, 'number')).toEqual([]);
    expect(columnFilterToQueryFilters('amount', { operator: 'between', value: 'x', valueTo: '5' }, 'number'))
      .toEqual([]);
    expect(isColumnFilterDraftActive({ operator: 'between', value: 2 })).toBe(false);
    expect(isColumnFilterDraftActive({ operator: 'between', value: 2, valueTo: 5 })).toBe(true);
  });

  it('keeps the date presets anchored to the injected clock and adds a date range', () => {
    const now = new Date(2026, 7, 25, 15, 30);
    expect(columnFilterToQueryFilters('due', { operator: 'today' }, 'date', now))
      .toEqual([{ field: 'due', op: 'gte', value: '2026-08-25' }]);
    expect(columnFilterToQueryFilters('due', { operator: 'past_7_days' }, 'date', now))
      .toEqual([{ field: 'due', op: 'gte', value: '2026-08-19' }]);
    expect(columnFilterToQueryFilters('due', { operator: 'before', value: '2026-01-01' }, 'date', now))
      .toEqual([{ field: 'due', op: 'lte', value: '2026-01-01' }]);
    expect(columnFilterToQueryFilters('due', { operator: 'between', value: '2026-01-01', valueTo: '2026-01-31' }, 'date'))
      .toEqual([
        { field: 'due', op: 'gte', value: '2026-01-01' },
        { field: 'due', op: 'lte', value: '2026-01-31' },
      ]);
    expect(columnFilterToQueryFilters('due', { operator: '' }, 'date', now)).toEqual([]);
  });

  it('leaves boolean and option-set filters on eq; only the option set takes a null test', () => {
    expect(columnFilterToQueryFilters('flag', { operator: 'eq', value: false }, 'boolean'))
      .toEqual([{ field: 'flag', op: 'eq', value: 'false' }]);
    expect(columnFilterToQueryFilters('status', { operator: 'eq', value: 'open' }, 'optionset'))
      .toEqual([{ field: 'status', op: 'eq', value: 'open' }]);
    expect(columnFilterToQueryFilters('status', { operator: 'is_null' }, 'optionset'))
      .toEqual([{ field: 'status', op: 'is_null' }]);
    expect(columnFilterToQueryFilters('flag', { operator: 'is_null' }, 'boolean')).toEqual([]);
    expect(columnFilterToQueryFilters('tags', { operator: 'contains', value: 'a' }, 'optionset'))
      .toEqual([{ field: 'tags', op: 'contains', value: 'a' }]);
  });
});

describe('entity-list generic draft accessors', () => {
  it('draftOperator falls back when the stored operator is absent or not in the valid set', () => {
    expect(draftOperator(undefined, ['a', 'b'] as const, 'a')).toBe('a');
    expect(draftOperator({ operator: 'bogus' }, ['a', 'b'] as const, 'a')).toBe('a');
    expect(draftOperator({ operator: 'b' }, ['a', 'b'] as const, 'a')).toBe('b');
  });

  it('draftValue/draftValueTo read the raw value as a string, empty when absent', () => {
    expect(draftValue(undefined)).toBe('');
    expect(draftValue({ value: 7 })).toBe('7');
    expect(draftValueTo({ valueTo: 'x' })).toBe('x');
    expect(draftValueTo({})).toBe('');
  });

  it('isValuelessOperator matches exactly the null-tests and relative date presets', () => {
    expect(isValuelessOperator('is_null')).toBe(true);
    expect(isValuelessOperator('today')).toBe(true);
    expect(isValuelessOperator('eq')).toBe(false);
  });

  it('fieldTypeToFilterKind maps the known field types and defaults everything else to text', () => {
    expect(fieldTypeToFilterKind('number')).toBe('number');
    expect(fieldTypeToFilterKind('date')).toBe('date');
    expect(fieldTypeToFilterKind('bool')).toBe('boolean');
    expect(fieldTypeToFilterKind('choice')).toBe('optionset');
    expect(fieldTypeToFilterKind('text')).toBe('text');
    expect(fieldTypeToFilterKind('lookup')).toBe('lookup');
    // U9: rich text and image filter as text; a formula column arrives as
    // its result type, so a stray 'formula' is text too.
    expect(fieldTypeToFilterKind('rich_text')).toBe('text');
    expect(fieldTypeToFilterKind('image')).toBe('text');
    expect(fieldTypeToFilterKind('formula')).toBe('text');
  });

  it('a lookup filter is id equality or emptiness, never contains (D-607)', () => {
    expect(columnFilterToQueryFilters('owner', { operator: 'eq', value: 'u-1' }, 'lookup'))
      .toEqual([{ field: 'owner', op: 'eq', value: 'u-1' }]);
    expect(columnFilterToQueryFilters('owner', { operator: 'neq', value: 'u-1' }, 'lookup'))
      .toEqual([{ field: 'owner', op: 'neq', value: 'u-1' }]);
    expect(columnFilterToQueryFilters('owner', { operator: 'contains', value: 'u-1' }, 'lookup'))
      .toEqual([{ field: 'owner', op: 'eq', value: 'u-1' }]);
    expect(columnFilterToQueryFilters('owner', { operator: 'is_null' }, 'lookup'))
      .toEqual([{ field: 'owner', op: 'is_null' }]);
    expect(columnFilterToQueryFilters('owner', { operator: 'eq', value: '' }, 'lookup')).toEqual([]);
  });

  it('an optionset filter can be negated', () => {
    expect(columnFilterToQueryFilters('status', { operator: 'neq', value: 'open' }, 'optionset'))
      .toEqual([{ field: 'status', op: 'neq', value: 'open' }]);
  });
});

describe('entity-list export filters (D-408)', () => {
  it('forwards every filter the export grammar expresses exactly', () => {
    const filters = [
      ...columnFilterToQueryFilters('name', { operator: 'contains', value: 'acme' }, 'text'),
      ...columnFilterToQueryFilters('amount', { operator: 'between', value: 10, valueTo: 20 }, 'number'),
      ...columnFilterToQueryFilters('closed_on', { operator: 'is_null' }, 'date'),
    ];
    const { exportable, unsupported } = splitExportFilters(filters);

    expect(unsupported).toEqual([]);
    expect(exportable).toEqual([
      { field: 'name', op: 'contains', value: 'acme' },
      { field: 'amount', op: 'gte', value: '10' },
      { field: 'amount', op: 'lte', value: '20' },
      { field: 'closed_on', op: 'is_null' },
    ]);
  });

  it('forwards the operators D-607 added to the shared compiler too', () => {
    const filters = [
      ...columnFilterToQueryFilters('name', { operator: 'starts_with', value: 'ac' }, 'text'),
      ...columnFilterToQueryFilters('amount', { operator: 'neq', value: 5 }, 'number'),
      ...columnFilterToQueryFilters('owner', { operator: 'is_not_null' }, 'text'),
      ...columnFilterToQueryFilters('status', { value: 'open' }, 'optionset'),
    ];
    const { exportable, unsupported } = splitExportFilters(filters);

    expect(unsupported).toEqual([]);
    expect(exportable.map(f => f.op)).toEqual(['starts_with', 'neq', 'is_not_null', 'eq']);
  });

  it('reports, never approximates, an operator export cannot express', () => {
    const { exportable, unsupported } = splitExportFilters([{ field: 'tags', op: 'contains_any', value: 'a' }]);
    expect(exportable).toEqual([]);
    expect(unsupported.map(f => f.op)).toEqual(['contains_any']);
  });
});
