import type { FieldSchema } from '@attome/xrm';
import { describe, expect, it } from 'vitest';
import {
  autoMatchColumns,
  columnsFromMapping,
  importableFields,
  mappingFieldsFromColumns,
  mappingProblems,
  normaliseName,
  sameMappingFields,
  unmatchedSources,
} from './csv-mapping';

function field(name: string, display: string, type: FieldSchema['field_type'] = 'text'): FieldSchema {
  return {
    id: name, entity_id: 'e', name, display_name: display, field_type: type,
    options: null, sort_order: 0, is_required: false,
  };
}

const FIELDS = [
  field('full_name', 'Full name'),
  field('email', 'E-mail'),
  field('account_ref', 'Account', 'lookup'),
  field('photo', 'Photo', 'file'),
  field('city', 'المدينة'),
];

describe('autoMatchColumns', () => {
  it('matches by logical name or display name, ignoring case, spaces and punctuation', () => {
    const cols = autoMatchColumns(['FULL NAME', 'Email', 'account', 'المدينة', 'Notes'], FIELDS);
    expect(cols.map(c => c.target)).toEqual(['full_name', 'email', 'account_ref', 'city', null]);
  });

  it('prefers a logical-name match and gives each attribute to one column only', () => {
    // "Account" is account_ref's display name; "account_ref" its logical name.
    const cols = autoMatchColumns(['Account', 'account_ref'], FIELDS);
    expect(cols.map(c => c.target)).toEqual([null, 'account_ref']);
  });

  it('never maps a file field', () => {
    expect(autoMatchColumns(['photo'], FIELDS)[0].target).toBeNull();
    expect(importableFields(FIELDS).map(f => f.name)).not.toContain('photo');
  });

  it('defaults a lookup to by_label unless every sampled value is a UUID', () => {
    expect(autoMatchColumns(['account'], FIELDS, [['Acme']])[0].lookupResolution).toBe('by_label');
    const id = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';
    expect(autoMatchColumns(['account'], FIELDS, [[id], ['']])[0].lookupResolution).toBe('by_id');
  });
});

describe('mapping fields (D-408 fields[])', () => {
  it('saves mapped columns only, with lookup settings on lookups only', () => {
    const cols = autoMatchColumns(['Full name', 'account', 'Ignored'], FIELDS, [['a', 'Acme', 'x']]);
    cols[1] = { ...cols[1], lookupResolution: 'by_natural_key', lookupMatchField: 'code' };
    expect(mappingFieldsFromColumns(cols, FIELDS)).toEqual([
      { source: 'Full name', target: 'full_name', lookup_resolution: 'by_id' },
      { source: 'account', target: 'account_ref', lookup_resolution: 'by_natural_key', lookup_match_field: 'code' },
    ]);
  });

  it('applies a saved mapping to a file and reports the sources it lacks', () => {
    const saved = [
      { source: 'Full name', target: 'full_name', lookup_resolution: 'by_id' as const },
      { source: 'Account', target: 'account_ref', lookup_resolution: 'by_label' as const },
    ];
    const cols = columnsFromMapping(['full name', 'Email'], saved);
    expect(cols.map(c => [c.source, c.target])).toEqual([['Full name', 'full_name'], ['Email', null]]);
    expect(unmatchedSources(['full name', 'Email'], saved)).toEqual(['Account']);
  });

  it('compares mappings regardless of order', () => {
    const a = [
      { source: 'x', target: 'full_name', lookup_resolution: 'by_id' as const },
      { source: 'y', target: 'email', lookup_resolution: 'by_id' as const },
    ];
    expect(sameMappingFields(a, [...a].reverse())).toBe(true);
    expect(sameMappingFields(a, [a[0]])).toBe(false);
  });

  it('reports what blocks saving', () => {
    const cols = autoMatchColumns(['full_name', 'Full name', 'account'], FIELDS);
    cols[1] = { ...cols[1], target: 'full_name' };
    cols[2] = { ...cols[2], lookupResolution: 'by_natural_key', lookupMatchField: ' ' };
    expect(mappingProblems(cols, FIELDS)).toEqual([
      { code: 'duplicate_target', target: 'full_name' },
      { code: 'match_field_missing', source: 'account' },
    ]);
    expect(mappingProblems(autoMatchColumns(['zzz'], FIELDS), FIELDS)).toEqual([{ code: 'none_mapped' }]);
  });

  it('normalises names', () => {
    expect(normaliseName(' First_Name-2 ')).toBe('firstname2');
  });
});
