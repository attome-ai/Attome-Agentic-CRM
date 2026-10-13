import type { FieldSchema } from '@attome/xrm';
import { describe, expect, it } from 'vitest';
import { chunkRecords, formatSourceRef, parseSourceRef, sha256Hex } from './csv-chunks';
import { buildRecords, coerceCell, parseBool, parseChoice, parseDate, parseNumber } from './csv-coerce';
import { autoMatchColumns } from './csv-mapping';
import { parseCsv } from './csv-parser';

const ISO = { dateFormat: 'iso' as const, decimal: '.' as const };

function field(name: string, type: FieldSchema['field_type'], options: FieldSchema['options'] = null): FieldSchema {
  return { id: name, entity_id: 'e', name, display_name: name, field_type: type, options, sort_order: 0, is_required: false };
}

describe('parseNumber', () => {
  it('reads point-decimal numbers with grouping', () => {
    expect(parseNumber('1,234.5', '.')).toBe(1234.5);
    expect(parseNumber('-12', '.')).toBe(-12);
    expect(parseNumber('.5', '.')).toBe(0.5);
    expect(parseNumber('1 234 567', '.')).toBe(1234567);
  });

  it('reads comma-decimal numbers with grouping', () => {
    expect(parseNumber('1.234,5', ',')).toBe(1234.5);
    expect(parseNumber('0,25', ',')).toBe(0.25);
  });

  it('reads Arabic-Indic digits and separators', () => {
    expect(parseNumber('١٬٢٣٤٫٥', '.')).toBe(1234.5);
    expect(parseNumber('۱۲', '.')).toBe(12);
  });

  it('refuses ambiguous or malformed text instead of guessing', () => {
    expect(parseNumber('1,5', '.')).toBeNull(); // not a thousands group
    expect(parseNumber('12a', '.')).toBeNull();
    expect(parseNumber('-', '.')).toBeNull();
    expect(parseNumber('1.2.3', '.')).toBeNull();
  });
});

describe('parseDate', () => {
  it('accepts ISO dates under every format', () => {
    expect(parseDate('2026-04-03', 'iso')).toBe('2026-04-03');
    expect(parseDate('2026-04-03', 'dmy')).toBe('2026-04-03');
    expect(parseDate('2026-04-03T10:00:00Z', 'iso')).toBe('2026-04-03T10:00:00.000Z');
    expect(parseDate('2026-04-03T10:00:00+03:00', 'iso')).toBe('2026-04-03T07:00:00.000Z');
  });

  it('reads dd/mm/yyyy and mm/dd/yyyy only when chosen', () => {
    expect(parseDate('03/04/2026', 'dmy')).toBe('2026-04-03');
    expect(parseDate('03/04/2026', 'mdy')).toBe('2026-03-04');
    expect(parseDate('3.4.2026', 'dmy')).toBe('2026-04-03');
    expect(parseDate('03/04/2026', 'iso')).toBeNull();
  });

  it('refuses impossible dates', () => {
    expect(parseDate('31/02/2026', 'dmy')).toBeNull();
    expect(parseDate('2026-13-01', 'iso')).toBeNull();
    expect(parseDate('yesterday', 'dmy')).toBeNull();
  });

  it('reads a local date-time as an instant', () => {
    const expected = new Date(2026, 3, 3, 14, 30, 0).toISOString();
    expect(parseDate('03/04/2026 14:30', 'dmy')).toBe(expected);
  });
});

describe('parseBool and parseChoice', () => {
  it('reads yes/no, true/false, 1/0 and Arabic words', () => {
    for (const t of ['yes', 'TRUE', '1', 'y', 'نعم']) expect(parseBool(t)).toBe(true);
    for (const f of ['no', 'False', '0', 'n', 'لا']) expect(parseBool(f)).toBe(false);
    expect(parseBool('maybe')).toBeNull();
  });

  it('matches a choice by value or label, case-insensitively', () => {
    const opts = { choices: ['new', 'won'], multi: false, option_labels: { new: 'New lead', won: 'Closed won' } };
    expect(parseChoice('won', opts)).toBe('won');
    expect(parseChoice('NEW', opts)).toBe('new');
    expect(parseChoice('closed won', opts)).toBe('won');
    expect(parseChoice('lost', opts)).toBeNull();
  });

  it('splits a multi-select cell', () => {
    const opts = { choices: ['a', 'b', 'c'], multi: true };
    expect(parseChoice('a; C|a', opts)).toEqual(['a', 'c']);
    expect(parseChoice('a;z', opts)).toBeNull();
  });
});

describe('coerceCell', () => {
  it('omits an empty cell and checks lookup ids only under by_id', () => {
    const lookup = field('acc', 'lookup');
    expect(coerceCell('  ', field('n', 'number'), 'by_id', ISO)).toEqual({ ok: true, value: undefined });
    expect(coerceCell('Acme', lookup, 'by_label', ISO)).toEqual({ ok: true, value: 'Acme' });
    expect(coerceCell('Acme', lookup, 'by_id', ISO)).toEqual({ ok: false, code: 'uuid' });
  });

  it('keeps text as written', () => {
    expect(coerceCell(' padded ', field('t', 'text'), 'by_id', ISO)).toEqual({ ok: true, value: ' padded ' });
  });
});

describe('buildRecords', () => {
  const FIELDS = [field('name', 'text'), field('amount', 'number'), field('active', 'bool')];

  it('coerces per target type, keys by header, and reports every bad cell with its row', () => {
    const parsed = parseCsv('name,amount,active\nA,"1,200.50",yes\nB,abc,maybe\nC,3\n,,\n');
    const cols = autoMatchColumns(parsed.headers, FIELDS);
    const built = buildRecords(parsed, cols, FIELDS, ISO);
    expect(built.records).toEqual([{ index: 0, data: { name: 'A', amount: 1200.5, active: true } }]);
    expect(built.invalidRows).toBe(3);
    expect(built.errors.map(e => [e.rowNumber, e.column, e.code])).toEqual([
      [3, 'amount', 'number'],
      [3, 'active', 'bool'],
      [4, null, 'ragged'],
      [5, null, 'empty'],
    ]);
  });

  it('leaves ignored columns out of the record', () => {
    const parsed = parseCsv('name,secret\nA,x\n');
    const cols = autoMatchColumns(parsed.headers, FIELDS);
    expect(buildRecords(parsed, cols, FIELDS, ISO).records[0].data).toEqual({ name: 'A' });
  });
});

describe('chunkRecords', () => {
  const records = Array.from({ length: 1201 }, (_, index) => ({ index, data: { name: `r${index}` } }));

  it('splits into at most 500 records per chunk, in order', () => {
    const chunks = chunkRecords(records);
    expect(chunks.map(c => c.records.length)).toEqual([500, 500, 201]);
    expect(chunks.map(c => c.index)).toEqual([0, 1, 2]);
    expect(chunks[1].records[0].index).toBe(500);
  });

  it('splits earlier when a chunk would exceed the byte budget', () => {
    const chunks = chunkRecords(records.slice(0, 10), 500, 60);
    expect(chunks.every(c => c.records.length <= 3)).toBe(true);
    expect(chunks.flatMap(c => c.records).length).toBe(10);
  });

  it('is deterministic, so a resume sees the same chunks', () => {
    expect(chunkRecords(records)).toEqual(chunkRecords(records));
  });
});

describe('source ref', () => {
  it('round-trips and rejects anything else', async () => {
    const sha = await sha256Hex(new TextEncoder().encode('abc'));
    expect(sha).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const ref = { sha256: sha, rows: 10, encoding: 'windows-1256' as const, dateFormat: 'dmy' as const, decimal: ',' as const };
    expect(parseSourceRef(formatSourceRef(ref))).toEqual(ref);
    expect(parseSourceRef('some legacy ref')).toBeNull();
    expect(parseSourceRef(null)).toBeNull();
  });
});
