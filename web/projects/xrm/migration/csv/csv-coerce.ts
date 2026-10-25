import type { ChoiceOptions, FieldSchema } from '@attome/xrm';
import type { ParsedCsv } from './csv-parser';
import type { ColumnMapping, LookupResolution } from './csv-mapping';

/**
 * U11 / D-606 — CSV cell text -> the JSON value the entity engine accepts for
 * the target attribute (`attome_field::validate`): numbers as JSON numbers,
 * dates as `YYYY-MM-DD` or RFC 3339, booleans as JSON booleans, choices as a
 * stored value (an array for a multi-select), lookups as text the mapping
 * resolves server-side. Done in the browser so every bad cell is reported
 * with its row and column before anything is staged; the server validates
 * again on stage and on apply.
 */

/** How to read `03/04/2026`. ISO dates (`2026-04-03`) are accepted under every setting. */
export type DateFormat = 'iso' | 'dmy' | 'mdy';
export type DecimalSeparator = '.' | ',';

export interface CoercionOptions {
  dateFormat: DateFormat;
  decimal: DecimalSeparator;
}

export type CellErrorCode = 'number' | 'date' | 'bool' | 'choice' | 'uuid' | 'color';
export type RowErrorCode = CellErrorCode | 'ragged' | 'empty';

/** `undefined` value = empty cell, omitted from the record. */
export type CellResult = { ok: true; value: unknown } | { ok: false; code: CellErrorCode };

const ARABIC_INDIC = /[\u0660-\u0669\u06f0-\u06f9]/g;

/** Arabic-Indic and Extended Arabic-Indic digits -> ASCII digits. */
export function asciiDigits(s: string): string {
  return s.replace(ARABIC_INDIC, ch => {
    const code = ch.charCodeAt(0);
    return String(code >= 0x06f0 ? code - 0x06f0 : code - 0x0660);
  });
}

export function coerceCell(
  raw: string,
  field: Pick<FieldSchema, 'field_type' | 'options'>,
  lookupResolution: LookupResolution,
  opts: CoercionOptions,
): CellResult {
  const trimmed = raw.trim();
  if (trimmed === '') return { ok: true, value: undefined };
  switch (field.field_type) {
    case 'number':
    case 'currency': {
      const n = parseNumber(trimmed, opts.decimal);
      return n === null ? { ok: false, code: 'number' } : { ok: true, value: n };
    }
    case 'date':
    case 'date_time': {
      const d = parseDate(trimmed, opts.dateFormat);
      return d === null ? { ok: false, code: 'date' } : { ok: true, value: d };
    }
    case 'bool': {
      const b = parseBool(trimmed);
      return b === null ? { ok: false, code: 'bool' } : { ok: true, value: b };
    }
    case 'choice': {
      const c = parseChoice(trimmed, field.options as ChoiceOptions | null);
      return c === null ? { ok: false, code: 'choice' } : { ok: true, value: c };
    }
    case 'lookup':
      if (lookupResolution === 'by_id' && !UUID_RE.test(trimmed)) return { ok: false, code: 'uuid' };
      return { ok: true, value: trimmed };
    case 'color':
      return /^#[0-9a-f]{6}$/i.test(trimmed) ? { ok: true, value: trimmed } : { ok: false, code: 'color' };
    case 'text':
      return { ok: true, value: raw };
    default:
      return { ok: true, value: trimmed };
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * `1,234.5` / `1.234,5` / `1 234,5` / `١٬٢٣٤٫٥`. Grouping must be in threes, so
 * `1,5` under a `.` decimal is an error rather than silently 15.
 */
export function parseNumber(input: string, decimal: DecimalSeparator): number | null {
  const group = decimal === '.' ? ',' : '.';
  let s = asciiDigits(input.trim())
    .replace(/\u066b/g, decimal) // Arabic decimal separator
    .replace(/[\u066c'\u00a0\u202f ]/g, group); // Arabic thousands, apostrophe, spaces
  const g = group === '.' ? '\\.' : ',';
  const d = decimal === '.' ? '\\.' : ',';
  const re = new RegExp(`^[+-]?(?:\\d{1,3}(?:${g}\\d{3})+|\\d+)?(?:${d}\\d+)?$`);
  if (!re.test(s) || !/\d/.test(s)) return null;
  s = s.split(group).join('');
  if (decimal === ',') s = s.replace(',', '.');
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const ISO_DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/i;
const SLASH_DATE = /^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/;

/**
 * Date-only input -> `YYYY-MM-DD`. Input with a time -> RFC 3339 in UTC; a
 * time without an offset is read in the browser's time zone.
 */
export function parseDate(input: string, format: DateFormat): string | null {
  const s = asciiDigits(input.trim());
  let m = ISO_DATE.exec(s);
  if (m) return validYmd(+m[1], +m[2], +m[3]) ? s : null;
  m = ISO_DATE_TIME.exec(s);
  if (m) {
    if (!validYmd(+m[1], +m[2], +m[3]) || !validTime(+m[4], +m[5], +(m[6] ?? 0))) return null;
    if (m[7]) {
      const zone = m[7].toUpperCase() === 'Z' ? 'Z' : m[7].replace(/^([+-]\d{2})(\d{2})$/, '$1:$2');
      const t = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}${zone}`);
      return Number.isNaN(t) ? null : new Date(t).toISOString();
    }
    return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] ?? 0)).toISOString();
  }
  if (format === 'iso') return null;
  m = SLASH_DATE.exec(s);
  if (!m) return null;
  const day = format === 'dmy' ? +m[1] : +m[2];
  const month = format === 'dmy' ? +m[2] : +m[1];
  const year = +m[3];
  if (!validYmd(year, month, day)) return null;
  if (m[4] === undefined) return `${year}-${pad(month)}-${pad(day)}`;
  if (!validTime(+m[4], +m[5], +(m[6] ?? 0))) return null;
  return new Date(year, month - 1, day, +m[4], +m[5], +(m[6] ?? 0)).toISOString();
}

function validYmd(y: number, m: number, d: number): boolean {
  if (m < 1 || m > 12 || d < 1) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function validTime(h: number, mi: number, s: number): boolean {
  return h <= 23 && mi <= 59 && s <= 59;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

const TRUE_WORDS = new Set(['true', 'yes', 'y', '1', 't', 'نعم', 'صح']);
const FALSE_WORDS = new Set(['false', 'no', 'n', '0', 'f', 'لا', 'خطأ']);

export function parseBool(input: string): boolean | null {
  const s = asciiDigits(input.trim()).toLocaleLowerCase();
  if (TRUE_WORDS.has(s)) return true;
  if (FALSE_WORDS.has(s)) return false;
  return null;
}

/**
 * A stored value or its label (case-insensitive). A multi-select cell lists
 * several, separated by `;` or `|`. A choice field with no declared choices
 * takes the text as it is.
 */
export function parseChoice(input: string, options: ChoiceOptions | null): string | string[] | null {
  const choices = options?.choices ?? [];
  if (choices.length === 0) return input.trim();
  const labels = options?.option_labels ?? {};
  const resolve = (token: string): string | null => {
    const t = token.trim();
    if (choices.includes(t)) return t;
    const lower = t.toLocaleLowerCase();
    return (
      choices.find(c => c.toLocaleLowerCase() === lower) ??
      choices.find(c => (labels[c] ?? '').toLocaleLowerCase() === lower && labels[c] !== undefined) ??
      null
    );
  };
  if (!options?.multi) return resolve(input);
  const out: string[] = [];
  for (const token of input.split(/[;|]/)) {
    if (token.trim() === '') continue;
    const v = resolve(token);
    if (v === null) return null;
    if (!out.includes(v)) out.push(v);
  }
  return out.length ? out : null;
}

export interface RowError {
  /** 0-based data-row index. */
  index: number;
  /** Spreadsheet row number (header = 1). */
  rowNumber: number;
  /** Column header, or null for a whole-row problem. */
  column: string | null;
  value: string;
  code: RowErrorCode;
}

export interface ImportRecord {
  /** 0-based data-row index in the file. */
  index: number;
  /** Keyed by column header (the mapping's `source`). */
  data: Record<string, unknown>;
}

export interface BuiltRecords {
  records: ImportRecord[];
  /** Data rows that produced at least one error; never staged. */
  invalidRows: number;
  /** Every error, capped at `errorCap` entries (`errorCount` is exact). */
  errors: RowError[];
  errorCount: number;
}

/**
 * Every data row -> an import record, or errors. A row with any error is left
 * out whole; rows are never partially imported.
 */
export function buildRecords(
  parsed: ParsedCsv,
  columns: ColumnMapping[],
  fields: FieldSchema[],
  opts: CoercionOptions,
  errorCap = 1000,
): BuiltRecords {
  const byName = new Map(fields.map(f => [f.name, f]));
  const mapped = columns
    .filter(c => c.target !== null && byName.has(c.target))
    .map(c => ({ col: c, field: byName.get(c.target as string) as FieldSchema }));
  const ragged = new Set(parsed.ragged.map(r => r.index));
  const records: ImportRecord[] = [];
  const errors: RowError[] = [];
  let errorCount = 0;
  let invalidRows = 0;
  const push = (e: RowError) => {
    errorCount++;
    if (errors.length < errorCap) errors.push(e);
  };

  parsed.rows.forEach((row, index) => {
    const rowNumber = parsed.rowNumbers[index];
    if (ragged.has(index)) {
      invalidRows++;
      push({ index, rowNumber, column: null, value: '', code: 'ragged' });
      return;
    }
    const data: Record<string, unknown> = {};
    let bad = false;
    for (const { col, field } of mapped) {
      const raw = row[col.column] ?? '';
      const result = coerceCell(raw, field, col.lookupResolution, opts);
      if (!result.ok) {
        bad = true;
        push({ index, rowNumber, column: col.source, value: raw, code: result.code });
      } else if (result.value !== undefined) {
        data[col.source] = result.value;
      }
    }
    if (bad) {
      invalidRows++;
      return;
    }
    if (Object.keys(data).length === 0) {
      invalidRows++;
      push({ index, rowNumber, column: null, value: '', code: 'empty' });
      return;
    }
    records.push({ index, data });
  });
  return { records, invalidRows, errors, errorCount };
}
