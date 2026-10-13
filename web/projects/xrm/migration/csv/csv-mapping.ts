import type { FieldSchema } from '@attome/xrm';

/**
 * U11 / D-606 — CSV columns onto entity attributes, expressed in D-408's one
 * mapping model (`data_mapping.fields[]`, `DataMappingField` in
 * `crates/engine/attome-records/src/data_mapping.rs`). A column's header is
 * the mapping's `source`; the server renames it to `target` and resolves
 * lookups (`by_id` passthrough, `by_label` against the referenced entity's
 * `name`, `by_natural_key` against `lookup_match_field`) when each chunk is
 * staged. Nothing here resolves a lookup itself.
 */

export type LookupResolution = 'by_id' | 'by_natural_key' | 'by_label';

/** `DataMappingField` on the wire. `transform` is never set here (D-408). */
export interface DataMappingField {
  source: string;
  target: string;
  transform?: string | null;
  lookup_resolution: LookupResolution;
  lookup_match_field?: string | null;
}

export interface ColumnMapping {
  /** 0-based column index in the parsed file. */
  column: number;
  /** The column's header: the mapping's `source`. */
  source: string;
  /** Target attribute logical name, or null when the column is ignored. */
  target: string | null;
  lookupResolution: LookupResolution;
  lookupMatchField: string | null;
}

/** Field types a CSV cell can carry. A file field holds an object key. */
export function importableFields(fields: FieldSchema[]): FieldSchema[] {
  return fields.filter(f => f.field_type !== 'file');
}

/** Case-, space-, `_`/`-`/`.`-insensitive comparison key. */
export function normaliseName(name: string): string {
  return name.normalize('NFKC').toLocaleLowerCase().replace(/[\s_\-.]+/g, '');
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Header -> attribute by logical name first, then by display name. Each
 * attribute is taken once, by the first column that matches it. A lookup
 * column defaults to `by_id` when every sampled value is a UUID and to
 * `by_label` otherwise — CSV exports usually carry the referenced record's
 * name, not its id.
 */
export function autoMatchColumns(
  headers: string[],
  fields: FieldSchema[],
  sampleRows: string[][] = [],
): ColumnMapping[] {
  const candidates = importableFields(fields);
  const byName = new Map(candidates.map(f => [normaliseName(f.name), f]));
  const byDisplay = new Map<string, FieldSchema>();
  for (const f of candidates) {
    const key = normaliseName(f.display_name ?? '');
    if (key && !byDisplay.has(key)) byDisplay.set(key, f);
  }
  // Two passes, so a logical-name match is never lost to an earlier column
  // that only matched the same attribute's display name.
  const taken = new Set<string>();
  const matches: (FieldSchema | null)[] = headers.map(() => null);
  for (const lookup of [byName, byDisplay]) {
    headers.forEach((source, column) => {
      if (matches[column]) return;
      const f = lookup.get(normaliseName(source));
      if (f && !taken.has(f.name)) {
        matches[column] = f;
        taken.add(f.name);
      }
    });
  }
  return headers.map((source, column) => {
    const match = matches[column];
    return {
      column,
      source,
      target: match?.name ?? null,
      lookupResolution: match?.field_type === 'lookup' ? defaultResolution(sampleRows, column) : 'by_id',
      lookupMatchField: null,
    };
  });
}

function defaultResolution(sampleRows: string[][], column: number): LookupResolution {
  const values = sampleRows.map(r => (r[column] ?? '').trim()).filter(v => v !== '');
  return values.length > 0 && values.every(v => UUID_RE.test(v)) ? 'by_id' : 'by_label';
}

/**
 * Applies a saved mapping to a file's headers: a column is mapped when its
 * header equals a `source` (exactly, else by `normaliseName`). Columns the
 * mapping does not name are ignored — a saved mapping is reused as it is.
 */
export function columnsFromMapping(headers: string[], mapping: DataMappingField[]): ColumnMapping[] {
  const exact = new Map(mapping.map(m => [m.source, m]));
  const loose = new Map(mapping.map(m => [normaliseName(m.source), m]));
  return headers.map((source, column) => {
    const m = exact.get(source) ?? loose.get(normaliseName(source)) ?? null;
    return {
      column,
      source: m?.source ?? source,
      target: m?.target ?? null,
      lookupResolution: m?.lookup_resolution ?? 'by_id',
      lookupMatchField: m?.lookup_match_field ?? null,
    };
  });
}

/** Mapping sources the file has no column for, so the mapping cannot be reused as is. */
export function unmatchedSources(headers: string[], mapping: DataMappingField[]): string[] {
  const cols = columnsFromMapping(headers, mapping);
  const present = new Set(cols.filter(c => c.target).map(c => c.source));
  return mapping.map(m => m.source).filter(s => !present.has(s));
}

/** The `fields[]` to save: mapped columns only, lookup settings only on lookups. */
export function mappingFieldsFromColumns(columns: ColumnMapping[], fields: FieldSchema[]): DataMappingField[] {
  const types = new Map(fields.map(f => [f.name, f.field_type]));
  return columns
    .filter(c => c.target !== null)
    .map(c => {
      const isLookup = types.get(c.target as string) === 'lookup';
      const out: DataMappingField = {
        source: c.source,
        target: c.target as string,
        lookup_resolution: isLookup ? c.lookupResolution : 'by_id',
      };
      if (isLookup && c.lookupResolution === 'by_natural_key') out.lookup_match_field = c.lookupMatchField;
      return out;
    });
}

/** Order-insensitive equality of two `fields[]` lists (decides reuse vs save). */
export function sameMappingFields(a: DataMappingField[], b: DataMappingField[]): boolean {
  const key = (f: DataMappingField) =>
    [f.source, f.target, f.lookup_resolution ?? 'by_id', f.lookup_match_field ?? '', f.transform ?? ''].join('\u0000');
  const ka = a.map(key).sort();
  const kb = b.map(key).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]);
}

export type MappingProblem =
  | { code: 'none_mapped' }
  | { code: 'duplicate_target'; target: string }
  | { code: 'match_field_missing'; source: string };

/** What must be fixed before the mapping can be saved (the server checks too). */
export function mappingProblems(columns: ColumnMapping[], fields: FieldSchema[]): MappingProblem[] {
  const problems: MappingProblem[] = [];
  const mapped = columns.filter(c => c.target !== null);
  if (mapped.length === 0) problems.push({ code: 'none_mapped' });
  const seen = new Set<string>();
  for (const c of mapped) {
    const target = c.target as string;
    if (seen.has(target)) problems.push({ code: 'duplicate_target', target });
    seen.add(target);
    const isLookup = fields.find(f => f.name === target)?.field_type === 'lookup';
    if (isLookup && c.lookupResolution === 'by_natural_key' && !c.lookupMatchField?.trim()) {
      problems.push({ code: 'match_field_missing', source: c.source });
    }
  }
  return problems;
}
