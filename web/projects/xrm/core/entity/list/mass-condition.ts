import type { QueryFilter } from './column-filters';

// AA10-T8: kept out of mass-confirm-dialog.component.ts so the list can
// import it without pulling the deferred dialog into its own chunk.

/** A query-engine condition (`query/run`'s `where`). */
export type MassCondition =
  | { kind: 'and'; all: MassCondition[] }
  | { kind: 'compare'; field: string; op: string; value?: string };

/** List filter ops the query engine cannot take as a `compare`. */
const NOT_A_COMPARE = new Set(['tagged']);

/**
 * The list's filters as one mass-operation condition: each filter is a
 * `compare` (both go through the same filter compiler, so the ops carry
 * over), all of them must hold. `null` is "every record"; `undefined`
 * means a filter (a tag filter) has no condition form, and the list must
 * not offer the mass action rather than run it over more than it shows.
 * Pure.
 */
export function filtersToCondition(filters: readonly QueryFilter[]): MassCondition | null | undefined {
  if (filters.some(f => NOT_A_COMPARE.has(f.op))) return undefined;
  const all: MassCondition[] = filters.map(f => (
    f.value === undefined
      ? { kind: 'compare', field: f.field, op: f.op }
      : { kind: 'compare', field: f.field, op: f.op, value: f.value }
  ));
  if (!all.length) return null;
  return all.length === 1 ? all[0] : { kind: 'and', all };
}
