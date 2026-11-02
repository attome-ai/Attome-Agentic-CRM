/**
 * P6-T1: a cohort widget's grid, from a stored query's rows and the widget's
 * config: `cohort_key_field` (one row per cohort), `period_field` (one column
 * per period since the cohort began) and `value_field` (the retained count or
 * rate). The query does the counting; this only lays its rows out. Cohorts
 * and periods are ordered numerically when every key is a number, otherwise
 * as text, which orders ISO dates by time. A cell no row fills is empty. Pure.
 */
export interface CohortRow {
  cohort: string;
  cells: (number | null)[];
}

export interface CohortGrid {
  periods: string[];
  rows: CohortRow[];
  /** A value's shade, 8-100 percent of the colour, by its share of the largest. */
  shade: (value: number) => number;
}

/** The most cohorts, and the most periods, one widget shows. */
export const MAX_COHORTS = 60;
export const MAX_PERIODS = 60;
/** The lightest shade, so the smallest value still reads as filled. */
const LIGHTEST = 8;

function field(config: Record<string, unknown> | null, key: string): string | null {
  const value = config?.[key];
  return typeof value === 'string' && value !== '' ? value : null;
}

function keyOf(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function numberOf(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN;
  return Number.isFinite(n) ? n : null;
}

function ordered(keys: Iterable<string>): string[] {
  const all = [...keys];
  return all.every(k => numberOf(k) !== null)
    ? all.sort((a, b) => Number(a) - Number(b))
    : all.sort((a, b) => a.localeCompare(b));
}

export function cohortGrid(
  rows: readonly Record<string, unknown>[],
  config: Record<string, unknown> | null,
): CohortGrid | null {
  const cohortField = field(config, 'cohort_key_field');
  const periodField = field(config, 'period_field');
  const valueField = field(config, 'value_field');
  if (!cohortField || !periodField || !valueField) return null;
  const values = new Map<string, Map<string, number>>();
  const periodKeys = new Set<string>();
  for (const row of rows) {
    const cohort = keyOf(row[cohortField]);
    const period = keyOf(row[periodField]);
    const value = numberOf(row[valueField]);
    if (cohort === null || period === null || value === null) continue;
    periodKeys.add(period);
    let byPeriod = values.get(cohort);
    if (!byPeriod) values.set(cohort, (byPeriod = new Map()));
    byPeriod.set(period, value);
  }
  if (values.size === 0) return null;
  const periods = ordered(periodKeys).slice(0, MAX_PERIODS);
  const cohorts = ordered(values.keys()).slice(0, MAX_COHORTS);
  const grid = cohorts.map(cohort => ({
    cohort,
    cells: periods.map(p => values.get(cohort)?.get(p) ?? null),
  }));
  const largest = Math.max(0, ...grid.flatMap(r => r.cells.flatMap(c => (c === null ? [] : [c]))));
  return {
    periods,
    rows: grid,
    shade: value => largest > 0 ? Math.round(LIGHTEST + (Math.max(0, value) / largest) * (100 - LIGHTEST)) : LIGHTEST,
  };
}
