import { describe, expect, it } from 'vitest';
import { MAX_COHORTS, cohortGrid } from './cohort-grid';

const config = { cohort_key_field: 'cohort', period_field: 'week', value_field: 'kept' };

describe('cohortGrid (P6-T1)', () => {
  it('lays rows out by cohort and period, in order, empty where no row fills a cell', () => {
    const grid = cohortGrid([
      { cohort: '2026-02-01', week: 0, kept: 80 },
      { cohort: '2026-01-01', week: 1, kept: 60 },
      { cohort: '2026-01-01', week: 0, kept: 100 },
      { cohort: '2026-01-01', week: 10, kept: 20 },
      { cohort: '2026-02-01', week: 2, kept: null },
    ], config);
    expect(grid?.periods).toEqual(['0', '1', '10']);
    expect(grid?.rows).toEqual([
      { cohort: '2026-01-01', cells: [100, 60, 20] },
      { cohort: '2026-02-01', cells: [80, null, null] },
    ]);
  });

  it('shades by share of the largest value, never below the lightest shade', () => {
    const grid = cohortGrid([
      { cohort: 'a', week: 0, kept: 50 },
      { cohort: 'a', week: 1, kept: 0 },
    ], config)!;
    expect(grid.shade(50)).toBe(100);
    expect(grid.shade(0)).toBe(8);
    expect(grid.shade(25)).toBe(54);
  });

  it('needs all three fields and at least one usable row', () => {
    expect(cohortGrid([{ cohort: 'a', week: 0, kept: 1 }], { cohort_key_field: 'cohort', period_field: 'week' })).toBeNull();
    expect(cohortGrid([{ cohort: 'a', week: 0, kept: 'n/a' }], config)).toBeNull();
    expect(cohortGrid([], null)).toBeNull();
  });

  it('caps the cohorts it shows', () => {
    const rows = Array.from({ length: MAX_COHORTS + 5 }, (_, i) => ({ cohort: i, week: 0, kept: i }));
    expect(cohortGrid(rows, config)?.rows).toHaveLength(MAX_COHORTS);
  });
});
