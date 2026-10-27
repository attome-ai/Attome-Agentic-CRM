import type { ChartCategory, ChartSeries } from '@attome/xrm/dashboard/chart';
import type { Matrix, SummaryLine } from './report-builder.model';

/** P1-T3: a summary as one series over its groups. Pure. */
export function summaryChart(lines: readonly SummaryLine[], name: string, colour: string): { categories: ChartCategory[]; series: ChartSeries[] } {
  const categories = lines.map((l, i) => ({ trackKey: `c${i}`, label: l.key }));
  return {
    categories,
    series: [{
      trackKey: 's0', name, color: colour,
      points: lines.map((l, i) => (l.value === null ? null : { trackKey: `s0:c${i}`, label: l.key, value: l.value, key: null })),
    }],
  };
}

/** P1-T3: a matrix as one series per column over its rows. Pure. */
export function matrixChart(m: Matrix, colours: readonly string[]): { categories: ChartCategory[]; series: ChartSeries[] } {
  const categories = m.rows.map((r, i) => ({ trackKey: `c${i}`, label: r }));
  const series = m.cols.map((c, s) => ({
    trackKey: `s${s}`, name: c, color: colours[s % colours.length],
    points: m.rows.map((r, i) => {
      const v = m.cells[r]?.[c];
      return v === null || v === undefined ? null : { trackKey: `s${s}:c${i}`, label: r, value: v, key: null, seriesLabel: c };
    }),
  }));
  return { categories, series };
}
