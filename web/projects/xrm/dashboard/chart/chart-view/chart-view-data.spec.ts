import { describe, expect, it } from 'vitest';
import type { ChartViewMetadata } from '@attome/xrm/core/query/data';
import {
  OTHER_KEY, aggregate, buildChartViewData, chartKindFor, dateBucketKey, isChartConfigured,
} from './chart-view-data';

const LABELS = { other: 'Other', empty: '(empty)', arabic: false };

const ROWS = [
  { id: '1', stage: 'won', amount: 100, owner: 'a' },
  { id: '2', stage: 'won', amount: '50', owner: 'b' },
  { id: '3', stage: 'lost', amount: 30, owner: 'a' },
  { id: '4', stage: 'open', amount: null, owner: 'a' },
  { id: '5', stage: null, amount: 5, owner: 'b' },
];

function meta(overrides: Partial<ChartViewMetadata>): Partial<ChartViewMetadata> {
  return {
    chart_type: 'bar', x_field: 'stage',
    y_fields: [{ field: 'amount', aggregation: 'sum', label: 'Amount' }],
    ...overrides,
  };
}

function valuesOf(data: ReturnType<typeof buildChartViewData>, series = 0): (number | null)[] {
  return data!.series[series].points.map(p => p?.value ?? null);
}

describe('chart view data', () => {
  it('needs an x field and a series before it draws', () => {
    expect(isChartConfigured({})).toBe(false);
    expect(isChartConfigured({ x_field: 'stage', y_fields: [] })).toBe(false);
    expect(buildChartViewData(ROWS, { x_field: '', y_fields: [] }, LABELS)).toBeNull();
    expect(isChartConfigured(meta({}))).toBe(true);
  });

  it('maps every chart type onto the dashboard chart kinds', () => {
    expect(chartKindFor('column')).toBe('bar');
    expect(chartKindFor('pie')).toBe('donut');
    expect(chartKindFor('funnel')).toBe('funnel');
    expect(chartKindFor(undefined)).toBe('line');
  });

  it('aggregates like SQL: counts skip nulls, numeric functions skip non-numbers', () => {
    expect(aggregate([1, null, 'x', 3], 'count')).toBe(3);
    expect(aggregate(['a', 'a', 'b', null], 'count_distinct')).toBe(2);
    expect(aggregate([1, '2', 'x'], 'sum')).toBe(3);
    expect(aggregate([1, 2, 6], 'avg')).toBe(3);
    expect(aggregate([4, 1, 9], 'median')).toBe(4);
    expect(aggregate([4, 1, 9, 10], 'median')).toBe(6.5);
    expect(aggregate([null], 'max')).toBeNull();
    expect(aggregate([], 'count')).toBe(0);
  });

  it('groups rows by the x field and sorts categories ascending by default', () => {
    const data = buildChartViewData(ROWS, meta({}), LABELS)!;

    expect(data.kind).toBe('bar');
    expect(data.categories.map(c => c.label)).toEqual(['(empty)', 'lost', 'open', 'won']);
    expect(valuesOf(data)).toEqual([5, 30, null, 150]);
  });

  it('sorts by value and applies the limit, folding the rest into Other', () => {
    const data = buildChartViewData(ROWS, meta({ sort: 'value_desc', limit: 2, other_bucket: true }), LABELS)!;

    expect(data.categories.map(c => c.label)).toEqual(['won', 'lost', 'Other']);
    expect(valuesOf(data)).toEqual([150, 30, 5]);
    expect(data.categories[2].trackKey).toBe('other');
  });

  it('drops the rest without other_bucket', () => {
    const data = buildChartViewData(ROWS, meta({ sort: 'value_desc', limit: 1 }), LABELS)!;

    expect(data.categories.map(c => c.label)).toEqual(['won']);
  });

  it('draws one series per group value', () => {
    const data = buildChartViewData(ROWS, meta({
      group_by_field: 'owner', y_fields: [{ field: 'id', aggregation: 'count', label: 'Deals' }],
    }), LABELS)!;

    expect(data.series.map(s => s.name)).toEqual(['a', 'b']);
    expect(valuesOf(data, 0)).toEqual([0, 1, 1, 1]);
    expect(valuesOf(data, 1)).toEqual([1, 0, 0, 1]);
  });

  it('applies percent of total, then cumulative', () => {
    const rows = [{ m: 'a', v: 1 }, { m: 'b', v: 1 }, { m: 'c', v: 2 }];
    const data = buildChartViewData(rows, {
      x_field: 'm', y_fields: [{ field: 'v', aggregation: 'sum', label: 'V' }],
      percent_of_total: true, cumulative: true,
    }, LABELS)!;

    expect(valuesOf(data)).toEqual([25, 50, 100]);
  });

  it('applies a trailing moving average', () => {
    const rows = [{ m: 'a', v: 2 }, { m: 'b', v: 4 }, { m: 'c', v: 6 }];
    const data = buildChartViewData(rows, {
      x_field: 'm', y_fields: [{ field: 'v', aggregation: 'sum', label: 'V' }], moving_average_window: 2,
    }, LABELS)!;

    expect(valuesOf(data)).toEqual([2, 3, 5]);
  });

  it('buckets dates, and carries the threshold and series labels', () => {
    const rows = [
      { created: '2026-01-15', v: 1 }, { created: '2026-01-31T10:00:00', v: 2 }, { created: '2026-03-02', v: 4 },
    ];
    const data = buildChartViewData(rows, {
      chart_type: 'line', x_field: 'created', x_bucket: 'month',
      y_fields: [{ field: 'v', aggregation: 'sum', label: 'Value', label_ar: 'القيمة', color: '#112233' }],
      threshold: { value: 3 },
    }, { ...LABELS, arabic: true })!;

    expect(data.categories.map(c => c.label)).toEqual(['2026-01', '2026-03']);
    expect(valuesOf(data)).toEqual([3, 4]);
    expect(data.threshold).toBe(3);
    expect(data.series[0].name).toBe('القيمة');
    expect(data.series[0].color).toBe('#112233');
  });

  it('computes every date bucket key', () => {
    expect(dateBucketKey('2026-09-23', 'day')).toBe('2026-09-23');
    expect(dateBucketKey('2026-09-23', 'week')).toBe('2026-09-21');
    expect(dateBucketKey('2026-09-23', 'quarter')).toBe('2026-Q3');
    expect(dateBucketKey('2026-09-23', 'year')).toBe('2026');
    expect(dateBucketKey('not a date', 'day')).toBeNull();
    expect(dateBucketKey(42, 'day')).toBeNull();
  });

  it('uses a lookup column\'s display name when the row carries one', () => {
    const rows = [{ owner: 'u1', v: 1, __lookups: { owner: { exists: true, is_active: true, name: 'Ada' } } }];
    const data = buildChartViewData(rows, {
      x_field: 'owner', y_fields: [{ field: 'v', aggregation: 'sum', label: 'V' }],
    }, LABELS)!;

    expect(data.categories[0].label).toBe('Ada');
  });

  it('never uses the Other key for a real category', () => {
    expect(OTHER_KEY.startsWith('\u0000')).toBe(true);
  });
});
