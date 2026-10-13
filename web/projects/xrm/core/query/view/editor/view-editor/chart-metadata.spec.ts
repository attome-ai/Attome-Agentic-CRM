import { describe, expect, it } from 'vitest';
import {
  ChartDraft, EMPTY_CHART_DRAFT, buildChartMetadata, chartDraftFromMetadata, emptySeries, isChartIdentifier,
} from './chart-metadata';

function draft(overrides: Partial<ChartDraft>): ChartDraft {
  return { ...EMPTY_CHART_DRAFT, ...overrides };
}

const SERIES = { ...emptySeries(), field: 'amount', aggregation: 'sum' as const, label: 'Amount' };

function errorOf(d: ChartDraft): string | null {
  const result = buildChartMetadata(d);
  return result.ok ? null : result.errorKey.replace('queryAdmin.viewKind.chartError.', '');
}

describe('chart view metadata (view editor)', () => {
  it('accepts an unconfigured chart, as the backend does', () => {
    expect(buildChartMetadata(EMPTY_CHART_DRAFT))
      .toEqual({ ok: true, metadata: { chart_type: 'line', x_field: '', y_fields: [] } });
  });

  it('builds the full metadata shape', () => {
    const result = buildChartMetadata(draft({
      chartType: 'bar', xField: ' created_on ', xBucket: 'month', groupByField: 'status', sort: 'x_asc',
      limit: '12', otherBucket: true, stacked: true, cumulative: true, percentOfTotal: true,
      movingAverage: '3', thresholdValue: '1000', thresholdLabel: 'Target', showLegend: false,
      series: [{ ...SERIES, labelAr: 'المبلغ', color: '#22c55e' }],
    }), { number_format: { decimals: 2 } });

    expect(result).toEqual({
      ok: true,
      metadata: {
        chart_type: 'bar', x_field: 'created_on', x_bucket: 'month', group_by_field: 'status', sort: 'x_asc',
        y_fields: [{ field: 'amount', aggregation: 'sum', label: 'Amount', label_ar: 'المبلغ', color: '#22c55e' }],
        limit: 12, moving_average_window: 3, threshold: { value: 1000, label: 'Target' },
        other_bucket: true, stacked: true, cumulative: true, percent_of_total: true, show_legend: false,
        number_format: { decimals: 2 },
      },
    });
  });

  it('mirrors the backend identifier rule', () => {
    expect(isChartIdentifier('created_on')).toBe(true);
    expect(isChartIdentifier('Created')).toBe(false);
    expect(isChartIdentifier('1st')).toBe(false);
    expect(isChartIdentifier('amount; DROP TABLE x')).toBe(false);
    expect(isChartIdentifier('a'.repeat(129))).toBe(false);
  });

  it('rejects what the backend rejects, naming the field', () => {
    expect(errorOf(draft({ xField: 'Bad Field' }))).toBe('xField');
    expect(errorOf(draft({ series: Array.from({ length: 9 }, () => SERIES) }))).toBe('tooManySeries');
    expect(errorOf(draft({ series: [{ ...SERIES, field: '' }] }))).toBe('seriesField');
    expect(errorOf(draft({ series: [{ ...SERIES, label: ' ' }] }))).toBe('seriesLabel');
    expect(errorOf(draft({ series: [{ ...SERIES, label: 'x'.repeat(201) }] }))).toBe('seriesLabel');
    expect(errorOf(draft({ series: [{ ...SERIES, color: 'red' }] }))).toBe('seriesColor');
    expect(errorOf(draft({ groupByField: 'x-y' }))).toBe('groupBy');
    expect(errorOf(draft({ limit: '0' }))).toBe('limit');
    expect(errorOf(draft({ limit: '367' }))).toBe('limit');
    expect(errorOf(draft({ limit: '1.5' }))).toBe('limit');
    expect(errorOf(draft({ movingAverage: '1' }))).toBe('movingAverage');
    expect(errorOf(draft({ movingAverage: '91' }))).toBe('movingAverage');
    expect(errorOf(draft({ thresholdValue: 'abc' }))).toBe('threshold');
    expect(errorOf(draft({ thresholdLabel: 'Target' }))).toBe('threshold');
  });

  it('accepts the bounds themselves', () => {
    expect(errorOf(draft({ limit: '1' }))).toBeNull();
    expect(errorOf(draft({ limit: '366' }))).toBeNull();
    expect(errorOf(draft({ movingAverage: '2' }))).toBeNull();
    expect(errorOf(draft({ movingAverage: '90' }))).toBeNull();
    expect(errorOf(draft({ series: Array.from({ length: 8 }, () => SERIES) }))).toBeNull();
    expect(errorOf(draft({ series: [{ ...SERIES, color: '#abc' }] }))).toBeNull();
    expect(errorOf(draft({ series: [{ ...SERIES, color: '#aabbccdd' }] }))).toBeNull();
  });

  it('round-trips stored metadata through the draft', () => {
    const stored = {
      chart_type: 'donut', x_field: 'stage', y_fields: [{ field: 'id', aggregation: 'count', label: 'Deals' }],
      sort: 'value_desc', limit: 5, other_bucket: true, threshold: { value: 10 },
    };
    const result = buildChartMetadata(chartDraftFromMetadata(stored), stored);

    expect(result).toEqual({ ok: true, metadata: stored });
  });

  it('reads unknown enum values back as the defaults', () => {
    const d = chartDraftFromMetadata({ chart_type: 'waffle', x_bucket: 'decade', y_fields: [{ field: 'a', aggregation: 'mode', label: 'A' }] });

    expect(d.chartType).toBe('line');
    expect(d.xBucket).toBe('');
    expect(d.series[0].aggregation).toBe('count');
  });
});
