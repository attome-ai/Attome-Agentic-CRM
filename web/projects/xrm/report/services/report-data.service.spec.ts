import { describe, expect, it } from 'vitest';
import { resolveDateRange, withDateRangeFilters } from './report-data.service';

describe('resolveDateRange', () => {
  it('returns null for "all" — no date filter at all', () => {
    expect(resolveDateRange({ preset: 'all' })).toBeNull();
    expect(resolveDateRange(undefined)).toBeNull();
  });

  it('returns null for "custom" with a missing bound', () => {
    expect(resolveDateRange({ preset: 'custom' })).toBeNull();
    expect(resolveDateRange({ preset: 'custom', from: '2026-01-01' })).toBeNull();
  });

  it('passes "custom" bounds through verbatim when both are present', () => {
    expect(resolveDateRange({ preset: 'custom', from: '2026-01-01', to: '2026-02-01' }))
      .toEqual({ from: '2026-01-01', to: '2026-02-01' });
  });

  it('resolves "today" to a 24-hour window starting at local midnight', () => {
    const bounds = resolveDateRange({ preset: 'today' });
    expect(bounds).not.toBeNull();
    const from = new Date(bounds!.from);
    const to = new Date(bounds!.to);
    expect(to.getTime() - from.getTime()).toBe(24 * 60 * 60 * 1000);
    expect(from.getHours()).toBe(0);
    expect(from.getMinutes()).toBe(0);
  });

  it('resolves "last_week" to a window ending tomorrow and starting 7 days before today', () => {
    const today = resolveDateRange({ preset: 'today' })!;
    const lastWeek = resolveDateRange({ preset: 'last_week' })!;
    expect(lastWeek.to).toBe(today.to);
    expect(new Date(today.from).getTime() - new Date(lastWeek.from).getTime()).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('resolves "last_month" to a window strictly wider than "last_week"', () => {
    const lastWeek = resolveDateRange({ preset: 'last_week' })!;
    const lastMonth = resolveDateRange({ preset: 'last_month' })!;
    expect(new Date(lastMonth.from).getTime()).toBeLessThan(new Date(lastWeek.from).getTime());
    expect(lastMonth.to).toBe(lastWeek.to);
  });
});

describe('withDateRangeFilters', () => {
  it('returns the original filters unchanged when no date_field is set', () => {
    const filters = [{ field: 'region', op: 'eq', value: 'GCC' }];
    expect(withDateRangeFilters(filters, undefined, { preset: 'today' })).toBe(filters);
  });

  it('returns the original filters unchanged for "all"', () => {
    const filters = [{ field: 'region', op: 'eq', value: 'GCC' }];
    expect(withDateRangeFilters(filters, 'created_at', { preset: 'all' })).toBe(filters);
  });

  it('appends exactly two gte/lt filters against the named date field', () => {
    const result = withDateRangeFilters([], 'created_at', { preset: 'today' });
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ field: 'created_at', op: 'gte' });
    expect(result[1]).toMatchObject({ field: 'created_at', op: 'lt' });
  });

  it('preserves existing filters ahead of the appended date-range pair', () => {
    const existing = [{ field: 'region', op: 'eq', value: 'GCC' }];
    const result = withDateRangeFilters(existing, 'created_at', { preset: 'today' });
    expect(result[0]).toEqual(existing[0]);
    expect(result).toHaveLength(3);
  });
});
