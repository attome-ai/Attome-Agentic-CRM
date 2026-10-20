import { describe, expect, it } from 'vitest';

import { chartMax, linePoints, rateSeries } from './deliverability-dashboard.component';
import type { ProviderDay } from './deliverability.service';

const row = (day: string, provider: string, sent: number, bounced: number): ProviderDay => ({
  day, mailbox_provider: provider, sent, delivered: sent - bounced, bounced, complaints: 0,
});

describe('deliverability chart helpers (E6-T13)', () => {
  it('gives each provider a rate per day, null where nothing was sent', () => {
    const { days, series } = rateSeries([
      row('2026-10-02', 'outlook', 200, 2),
      row('2026-10-01', 'gmail', 100, 4),
      row('2026-10-02', 'gmail', 0, 0),
    ], 'bounced');
    expect(days).toEqual(['2026-10-01', '2026-10-02']);
    expect(series).toEqual([
      { provider: 'gmail', rates: [4, null] },
      { provider: 'outlook', rates: [null, 1] },
    ]);
  });

  it('scales the chart to the larger of the data and the limit', () => {
    expect(chartMax([{ provider: 'gmail', rates: [1, null] }], 2)).toBeCloseTo(2.3);
    expect(chartMax([{ provider: 'gmail', rates: [4] }], 2)).toBeCloseTo(4.6);
    expect(chartMax([], null)).toBe(1);
  });

  it('draws points across the frame and skips empty days', () => {
    expect(linePoints([0, null, 2], 2)).toBe('0.0,160.0 600.0,0.0');
  });
});
