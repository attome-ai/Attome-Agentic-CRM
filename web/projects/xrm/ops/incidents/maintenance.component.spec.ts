import { describe, expect, it } from 'vitest';

import { localToIso, windowProblem } from './maintenance.component';

describe('maintenance form (AB11-T9)', () => {
  const now = Date.parse('2026-10-28T08:00:00Z');

  it('needs both titles, both times, an end after the start and a future start', () => {
    expect(windowProblem('Upgrade', '', '2026-10-29T08:00:00Z', '2026-10-29T09:00:00Z', now)).toBe('ops.status.bothTitles');
    expect(windowProblem('Upgrade', 'ترقية', null, '2026-10-29T09:00:00Z', now)).toBe('ops.status.needTimes');
    expect(windowProblem('Upgrade', 'ترقية', '2026-10-29T09:00:00Z', '2026-10-29T08:00:00Z', now)).toBe('ops.status.endAfterStart');
    expect(windowProblem('Upgrade', 'ترقية', '2026-10-27T08:00:00Z', '2026-10-27T09:00:00Z', now)).toBe('ops.status.startInFuture');
    expect(windowProblem('Upgrade', 'ترقية', '2026-10-29T08:00:00Z', '2026-10-29T09:00:00Z', now)).toBeNull();
  });

  it('reads a datetime-local value as a moment', () => {
    expect(localToIso('')).toBeNull();
    expect(localToIso('not a date')).toBeNull();
    expect(localToIso('2026-10-29T08:00')).toMatch(/^2026-10-29T/);
  });
});
