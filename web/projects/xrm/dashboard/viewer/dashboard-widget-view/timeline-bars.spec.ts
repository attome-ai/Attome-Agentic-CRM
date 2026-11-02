import { describe, expect, it } from 'vitest';

import { MAX_BARS, timelineBars } from './timeline-bars';

const CONFIG = { label_field: 'name', start_field: 'starts_on', end_field: 'ends_on' };

describe('timelineBars (P6-T1)', () => {
  it('places each bar as a share of the whole span, earliest first', () => {
    const timeline = timelineBars([
      { name: 'Build', starts_on: '2026-01-11T00:00:00Z', ends_on: '2026-01-21T00:00:00Z' },
      { name: 'Design', starts_on: '2026-01-01T00:00:00Z', ends_on: '2026-01-11T00:00:00Z' },
    ], CONFIG)!;
    expect(timeline.bars.map(b => b.label)).toEqual(['Design', 'Build']);
    expect(timeline.bars[0].offset).toBe(0);
    expect(timeline.bars[0].length).toBe(50);
    expect(timeline.bars[1].offset).toBe(50);
    expect(timeline.bars[1].length).toBe(50);
    expect(timeline.to.toISOString()).toBe('2026-01-21T00:00:00.000Z');
  });

  it('draws a row without an end as a point and leaves out rows without a start', () => {
    const timeline = timelineBars([
      { name: 'Kick-off', starts_on: '2026-01-01T00:00:00Z' },
      { name: 'Launch', starts_on: '2026-01-31T00:00:00Z', ends_on: null },
      { name: 'Undated', starts_on: null },
      { name: 'Backwards', starts_on: '2026-01-10T00:00:00Z', ends_on: '2026-01-05T00:00:00Z' },
    ], CONFIG)!;
    expect(timeline.bars.map(b => b.label)).toEqual(['Kick-off', 'Backwards', 'Launch']);
    expect(timeline.bars.every(b => b.length > 0)).toBe(true);
    expect(timeline.bars[1].end.getTime()).toBe(timeline.bars[1].start.getTime());
  });

  it('needs a label and a start field, and caps the bars', () => {
    expect(timelineBars([{ a: 1 }], { start_field: 'starts_on' })).toBeNull();
    expect(timelineBars([], CONFIG)).toBeNull();
    const many = Array.from({ length: MAX_BARS + 5 }, (_, i) => ({
      name: `T${i}`, starts_on: new Date(Date.UTC(2026, 0, 1 + i)).toISOString(),
    }));
    expect(timelineBars(many, CONFIG)!.bars).toHaveLength(MAX_BARS);
  });
});
