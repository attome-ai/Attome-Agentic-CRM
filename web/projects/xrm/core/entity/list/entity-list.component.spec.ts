import { describe, expect, it } from 'vitest';
import { formatDateCell } from './entity-list.component';

describe('entity-list date cells', () => {
  it('renders a timestamp as dd-mm-yyyy hh:mm in the viewer local zone', () => {
    // Fixed instant, asserted through the same local-time conversion the
    // formatter performs, so the expectation holds in any CI timezone.
    const raw = '2026-08-07T17:34:59.339617+00:00';
    const local = new Date(raw);
    const pad = (n: number) => String(n).padStart(2, '0');
    expect(formatDateCell(raw)).toBe(
      `${pad(local.getDate())}-${pad(local.getMonth() + 1)}-${local.getFullYear()} `
      + `${pad(local.getHours())}:${pad(local.getMinutes())}`,
    );
  });

  it('renders a date-only value as dd-mm-yyyy without a timezone shift', () => {
    expect(formatDateCell('2026-08-07')).toBe('07-08-2026');
    expect(formatDateCell('2026-01-01')).toBe('01-01-2026');
  });

  it('accepts the ISO variants PostgreSQL emits', () => {
    expect(formatDateCell('2026-08-07T05:06:07Z')).toMatch(/^\d{2}-\d{2}-2026 \d{2}:\d{2}$/);
    expect(formatDateCell('2026-08-07 05:06:07')).toBe('07-08-2026 05:06');
    expect(formatDateCell('2026-08-07T05:06')).toBe('07-08-2026 05:06');
  });

  it('leaves anything that is not an ISO date alone', () => {
    expect(formatDateCell('greg')).toBeNull();
    expect(formatDateCell('2')).toBeNull();
    expect(formatDateCell('')).toBeNull();
    expect(formatDateCell('0198c2a1-1f3e-7c8a-9b2d-4e5f60718293')).toBeNull();
    expect(formatDateCell('2026-08-07T17:34:59.339617+00:00 extra')).toBeNull();
  });
});
