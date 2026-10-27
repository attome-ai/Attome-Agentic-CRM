import { describe, expect, it } from 'vitest';
import { ROW_HEIGHT, VIRTUAL_FROM, rowWindow } from './entity-list.component';

describe('rowWindow (Y14-T4)', () => {
  it('renders the rows in view plus overscan, and spaces the rest', () => {
    const w = rowWindow(0, 800, 1000);
    expect(w.start).toBe(0);
    expect(w.end).toBe(Math.ceil(800 / ROW_HEIGHT) + 15);
    expect(w.before).toBe(0);
    expect(w.after).toBe((1000 - w.end) * ROW_HEIGHT);
  });

  it('follows the scroll and stays inside the list', () => {
    const mid = rowWindow(ROW_HEIGHT * 500, 800, 1000);
    expect(mid.start).toBe(485);
    expect(mid.before).toBe(485 * ROW_HEIGHT);
    const bottom = rowWindow(ROW_HEIGHT * 2000, 800, 1000);
    expect(bottom.end).toBe(1000);
    expect(bottom.after).toBe(0);
    expect(bottom.start).toBeLessThan(bottom.end);
    expect(rowWindow(-50, 0, 10).start).toBe(0);
  });

  it('only long lists are windowed', () => {
    expect(VIRTUAL_FROM).toBe(100);
  });
});
