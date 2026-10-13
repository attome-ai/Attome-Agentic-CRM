import { describe, expect, it } from 'vitest';
import { barRects, donutPaths, plotArea, scale, valueAxis } from './chart-geometry';

// Dashboard 10/10 Phase 4.1 — placement rules of the chart primitive.

describe('chart geometry', () => {
  it('a value axis starts at zero and ends on a round tick above the maximum', () => {
    const axis = valueAxis([117, 4]);
    expect(axis.min).toBe(0);
    expect(axis.max).toBeGreaterThanOrEqual(117);
    expect(axis.ticks[0]).toBe(0);
    expect(axis.ticks[axis.ticks.length - 1]).toBe(axis.max);
    expect(axis.ticks).toEqual([0, 50, 100, 150]);
  });

  it('includes negative values and keeps fractional ticks exact', () => {
    expect(valueAxis([-30, 70]).min).toBeLessThanOrEqual(-30);
    expect(valueAxis([0.3]).ticks).toContain(0.1);
    expect(valueAxis([0.3]).ticks.every(t => String(t).length <= 4)).toBe(true);
  });

  it('an empty or all-zero series still has a drawable axis', () => {
    expect(valueAxis([])).toMatchObject({ min: 0, max: 1 });
    expect(valueAxis([0, 0]).max).toBe(1);
  });

  it('scales linearly and inverts for the y axis', () => {
    const axis = { min: 0, max: 100, ticks: [] };
    expect(scale(50, axis, 200, 0)).toBe(100);
    expect(scale(0, axis, 200, 0)).toBe(200);
  });

  it('bars grow from the zero line, negatives hang below it', () => {
    const axis = valueAxis([-50, 100]);
    const area = plotArea(320, 180, 30);
    const [up, down] = barRects([[100, -50]], axis, area);
    const zero = scale(0, axis, area.top + area.height, area.top);
    expect(up.y + up.height).toBeCloseTo(zero);
    expect(down.y).toBeCloseTo(zero);
    expect(up.x).toBeLessThan(down.x);
  });

  it('mirrors category order and moves the value labels to the right in RTL', () => {
    const axis = valueAxis([1, 2]);
    const rtlArea = plotArea(320, 180, 30, true);
    const [first, second] = barRects([[1, 2]], axis, rtlArea, true);
    expect(first.x).toBeGreaterThan(second.x);
    expect(rtlArea.left).toBe(8);
  });

  it('draws a donut slice per positive value, and a lone slice as a full ring', () => {
    const paths = donutPaths([3, 0, -2, 1], 50, 50, 50, 30);
    expect(paths[0]).not.toBeNull();
    expect(paths[1]).toBeNull();
    expect(paths[2]).toBeNull();
    expect(paths[3]).not.toBeNull();
    const full = donutPaths([5], 50, 50, 50, 30)[0]!;
    expect(full.match(/M/g)?.length).toBe(2);
    expect(donutPaths([0, 0], 50, 50, 50, 30)).toEqual([null, null]);
  });
});
