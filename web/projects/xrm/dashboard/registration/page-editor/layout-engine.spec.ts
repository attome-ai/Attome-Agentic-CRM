import { describe, expect, it } from 'vitest';
import {
  GridMetrics, WidgetRect,
  applyResize, canvasHeightStyle, clamp, computeGridMetrics, diffLayout, diffPatch,
  dragTarget, resolveCollisions, snapToGrid, snapToGridClamped, tileBoxStyle, widgetRects,
} from './layout-engine';

/** Deterministic PRNG (mulberry32) — same seed always produces the same
 * sequence, so a failing case here is reproducible, unlike `Math.random()`. */
function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function rectsOverlap(a: WidgetRect, b: WidgetRect): boolean {
  return (
    a.col < b.col + b.colSpan &&
    a.col + a.colSpan > b.col &&
    a.row < b.row + b.rowSpan &&
    a.row + a.rowSpan > b.row
  );
}

function assertNoOverlaps(rects: WidgetRect[]): void {
  for (let i = 0; i < rects.length; i++) {
    for (let j = i + 1; j < rects.length; j++) {
      expect(rectsOverlap(rects[i], rects[j])).toBe(false);
    }
  }
}

describe('resolveCollisions', () => {
  const COLS = 12;

  it('never leaves two rects overlapping, across 200 random inputs (seeded)', () => {
    const rand = mulberry32(20260906);
    for (let trial = 0; trial < 200; trial++) {
      const n = 2 + Math.floor(rand() * 10); // 2..11 widgets
      const widgets: WidgetRect[] = Array.from({ length: n }, (_, i) => {
        const colSpan = 1 + Math.floor(rand() * 4);
        return {
          id: `w${i}`,
          col: Math.floor(rand() * Math.max(1, COLS - colSpan + 1)),
          row: Math.floor(rand() * 6),
          colSpan,
          rowSpan: 1 + Math.floor(rand() * 3),
        };
      });
      const movedId = widgets[Math.floor(rand() * n)].id;

      const result = resolveCollisions(widgets, movedId, COLS);

      expect(result).toHaveLength(n);
      assertNoOverlaps(result);
    }
  });

  it('never moves the moved widget — it keeps exactly the rect it was given', () => {
    const rand = mulberry32(7);
    for (let trial = 0; trial < 200; trial++) {
      const n = 2 + Math.floor(rand() * 10);
      const widgets: WidgetRect[] = Array.from({ length: n }, (_, i) => ({
        id: `w${i}`,
        col: Math.floor(rand() * 8),
        row: Math.floor(rand() * 6),
        colSpan: 1 + Math.floor(rand() * 4),
        rowSpan: 1 + Math.floor(rand() * 3),
      }));
      const movedId = widgets[Math.floor(rand() * n)].id;
      const moved = widgets.find(w => w.id === movedId)!;

      const result = resolveCollisions(widgets, movedId, COLS);
      const movedResult = result.find(w => w.id === movedId)!;
      expect(movedResult).toEqual(moved);
    }
  });

  it('terminates (and stays overlap-free) on a maximal cascade — every widget stacked on the same cell', () => {
    const n = 60;
    const widgets: WidgetRect[] = Array.from({ length: n }, (_, i) => ({
      id: `w${i}`, col: 0, row: 0, colSpan: 1, rowSpan: 1,
    }));
    // A hang here would time out the whole suite — completing at all proves
    // termination; the assertions below prove it terminated correctly.
    const result = resolveCollisions(widgets, 'w0', COLS);
    expect(result).toHaveLength(n);
    assertNoOverlaps(result);
    expect(result.find(w => w.id === 'w0')).toEqual(widgets[0]);
  });

  it('clamps a widget whose stored column no longer fits the grid instead of leaving it out of bounds', () => {
    const widgets: WidgetRect[] = [
      { id: 'moved', col: 0, row: 0, colSpan: 2, rowSpan: 1 },
      { id: 'stale', col: 11, row: 0, colSpan: 4, rowSpan: 1 }, // col+colSpan = 15 > 12
    ];
    const result = resolveCollisions(widgets, 'moved', COLS);
    const stale = result.find(w => w.id === 'stale')!;
    expect(stale.col + stale.colSpan).toBeLessThanOrEqual(COLS);
  });
});

describe('diffPatch', () => {
  it('emits only the keys in `keys` whose value actually changed, including view_id (R-02 regression)', () => {
    const before = { name: 'A', view_id: null, query_id: 'q1', grid_col: 0 };
    const after = { name: 'A', view_id: 'view-abc', query_id: 'q1', grid_col: 4 };
    expect(diffPatch(before, after, ['name', 'view_id', 'query_id', 'grid_col'])).toEqual({
      view_id: 'view-abc',
      grid_col: 4,
    });
  });

  it('ignores keys outside the `keys` list even when they changed', () => {
    const before = { a: 1, untracked: 'x' };
    const after = { a: 1, untracked: 'y' };
    expect(diffPatch(before, after, ['a'])).toEqual({});
  });

  it('treats a missing `before` as every tracked key starting at null', () => {
    expect(diffPatch(undefined, { view_id: 'v1' }, ['view_id'])).toEqual({ view_id: 'v1' });
  });

  it('emits nothing when every tracked key is unchanged', () => {
    const before = { a: 1, b: 2 };
    const after = { a: 1, b: 2 };
    expect(diffPatch(before, after, ['a', 'b'])).toEqual({});
  });
});

describe('grid pixel math', () => {
  const metrics: GridMetrics = computeGridMetrics(1200); // columns:12 gap:12 cellH:100, cellW≈89

  it('computeGridMetrics derives cellW from measured width and never goes below the 20px floor', () => {
    expect(metrics.columns).toBe(12);
    expect(metrics.gap).toBe(12);
    expect(metrics.cellH).toBe(100);
    expect(metrics.cellW).toBeGreaterThan(0);
    expect(computeGridMetrics(0).cellW).toBe(20);
  });

  it('snapToGrid rounds a pixel offset to the nearest cell', () => {
    const colStep = metrics.cellW + metrics.gap;
    expect(snapToGrid({ x: colStep * 2.4, y: 0 }, metrics)).toEqual({ col: 2, row: 0 });
    expect(snapToGrid({ x: colStep * 2.6, y: 0 }, metrics)).toEqual({ col: 3, row: 0 });
  });

  it('snapToGridClamped keeps a colSpan-wide footprint on the grid and never above row 0', () => {
    const far = snapToGridClamped({ x: 100000, y: -100000 }, metrics, 4);
    expect(far.col).toBeLessThanOrEqual(metrics.columns - 4);
    expect(far.row).toBeGreaterThanOrEqual(0);
  });

  it('dragTarget resolves a relative pixel delta against the drag origin, clamped to the grid', () => {
    const origin = { col: 2, row: 1, colSpan: 3 };
    const noMove = dragTarget(origin, { dx: 0, dy: 0 }, metrics);
    expect(noMove).toEqual({ col: 2, row: 1 });
    const farLeft = dragTarget(origin, { dx: -1_000_000, dy: -1_000_000 }, metrics);
    expect(farLeft).toEqual({ col: 0, row: 0 });
  });

  it('applyResize grows/shrinks span by whole cells, floors at 1x1, and clamps colSpan to the grid', () => {
    const rect: WidgetRect = { id: 'w', col: 0, row: 0, colSpan: 2, rowSpan: 2 };
    const grown = applyResize(rect, metrics.cellW + metrics.gap, 0, metrics);
    expect(grown.colSpan).toBe(3);
    expect(grown.rowSpan).toBe(2);
    const shrunk = applyResize(rect, -1_000_000, -1_000_000, metrics);
    expect(shrunk.colSpan).toBe(1);
    expect(shrunk.rowSpan).toBe(1);
    const wide: WidgetRect = { id: 'w', col: 10, row: 0, colSpan: 2, rowSpan: 1 };
    const overGrown = applyResize(wide, 1_000_000, 0, metrics);
    expect(overGrown.col + overGrown.colSpan).toBeLessThanOrEqual(metrics.columns);
  });

  it('tileBoxStyle renders a position:absolute CSS text string sized from the rect', () => {
    const css = tileBoxStyle({ id: 'w', col: 1, row: 0, colSpan: 2, rowSpan: 1 }, metrics);
    expect(css).toContain('position:absolute');
    expect(css).toMatch(/left:\d+(\.\d+)?px/);
    expect(css).toMatch(/width:\d+(\.\d+)?px/);
  });

  it('tileBoxStyle in resizing mode grows width/height by the delta with an 80x60 floor, not left/top', () => {
    const rect: WidgetRect = { id: 'w', col: 0, row: 0, colSpan: 1, rowSpan: 1 };
    const css = tileBoxStyle(rect, metrics, { delta: { dx: -100000, dy: -100000 }, resizing: true, active: true });
    expect(css).toContain('width:80px');
    expect(css).toContain('height:60px');
    expect(css).toContain('left:0px');
    expect(css).toContain('top:0px');
    expect(css).toContain('transition:none');
  });

  it('canvasHeightStyle grows to fit the tallest rect (including live/ghost rects) plus 4 rows, min 8', () => {
    const short = canvasHeightStyle([], [], metrics);
    const tall = canvasHeightStyle([{ id: 'w', col: 0, row: 20, colSpan: 1, rowSpan: 1 }], [], metrics);
    expect(parseInt(tall.minHeight, 10)).toBeGreaterThan(parseInt(short.minHeight, 10));
  });
});

describe('widgetRects / diffLayout', () => {
  it('widgetRects reads the four grid_* fields, defaulting a missing span to 1', () => {
    const rects = widgetRects([{ id: 'w1', data: { grid_col: 3, grid_row: 2 } }]);
    expect(rects).toEqual([{ id: 'w1', col: 3, row: 2, colSpan: 1, rowSpan: 1 }]);
  });

  it('diffLayout emits a patch using entity column names, only for widgets whose tracked keys moved', () => {
    const originals: WidgetRect[] = [
      { id: 'w1', col: 0, row: 0, colSpan: 2, rowSpan: 1 },
      { id: 'w2', col: 4, row: 0, colSpan: 2, rowSpan: 1 },
    ];
    const next = new Map<string, WidgetRect>([
      ['w1', { id: 'w1', col: 0, row: 2, colSpan: 2, rowSpan: 1 }], // row moved
      ['w2', { id: 'w2', col: 4, row: 0, colSpan: 2, rowSpan: 1 }], // unchanged
    ]);
    expect(diffLayout(originals, next, ['col', 'row'])).toEqual([
      { widgetId: 'w1', patch: { grid_row: 2 } },
    ]);
  });

  it('diffLayout skips a widget in `next` that has no known original', () => {
    const next = new Map<string, WidgetRect>([['ghost', { id: 'ghost', col: 0, row: 0, colSpan: 1, rowSpan: 1 }]]);
    expect(diffLayout([], next, ['col', 'row'])).toEqual([]);
  });
});

describe('clamp', () => {
  it('bounds a value into [min, max]', () => {
    expect(clamp(5, 0, 10)).toBe(5);
    expect(clamp(-5, 0, 10)).toBe(0);
    expect(clamp(50, 0, 10)).toBe(10);
  });
});
