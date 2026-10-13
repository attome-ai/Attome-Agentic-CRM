/**
 * Pure grid-layout math for the Page Editor — no Angular imports, no DOM
 * access. Everything here is a plain function over plain data so it can be
 * unit-tested without a `TestBed` and reused by `page-editor.component.ts`'s
 * pointer drag/resize handlers without those handlers re-deriving the same
 * pixel arithmetic (R-11, M26-dashboard-remediation).
 */

/** A widget's grid footprint — the same four fields
 * `dashboard_widget.grid_col`/`grid_row`/`grid_col_span`/`grid_row_span`
 * carry, plus the widget id so a set of rects can be diffed/looked up. */
export interface WidgetRect {
  id:      string;
  col:     number;
  row:     number;
  colSpan: number;
  rowSpan: number;
}

/** The canvas's current cell geometry — `columns`/`gap`/`cellH` are fixed
 * constants of this editor's grid, `cellW` is the one value that depends on
 * a DOM measurement (the canvas element's `clientWidth`), which is why it is
 * threaded through as data instead of re-measured by every pure function
 * that needs it. */
export interface GridMetrics {
  columns: number;
  gap:     number;
  cellW:   number;
  cellH:   number;
}

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/** Derives `GridMetrics` from one DOM measurement (the canvas's measured
 * pixel width) plus this editor's fixed grid constants — the only place
 * `cellW` is computed, so a `ResizeObserver` callback can call this once per
 * resize instead of every consumer re-deriving it from `clientWidth`. */
export function computeGridMetrics(
  measuredWidth: number,
  columns = 12,
  gap = 12,
  cellH = 100,
): GridMetrics {
  const cellW = Math.max(20, (measuredWidth - gap * (columns - 1)) / columns);
  return { columns, gap, cellW, cellH };
}

/** Pixel offset (relative to the grid's own origin) -> nearest grid cell.
 * Used both for an absolute drop position (palette DnD) and for a relative
 * pointer delta (drag/resize), since both are "how many cells does this many
 * pixels correspond to" — the caller decides which meaning applies. */
export function snapToGrid(px: { x: number; y: number }, metrics: GridMetrics): { col: number; row: number } {
  const colStep = metrics.cellW + metrics.gap;
  const rowStep = metrics.cellH + metrics.gap;
  return {
    col: Math.round(px.x / colStep),
    row: Math.round(px.y / rowStep),
  };
}

/** `rect` resized by a raw pixel delta (`dx`/`dy`) — column/row stay fixed,
 * `colSpan`/`rowSpan` grow or shrink by the nearest whole cell, clamped to a
 * minimum footprint of 1x1 and to the grid's column count. */
export function applyResize(rect: WidgetRect, dx: number, dy: number, metrics: GridMetrics): WidgetRect {
  const colStep = metrics.cellW + metrics.gap;
  const rowStep = metrics.cellH + metrics.gap;
  const deltaColSpan = Math.round(dx / colStep);
  const deltaRowSpan = Math.round(dy / rowStep);
  const colSpan = clamp(rect.colSpan + deltaColSpan, 1, Math.max(1, metrics.columns - rect.col));
  const rowSpan = Math.max(1, rect.rowSpan + deltaRowSpan);
  return { ...rect, colSpan, rowSpan };
}

function rectsOverlap(a: WidgetRect, b: WidgetRect): boolean {
  return (
    a.col < b.col + b.colSpan &&
    a.col + a.colSpan > b.col &&
    a.row < b.row + b.rowSpan &&
    a.row + a.rowSpan > b.row
  );
}

/**
 * Downward-push collision resolution. `widgets` must already contain
 * `movedId` at its target rect (the caller — a drag/resize gesture already
 * knows the moved widget's proposed position); every other entry keeps its
 * last-known rect. Returns a new array in which no two rects overlap.
 *
 * Termination is by construction, not an iteration cap. Widgets are
 * processed exactly once, in row-major order (lowest `row`, then lowest
 * `col`, first) — `movedId`'s rect goes in first and is never revisited.
 * Each subsequent widget is pushed **down only** (its `row` only ever
 * increases, `col`/`colSpan`/`rowSpan` never change) just far enough to
 * clear every already-placed widget it overlaps. Once a widget is placed it
 * is never touched again by a later widget's placement — there is no
 * feedback loop that could cycle, so the whole pass always halts, and it
 * halts after visiting each of the `n` input widgets exactly once (an
 * individual widget's own settle step is itself bounded: each iteration of
 * its inner loop strictly increases its row past at least one previously
 * distinct clearance threshold among the already-placed widgets, of which
 * there are finitely many).
 */
export function resolveCollisions(widgets: WidgetRect[], movedId: string, cols: number): WidgetRect[] {
  const moved = widgets.find(w => w.id === movedId);
  const rest = widgets
    .filter(w => w.id !== movedId)
    .slice()
    .sort((a, b) => (a.row - b.row) || (a.col - b.col));

  const placed: WidgetRect[] = moved ? [{ ...moved }] : [];

  for (const w of rest) {
    const next: WidgetRect = { ...w, col: clamp(w.col, 0, Math.max(0, cols - w.colSpan)) };
    let settled = false;
    while (!settled) {
      settled = true;
      for (const p of placed) {
        if (rectsOverlap(next, p)) {
          next.row = p.row + p.rowSpan;
          settled = false;
        }
      }
    }
    placed.push(next);
  }

  return placed;
}

/** `EntityRecord[]` (or anything shaped like one) -> `WidgetRect[]`, reading
 * the same `grid_col`/`grid_row`/`grid_col_span`/`grid_row_span` fields
 * `dashboard_widget` stores. Takes a minimal structural type rather than
 * importing `EntityRecord` so this module stays free of any `@attome/xrm`
 * dependency, not just `@angular/core`. */
export function widgetRects(widgets: readonly { id: string; data: Record<string, unknown> }[]): WidgetRect[] {
  return widgets.map(w => ({
    id: w.id,
    col: Number(w.data['grid_col'] ?? 0),
    row: Number(w.data['grid_row'] ?? 0),
    colSpan: Number(w.data['grid_col_span'] ?? 1),
    rowSpan: Number(w.data['grid_row_span'] ?? 1),
  }));
}

/** Absolute pixel position (relative to the grid origin) -> the nearest
 * grid cell, clamped so a `colSpan`-wide footprint never starts past the
 * grid's right edge and never lands above row 0. Used for palette-to-canvas
 * drop positioning, where the pointer position IS the target cell. */
export function snapToGridClamped(
  px: { x: number; y: number },
  metrics: GridMetrics,
  colSpan: number,
): { col: number; row: number } {
  const { col, row } = snapToGrid(px, metrics);
  return { col: clamp(col, 0, Math.max(0, metrics.columns - colSpan)), row: Math.max(0, row) };
}

/** A move gesture's raw pixel delta, resolved against `origin` (the
 * widget's col/row/colSpan at drag-start) into its new target cell. */
export function dragTarget(
  origin: { col: number; row: number; colSpan: number },
  delta: { dx: number; dy: number },
  metrics: GridMetrics,
): { col: number; row: number } {
  const { col: deltaCol, row: deltaRow } = snapToGrid({ x: delta.dx, y: delta.dy }, metrics);
  return {
    col: clamp(origin.col + deltaCol, 0, Math.max(0, metrics.columns - origin.colSpan)),
    row: Math.max(0, origin.row + deltaRow),
  };
}

/** `rect`'s on-canvas pixel box as a ready-to-assign `[style]` CSS text
 * string — the single place this editor turns a grid position into pixels
 * for rendering, replacing the old `widgetStyle()` method that recomputed
 * this (and force-read `clientWidth` doing it) once per tile on every
 * change-detection pass. `delta` is a live raw-pixel offset added on top of
 * `rect`'s own grid position, for a gesture in progress; `resizing: true`
 * grows/shrinks width/height by it instead of translating position, with the
 * same 80x60px minimum footprint the pointer resize handler always enforced;
 * `active` drops the idle position/size transition so a live drag/resize
 * tracks the pointer with zero lag. */
export function tileBoxStyle(
  rect: WidgetRect,
  metrics: GridMetrics,
  opts: { delta?: { dx: number; dy: number } | null; resizing?: boolean; active?: boolean } = {},
): string {
  const { cellW, cellH, gap } = metrics;
  const { delta, resizing, active } = opts;
  const left = rect.col * (cellW + gap) + (!resizing ? delta?.dx ?? 0 : 0);
  const top = rect.row * (cellH + gap) + (!resizing ? delta?.dy ?? 0 : 0);
  const baseWidth = rect.colSpan * cellW + (rect.colSpan - 1) * gap;
  const baseHeight = rect.rowSpan * cellH + (rect.rowSpan - 1) * gap;
  const width = resizing ? Math.max(80, baseWidth + (delta?.dx ?? 0)) : baseWidth;
  const height = resizing ? Math.max(60, baseHeight + (delta?.dy ?? 0)) : baseHeight;
  const transition = active
    ? 'none'
    : 'left 0.2s cubic-bezier(0.25, 1, 0.5, 1), top 0.2s cubic-bezier(0.25, 1, 0.5, 1), width 0.18s ease-out, height 0.18s ease-out';
  const zIndex = active ? (resizing ? 90 : 100) : 2;
  return `position:absolute;left:${left}px;top:${top}px;width:${width}px;height:${height}px;transition:${transition};z-index:${zIndex}`;
}

/** The canvas's own `[style]` — tall enough for every widget rect plus any
 * live drag/resize/drop-ghost rect not yet committed to `rects`, with 4 rows
 * of breathing room below the lowest occupant (min 8 total). */
export function canvasHeightStyle(
  rects: readonly WidgetRect[],
  liveRects: readonly WidgetRect[],
  metrics: GridMetrics,
): Record<string, string> {
  let maxRow = 6;
  for (const r of [...rects, ...liveRects]) maxRow = Math.max(maxRow, r.row + r.rowSpan);
  const totalRows = Math.max(8, maxRow + 4);
  const minHeightPx = totalRows * metrics.cellH + (totalRows - 1) * metrics.gap;
  return { position: 'relative', width: '100%', minHeight: `${minHeightPx}px`, boxSizing: 'border-box' };
}

const RECT_FIELD_NAMES = {
  col: 'grid_col', row: 'grid_row', colSpan: 'grid_col_span', rowSpan: 'grid_row_span',
} as const satisfies Record<keyof Omit<WidgetRect, 'id'>, string>;

/** Diffs a resolved layout (e.g. `resolveCollisions`'s result) against each
 * widget's last-known rect and returns one `{ widgetId, patch }` per widget
 * whose `keys` actually moved — `patch` uses `dashboard_widget`'s own
 * column names, ready to hand to `EntityService.update`. */
export function diffLayout(
  originals: readonly WidgetRect[],
  next: ReadonlyMap<string, WidgetRect>,
  keys: readonly (keyof Omit<WidgetRect, 'id'>)[],
): { widgetId: string; patch: Record<string, unknown> }[] {
  const byId = new Map(originals.map(r => [r.id, r]));
  const commits: { widgetId: string; patch: Record<string, unknown> }[] = [];
  for (const [id, rect] of next.entries()) {
    const original = byId.get(id);
    if (!original) continue;
    const patch: Record<string, unknown> = {};
    for (const k of keys) {
      if (original[k] !== rect[k]) patch[RECT_FIELD_NAMES[k]] = rect[k];
    }
    if (Object.keys(patch).length > 0) commits.push({ widgetId: id, patch });
  }
  return commits;
}

/** Shallow patch of only the keys in `keys` whose value actually changed
 * between `before` and `after` (deep-compared via JSON, fine for the plain
 * scalar/JSON-text fields this editor edits). Moved from
 * `page-editor.component.ts` unchanged (R-02 depends on this exact
 * behavior/signature — `saveChanges()`'s widget/page draft diff). */
export function diffPatch(
  before: Record<string, unknown> | undefined,
  after: Record<string, unknown>,
  keys: readonly string[],
): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const k of keys) {
    if (JSON.stringify(after[k] ?? null) !== JSON.stringify(before?.[k] ?? null)) {
      patch[k] = after[k];
    }
  }
  return patch;
}
