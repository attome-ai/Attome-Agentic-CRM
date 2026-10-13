/**
 * Pure geometry for `DashboardChartComponent` (Dashboard 10/10 Phase 4.1).
 *
 * Nothing here aggregates: every value is a number the server already
 * computed (D-522). These functions only place those numbers on a surface —
 * axis ticks, scales, bar rectangles, line points and donut arcs — so the
 * rendering rules can be tested without a DOM.
 */

/** A value axis: its domain and the tick values drawn on it. */
export interface ValueAxis {
  min: number;
  max: number;
  ticks: number[];
}

/** The largest "nice" step (1, 2, 2.5 or 5 × 10ⁿ) giving at most `count` intervals. */
function niceStep(span: number, count: number): number {
  const raw = span / Math.max(1, count);
  const magnitude = Math.pow(10, Math.floor(Math.log10(raw)));
  const residual = raw / magnitude;
  const factor = residual <= 1 ? 1 : residual <= 2 ? 2 : residual <= 2.5 ? 2.5 : residual <= 5 ? 5 : 10;
  return factor * magnitude;
}

/**
 * A value axis that always includes zero (bars grow from zero; a line whose
 * axis starts elsewhere exaggerates change) and ends on round ticks.
 * An all-zero or empty series gets `0..1`.
 */
export function valueAxis(values: readonly number[], tickCount = 4): ValueAxis {
  const finite = values.filter(v => Number.isFinite(v));
  let lo = Math.min(0, ...finite);
  let hi = Math.max(0, ...finite);
  if (lo === hi) hi = lo + 1;
  const step = niceStep(hi - lo, tickCount);
  lo = Math.floor(lo / step) * step;
  hi = Math.ceil(hi / step) * step;
  const ticks: number[] = [];
  // Rounded to the step's precision so 0.1 + 0.2 never renders as 0.30000000000000004.
  const precision = Math.max(0, -Math.floor(Math.log10(step)) + 1);
  for (let t = lo; t <= hi + step / 2; t += step) ticks.push(Number(t.toFixed(precision)));
  return { min: lo, max: hi, ticks };
}

/** Linear map of `value` from `axis` onto `[rangeStart, rangeEnd]`. */
export function scale(value: number, axis: ValueAxis, rangeStart: number, rangeEnd: number): number {
  const span = axis.max - axis.min || 1;
  return rangeStart + ((value - axis.min) / span) * (rangeEnd - rangeStart);
}

/** The drawing area inside the axes, in pixels. */
export interface PlotArea {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** Leaves room for value labels on the y axis (the reading-start side, so
 * the right in RTL) and category labels below. */
export function plotArea(width: number, height: number, yLabelWidth: number, rtl = false): PlotArea {
  const top = 8;
  const bottom = 22;
  const left = rtl ? 8 : yLabelWidth + 8;
  const right = rtl ? yLabelWidth + 8 : 8;
  return {
    left,
    top,
    width: Math.max(10, width - left - right),
    height: Math.max(10, height - top - bottom),
  };
}

/** One bar of a (possibly grouped) column chart. */
export interface BarRect {
  category: number;
  series: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Grouped columns: `values[series][category]`. A negative value hangs below
 * the zero line. `rtl` mirrors category order so the first category starts
 * on the reading side.
 */
export function barRects(values: readonly (readonly number[])[], axis: ValueAxis, area: PlotArea, rtl = false): BarRect[] {
  const categories = Math.max(0, ...values.map(s => s.length));
  if (categories === 0) return [];
  const band = area.width / categories;
  const groupWidth = band * 0.7;
  const barWidth = groupWidth / Math.max(1, values.length);
  const zeroY = scale(0, axis, area.top + area.height, area.top);
  const rects: BarRect[] = [];
  values.forEach((series, s) => series.forEach((value, c) => {
    const slot = rtl ? categories - 1 - c : c;
    const y = scale(value, axis, area.top + area.height, area.top);
    rects.push({
      category: c,
      series: s,
      x: area.left + slot * band + (band - groupWidth) / 2 + s * barWidth,
      y: Math.min(y, zeroY),
      width: Math.max(1, barWidth - 1),
      height: Math.max(1, Math.abs(zeroY - y)),
    });
  }));
  return rects;
}

/** The x centre of a category band. */
export function bandCenter(category: number, categories: number, area: PlotArea, rtl = false): number {
  const band = area.width / Math.max(1, categories);
  const slot = rtl ? categories - 1 - category : category;
  return area.left + slot * band + band / 2;
}

export function pointsAttr(points: readonly { x: number; y: number }[]): string {
  return points.map(p => `${round(p.x)},${round(p.y)}`).join(' ');
}

/** The closed polygon between a line and the zero line. */
export function areaAttr(points: readonly { x: number; y: number }[], axis: ValueAxis, area: PlotArea): string {
  if (points.length === 0) return '';
  const zeroY = round(scale(0, axis, area.top + area.height, area.top));
  return `${round(points[0].x)},${zeroY} ${pointsAttr(points)} ${round(points[points.length - 1].x)},${zeroY}`;
}

/**
 * Donut slices as SVG path data. Negative values carry no area and are
 * skipped (the table alternative still lists them); a single full slice is
 * drawn as two half arcs because one 360° arc has no extent in SVG.
 */
export function donutPaths(values: readonly number[], cx: number, cy: number, outer: number, inner: number): (string | null)[] {
  const total = values.reduce((sum, v) => sum + (v > 0 ? v : 0), 0);
  if (total <= 0) return values.map(() => null);
  let angle = -Math.PI / 2;
  return values.map(v => {
    if (!(v > 0)) return null;
    const sweep = (v / total) * Math.PI * 2;
    const start = angle;
    angle += sweep;
    if (sweep >= Math.PI * 2 - 1e-9) {
      const mid = start + Math.PI;
      return arc(cx, cy, outer, inner, start, mid) + ' ' + arc(cx, cy, outer, inner, mid, start + Math.PI * 2);
    }
    return arc(cx, cy, outer, inner, start, angle);
  });
}

function arc(cx: number, cy: number, outer: number, inner: number, from: number, to: number): string {
  const large = to - from > Math.PI ? 1 : 0;
  const p = (r: number, a: number) => `${round(cx + r * Math.cos(a))},${round(cy + r * Math.sin(a))}`;
  return `M${p(outer, from)} A${outer},${outer} 0 ${large} 1 ${p(outer, to)} L${p(inner, to)} A${inner},${inner} 0 ${large} 0 ${p(inner, from)} Z`;
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
