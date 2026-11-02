/**
 * P6-T1: the bars of a Gantt or timeline widget, from a stored query's rows
 * and the widget's config: `label_field`, `start_field` and, for a bar with
 * a length, `end_field` (without one, or where a row has none, each row is a
 * point). Positions are percentages of the span from the earliest start to
 * the latest end, so the template places them with logical CSS and they
 * mirror in Arabic. Rows without a valid start are left out. Pure.
 */
export interface TimelineBar {
  label: string;
  start: Date;
  end: Date;
  /** Where the bar begins, as a percentage of the whole span. */
  offset: number;
  /** Its length, as a percentage; a point gets the smallest visible width. */
  length: number;
  row: Record<string, unknown>;
}

export interface Timeline {
  bars: TimelineBar[];
  from: Date;
  to: Date;
}

/** The most bars one widget draws. */
export const MAX_BARS = 200;
/** A point's width, in percent. */
const POINT = 0.75;

function field(config: Record<string, unknown> | null, key: string): string | null {
  const value = config?.[key];
  return typeof value === 'string' && value !== '' ? value : null;
}

function dateOf(value: unknown): Date | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at;
}

export function timelineBars(
  rows: readonly Record<string, unknown>[],
  config: Record<string, unknown> | null,
): Timeline | null {
  const labelField = field(config, 'label_field');
  const startField = field(config, 'start_field');
  const endField = field(config, 'end_field');
  if (!labelField || !startField) return null;
  const spans = rows.flatMap(row => {
    const start = dateOf(row[startField]);
    if (!start) return [];
    const end = (endField ? dateOf(row[endField]) : null) ?? start;
    const label = row[labelField];
    return [{
      label: label === null || label === undefined ? '' : String(label),
      start,
      end: end < start ? start : end,
      row,
    }];
  });
  if (spans.length === 0) return null;
  spans.sort((a, b) => a.start.getTime() - b.start.getTime());
  const shown = spans.slice(0, MAX_BARS);
  const from = shown[0].start;
  const to = new Date(Math.max(...shown.map(s => s.end.getTime())));
  const whole = Math.max(1, to.getTime() - from.getTime());
  return {
    from,
    to,
    bars: shown.map(s => {
      const offset = ((s.start.getTime() - from.getTime()) / whole) * 100;
      const length = Math.max(POINT, ((s.end.getTime() - s.start.getTime()) / whole) * 100);
      return { ...s, offset, length: Math.min(length, 100 - offset) || POINT };
    }),
  };
}
