import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { AssignmentView, DayCoverage, PickOption, ScheduleDetail } from '../workforce-api.service';

/** One shift or break drawn in a day cell, as a share of the day. */
export interface GridBar {
  id: string;
  /** Percent of the day from midnight (UTC) to the start. */
  start: number;
  /** Percent of the day it lasts. */
  width: number;
  activity: string;
  assignment: AssignmentView;
}

/** One person's row: a list of bars per day. */
export interface GridRow {
  userId: string;
  label: string;
  days: GridBar[][];
}

/** A day's required and scheduled agent-intervals, for the coverage chart. */
export interface DayTotal {
  day: string;
  required: number;
  scheduled: number;
  under: number;
}

const DAY_MS = 86_400_000;

/** Every day from `from` to `to` (inclusive, `YYYY-MM-DD`), at most `max`. Pure. */
export function scheduleDays(from: string | null | undefined, to: string | null | undefined, max = 31): string[] {
  const start = Date.parse(`${from ?? ''}T00:00:00Z`);
  const end = Date.parse(`${to ?? from ?? ''}T00:00:00Z`);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return [];
  const out: string[] = [];
  for (let t = start; t <= end && out.length < max; t += DAY_MS) {
    out.push(new Date(t).toISOString().slice(0, 10));
  }
  return out;
}

/** The people of `assignments` (by `names`' order, then the rest) with their bars per day. Pure. */
export function gridRows(
  assignments: readonly AssignmentView[],
  days: readonly string[],
  names: ReadonlyMap<string, string>,
): GridRow[] {
  const byUser = new Map<string, AssignmentView[]>();
  for (const a of assignments) {
    if (!a.user_id) continue;
    const list = byUser.get(a.user_id) ?? [];
    list.push(a);
    byUser.set(a.user_id, list);
  }
  const users = [...byUser.keys()].sort((x, y) => (names.get(x) ?? x).localeCompare(names.get(y) ?? y));
  return users.map(userId => ({
    userId,
    label: names.get(userId) ?? userId,
    days: days.map(day => {
      const dayStart = Date.parse(`${day}T00:00:00Z`);
      return (byUser.get(userId) ?? [])
        .map(a => {
          const s = Date.parse(a.start_at ?? '');
          const e = Date.parse(a.end_at ?? '');
          if (!Number.isFinite(s) || !Number.isFinite(e) || e <= dayStart || s >= dayStart + DAY_MS) return null;
          const from = Math.max(s, dayStart);
          const until = Math.min(e, dayStart + DAY_MS);
          return {
            id: a.id,
            start: ((from - dayStart) / DAY_MS) * 100,
            width: Math.max(((until - from) / DAY_MS) * 100, 0.5),
            activity: a.activity ?? 'work',
            assignment: a,
          };
        })
        .filter((b): b is GridBar => b !== null);
    }),
  }));
}

/** Required and scheduled totals of each coverage day. Pure. */
export function dayTotals(coverage: readonly DayCoverage[]): DayTotal[] {
  const sum = (v: readonly number[]) => v.reduce((a, b) => a + b, 0);
  return coverage.map(c => ({ day: c.day, required: sum(c.requirement), scheduled: sum(c.after), under: c.under }));
}

/**
 * G17-T13: a schedule as a grid, people by days, each shift a bar placed
 * along its day (breaks and meals shaded), and under it the coverage per day:
 * required against scheduled agent-intervals. Bars are placed with logical
 * insets, so the grid mirrors in right-to-left. Dates show Gregorian with
 * Hijri beside them.
 */
@Component({
  selector: 'xrm-workforce-schedule-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  templateUrl: './schedule-grid.component.html',
  styleUrl: './schedule-grid.component.css',
})
export class ScheduleGridComponent {
  readonly schedule = input.required<ScheduleDetail>();
  readonly users = input<PickOption[]>([]);
  readonly selectAssignment = output<AssignmentView>();

  readonly days = computed(() => scheduleDays(this.schedule().period_from, this.schedule().period_to));
  private readonly names = computed(() => new Map(this.users().map(u => [u.id, u.label])));
  readonly rows = computed(() => gridRows(this.schedule().assignments, this.days(), this.names()));
  readonly totals = computed(() => dayTotals(this.schedule().coverage));
  readonly maxTotal = computed(() => Math.max(1, ...this.totals().map(t => Math.max(t.required, t.scheduled))));

  share(value: number): number {
    return (value / this.maxTotal()) * 100;
  }

  activityKey(activity: string): string {
    switch (activity) {
      case 'break': return 'xrm.workforce.activity.break';
      case 'meal': return 'xrm.workforce.activity.meal';
      case 'training': return 'xrm.workforce.activity.training';
      default: return 'xrm.workforce.activity.work';
    }
  }
}
