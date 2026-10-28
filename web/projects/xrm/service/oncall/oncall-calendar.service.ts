import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { Observable, map } from 'rxjs';

/** An on-call schedule (`oncall_schedule`, itsm pack 0003). */
export interface OncallScheduleRef {
  id: string;
  name: string;
}

/** `attome_service::oncall::calendar::OnCallStretchView`. */
export interface OnCallStretch {
  start: string;
  end: string;
  user_id: string;
  user_name: string | null;
  via: 'override' | 'layer' | string;
  layer: number | null;
}

/** One day of the calendar and the stretches that fall in it, clipped. */
export interface CalendarDay {
  /** The day's start (UTC midnight), ISO. */
  day: string;
  stretches: OnCallStretch[];
}

const DAY_MS = 86_400_000;

/** Monday 00:00 UTC of the week holding `at`. Pure. */
export function weekStart(at: Date): Date {
  const midnight = Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate());
  const sinceMonday = (new Date(midnight).getUTCDay() + 6) % 7;
  return new Date(midnight - sinceMonday * DAY_MS);
}

/** The `days` days from `from`, each with the stretches overlapping it,
 *  clipped to the day. Pure. */
export function byDay(stretches: readonly OnCallStretch[], from: Date, days: number): CalendarDay[] {
  const out: CalendarDay[] = [];
  for (let i = 0; i < days; i++) {
    const start = from.getTime() + i * DAY_MS;
    const end = start + DAY_MS;
    out.push({
      day: new Date(start).toISOString(),
      stretches: stretches
        .filter(s => Date.parse(s.start) < end && Date.parse(s.end) > start)
        .map(s => ({
          ...s,
          start: new Date(Math.max(Date.parse(s.start), start)).toISOString(),
          end: new Date(Math.min(Date.parse(s.end), end)).toISOString(),
        })),
    });
  }
  return out;
}

/** H7-T2: the on-call schedules, and who is on call on one over a range. */
@Injectable({ providedIn: 'root' })
export class OncallCalendarService {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);

  schedules(): Observable<OncallScheduleRef[]> {
    return this.entities.list('oncall_schedule', { limit: 200, sorts: [{ field: 'name', dir: 'asc' }] }).pipe(
      map(page => page.data.map(r => {
        const name = (r.data as Record<string, unknown>)['name'];
        return { id: r.id, name: typeof name === 'string' && name ? name : r.id };
      })),
    );
  }

  calendar(schedule: string, from: Date, to: Date): Observable<OnCallStretch[]> {
    return this.api.get<{ items: OnCallStretch[] }>(
      `/api/v1/service/oncall/schedules/${encodeURIComponent(schedule)}/calendar`,
      { from: from.toISOString(), to: to.toISOString() },
    ).pipe(map(page => page.items));
  }
}
