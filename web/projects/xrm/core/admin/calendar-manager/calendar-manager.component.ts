import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';

import {
  AdminService,
  CalendarAdminItem,
  CalendarException,
  CalendarHoliday,
  CalendarMutation,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

const WEEKDAYS: { key: string; label: string }[] = [
  { key: 'sun', label: 'Sun' }, { key: 'mon', label: 'Mon' }, { key: 'tue', label: 'Tue' },
  { key: 'wed', label: 'Wed' }, { key: 'thu', label: 'Thu' }, { key: 'fri', label: 'Fri' },
  { key: 'sat', label: 'Sat' },
];

/** `"09:00"` <-> `540` (minutes from midnight) — the `<input type="time">` <-> `TimeRange` bridge. */
function minutesToClock(minutes: number): string {
  const h = Math.floor(minutes / 60).toString().padStart(2, '0');
  const m = (minutes % 60).toString().padStart(2, '0');
  return `${h}:${m}`;
}
function clockToMinutes(clock: string): number {
  const [h, m] = clock.split(':').map(Number);
  return (h || 0) * 60 + (m || 0);
}

interface CalendarDraft {
  name: string;
  description: string;
  tz: string;
  workingDays: Set<string>;
  startClock: string;
  endClock: string;
  is_default: boolean;
}

/**
 * D-404 / M83 Phase 1 admin page for `calendar` +
 * `calendar_holiday` + (D-592) `calendar_exception`.
 * An exception here is one range or closed; the API accepts several ranges
 * per date, and such an exception is shown with every range. Mirrors `SidebarManagerComponent`'s shape
 * (list + inline `FormsModule` editor), simplified one notch further for
 * `hours`: this editor applies one start/end time to every selected working
 * day rather than exposing attome-calendar's full per-day-multiple-ranges
 * shape (lunch breaks, split shifts) — the common case, and the same
 * simplification `BusinessCalendar::simple()` already makes on the Rust
 * side. A calendar authored with richer per-day hours (via the API/bundle
 * directly) still round-trips through this page's read path; editing one
 * here collapses it back to the single-range shape on save.
 */
@Component({
  selector: 'xrm-calendar-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [OwnerLayerBadgeComponent, FormsModule],
  styleUrls: ['./calendar-manager.component.css'],
  templateUrl: './calendar-manager.component.html',
})
export class CalendarManagerComponent implements OnInit {
  private readonly service = inject(AdminService);

  readonly weekdays = WEEKDAYS;
  readonly calendars = signal<CalendarAdminItem[]>([]);
  readonly holidays = signal<CalendarHoliday[]>([]);
  readonly exceptions = signal<CalendarException[]>([]);
  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly error = signal('');
  readonly message = signal('');
  readonly selectedId = signal<string | null>(null);
  readonly editing = signal(false);
  readonly creating = signal(false);
  search = '';
  draft: CalendarDraft = this.blankDraft();
  newHolidayName = '';
  newHolidayDate = '';
  newExceptionName = '';
  newExceptionDate = '';
  newExceptionClosed = true;
  newExceptionStart = '09:00';
  newExceptionEnd = '13:00';

  readonly filtered = computed(() => {
    const query = this.search.trim().toLowerCase();
    return this.calendars().filter(c => !query || c.name.toLowerCase().includes(query));
  });

  ngOnInit(): void { this.reload(); }

  reload(): void {
    this.loading.set(true); this.error.set('');
    this.service.listCalendars().subscribe({
      next: items => { this.calendars.set(items); this.loading.set(false); },
      error: (err: ApiError) => { this.error.set(err.message); this.loading.set(false); },
    });
  }

  select(item: CalendarAdminItem): void {
    this.selectedId.set(item.id); this.creating.set(false); this.editing.set(true);
    this.message.set(''); this.error.set('');
    this.draft = this.fromItem(item);
    this.loadDates(item.id);
  }

  startCreate(): void {
    this.selectedId.set(null); this.creating.set(true); this.editing.set(true);
    this.message.set(''); this.error.set('');
    this.draft = this.blankDraft();
    this.holidays.set([]);
    this.exceptions.set([]);
  }

  cancel(): void { this.editing.set(false); this.creating.set(false); this.selectedId.set(null); }

  toggleWorkingDay(key: string): void {
    if (this.draft.workingDays.has(key)) this.draft.workingDays.delete(key);
    else this.draft.workingDays.add(key);
  }
  hasWorkingDay(key: string): boolean { return this.draft.workingDays.has(key); }

  save(): void {
    this.saving.set(true); this.error.set(''); this.message.set('');
    const body = this.toMutation();
    const request = this.creating()
      ? this.service.createCalendar(body)
      : this.service.updateCalendar(this.selectedId()!, body);
    request.subscribe({
      next: saved => {
        this.calendars.update(items =>
          this.creating() ? [...items, saved] : items.map(c => c.id === saved.id ? saved : c));
        this.saving.set(false); this.creating.set(false); this.selectedId.set(saved.id);
        this.draft = this.fromItem(saved);
        this.message.set('Calendar saved.');
        this.loadDates(saved.id);
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  deactivate(): void {
    const id = this.selectedId();
    if (!id) return;
    this.saving.set(true); this.error.set('');
    this.service.deleteCalendar(id).subscribe({
      next: () => {
        this.calendars.update(items => items.filter(c => c.id !== id));
        this.saving.set(false);
        this.cancel();
        this.message.set('Calendar deactivated.');
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  private loadDates(calendarId: string): void {
    this.service.listHolidays(calendarId).subscribe({
      next: rows => this.holidays.set(rows),
      error: () => this.holidays.set([]),
    });
    this.service.listExceptions(calendarId).subscribe({
      next: rows => this.exceptions.set(rows),
      error: () => this.exceptions.set([]),
    });
  }

  addHoliday(): void {
    const id = this.selectedId();
    if (!id || !this.newHolidayName.trim() || !this.newHolidayDate) return;
    this.service.createHoliday(id, { name: this.newHolidayName.trim(), holiday_date: this.newHolidayDate })
      .subscribe({
        next: row => {
          this.holidays.update(rows => [...rows, row].sort((a, b) => a.holiday_date.localeCompare(b.holiday_date)));
          this.newHolidayName = ''; this.newHolidayDate = '';
        },
        error: (err: ApiError) => this.error.set(err.message),
      });
  }

  removeHoliday(holiday: CalendarHoliday): void {
    const id = this.selectedId();
    if (!id) return;
    this.service.deleteHoliday(id, holiday.id).subscribe({
      next: () => this.holidays.update(rows => rows.filter(h => h.id !== holiday.id)),
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  addException(): void {
    const id = this.selectedId();
    if (!id || !this.newExceptionName.trim() || !this.newExceptionDate) return;
    const ranges = this.newExceptionClosed
      ? []
      : [{ start_minute: clockToMinutes(this.newExceptionStart), end_minute: clockToMinutes(this.newExceptionEnd) }];
    this.service.createException(id, {
      name: this.newExceptionName.trim(), exception_date: this.newExceptionDate, ranges,
    }).subscribe({
      next: row => {
        this.exceptions.update(rows => [...rows, row].sort((a, b) => a.exception_date.localeCompare(b.exception_date)));
        this.newExceptionName = ''; this.newExceptionDate = '';
      },
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  removeException(exception: CalendarException): void {
    const id = this.selectedId();
    if (!id) return;
    this.service.deleteException(id, exception.id).subscribe({
      next: () => this.exceptions.update(rows => rows.filter(e => e.id !== exception.id)),
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  /** `"Closed"` or `"09:00–13:00, 14:00–16:00"`. */
  describeRanges(exception: CalendarException): string {
    if (!exception.ranges.length) return 'Closed';
    return exception.ranges
      .map(r => `${minutesToClock(r.start_minute)}–${minutesToClock(r.end_minute)}`)
      .join(', ');
  }

  private fromItem(item: CalendarAdminItem): CalendarDraft {
    // Reads back the first range of the first working day as the
    // representative single range (see the class doc comment).
    const firstDay = item.working_days.find(d => item.hours[d]?.length);
    const firstRange = firstDay ? item.hours[firstDay][0] : undefined;
    return {
      name: item.name,
      description: item.description ?? '',
      tz: item.tz,
      workingDays: new Set(item.working_days),
      startClock: minutesToClock(firstRange?.start_minute ?? 540),
      endClock: minutesToClock(firstRange?.end_minute ?? 1020),
      is_default: item.is_default,
    };
  }

  private blankDraft(): CalendarDraft {
    return {
      name: '', description: '', tz: 'UTC',
      workingDays: new Set(['mon', 'tue', 'wed', 'thu', 'fri']),
      startClock: '09:00', endClock: '17:00',
      is_default: false,
    };
  }

  private toMutation(): CalendarMutation {
    const range = { start_minute: clockToMinutes(this.draft.startClock), end_minute: clockToMinutes(this.draft.endClock) };
    const workingDays = [...this.draft.workingDays];
    const hours: CalendarMutation['hours'] = {};
    for (const day of workingDays) hours[day] = [range];
    return {
      name: this.draft.name.trim(),
      description: this.draft.description.trim() || null,
      tz: this.draft.tz.trim(),
      working_days: workingDays,
      hours,
      is_default: this.draft.is_default,
    };
  }
}
