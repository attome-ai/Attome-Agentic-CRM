import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import {
  AdminService,
  CalendarAdminItem,
  CalendarAssignment,
  CalendarException,
  CalendarExpandedRules,
  CalendarFeed,
  CalendarHoliday,
  CalendarMutation,
  CalendarPack,
  CalendarRule,
  CalendarRuleBody,
  CalendarSeason,
  CalendarSeasonBody,
  CalendarSighting,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const;

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
  name_ar: string;
  parent_calendar_id: string;
  description: string;
  tz: string;
  workingDays: Set<string>;
  startClock: string;
  endClock: string;
  is_default: boolean;
}

export type RuleKind = 'fixed' | 'nth_weekday' | 'hijri' | 'one_off';

/** The holiday rule form (Z12-T13). */
export interface RuleDraft {
  name: string;
  name_ar: string;
  kind: RuleKind;
  month: number;
  day: number;
  weekday: string;
  n: number;
  date: string;
  span_days: number;
  needs_sighting: boolean;
}

export function blankRule(): RuleDraft {
  return {
    name: '', name_ar: '', kind: 'hijri', month: 10, day: 1, weekday: 'fri', n: 1,
    date: '', span_days: 1, needs_sighting: false,
  };
}

/** The rule body `POST .../holiday-rules` takes, from the form. Pure. */
export function ruleBody(draft: RuleDraft): CalendarRuleBody {
  const span_days = Math.max(1, Math.min(15, Math.trunc(draft.span_days) || 1));
  const rule = (() => {
    switch (draft.kind) {
      case 'fixed':       return { kind: 'fixed', month: draft.month, day: draft.day, span_days };
      case 'nth_weekday': return { kind: 'nth_weekday', month: draft.month, weekday: draft.weekday, n: draft.n, span_days };
      case 'hijri':       return { kind: 'hijri', month: draft.month, day: draft.day, span_days };
      case 'one_off':     return { kind: 'one_off', date: draft.date, span_days };
    }
  })();
  return {
    name: draft.name.trim(),
    name_ar: draft.name_ar.trim() || null,
    needs_sighting: draft.kind === 'hijri' && draft.needs_sighting,
    rule: rule as unknown as CalendarRuleBody['rule'],
  };
}

/** The season form: a Hijri start and end, and hours per weekday. */
export interface SeasonDraft {
  name: string;
  name_ar: string;
  startMonth: number;
  startDay: number;
  endMonth: number;
  endDay: number;
  days: Record<string, { on: boolean; start: string; end: string }>;
}

export function blankSeason(): SeasonDraft {
  const days: SeasonDraft['days'] = {};
  for (const d of WEEKDAYS) days[d] = { on: d !== 'fri' && d !== 'sat', start: '10:00', end: '15:00' };
  return { name: '', name_ar: '', startMonth: 9, startDay: 1, endMonth: 9, endDay: 29, days };
}

/** The season body `POST .../seasons` takes. Pure. */
export function seasonBody(draft: SeasonDraft): CalendarSeasonBody {
  const hours: Record<string, { start_minute: number; end_minute: number }[]> = {};
  for (const [day, value] of Object.entries(draft.days)) {
    if (value.on) hours[day] = [{ start_minute: clockToMinutes(value.start), end_minute: clockToMinutes(value.end) }];
  }
  const definition = {
    start: { kind: 'hijri', month: draft.startMonth, day: draft.startDay, span_days: 1 },
    end: { kind: 'hijri', month: draft.endMonth, day: draft.endDay, span_days: 1 },
    hours,
  };
  return {
    name: draft.name.trim(),
    name_ar: draft.name_ar.trim() || null,
    definition: definition as unknown as CalendarSeasonBody['definition'],
  };
}

type Tab = 'details' | 'dates' | 'rules' | 'seasons' | 'sightings' | 'feeds' | 'assignments';

/**
 * D-404 / M83 Phase 1 admin page for `calendar` + `calendar_holiday` +
 * (D-592) `calendar_exception`, extended by Z12-T13 for inheritance (a
 * parent calendar and an Arabic name), holiday rules with their next two
 * years of dates in both calendars, Ramadan-style seasons, sightings to
 * confirm, country packs, iCal feeds, and which calendar a user or team
 * works on. Every label is in the catalogs, Arabic first like the rest of
 * the admin UI; logical CSS only.
 *
 * The working hours editor applies one start/end time to every selected
 * working day (the common case, as `BusinessCalendar::simple()` does); a
 * calendar authored with richer per-day hours through the API still reads
 * back here, and saving it collapses it to one range per day.
 */
@Component({
  selector: 'xrm-calendar-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [OwnerLayerBadgeComponent, FormsModule, TranslatePipe, LocalDatePipe],
  styleUrls: ['./calendar-manager.component.css'],
  templateUrl: './calendar-manager.component.html',
})
export class CalendarManagerComponent implements OnInit {
  private readonly service = inject(AdminService);
  private readonly lang = inject(LangService);

  readonly weekdays = WEEKDAYS;
  readonly tabs: Tab[] = ['details', 'dates', 'rules', 'seasons', 'sightings', 'feeds', 'assignments'];
  readonly ruleKinds: RuleKind[] = ['fixed', 'nth_weekday', 'hijri', 'one_off'];
  readonly calendars = signal<CalendarAdminItem[]>([]);
  readonly holidays = signal<CalendarHoliday[]>([]);
  readonly exceptions = signal<CalendarException[]>([]);
  readonly rules = signal<CalendarRule[]>([]);
  readonly seasons = signal<CalendarSeason[]>([]);
  readonly expanded = signal<CalendarExpandedRules | null>(null);
  readonly sightings = signal<CalendarSighting[]>([]);
  readonly packs = signal<CalendarPack[]>([]);
  readonly feeds = signal<CalendarFeed[]>([]);
  readonly assignment = signal<CalendarAssignment | null>(null);
  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly error = signal('');
  readonly message = signal('');
  readonly selectedId = signal<string | null>(null);
  readonly editing = signal(false);
  readonly creating = signal(false);
  readonly tab = signal<Tab>('details');
  readonly packsOpen = signal(false);
  /** The sighting rows being confirmed, by `rule_id:hijri_year`. */
  readonly confirming = signal<ReadonlySet<string>>(new Set());
  search = '';
  draft: CalendarDraft = this.blankDraft();
  ruleDraft: RuleDraft = blankRule();
  seasonDraft: SeasonDraft = blankSeason();
  /** The date each sighting row will be confirmed with, by row key. */
  sightingDates: Record<string, string> = {};
  newHolidayName = '';
  newHolidayDate = '';
  newExceptionName = '';
  newExceptionDate = '';
  newExceptionClosed = true;
  newExceptionStart = '09:00';
  newExceptionEnd = '13:00';
  newFeedUrl = '';
  newFeedEnabled = true;
  subjectType: 'user' | 'team' = 'user';
  subjectId = '';
  assignCalendarId = '';

  readonly filtered = computed(() => {
    const query = this.search.trim().toLowerCase();
    return this.calendars().filter(c =>
      !query || c.name.toLowerCase().includes(query) || (c.name_ar ?? '').includes(query));
  });

  /** The calendars a calendar may inherit from: every other one. */
  readonly parentChoices = computed(() => this.calendars().filter(c => c.id !== this.selectedId()));

  readonly calendarSightings = computed(() =>
    this.sightings().filter(s => s.calendar_id === this.selectedId()));

  ngOnInit(): void { this.reload(); }

  t(key: string, params?: Record<string, unknown>): string {
    return this.lang.translate(`calendarManager.${key}`, params);
  }

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
    this.assignCalendarId = item.id;
    this.loadDates(item.id);
  }

  startCreate(): void {
    this.selectedId.set(null); this.creating.set(true); this.editing.set(true);
    this.message.set(''); this.error.set('');
    this.tab.set('details');
    this.draft = this.blankDraft();
    this.holidays.set([]);
    this.exceptions.set([]);
    this.rules.set([]);
    this.seasons.set([]);
    this.expanded.set(null);
    this.feeds.set([]);
  }

  cancel(): void { this.editing.set(false); this.creating.set(false); this.selectedId.set(null); }

  setTab(tab: Tab): void {
    this.tab.set(tab);
    if (tab === 'sightings') this.loadSightings();
  }

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
        this.message.set(this.t('saved'));
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
        this.message.set(this.t('deactivated'));
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
    this.service.getCalendar(calendarId).subscribe({
      next: full => { this.rules.set(full.rules); this.seasons.set(full.seasons); },
      error: () => { this.rules.set([]); this.seasons.set([]); },
    });
    this.loadExpanded(calendarId);
    this.service.listFeeds(calendarId).subscribe({
      next: rows => this.feeds.set(rows),
      error: () => this.feeds.set([]),
    });
  }

  private loadExpanded(calendarId: string): void {
    this.service.expandedRules(calendarId).subscribe({
      next: rows => this.expanded.set(rows),
      error: () => this.expanded.set(null),
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

  /** "Closed", or the ranges, such as "09:00–13:00, 14:00–16:00". */
  describeRanges(exception: CalendarException): string {
    if (!exception.ranges.length) return this.t('closed');
    return exception.ranges
      .map(r => `${minutesToClock(r.start_minute)}–${minutesToClock(r.end_minute)}`)
      .join(', ');
  }

  /** The localized name: Arabic when the page is Arabic and one is set. */
  nameOf(item: { name: string; name_ar?: string | null }): string {
    return this.lang.current() === 'ar' && item.name_ar ? item.name_ar : item.name;
  }

  // ── Holiday rules ────────────────────────────────────────────────────────

  addRule(): void {
    const id = this.selectedId();
    if (!id || !this.ruleDraft.name.trim()) return;
    if (this.ruleDraft.kind === 'one_off' && !this.ruleDraft.date) return;
    this.saving.set(true); this.error.set('');
    this.service.createRule(id, ruleBody(this.ruleDraft)).subscribe({
      next: rule => {
        this.rules.update(rows => [...rows.filter(r => r.name !== rule.name), rule]
          .sort((a, b) => a.name.localeCompare(b.name)));
        this.ruleDraft = blankRule();
        this.saving.set(false);
        this.loadExpanded(id);
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  removeRule(rule: CalendarRule): void {
    const id = this.selectedId();
    if (!id) return;
    this.service.deleteRule(id, rule.id).subscribe({
      next: () => { this.rules.update(rows => rows.filter(r => r.id !== rule.id)); this.loadExpanded(id); },
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  /** A rule in words, from its stored JSON. */
  describeRule(rule: CalendarRule): string {
    const r = rule.rule as unknown as Record<string, unknown>;
    const span = Number(r['span_days'] ?? 1);
    const days = this.t('spanDays', { count: span });
    switch (r['kind']) {
      case 'fixed': return `${this.t('kind.fixed')}: ${r['day']}/${r['month']} · ${days}`;
      case 'nth_weekday':
        return `${this.t('kind.nth_weekday')}: ${r['n']} × ${this.t('weekday.' + r['weekday'])} / ${r['month']} · ${days}`;
      case 'hijri': return `${this.t('kind.hijri')}: ${r['day']}/${r['month']} · ${days}`;
      case 'one_off': return `${this.t('kind.one_off')}: ${r['date']} · ${days}`;
      default: return String(r['kind'] ?? '');
    }
  }

  // ── Seasons ──────────────────────────────────────────────────────────────

  addSeason(): void {
    const id = this.selectedId();
    if (!id || !this.seasonDraft.name.trim()) return;
    this.saving.set(true); this.error.set('');
    this.service.createSeason(id, seasonBody(this.seasonDraft)).subscribe({
      next: season => {
        this.seasons.update(rows => [...rows.filter(s => s.name !== season.name), season]
          .sort((a, b) => a.name.localeCompare(b.name)));
        this.seasonDraft = blankSeason();
        this.saving.set(false);
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  removeSeason(season: CalendarSeason): void {
    const id = this.selectedId();
    if (!id) return;
    this.service.deleteSeason(id, season.id).subscribe({
      next: () => this.seasons.update(rows => rows.filter(s => s.id !== season.id)),
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  // ── Sightings ────────────────────────────────────────────────────────────

  sightingKey(row: CalendarSighting): string { return `${row.rule_id}:${row.hijri_year}`; }

  loadSightings(): void {
    this.service.listSightings(new Date().getFullYear()).subscribe({
      next: rows => {
        this.sightings.set(rows);
        for (const row of rows) {
          const key = this.sightingKey(row);
          this.sightingDates[key] ??= row.confirmed_start ?? row.expected_start;
        }
      },
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  /** Whether confirming `row` would change nothing: its chosen date is already confirmed. */
  sightingUnchanged(row: CalendarSighting): boolean {
    return (this.sightingDates[this.sightingKey(row)] || row.expected_start) === row.confirmed_start;
  }

  /** Confirms the start: one post per change, the button off while it runs
   * and once the chosen date is the confirmed one. */
  confirmSighting(row: CalendarSighting): void {
    const key = this.sightingKey(row);
    const date = this.sightingDates[key] || row.expected_start;
    if (this.confirming().has(key) || this.sightingUnchanged(row)) return;
    this.confirming.update(set => new Set(set).add(key));
    this.service.confirmSighting({ rule_id: row.rule_id, hijri_year: row.hijri_year, confirmed_start: date })
      .subscribe({
        next: () => {
          this.sightings.update(rows => rows.map(r =>
            this.sightingKey(r) === key ? { ...r, confirmed_start: date } : r));
          this.confirming.update(set => { const next = new Set(set); next.delete(key); return next; });
          this.message.set(this.t('sightingConfirmed', { name: row.rule_name, date }));
        },
        error: (err: ApiError) => {
          this.confirming.update(set => { const next = new Set(set); next.delete(key); return next; });
          this.error.set(err.message);
        },
      });
  }

  // ── Packs ────────────────────────────────────────────────────────────────

  openPacks(): void {
    this.packsOpen.set(true);
    this.service.listPacks().subscribe({
      next: rows => this.packs.set(rows),
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  applyPack(pack: CalendarPack): void {
    this.saving.set(true); this.error.set('');
    this.service.applyPack(pack.code).subscribe({
      next: applied => {
        this.saving.set(false);
        this.packsOpen.set(false);
        this.message.set(this.t('packApplied', {
          name: this.nameOf(pack), rules: applied.rules_changed, seasons: applied.seasons_changed,
        }));
        this.service.listCalendars().subscribe(items => {
          this.calendars.set(items);
          const calendar = items.find(c => c.id === applied.calendar_id);
          if (calendar) this.select(calendar);
        });
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  // ── Feeds ────────────────────────────────────────────────────────────────

  addFeed(): void {
    const id = this.selectedId();
    if (!id || !this.newFeedUrl.trim()) return;
    this.service.createFeed({ calendar_id: id, url: this.newFeedUrl.trim(), enabled: this.newFeedEnabled })
      .subscribe({
        next: feed => { this.feeds.update(rows => [...rows, feed]); this.newFeedUrl = ''; },
        error: (err: ApiError) => this.error.set(err.message),
      });
  }

  removeFeed(feed: CalendarFeed): void {
    this.service.deleteFeed(feed.id).subscribe({
      next: () => this.feeds.update(rows => rows.filter(f => f.id !== feed.id)),
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  // ── Assignments ──────────────────────────────────────────────────────────

  findAssignment(): void {
    const subject = this.subjectId.trim();
    if (!subject) return;
    this.error.set('');
    this.service.getAssignment(this.subjectType, subject).subscribe({
      next: row => { this.assignment.set(row); this.assignCalendarId = row.calendar_id; },
      error: () => this.assignment.set(null),
    });
  }

  saveAssignment(): void {
    const subject = this.subjectId.trim();
    if (!subject || !this.assignCalendarId) return;
    this.service.putAssignment(this.subjectType, subject, this.assignCalendarId, this.assignment()?.row_version)
      .subscribe({
        next: row => { this.assignment.set(row); this.message.set(this.t('assigned')); },
        error: (err: ApiError) => this.error.set(err.message),
      });
  }

  clearAssignment(): void {
    const subject = this.subjectId.trim();
    if (!subject) return;
    this.service.deleteAssignment(this.subjectType, subject).subscribe({
      next: () => { this.assignment.set(null); this.message.set(this.t('unassigned')); },
      error: (err: ApiError) => this.error.set(err.message),
    });
  }

  private fromItem(item: CalendarAdminItem): CalendarDraft {
    // Reads back the first range of the first working day as the
    // representative single range (see the class doc comment).
    const firstDay = item.working_days.find(d => item.hours[d]?.length);
    const firstRange = firstDay ? item.hours[firstDay][0] : undefined;
    return {
      name: item.name,
      name_ar: item.name_ar ?? '',
      parent_calendar_id: item.parent_calendar_id ?? '',
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
      name: '', name_ar: '', parent_calendar_id: '', description: '', tz: 'UTC',
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
      name_ar: this.draft.name_ar.trim() || null,
      parent_calendar_id: this.draft.parent_calendar_id || null,
      description: this.draft.description.trim() || null,
      tz: this.draft.tz.trim(),
      working_days: workingDays,
      hours,
      is_default: this.draft.is_default,
    };
  }
}
