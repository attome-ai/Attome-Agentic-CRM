import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LiveChannel, LocalDatePipe, TranslatePipe, UserPreferencesService } from '@attome/base';
import { forkJoin } from 'rxjs';
import { AssignmentView, OfferRow, PickOption, WorkforceApiService } from '../workforce-api.service';
import { writeErrorKey } from '../workforce-page.component';

/** Days of schedule the view shows, from today. */
export const MY_SCHEDULE_DAYS = 14;

/** One day of the caller's shifts. */
export interface ScheduleDay {
  /** `YYYY-MM-DD` in the person's time zone. */
  day: string;
  shifts: AssignmentView[];
}

/** `at` as a `YYYY-MM-DD` day in `timeZone` (the browser's when null). Pure. */
export function dayKey(at: string, timeZone: string | null): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: timeZone ?? undefined, year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date(at));
}

/** The shifts grouped by day, days and shifts in time order; a shift without a start is left out. Pure. */
export function scheduleByDay(shifts: readonly AssignmentView[], timeZone: string | null): ScheduleDay[] {
  const days = new Map<string, AssignmentView[]>();
  for (const s of [...shifts].filter(s => s.start_at).sort((a, b) => (a.start_at ?? '').localeCompare(b.start_at ?? ''))) {
    const key = dayKey(s.start_at as string, timeZone);
    days.set(key, [...(days.get(key) ?? []), s]);
  }
  return [...days.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([day, list]) => ({ day, shifts: list }));
}

/** `YYYY-MM-DD` of `date` plus `days`, in UTC. Pure. */
export function addDays(date: Date, days: number): string {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + days));
  return d.toISOString().slice(0, 10);
}

/**
 * G17-T14: a person's own workforce view, laid out for a phone (one column
 * from 360 px): the next two weeks of published shifts by day, giving a
 * shift to a colleague (a swap request, which may wait for a planner), and
 * the overtime and time-off offers sent to people, to accept (the first to
 * accept gets one). Leave is requested on the leave form, linked here.
 * A published schedule, a decided swap or a taken offer tells the person
 * through a notification; when one arrives, or a shift or offer changes,
 * the view reloads.
 */
@Component({
  selector: 'xrm-workforce-my-schedule',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  templateUrl: './my-schedule.component.html',
  styleUrl: './my-schedule.component.css',
})
export class MyScheduleComponent implements OnInit {
  private readonly api = inject(WorkforceApiService);
  private readonly lang = inject(LangService);
  private readonly prefs = inject(UserPreferencesService);
  private readonly live = inject(LiveChannel);
  private readonly destroyRef = inject(DestroyRef);

  readonly shifts = signal<AssignmentView[]>([]);
  readonly offers = signal<OfferRow[]>([]);
  readonly colleagues = signal<PickOption[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);
  /** The shift being given away, and to whom. */
  readonly giving = signal<string | null>(null);
  readonly giveTo = signal('');
  readonly giveReason = signal('');

  readonly days = computed(() => scheduleByDay(this.shifts(), this.prefs.timezone()));
  readonly dayCount = MY_SCHEDULE_DAYS;

  ngOnInit(): void {
    this.load();
    const unwatchShifts = this.live.watch('wfm_assignment');
    const unwatchOffers = this.live.watch('wfm_offer');
    const records = this.live.records.subscribe(() => this.load());
    const notifications = this.live.notifications.subscribe(() => this.load());
    this.destroyRef.onDestroy(() => {
      unwatchShifts();
      unwatchOffers();
      records.unsubscribe();
      notifications.unsubscribe();
    });
    // Colleagues to give a shift to; without access to the people list the
    // give-away stays closed.
    this.api.users().subscribe({ next: u => this.colleagues.set(u), error: () => this.colleagues.set([]) });
  }

  load(): void {
    const today = new Date();
    forkJoin({
      shifts: this.api.mySchedule(addDays(today, 0), addDays(today, MY_SCHEDULE_DAYS)),
      offers: this.api.openOffers(),
    }).subscribe({
      next: r => {
        this.shifts.set(r.shifts);
        this.offers.set(r.offers);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  activityKey(activity: string): string {
    switch (activity) {
      case 'break': return 'xrm.workforce.activity.break';
      case 'meal': return 'xrm.workforce.activity.meal';
      case 'training': return 'xrm.workforce.activity.training';
      default: return 'xrm.workforce.activity.work';
    }
  }

  pickColleague(event: Event): void {
    this.giveTo.set((event.target as HTMLSelectElement).value);
  }

  typeReason(event: Event): void {
    this.giveReason.set((event.target as HTMLInputElement).value);
  }

  startGiving(id: string): void {
    this.giving.set(this.giving() === id ? null : id);
    this.giveTo.set('');
    this.giveReason.set('');
  }

  give(): void {
    const id = this.giving();
    const to = this.giveTo();
    if (!id || !to || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.giveAway(id, to, this.giveReason().trim() || null).subscribe({
      next: r => {
        this.busy.set(false);
        this.giving.set(null);
        this.notice.set(this.lang.translate(r.status === 'approved' ? 'xrm.workforce.me.given' : 'xrm.workforce.me.giveWaiting'));
        this.load();
      },
      error: (e: ApiError) => this.failed(e),
    });
  }

  accept(offer: OfferRow): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.acceptOffer(offer.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set(this.lang.translate('xrm.workforce.me.accepted'));
        this.load();
      },
      error: (e: ApiError) => this.failed(e),
    });
  }

  private failed(e: ApiError): void {
    this.busy.set(false);
    const key = e.status === 409 ? 'xrm.workforce.me.taken' : writeErrorKey(e);
    this.error.set(key ? this.lang.translate(key) : this.lang.errorText(e));
  }
}
