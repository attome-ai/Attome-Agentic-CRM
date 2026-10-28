import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { logicalToUrlPath } from '@attome/xrm/core/entity';

import {
  CalendarDay, OnCallStretch, OncallCalendarService, OncallScheduleRef, byDay, weekStart,
} from './oncall-calendar.service';

const WEEK_DAYS = 7;
const DAY_MS = 86_400_000;

/**
 * H7-T2: the on-call calendar (`service/oncall`). Pick a schedule and see
 * who is on call each day of a week, from the rotation or an override, with
 * links to the schedule's layers and overrides, which are managed through
 * their own forms.
 */
@Component({
  selector: 'xrm-oncall-calendar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  templateUrl: './oncall-calendar.component.html',
  styleUrl: './oncall-calendar.component.css',
})
export class OncallCalendarComponent implements OnInit {
  private readonly service = inject(OncallCalendarService);
  private readonly lang = inject(LangService);

  readonly schedules = signal<OncallScheduleRef[]>([]);
  readonly schedule = signal('');
  readonly from = signal(weekStart(new Date()));
  readonly stretches = signal<OnCallStretch[]>([]);
  readonly error = signal<string | null>(null);
  readonly loading = signal(false);
  readonly days = computed<CalendarDay[]>(() => byDay(this.stretches(), this.from(), WEEK_DAYS));
  readonly to = computed(() => new Date(this.from().getTime() + WEEK_DAYS * DAY_MS));
  readonly layersPath = `/${logicalToUrlPath('oncall_layer')}`;
  readonly overridesPath = `/${logicalToUrlPath('oncall_override')}`;

  ngOnInit(): void {
    this.service.schedules().subscribe({
      next: schedules => {
        this.schedules.set(schedules);
        if (!this.schedule() && schedules.length) {
          this.schedule.set(schedules[0].id);
          this.load();
        }
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  load(): void {
    const schedule = this.schedule();
    if (!schedule) return;
    this.error.set(null);
    this.loading.set(true);
    this.service.calendar(schedule, this.from(), this.to()).subscribe({
      next: stretches => {
        this.stretches.set(stretches);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.stretches.set([]);
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  onSchedule(event: Event): void {
    this.schedule.set((event.target as HTMLSelectElement).value);
    this.load();
  }

  /** Moves the week by `weeks` (negative: earlier). */
  shift(weeks: number): void {
    this.from.set(new Date(this.from().getTime() + weeks * WEEK_DAYS * DAY_MS));
    this.load();
  }

  thisWeek(): void {
    this.from.set(weekStart(new Date()));
    this.load();
  }

  who(s: OnCallStretch): string {
    return s.user_name || s.user_id;
  }
}
