import { ChangeDetectionStrategy, Component, computed, DestroyRef, inject, input, signal } from '@angular/core';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { relativeTime, SlaBadgeKind, slaBadgeState } from '../sla-status';

const ICONS: Record<SlaBadgeKind, string> = {
  due:               'las la-stopwatch',
  warning:           'las la-exclamation-circle',
  overdue:           'las la-exclamation-triangle',
  breached:          'las la-exclamation-triangle',
  resolved:          'las la-check-circle',
  resolved_breached: 'las la-check-circle',
  not_calculated:    'las la-question-circle',
};

/** How often the relative "due in …" text is refreshed while the badge is on screen. */
export const SLA_BADGE_TICK_MS = 60_000;

/**
 * A ticket's SLA status as one badge (U14): due in / warning / overdue /
 * breached / resolved / not calculated (with the D-517 reason). Reads the
 * ticket's own SLA columns — see `slaBadgeState` — so it renders nothing
 * for a ticket with no SLA. Colour is always paired with an icon and text.
 */
@Component({
  selector: 'xrm-sla-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe],
  styleUrls: ['./sla-badge.component.css'],
  templateUrl: './sla-badge.component.html',
})
export class SlaBadgeComponent {
  /** The ticket record's `data` (or `null` while it loads). */
  readonly ticket = input<Record<string, unknown> | null>(null);

  private readonly lang = inject(LangService);
  private readonly now = signal(Date.now());

  readonly state = computed(() => slaBadgeState(this.ticket(), this.now()));
  readonly icon = computed(() => {
    const s = this.state();
    return s ? ICONS[s.kind] : '';
  });
  /** "in 3 hours" / "2 hours ago", or '' when there is no deadline. */
  readonly when = computed(() => {
    const s = this.state();
    return s?.dueAt ? relativeTime(s.dueAt, this.now(), this.lang.intlLocale()) : '';
  });
  readonly reasonKey = computed(() => {
    const reason = this.state()?.reason;
    return reason ? `serviceSla.reason.${reason}` : null;
  });

  constructor() {
    const timer = setInterval(() => this.now.set(Date.now()), SLA_BADGE_TICK_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }
}
