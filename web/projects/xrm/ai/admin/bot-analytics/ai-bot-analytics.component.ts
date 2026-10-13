import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { Subscription } from 'rxjs';
import type { ApiError } from '@attome/base';
import { AdminAiService } from '../../services/admin-ai.service';
import type { BotAnalytics } from '../../services/admin-ai.service';

/** The windows the card offers, in days. */
const WINDOWS = [7, 30] as const;
type WindowDays = (typeof WINDOWS)[number];

/**
 * Assistant analytics (C10 B2b): the admin analytics route —
 * `GET /api/v1/admin/ai/bot-analytics` — as a card on the Live Sessions page.
 *
 * Aggregates only, administrators only, and nothing here computes a figure of
 * its own: every number is the server's, from the formulas in the plan's
 * `01` § "C10-B". The same seven-day figures are also shipped as metrics
 * (`platform-bundles/attome-ai-bot-analytics*.json`) for any dashboard's KPI
 * widgets, and a server test proves the two agree.
 *
 * A 403 hides the card: a supervisor who is not an administrator sees the
 * sessions table and nothing that would be refused.
 */
@Component({
  selector: 'attome-ai-bot-analytics',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalNumberPipe],
  styleUrls: ['./ai-bot-analytics.component.css'],
  templateUrl: './ai-bot-analytics.component.html',
})
export class AiBotAnalyticsComponent implements OnInit {
  private readonly adminAi = inject(AdminAiService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);
  /** The report in flight; a newer window cancels it, so the last click wins. */
  private inFlight: Subscription | null = null;

  readonly windows = WINDOWS;
  readonly days = signal<WindowDays>(7);
  readonly report = signal<BotAnalytics | null>(null);
  readonly visible = signal(false);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  /** Handoff reasons with a count, largest first. */
  readonly handoffReasons = computed(() => {
    const byReason = this.report()?.handoffs.by_reason ?? {};
    return Object.entries(byReason)
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1]);
  });

  ngOnInit(): void {
    this.load();
  }

  select(days: WindowDays): void {
    if (days === this.days()) return;
    this.days.set(days);
    this.load();
  }

  /**
   * A 0..1 rate as a whole percentage in the viewer's locale (Arabic-Indic
   * digits in Arabic), or an em dash when there is no denominator.
   */
  percent(rate: number | null | undefined): string {
    if (rate === null || rate === undefined) return '—';
    return new Intl.NumberFormat(this.lang.intlLocale(), {
      style: 'percent',
      maximumFractionDigits: 0,
    }).format(rate);
  }

  private load(): void {
    const to = new Date();
    const from = new Date(to.getTime() - this.days() * 24 * 60 * 60 * 1000);
    this.loading.set(true);
    this.error.set(null);
    this.inFlight?.unsubscribe();
    this.inFlight = this.adminAi
      .botAnalytics(from.toISOString(), to.toISOString())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (report) => {
          this.report.set(report);
          this.visible.set(true);
          this.loading.set(false);
        },
        error: (err: ApiError) => {
          this.loading.set(false);
          if (err.status !== 403 && err.status !== 404) this.error.set(err.message);
        },
      });
  }
}
