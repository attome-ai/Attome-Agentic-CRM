import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `attome_core::change_feed::ConsumerHealth`. */
export interface ConsumerHealth {
  consumer: string;
  kind: 'internal' | 'external';
  status: 'active' | 'expired';
  lag_events: number;
  lag_seconds: number;
  last_read_at: string;
  last_event_at: string | null;
  max_lag_hours: number;
}

/** A consumer past this many seconds behind is flagged (the alert's line). */
export const LAG_ALERT_SECONDS = 300;

/** Whether a consumer is behind enough to be flagged. */
export function isLagging(c: ConsumerHealth): boolean {
  return c.status === 'expired' || c.lag_seconds > LAG_ALERT_SECONDS;
}

/** A lag in seconds as the largest whole unit: `45s`, `12m`, `3h`, `2d`. */
export function lagText(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

/**
 * Events monitor (roadmap Y7-T6): every change-feed consumer with its lag in
 * events and time, when it last read, and whether it fell behind (more than
 * five minutes, the `ChangeFeedConsumerLagging` alert's line) or expired.
 * Lagging consumers sort first. Logical CSS only; the table scrolls on a
 * phone.
 */
@Component({
  selector: 'xrm-events-monitor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="em">
      <h3>{{ 'eventsMonitor.title' | translate }}</h3>
      <p class="em-muted">{{ 'eventsMonitor.intro' | translate }}</p>
      @if (error(); as message) { <p class="em-error" role="alert">{{ message }}</p> }
      <div class="em-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">{{ 'eventsMonitor.consumer' | translate }}</th>
              <th scope="col">{{ 'eventsMonitor.kind' | translate }}</th>
              <th scope="col">{{ 'eventsMonitor.status' | translate }}</th>
              <th scope="col">{{ 'eventsMonitor.lagEvents' | translate }}</th>
              <th scope="col">{{ 'eventsMonitor.lagTime' | translate }}</th>
              <th scope="col">{{ 'eventsMonitor.lastRead' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (c of consumers(); track c.consumer) {
              <tr [attr.data-consumer]="c.consumer" [class.em-lagging]="lagging(c)">
                <td dir="ltr">{{ c.consumer }}</td>
                <td>{{ 'eventsMonitor.kinds.' + c.kind | translate }}</td>
                <td>{{ 'eventsMonitor.statuses.' + (lagging(c) && c.status === 'active' ? 'behind' : c.status) | translate }}</td>
                <td dir="ltr">{{ c.lag_events }}</td>
                <td dir="ltr">{{ lag(c.lag_seconds) }}</td>
                <td dir="ltr">{{ c.last_read_at.slice(0, 19).replace('T', ' ') }}</td>
              </tr>
            } @empty {
              <tr><td colspan="6" class="em-muted">{{ 'eventsMonitor.empty' | translate }}</td></tr>
            }
          </tbody>
        </table>
      </div>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .em { display: flex; flex-direction: column; gap: 0.75rem; }
    .em h3 { margin-block: 0; font-size: 1rem; }
    .em-scroll { overflow-x: auto; }
    table { inline-size: 100%; border-collapse: collapse; font-size: 0.8125rem; }
    th, td { text-align: start; padding-block: 0.375rem; padding-inline: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .em-lagging td { color: var(--color-danger); }
    .em-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .em-error { color: var(--color-danger); }
  `],
})
export class EventsMonitorComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly consumers = signal<ConsumerHealth[]>([]);
  readonly error = signal<string | null>(null);

  readonly lagging = isLagging;
  readonly lag = lagText;

  ngOnInit(): void {
    this.api.get<{ items: ConsumerHealth[] }>('/api/v1/admin/change-feed/consumers').subscribe({
      next: body => this.consumers.set(
        [...body.items].sort((a, b) => Number(isLagging(b)) - Number(isLagging(a)) || b.lag_seconds - a.lag_seconds),
      ),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
