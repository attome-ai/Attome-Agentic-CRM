import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { ChangeFeedService, type ChangeConsumer } from '@attome/xrm/core/admin/data';

/** `lag_seconds` as the largest whole unit: `45 s`, `12 min`, `3 h`, `2 d`. */
export function lagText(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86_400)} d`;
}

/**
 * L7-T7 — who reads the change feed and how far behind each is: the
 * platform's own consumers and subscriptions, with a status chip (active or
 * expired), unread events, lag and last read. Logical CSS only.
 */
@Component({
  selector: 'xrm-change-consumers',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, LocalNumberPipe, TranslatePipe],
  template: `
    <section class="cc">
      <h3>{{ 'governance.changes.consumers.title' | translate }}</h3>
      @if (error(); as message) { <p class="cc-error" role="alert">{{ message }}</p> }
      @if (consumers().length === 0) {
        <p class="cc-muted">{{ 'governance.changes.consumers.none' | translate }}</p>
      } @else {
        <table class="cc-table">
          <thead>
            <tr>
              <th scope="col">{{ 'governance.changes.consumers.name' | translate }}</th>
              <th scope="col">{{ 'governance.changes.consumers.kind' | translate }}</th>
              <th scope="col">{{ 'governance.changes.consumers.status' | translate }}</th>
              <th scope="col">{{ 'governance.changes.consumers.unread' | translate }}</th>
              <th scope="col">{{ 'governance.changes.consumers.lag' | translate }}</th>
              <th scope="col">{{ 'governance.changes.consumers.lastRead' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (c of consumers(); track c.consumer) {
              <tr [attr.data-consumer]="c.consumer">
                <td dir="ltr">{{ c.consumer }}</td>
                <td>{{ 'governance.changes.consumers.kinds.' + c.kind | translate }}</td>
                <td>
                  <span class="cc-chip" [class.cc-expired]="c.status === 'expired'">
                    {{ 'governance.changes.consumers.statuses.' + c.status | translate }}
                  </span>
                </td>
                <td>{{ c.lag_events | localNumber }}</td>
                <td dir="ltr">{{ lag(c) }}</td>
                <td>{{ c.last_read_at | localDate }}</td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>
  `,
  styles: [`
    :host { display: block; margin-block-start: 1.5rem; }
    .cc h3 { margin-block: 0 0.5rem; font-size: 1rem; }
    .cc-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .cc-table th, .cc-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); }
    .cc-chip { display: inline-block; padding-block: 0.125rem; padding-inline: 0.5rem; border-radius: 999px;
      font-size: 0.75rem; background: color-mix(in srgb, var(--color-success) 15%, transparent); }
    .cc-chip.cc-expired { background: color-mix(in srgb, var(--color-danger) 15%, transparent); }
    .cc-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .cc-error { color: var(--color-danger); }
  `],
})
export class ChangeConsumersComponent implements OnInit {
  private readonly svc = inject(ChangeFeedService);

  readonly consumers = signal<ChangeConsumer[]>([]);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.listConsumers().subscribe({
      next: page => this.consumers.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  lag(consumer: ChangeConsumer): string {
    return lagText(consumer.lag_seconds);
  }
}
