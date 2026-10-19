import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { Page } from '@attome/base';

/** M10-T4: one pending timer (`attome_core::timer::PendingTimer`). */
export interface PendingTimer {
  id: string;
  kind: string;
  target_entity: string | null;
  target_id: string | null;
  run_id: string | null;
  due_at: string;
  created_at: string;
}

/**
 * M10-T4 — what the platform is waiting to do, and when. On a record form
 * (`entity` and `recordId` set) it lists that record's pending timers and
 * renders nothing when there are none; without a record it is the
 * administrators' list of every pending timer.
 */
@Component({
  selector: 'xrm-pending-timers',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styles: `
    :host { display: block; }
    .timers { margin-block: 8px; padding-block: 10px; padding-inline: 12px;
              border: 1px solid var(--color-border, #e5e7eb); border-radius: 8px; }
    h3 { margin-block: 0 6px; font-size: 14px; }
    ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
    li { display: flex; gap: 8px; font-size: 13px; }
    .when { font-weight: 600; min-inline-size: 140px; }
    .record { opacity: 0.75; }
  `,
  template: `
    @if (timers().length || !recordId()) {
      <section class="timers" data-pending-timers>
        <h3>{{ (recordId() ? 'pendingTimers.recordTitle' : 'pendingTimers.allTitle') | translate }}</h3>
        @if (!timers().length) {
          <p data-pending-timers-empty>{{ 'pendingTimers.empty' | translate }}</p>
        } @else {
          <ul>
            @for (timer of timers(); track timer.id) {
              <li [attr.data-pending-timer]="timer.id">
                <span class="when">{{ time(timer.due_at) }}</span>
                <span>{{ kindLabel(timer.kind) }}</span>
                @if (!recordId() && timer.target_entity) {
                  <span class="record">{{ timer.target_entity }} {{ timer.target_id }}</span>
                }
              </li>
            }
          </ul>
        }
      </section>
    }
  `,
})
export class PendingTimersComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  /** The record's entity; with `recordId`, the record's own timers. */
  readonly entity = input<string | null>(null);
  readonly recordId = input<string | null>(null);

  readonly timers = signal<PendingTimer[]>([]);

  constructor() {
    effect(onCleanup => {
      const entity = this.entity();
      const id = this.recordId();
      this.timers.set([]);
      const url = entity && id ? `/api/v1/${entity}/${id}/timers` : '/api/v1/admin/timers';
      if ((entity && !id) || (!entity && id)) return;
      const sub = this.api.get<Page<PendingTimer>>(url, entity ? undefined : { page_size: '200' }).subscribe({
        next: page => this.timers.set(page.items),
        // Nothing to show (or not allowed to see it): the form shows nothing.
        error: () => this.timers.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  /** A known kind's name, else the kind itself. */
  kindLabel(kind: string): string {
    const key = `pendingTimers.kinds.${kind}`;
    const text = this.lang.translate(key);
    return text === key ? kind : text;
  }

  time(at: string): string {
    const date = new Date(at);
    return Number.isNaN(date.getTime())
      ? at
      : new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }
}
