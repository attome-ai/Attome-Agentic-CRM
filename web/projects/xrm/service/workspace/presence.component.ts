import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, effect, inject, input, signal,
} from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';

/** The person's presence on the service desk (`service.presence`). */
export type Presence = 'available' | 'busy' | 'away';

export const PRESENCES: readonly Presence[] = ['available', 'busy', 'away'];

/** One colleague viewing the same record. */
export interface Viewer {
  user_id: string;
  name:    string;
}

interface ViewingResponse {
  viewers:        Viewer[];
  heartbeat_secs: number;
}

interface MySetting {
  key:   string;
  value: unknown;
}

/** The presence a stored value means; anything unknown is available. Pure. */
export function toPresence(value: unknown): Presence {
  return value === 'busy' || value === 'away' ? value : 'available';
}

/**
 * G5-T3: the agent's presence control (available, busy, away — round-robin
 * and least-loaded queues route new work only to available people) and,
 * when a record is given, the colleagues viewing it now. Presence is the
 * person's own setting; viewing is a heartbeat every 30 seconds while the
 * record is shown (`POST /api/v1/service/viewing`).
 */
@Component({
  selector: 'xrm-service-presence',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="presence">
      <label class="presence-control">
        <span class="presence-dot" [attr.data-presence]="presence()" aria-hidden="true"></span>
        <span class="sr-only">{{ 'servicePresence.label' | translate }}</span>
        <select data-testid="presence-select" [value]="presence()" [disabled]="saving()"
                [attr.aria-label]="'servicePresence.label' | translate"
                (change)="setPresence($any($event.target).value)">
          @for (p of presences; track p) {
            <option [value]="p">{{ 'servicePresence.' + p | translate }}</option>
          }
        </select>
      </label>
      @if (recordId()) {
        <p class="presence-viewers hint" data-testid="presence-viewers" aria-live="polite">
          @if (viewers().length) {
            {{ 'servicePresence.alsoViewing' | translate }}
            @for (v of viewers(); track v.user_id; let last = $last) {
              <span data-testid="presence-viewer">{{ v.name }}</span>@if (!last) {<span>{{ 'servicePresence.separator' | translate }}</span>}
            }
          } @else {
            {{ 'servicePresence.nobodyElse' | translate }}
          }
        </p>
      }
      @if (error()) { <p class="error-msg" role="alert">{{ 'servicePresence.saveFailed' | translate }}</p> }
    </div>
  `,
  styles: [`
    .presence { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2, 8px); }
    .presence-control { display: inline-flex; align-items: center; gap: var(--space-1, 4px); }
    .presence-dot { inline-size: 10px; block-size: 10px; border-radius: 50%; background: var(--color-success, #2e7d32); }
    .presence-dot[data-presence='busy'] { background: var(--color-danger, #c62828); }
    .presence-dot[data-presence='away'] { background: var(--color-warning, #f9a825); }
    .presence-viewers { margin: 0; }
    .sr-only { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  `],
})
export class PresenceComponent implements OnInit {
  private readonly api = inject(ApiService);

  /** The record being viewed, if any. */
  readonly entity = input<string | null>(null);
  readonly recordId = input<string | null>(null);

  readonly presences = PRESENCES;
  readonly presence = signal<Presence>('available');
  readonly viewers = signal<Viewer[]>([]);
  readonly saving = signal(false);
  readonly error = signal(false);

  private timer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stop());
    // A new record restarts the heartbeat.
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      this.stop();
      this.viewers.set([]);
      if (entity && recordId) {
        this.beat(entity, recordId);
        this.timer = setInterval(() => this.beat(entity, recordId), 30_000);
      }
    });
  }

  ngOnInit(): void {
    this.api.get<{ items: MySetting[] }>('/api/v1/settings/me').subscribe({
      next: res => {
        const mine = res.items.find(s => s.key === 'service.presence');
        this.presence.set(toPresence(mine?.value));
      },
      error: () => this.presence.set('available'),
    });
  }

  setPresence(value: string): void {
    const next = toPresence(value);
    const before = this.presence();
    this.presence.set(next);
    this.saving.set(true);
    this.error.set(false);
    this.api.put('/api/v1/settings/me/service.presence', { value: next }).subscribe({
      next: () => this.saving.set(false),
      error: () => {
        this.presence.set(before);
        this.saving.set(false);
        this.error.set(true);
      },
    });
  }

  private beat(entity: string, recordId: string): void {
    this.api.post<ViewingResponse>('/api/v1/service/viewing', { entity, record_id: recordId }).subscribe({
      next: res => this.viewers.set(res.viewers ?? []),
      // Presence of others is a courtesy: on failure, show nobody.
      error: () => this.viewers.set([]),
    });
  }

  private stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
