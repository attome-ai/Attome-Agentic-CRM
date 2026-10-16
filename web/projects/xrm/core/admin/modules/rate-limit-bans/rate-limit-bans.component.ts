import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `attome_server::middleware::rate_limit::ActiveBan`. */
export interface ActiveBan {
  bucket: string;
  category: string | null;
  seconds_left: number;
}

/** Minutes left, rounded up, never below one. */
export function minutesLeft(ban: ActiveBan): number {
  return Math.max(1, Math.ceil(ban.seconds_left / 60));
}

/**
 * Rate-limit bans (roadmap Q20-T5): who is under a temporary ban after
 * repeatedly tripping a limit, for how much longer, and a button to lift
 * one (audited). Logical CSS only.
 */
@Component({
  selector: 'xrm-rate-limit-bans',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="rlb">
      <h3>{{ 'rateLimitBans.title' | translate }}</h3>
      <p class="rlb-muted">{{ 'rateLimitBans.intro' | translate }}</p>
      @if (error(); as message) { <p class="rlb-error" role="alert">{{ message }}</p> }
      <ul class="rlb-list">
        @for (ban of bans(); track ban.bucket) {
          <li [attr.data-bucket]="ban.bucket">
            <span dir="ltr">{{ ban.bucket }}</span>
            <small>{{ 'rateLimitBans.left' | translate: { minutes: minutes(ban) } }}</small>
            <button type="button" (click)="lift(ban)" [disabled]="busy()">{{ 'rateLimitBans.lift' | translate }}</button>
          </li>
        } @empty {
          <li class="rlb-muted">{{ 'rateLimitBans.none' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .rlb { display: flex; flex-direction: column; gap: 0.75rem; }
    .rlb h3 { margin-block: 0; font-size: 1rem; }
    .rlb-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .rlb-list li { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center;
      padding-block: 0.375rem; border-block-end: 1px solid var(--color-border); }
    .rlb-list button { margin-inline-start: auto; }
    .rlb-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .rlb-error { color: var(--color-danger); }
  `],
})
export class RateLimitBansComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly bans = signal<ActiveBan[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly minutes = minutesLeft;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: ActiveBan[] }>('/api/v1/admin/rate-limits/bans').subscribe({
      next: body => this.bans.set(body.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  lift(ban: ActiveBan): void {
    this.busy.set(true);
    this.api.delete(`/api/v1/admin/rate-limits/bans/${encodeURIComponent(ban.bucket)}`).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
