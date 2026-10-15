import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';

/** `system_health::SystemStatus`. */
export interface SystemStatus {
  read_only: boolean;
  degraded: { feature: string; message_key: string }[];
}

/** How often the status is read again. */
export const STATUS_POLL_MS = 30_000;

/**
 * AB5-T9: tells the person what is down or slow right now, and when changes
 * are refused, from `GET /api/v1/system/status`, read every 30 seconds.
 * Shows nothing while all is well.
 */
@Component({
  selector: 'xrm-status-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (status(); as s) {
      @if (s.read_only || s.degraded.length) {
        <div class="sb" role="status" data-status-banner>
          @if (s.read_only) {
            <p class="sb-line sb-strong" data-read-only>
              <i class="las la-lock" aria-hidden="true"></i> {{ 'systemStatus.readOnly' | translate }}
            </p>
          }
          @for (d of s.degraded; track d.feature) {
            <p class="sb-line" [attr.data-feature]="d.feature">
              <i class="las la-exclamation-triangle" aria-hidden="true"></i> {{ d.message_key | translate }}
            </p>
          }
        </div>
      }
    }
  `,
  styles: [`
    .sb { display: flex; flex-direction: column; gap: 0.25rem; padding-block: 0.5rem; padding-inline: 1rem;
      background: var(--color-warning-bg, var(--color-bg)); border-block-end: 1px solid var(--color-border);
      font-size: 0.875rem; }
    .sb-line { margin: 0; display: flex; align-items: center; gap: 0.5rem; }
    .sb-strong { font-weight: 600; }
  `],
})
export class StatusBannerComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);

  readonly status = signal<SystemStatus | null>(null);

  ngOnInit(): void {
    this.refresh();
    const timer = setInterval(() => this.refresh(), STATUS_POLL_MS);
    this.destroyRef.onDestroy(() => clearInterval(timer));
  }

  /** Reads the status again; a failed read keeps what was shown. */
  refresh(): void {
    this.api.get<SystemStatus>('/api/v1/system/status').subscribe({
      next: status => this.status.set(status),
      error: () => undefined,
    });
  }
}
