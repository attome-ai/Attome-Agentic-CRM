import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';

/** `system_health::SystemStatus`. */
export interface SystemStatus {
  read_only: boolean;
  degraded: { feature: string; message_key: string }[];
}

/** How often the status is read again. */
export const STATUS_POLL_MS = 30_000;

/** AB11-T9: `attome_ops::public_status::StatusBanner`. */
export interface OpsNotice {
  kind: 'incident' | 'maintenance';
  id: string;
  title: string;
  impact?: string | null;
  starts_at: string;
  ends_at?: string | null;
}

/** AB11-T9: how often the status page notice is read again. */
export const OPS_NOTICE_POLL_MS = 60_000;

/**
 * AB5-T9: tells the person what is down or slow right now, and when changes
 * are refused, from `GET /api/v1/system/status`, read every 30 seconds.
 * AB11-T9: the same bar carries the status page's notice (the worst open
 * incident or maintenance within a day, `GET /api/v1/ops/status/banner`),
 * read every minute while the tab is visible and dismissible per notice.
 * Shows nothing while all is well (a 204, or no ops module).
 */
@Component({
  selector: 'xrm-status-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (notice(); as n) {
      @if (n.id !== dismissed()) {
        <div class="sb sb-row" role="status" [attr.data-ops-notice]="n.kind">
          <p class="sb-line">
            <i class="las la-info-circle" aria-hidden="true"></i>
            {{ (n.kind === 'incident' ? 'systemStatus.incident' : 'systemStatus.maintenance') | translate: { title: n.title } }}
          </p>
          <button type="button" class="sb-dismiss" data-dismiss (click)="dismissed.set(n.id)"
                  [attr.aria-label]="'systemStatus.dismiss' | translate">
            <i class="las la-times" aria-hidden="true"></i>
          </button>
        </div>
      }
    }
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
    .sb-row { flex-direction: row; justify-content: space-between; align-items: center; }
    .sb-dismiss { background: none; border: 0; cursor: pointer; color: inherit; padding-inline: 0.25rem; }
  `],
})
export class StatusBannerComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);

  readonly status = signal<SystemStatus | null>(null);
  readonly notice = signal<OpsNotice | null>(null);
  /** The notice the person closed; a new notice shows again. */
  readonly dismissed = signal<string | null>(null);

  ngOnInit(): void {
    this.refresh();
    this.refreshNotice();
    const timer = setInterval(() => this.refresh(), STATUS_POLL_MS);
    const noticeTimer = setInterval(() => this.refreshNotice(), OPS_NOTICE_POLL_MS);
    this.destroyRef.onDestroy(() => {
      clearInterval(timer);
      clearInterval(noticeTimer);
    });
  }

  /** Reads the status page notice, unless the tab is hidden; nothing (204) clears it. */
  refreshNotice(): void {
    if (typeof document !== 'undefined' && document.hidden) return;
    this.api.get<OpsNotice | null>('/api/v1/ops/status/banner').subscribe({
      next: notice => this.notice.set(notice && notice.id ? notice : null),
      error: () => this.notice.set(null),
    });
  }

  /** Reads the status again; a failed read keeps what was shown. */
  refresh(): void {
    this.api.get<SystemStatus>('/api/v1/system/status').subscribe({
      next: status => this.status.set(status),
      error: () => undefined,
    });
  }
}
