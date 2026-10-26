import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import { OfflineQueueService } from './offline-queue.service';
import { SyncService } from './sync.service';

/**
 * B18-T10: the header's sync state for a device that syncs offline: online
 * or offline, how many changes wait, when the last sync finished, and Sync
 * now. Shown only once syncing has started for a registered device.
 */
@Component({
  selector: 'xrm-sync-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    @if (sync.active()) {
      <div class="ss" data-testid="sync-status" role="status">
        <span class="ss-dot" [class.ss-online]="online()" aria-hidden="true"></span>
        <span>{{ (online() ? 'offline.status.online' : 'offline.status.offline') | translate }}</span>
        @if (queue.waiting()) {
          <span class="ss-waiting" data-testid="sync-status-waiting">
            {{ 'offline.status.waiting' | translate: { count: queue.waiting() } }}
          </span>
        }
        @if (sync.syncing()) {
          <span>{{ 'offline.status.syncing' | translate }}</span>
        } @else if (sync.lastError()) {
          <span class="ss-failed" [title]="'offline.status.failed' | translate">
            <i class="las la-exclamation-triangle" aria-hidden="true"></i>
            <span class="ss-sr">{{ 'offline.status.failed' | translate }}</span>
          </span>
        }
        <span class="ss-last">
          @if (sync.lastSyncAt(); as at) {
            {{ 'offline.status.lastSync' | translate: { time: (at | localDate: timeFormat) } }}
          } @else {
            {{ 'offline.status.never' | translate }}
          }
        </span>
        <button type="button" class="ss-now" data-testid="sync-now"
                [disabled]="!online() || sync.syncing()" (click)="syncNow()">
          <i class="las la-sync" aria-hidden="true"></i>
          {{ 'offline.status.syncNow' | translate }}
        </button>
      </div>
    }
  `,
  styles: [`
    .ss { display: inline-flex; align-items: center; gap: 0.375rem; font-size: 0.8125rem; white-space: nowrap; }
    .ss-dot { inline-size: 0.5rem; block-size: 0.5rem; border-radius: 50%; background: var(--color-warning); }
    .ss-dot.ss-online { background: var(--color-success); }
    .ss-waiting { font-weight: 600; }
    .ss-failed { color: var(--color-danger); }
    .ss-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
    .ss-last { color: var(--color-text-muted); }
    .ss-now { display: inline-flex; align-items: center; gap: 0.25rem; border: 1px solid var(--color-border);
      border-radius: 6px; background: var(--color-surface); color: inherit; cursor: pointer;
      padding-block: 0.125rem; padding-inline: 0.5rem; }
    .ss-now:disabled { opacity: 0.6; cursor: default; }
    @media (max-width: 640px) { .ss-last { display: none; } }
  `],
})
export class SyncStatusComponent {
  readonly sync = inject(SyncService);
  readonly queue = inject(OfflineQueueService);

  readonly online = signal(typeof navigator === 'undefined' || navigator.onLine !== false);
  readonly timeFormat: Intl.DateTimeFormatOptions = { dateStyle: 'short', timeStyle: 'short' };

  constructor() {
    const up = () => this.online.set(true);
    const down = () => this.online.set(false);
    globalThis.addEventListener?.('online', up);
    globalThis.addEventListener?.('offline', down);
    inject(DestroyRef).onDestroy(() => {
      globalThis.removeEventListener?.('online', up);
      globalThis.removeEventListener?.('offline', down);
    });
  }

  syncNow(): void {
    void this.sync.sync();
  }
}
