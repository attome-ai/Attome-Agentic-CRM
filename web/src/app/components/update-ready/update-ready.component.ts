import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { SwUpdate, VersionReadyEvent } from '@angular/service-worker';
import { TranslatePipe } from '@attome/base';
import { filter } from 'rxjs';

/**
 * B19-T1 — the installed app updates itself in the background: the service
 * worker fetches a new version while this one keeps running, and this notice
 * says when it is ready. Reloading applies it; otherwise it applies the next
 * time the app opens. Renders nothing while the service worker is off (a
 * development build, or a browser without one).
 */
@Component({
  selector: 'app-update-ready',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (ready()) {
      <div class="update-ready" role="status" data-update-ready>
        <span>{{ 'updateReady.text' | translate }}</span>
        <button type="button" class="update-ready-reload" (click)="reload()">
          {{ 'updateReady.reload' | translate }}
        </button>
        <button type="button" class="update-ready-later" (click)="ready.set(false)">
          {{ 'updateReady.later' | translate }}
        </button>
      </div>
    }
  `,
  styles: `
    .update-ready {
      position: fixed;
      inset-block-end: 16px;
      inset-inline-end: 16px;
      z-index: 1000;
      display: flex;
      align-items: center;
      gap: 8px;
      padding-block: 10px;
      padding-inline: 14px;
      border-radius: 8px;
      background: var(--color-text-primary, #111827);
      color: #fff;
      font-size: 13px;
    }
    .update-ready button {
      border: 0;
      border-radius: 4px;
      padding-block: 4px;
      padding-inline: 10px;
      cursor: pointer;
    }
    .update-ready-later {
      background: transparent;
      color: #fff;
    }
  `,
})
export class UpdateReadyComponent {
  private readonly updates = inject(SwUpdate);

  /** A new version is downloaded and waits for a reload. */
  readonly ready = signal(false);

  constructor() {
    if (!this.updates.isEnabled) return;
    this.updates.versionUpdates
      .pipe(
        filter((event): event is VersionReadyEvent => event.type === 'VERSION_READY'),
        takeUntilDestroyed(),
      )
      .subscribe(() => this.ready.set(true));
  }

  reload(): void {
    document.location.reload();
  }
}
