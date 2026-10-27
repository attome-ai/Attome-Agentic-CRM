import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { ImpersonationService, TranslatePipe } from '@attome/base';

/**
 * Q13-T2 — while this tab works in a view-as or act-as session, says so on
 * every page: whose access is in use, whether changes are refused, the
 * minutes left, and an End button. Shows nothing otherwise.
 */
@Component({
  selector: 'xrm-impersonation-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (session(); as s) {
      <div class="ib" [class.ib-act]="s.mode === 'act'" role="alert" data-impersonation-banner>
        <i class="las la-user-secret" aria-hidden="true"></i>
        <p class="ib-text">
          {{ (s.mode === 'act' ? 'impersonation.acting' : 'impersonation.viewing')
             | translate: { name: s.subject_label || s.subject_id } }}
          <span class="ib-left">{{ 'impersonation.minutesLeft' | translate: { count: minutesLeft() } }}</span>
        </p>
        <button type="button" class="ib-end" (click)="end()" [disabled]="ending()">
          {{ 'impersonation.end' | translate }}
        </button>
      </div>
    }
  `,
  styles: [`
    .ib { display: flex; align-items: center; gap: 0.75rem; padding-block: 0.5rem; padding-inline: 1rem;
      background: var(--color-info-bg, var(--color-bg)); border-block-end: 2px solid var(--color-primary, #2563eb);
      font-size: 0.875rem; }
    .ib-act { background: var(--color-warning-bg, var(--color-bg)); border-block-end-color: var(--color-danger, #dc2626); }
    .ib-text { margin: 0; flex: 1; }
    .ib-left { margin-inline-start: 0.5rem; color: var(--color-text-secondary); }
    .ib-end { margin-inline-start: auto; }
  `],
})
export class ImpersonationBannerComponent {
  private readonly impersonation = inject(ImpersonationService);
  private readonly now = signal(Date.now());

  readonly session = this.impersonation.session;
  readonly ending = signal(false);
  readonly minutesLeft = computed(() => {
    const s = this.session();
    if (!s) return 0;
    return Math.max(0, Math.ceil((Date.parse(s.expires_at) - this.now()) / 60_000));
  });

  constructor() {
    const timer = setInterval(() => this.now.set(Date.now()), 15_000);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  end(): void {
    this.ending.set(true);
    this.impersonation.end().subscribe({
      next: () => this.ending.set(false),
      error: () => this.ending.set(false),
    });
  }
}
