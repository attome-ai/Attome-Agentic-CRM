import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { IdleSessionService } from './idle-session.service';
import { TranslatePipe } from './translate.pipe';

/**
 * Q8-T9: the warning a minute before an idle sign-out, with a countdown and
 * "Stay signed in". Mount it once in the signed-in shell.
 */
@Component({
  selector: 'base-idle-warning',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styles: [`
    .idle-warning {
      position: fixed; inset-block-end: 1rem; inset-inline-end: 1rem; z-index: 1000;
      max-inline-size: 22rem; padding: 1rem; border-radius: 0.5rem;
      background: var(--color-surface, #fff); color: var(--color-text, #111);
      box-shadow: 0 4px 16px var(--color-card-shadow);
    }
    .idle-warning p { margin-block: 0 0.75rem; }
  `],
  template: `
    @if (idle.warning()) {
      <div class="idle-warning" role="alertdialog" aria-live="assertive" aria-labelledby="idle-warning-text">
        <p id="idle-warning-text">{{ 'idleWarning.text' | translate: { seconds: idle.secondsLeft() } }}</p>
        <button type="button" class="btn-primary" (click)="idle.stay()" data-testid="idle-stay">
          {{ 'idleWarning.stay' | translate }}
        </button>
      </div>
    }
  `,
})
export class IdleWarningComponent {
  readonly idle = inject(IdleSessionService);
}
