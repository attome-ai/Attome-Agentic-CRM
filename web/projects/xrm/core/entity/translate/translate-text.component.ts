import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

/** What `POST /api/v1/actions/text.translate/invoke` returns. */
type TranslateOutcome =
  | { status: 'completed'; result: { translation?: string } }
  | { status: 'confirmation_required' | 'approval_required' };

/**
 * A translate button under a piece of text (roadmap N20-T2): translates it
 * into the viewer's current language through `text.translate` and shows the
 * result under the original, which stays visible. Used on notes and replies.
 * Calls the action endpoint directly so `core` does not depend on `ai`; on a
 * deployment without AI the call fails and the button says so.
 */
@Component({
  selector:        'xrm-translate-text',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  template: `
    @if (translation(); as text) {
      <div class="xtt-result" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-test="translation">{{ text }}</div>
      <button type="button" class="xtt-link" (click)="translation.set(null)">{{ 'translateText.hide' | translate }}</button>
    } @else {
      <button type="button" class="xtt-link" [disabled]="busy()" (click)="translate()">
        {{ (busy() ? 'translateText.working' : 'translateText.translate') | translate }}
      </button>
    }
    @if (error()) {
      <span class="xtt-error" role="alert">{{ 'translateText.failed' | translate }}</span>
    }
  `,
  styles: [`
    :host { display: block; margin-block-start: 0.25rem; }
    .xtt-link { background: none; border: 0; padding: 0; color: var(--accent-color, #2563eb); cursor: pointer; font-size: 0.8125rem; }
    .xtt-link:disabled { opacity: 0.6; cursor: default; }
    .xtt-result { margin-block: 0.25rem; padding-inline-start: 0.5rem; border-inline-start: 2px solid var(--border-color, #d0d4da); white-space: pre-wrap; }
    .xtt-error { color: var(--danger-color, #b42318); font-size: 0.8125rem; margin-inline-start: 0.5rem; }
  `],
})
export class TranslateTextComponent {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);

  /** The text to translate. */
  readonly text = input.required<string>();

  readonly translation = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal(false);

  translate(): void {
    const text = this.text().trim();
    if (!text) return;
    this.busy.set(true);
    this.error.set(false);
    this.api.post<TranslateOutcome>('/api/v1/actions/text.translate/invoke', {
      args: { text, to: this.lang.current() },
    }).subscribe({
      next: outcome => {
        this.busy.set(false);
        const translated = outcome.status === 'completed' ? outcome.result.translation : undefined;
        if (translated) this.translation.set(translated);
        else this.error.set(true);
      },
      error: (_: ApiError) => { this.busy.set(false); this.error.set(true); },
    });
  }
}
