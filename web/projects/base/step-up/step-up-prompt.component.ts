import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { LangService, TranslatePipe, trapFocus, ModalHandle, pushModal } from '@attome/base';
import { StepUpLocalFactor, StepUpProvider, StepUpService } from './step-up.service';

/**
 * The operations `stepUp.operation.*` has a specific verb for; anything else
 * renders `stepUp.operation.default`. Exported so catalog-coverage.spec.ts
 * requires a catalog entry per value (NGB-3.5).
 */
export const KNOWN_OPERATIONS = ['identity_link', 'api_key_create'] as const;

/**
 * Renders `StepUpService.prompt` (D-510 rule 9). Mount exactly once, next to
 * `<base-dialog-host />`. The credential lives only in this component and is
 * cleared as soon as it is submitted.
 *
 * NGB-4.3 — Escape is a `host` binding (D-308). The step-up prompt sits above
 * the dialog host (z-index 10060 over 10050), so it is the top-most modal
 * whenever both are open, and the LIFO stack in a11y/modal-stack.ts is what
 * makes Escape close this one only.
 */
@Component({
  selector: 'base-step-up-prompt',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  host: { '(document:keydown.escape)': 'onEscape()' },
  template: `
    @if (state(); as s) {
      <div class="attome-step-up-backdrop" role="presentation">
        <div
          #card
          class="attome-step-up-card"
          role="dialog"
          aria-modal="true"
          aria-labelledby="attome-step-up-title"
          aria-describedby="attome-step-up-intro"
          [attr.aria-busy]="s.busy"
        >
          <h3 id="attome-step-up-title" class="attome-step-up-title">{{ 'stepUp.title' | translate }}</h3>
          <p id="attome-step-up-intro" class="attome-step-up-message">{{ intro() }}</p>

          @if (s.enrollmentRequired) {
            <p class="attome-step-up-notice" role="status">{{ 'stepUp.enrollmentRequired' | translate }}</p>
            <div class="attome-step-up-actions">
              <button #closeBtn type="button" class="attome-step-up-btn attome-step-up-btn-secondary" (click)="cancel()">
                {{ 'stepUp.close' | translate }}
              </button>
            </div>
          } @else {
            @if (s.localFactors.length > 0) {
              <form class="attome-step-up-form" (submit)="$event.preventDefault(); submit()">
                @if (s.localFactors.length > 1) {
                  <fieldset class="attome-step-up-factors" [disabled]="s.busy">
                    <legend class="attome-step-up-label">{{ 'stepUp.chooseFactor' | translate }}</legend>
                    @for (f of s.localFactors; track f) {
                      <label class="attome-step-up-factor">
                        <input
                          type="radio"
                          name="attome-step-up-factor"
                          [value]="f"
                          [checked]="factor() === f"
                          (change)="selectFactor(f)"
                        />
                        {{ 'stepUp.factor.' + f | translate }}
                      </label>
                    }
                  </fieldset>
                }

                <label class="attome-step-up-label" for="attome-step-up-credential">
                  {{ 'stepUp.factor.' + factor() | translate }}
                </label>
                <!-- One input: a password is masked; TOTP and recovery codes are
                     one-time codes, and only TOTP is numeric. -->
                <input
                  #credentialInput
                  id="attome-step-up-credential"
                  class="attome-step-up-input"
                  autocapitalize="off"
                  spellcheck="false"
                  [type]="factor() === 'password' ? 'password' : 'text'"
                  [attr.autocomplete]="factor() === 'password' ? 'current-password' : 'one-time-code'"
                  [attr.inputmode]="factor() === 'totp' ? 'numeric' : null"
                  [value]="credential()"
                  [disabled]="s.busy"
                  (input)="onCredentialInput($event)"
                />

                @if (s.error) {
                  <p class="attome-step-up-error" role="alert">{{ s.error | translate }}</p>
                }

                <div class="attome-step-up-actions">
                  <button type="button" class="attome-step-up-btn attome-step-up-btn-secondary" (click)="cancel()">
                    {{ 'stepUp.cancel' | translate }}
                  </button>
                  <button
                    type="submit"
                    class="attome-step-up-btn attome-step-up-btn-primary"
                    [disabled]="s.busy || credential().length === 0"
                  >
                    {{ (s.busy ? 'stepUp.verifying' : 'stepUp.verify') | translate }}
                  </button>
                </div>
              </form>
            }

            @if (s.federated) {
              <div class="attome-step-up-federated">
                <p class="attome-step-up-message">{{ 'stepUp.federatedIntro' | translate }}</p>
                @if (s.providersLoading) {
                  <p class="attome-step-up-message" role="status">{{ 'stepUp.providersLoading' | translate }}</p>
                } @else if (s.providers.length === 0) {
                  <p class="attome-step-up-message">{{ 'stepUp.noProviders' | translate }}</p>
                } @else {
                  @for (p of s.providers; track p.protocol + ':' + p.key) {
                    <button
                      type="button"
                      class="attome-step-up-btn attome-step-up-btn-secondary attome-step-up-provider"
                      [disabled]="s.busy"
                      (click)="startFederated(p)"
                    >
                      {{ 'stepUp.continueWith' | translate: { provider: p.displayName } }}
                    </button>
                  }
                }
                @if (s.error && s.localFactors.length === 0) {
                  <p class="attome-step-up-error" role="alert">{{ s.error | translate }}</p>
                }
              </div>
              @if (s.localFactors.length === 0) {
                <div class="attome-step-up-actions">
                  <button type="button" class="attome-step-up-btn attome-step-up-btn-secondary" (click)="cancel()">
                    {{ 'stepUp.cancel' | translate }}
                  </button>
                </div>
              }
            }
          }
        </div>
      </div>
    }
  `,
  styles: [`
    .attome-step-up-backdrop {
      position: fixed; inset: 0; z-index: 10060; background: rgba(0,0,0,.72);
      display: flex; align-items: center; justify-content: center; padding: 20px;
    }
    /* NGB-3.4 — theme tokens, with the previous literals as fallbacks. */
    .attome-step-up-card {
      width: 100%; max-width: 420px; box-sizing: border-box;
      background: var(--color-bg-alt, #121829); color: var(--color-text-primary, #f1f5f9);
      border: 1px solid var(--color-border, rgba(255,255,255,.12)); border-radius: 14px; padding: 22px 24px 20px;
    }
    /* NGB-3.2 — the card's entrance is decoration; honour reduced motion. */
    @media (prefers-reduced-motion: reduce) {
      .attome-step-up-card { animation: none; }
      .attome-step-up-btn { transition: none; }
    }
    .attome-step-up-title { font-size: 16px; font-weight: 600; margin: 0 0 6px; color: var(--color-text-primary, #f8fafc); }
    .attome-step-up-message { font-size: 13px; color: var(--color-text-secondary, #94a3b8); margin: 0 0 14px; }
    .attome-step-up-notice { font-size: 13px; color: #fde68a; margin: 0 0 16px; }
    .attome-step-up-form, .attome-step-up-federated { display: flex; flex-direction: column; gap: 8px; }
    .attome-step-up-federated { margin-top: 12px; }
    .attome-step-up-factors { border: 0; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 12px; }
    .attome-step-up-factor, .attome-step-up-label { font-size: 13px; color: var(--color-text-secondary, #cbd5e1); }
    .attome-step-up-input {
      box-sizing: border-box; width: 100%; padding: 10px 14px; font-size: 14px;
      color: var(--color-text-primary, #f8fafc);
      background: var(--color-bg, #0f172a); border: 1px solid var(--color-border, rgba(255,255,255,.14));
      border-radius: 8px;
    }
    .attome-step-up-error { font-size: 12px; color: #f87171; margin: 0; }
    .attome-step-up-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 12px; }
    .attome-step-up-btn { padding: 8px 16px; font-size: 13px; border-radius: 7px; border: 0; cursor: pointer; }
    .attome-step-up-btn:disabled { opacity: .45; cursor: not-allowed; }
    .attome-step-up-btn-secondary { background: rgba(255,255,255,.1); color: var(--color-text-secondary, #cbd5e1); }
    .attome-step-up-btn-primary { background: var(--color-accent, #5D5CDE); color: #fff; }
  `],
})
export class StepUpPromptComponent {
  private readonly stepUp = inject(StepUpService);
  private readonly lang   = inject(LangService);

  readonly state      = this.stepUp.prompt;
  readonly factor     = signal<StepUpLocalFactor>('password');
  readonly credential = signal('');

  private readonly cardRef         = viewChild<ElementRef<HTMLElement>>('card');
  private readonly credentialInput = viewChild<ElementRef<HTMLInputElement>>('credentialInput');
  private readonly closeBtn        = viewChild<ElementRef<HTMLButtonElement>>('closeBtn');

  /** NGB-3.1 — Tab stays inside the prompt, and focus returns to the trigger. */
  private releaseTrap: (() => void) | null = null;
  /** NGB-4.3 — the Escape claim while this prompt is open. */
  private modalHandle: ModalHandle | null = null;

  readonly intro = computed(() => {
    const op = this.state()?.operation ?? '';
    const key = (KNOWN_OPERATIONS as readonly string[]).includes(op)
      ? `stepUp.operation.${op}`
      : 'stepUp.operation.default';
    return this.lang.translate('stepUp.intro', { operation: this.lang.translate(key) });
  });

  private openedId: number | null = null;

  constructor() {
    // Reset the factor and credential each time a new prompt opens (not on
    // every busy/error update of the same prompt), then move focus into it.
    effect(onCleanup => {
      const s = this.state();
      const id = s?.id ?? null;
      if (id === this.openedId) return;
      this.openedId = id;
      if (!s) {
        onCleanup(() => { this.releaseTrap?.(); this.releaseTrap = null; });
        return;
      }
      this.modalHandle ??= pushModal();
      untracked(() => {
        this.factor.set(s.localFactors[0] ?? 'password');
        this.credential.set('');
      });
      // NGB-3.1: the view is laid out after this tick, so the trap and the
      // initial focus are installed on the next macrotask.
      const timer = setTimeout(() => {
        const card = this.cardRef()?.nativeElement;
        if (card) {
          this.releaseTrap?.();
          this.releaseTrap = trapFocus(card);
        }
        (this.credentialInput() ?? this.closeBtn())?.nativeElement.focus();
      }, 30);
      onCleanup(() => {
        clearTimeout(timer);
        this.releaseTrap?.();
        this.releaseTrap = null;
        this.modalHandle?.release();
        this.modalHandle = null;
      });
    });
  }

  /** NGB-4.3 — only the top-most modal answers Escape. */
  onEscape(): void {
    if (!this.state()) return;
    if (this.modalHandle && !this.modalHandle.isTop()) return;
    this.cancel();
  }

  selectFactor(f: StepUpLocalFactor): void {
    this.factor.set(f);
    this.credential.set('');
  }

  onCredentialInput(event: Event): void {
    this.credential.set((event.target as HTMLInputElement).value);
  }

  submit(): void {
    const credential = this.credential();
    if (!credential) return;
    this.credential.set('');
    this.stepUp.submit(this.factor(), credential);
  }

  startFederated(p: StepUpProvider): void {
    this.stepUp.startFederated(p);
  }

  cancel(): void {
    this.credential.set('');
    this.stepUp.cancel();
  }
}
