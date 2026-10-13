import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { DialogService } from './dialog.service';
import { LangService, trapFocus, ModalHandle, pushModal } from '@attome/base';

/**
 * NGB-3.2 — the dialog host is the a11y reference for every modal in the app
 * (the frontend skill points authors here). Each dialog is named and described
 * (`aria-labelledby`/`aria-describedby`), an error is an `alertdialog`, the
 * decorative Line Awesome glyphs are `aria-hidden`, the prompt input has a real
 * label and ties its validation to the input, Tab is trapped inside the card,
 * focus returns to the trigger on close, and the animations respect
 * `prefers-reduced-motion`.
 *
 * NGB-3.3 — every default string is a catalog key (`dialog.*`), not English
 * prose baked into the template.
 *
 * NGB-3.4 — colours go through the `--color-*` tokens ThemeService publishes,
 * with the previous literals as fallbacks.
 *
 * NGB-4.3 — Escape is a `host` binding (D-308), and the handler defers to the
 * step-up prompt when that is the top-most modal (see a11y/modal-stack.ts).
 */
@Component({
  selector: 'base-dialog-host',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [],
  host: { '(document:keydown.escape)': 'onEscape()' },
  template: `
    @if (state(); as current) {
      <div
        class="attome-dialog-backdrop"
        (click)="onBackdropClick($event)"
        role="presentation"
      >
        <!-- This click only stops propagation so a click inside the dialog
             card doesn't reach the backdrop's dismiss handler above; it isn't
             itself an interactive control. -->
        <!-- The card's click only stops propagation to the backdrop; it is not
             an interaction, and the role is bound (dialog / alertdialog) so the
             linter cannot see that statically. -->
        <!-- eslint-disable-next-line @angular-eslint/template/click-events-have-key-events, @angular-eslint/template/interactive-supports-focus -->
        <div
          #card
          class="attome-dialog-card"
          [class.attome-dialog-danger]="isDanger()"
          [class.attome-dialog-error]="current.kind === 'error'"
          [attr.role]="current.kind === 'error' ? 'alertdialog' : 'dialog'"
          aria-modal="true"
          [attr.aria-labelledby]="TITLE_ID"
          [attr.aria-describedby]="MESSAGE_ID"
          (click)="$event.stopPropagation()"
        >
          <!-- ── Confirmation Dialog ── -->
          @if (current.kind === 'confirm') {
            <div class="attome-dialog-header">
              <div class="attome-dialog-icon-wrapper" [class.danger]="current.options.variant === 'danger'">
                <i [class]="getConfirmIcon(current.options.variant, current.options.icon)" aria-hidden="true"></i>
              </div>
              <div class="attome-dialog-header-text">
                <h3 [id]="TITLE_ID" class="attome-dialog-title">{{ current.options.title || lang.translate('dialog.confirmTitle') }}</h3>
                <p [id]="MESSAGE_ID" class="attome-dialog-message">{{ current.options.message }}</p>
              </div>
            </div>
            <div class="attome-dialog-actions">
              <button
                type="button"
                class="attome-dialog-btn attome-dialog-btn-secondary"
                (click)="onCancel()"
              >
                {{ current.options.cancelText || lang.translate('dialog.cancel') }}
              </button>
              <button
                type="button"
                #confirmBtn
                class="attome-dialog-btn"
                [class.attome-dialog-btn-danger]="current.options.variant === 'danger'"
                [class.attome-dialog-btn-primary]="current.options.variant !== 'danger'"
                (click)="onConfirm()"
              >
                {{ current.options.confirmText || lang.translate('dialog.confirm') }}
              </button>
            </div>
          }

          <!-- ── Prompt / Rename Dialog ── -->
          @if (current.kind === 'prompt') {
            <div class="attome-dialog-header">
              <div class="attome-dialog-icon-wrapper primary">
                <i class="las la-edit" aria-hidden="true"></i>
              </div>
              <div class="attome-dialog-header-text">
                <h3 [id]="TITLE_ID" class="attome-dialog-title">{{ current.options.title }}</h3>
                @if (current.options.message) {
                  <p [id]="MESSAGE_ID" class="attome-dialog-message">{{ current.options.message }}</p>
                }
              </div>
            </div>
            <form (submit)="$event.preventDefault(); onSubmitPrompt()" class="attome-dialog-form">
              <div class="attome-dialog-input-group">
                <label class="attome-dialog-sr-only" [attr.for]="INPUT_ID">
                  {{ current.options.label || current.options.title }}
                </label>
                <input
                  #promptInput
                  [id]="INPUT_ID"
                  type="text"
                  class="attome-dialog-input"
                  [class.has-error]="!!promptValidationMessage()"
                  [value]="promptValue()"
                  [placeholder]="current.options.placeholder || ''"
                  [attr.aria-invalid]="promptValidationMessage() ? 'true' : null"
                  [attr.aria-describedby]="promptValidationMessage() ? ERROR_ID : null"
                  (input)="onInputChange($event)"
                  autocomplete="off"
                  spellcheck="false"
                />
                @if (promptValidationMessage(); as valErr) {
                  <span [id]="ERROR_ID" class="attome-dialog-input-error" role="alert">{{ valErr }}</span>
                }
              </div>
              <div class="attome-dialog-actions">
                <button
                  type="button"
                  class="attome-dialog-btn attome-dialog-btn-secondary"
                  (click)="onCancel()"
                >
                  {{ current.options.cancelText || lang.translate('dialog.cancel') }}
                </button>
                <button
                  type="submit"
                  class="attome-dialog-btn attome-dialog-btn-primary"
                  [disabled]="!isPromptSubmittable()"
                >
                  {{ current.options.confirmText || lang.translate('dialog.save') }}
                </button>
              </div>
            </form>
          }

          <!-- ── Error Dialog ── -->
          @if (current.kind === 'error') {
            <div class="attome-dialog-header">
              <div class="attome-dialog-icon-wrapper danger">
                <i class="las la-exclamation-circle" aria-hidden="true"></i>
              </div>
              <div class="attome-dialog-header-text">
                <h3 [id]="TITLE_ID" class="attome-dialog-title">{{ current.options.title || lang.translate('dialog.errorTitle') }}</h3>
                <p [id]="MESSAGE_ID" class="attome-dialog-message">{{ current.options.message }}</p>
              </div>
            </div>
            @if (current.options.details) {
              <div class="attome-dialog-details">
                <pre>{{ current.options.details }}</pre>
              </div>
            }
            <div class="attome-dialog-actions">
              <button
                type="button"
                #errorCloseBtn
                class="attome-dialog-btn attome-dialog-btn-secondary"
                (click)="onErrorClose()"
              >
                {{ current.options.buttonText || lang.translate('dialog.close') }}
              </button>
            </div>
          }
        </div>
      </div>
    }
  `,
  styles: [`
    .attome-dialog-backdrop {
      position: fixed;
      inset: 0;
      z-index: 10050;
      background: rgba(0, 0, 0, 0.72);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      animation: dialogFadeIn 0.15s ease-out;
    }

    @keyframes dialogFadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .attome-dialog-card {
      position: relative;
      width: 100%;
      max-width: 440px;
      background: var(--color-bg-alt, #121829);
      border: 1px solid var(--color-border, rgba(255, 255, 255, 0.12));
      box-shadow: 0 24px 60px -12px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.05);
      border-radius: 14px;
      padding: 22px 24px 20px;
      color: var(--color-text-primary, #f1f5f9);
      font-family: inherit;
      animation: dialogSlideUp 0.18s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes dialogSlideUp {
      from {
        opacity: 0;
        transform: translateY(12px) scale(0.97);
      }
      to {
        opacity: 1;
        transform: translateY(0) scale(1);
      }
    }

    /* NGB-3.2 — a modal that fades and slides is decoration; honour the
       viewer's motion preference (and the reduced-motion branch of the
       world-readable a11y checklist). */
    @media (prefers-reduced-motion: reduce) {
      .attome-dialog-backdrop,
      .attome-dialog-card {
        animation: none;
      }
      .attome-dialog-btn {
        transition: none;
      }
    }

    .attome-dialog-header {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      margin-bottom: 18px;
    }

    .attome-dialog-icon-wrapper {
      flex: none;
      width: 40px;
      height: 40px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      background: rgba(93, 92, 222, 0.15);
      color: var(--color-accent, #818cf8);
      border: 1px solid rgba(93, 92, 222, 0.25);
    }

    .attome-dialog-icon-wrapper.danger {
      background: rgba(239, 68, 68, 0.14);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.28);
    }

    .attome-dialog-icon-wrapper.primary {
      background: rgba(93, 92, 222, 0.16);
      color: var(--color-accent, #a5b4fc);
      border: 1px solid rgba(93, 92, 222, 0.3);
    }

    .attome-dialog-header-text {
      flex: 1;
      min-width: 0;
    }

    .attome-dialog-title {
      font-size: 16px;
      font-weight: 600;
      color: var(--color-text-primary, #f8fafc);
      margin: 0 0 5px;
      line-height: 1.35;
      letter-spacing: -0.01em;
    }

    .attome-dialog-message {
      font-size: 13px;
      color: var(--color-text-secondary, #94a3b8);
      margin: 0;
      line-height: 1.45;
      word-break: break-word;
    }

    /* Visually hidden, still the input's accessible name. */
    .attome-dialog-sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      white-space: nowrap;
      border: 0;
    }

    .attome-dialog-form {
      margin-bottom: 4px;
    }

    .attome-dialog-input-group {
      margin-bottom: 18px;
    }

    .attome-dialog-input {
      width: 100%;
      padding: 10px 14px;
      background: var(--color-bg, rgba(15, 23, 42, 0.85));
      border: 1px solid var(--color-border, rgba(255, 255, 255, 0.14));
      border-radius: 8px;
      color: var(--color-text-primary, #f8fafc);
      font-size: 14px;
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
      box-sizing: border-box;
    }

    .attome-dialog-input:focus {
      border-color: var(--color-accent, #6366f1);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
    }

    .attome-dialog-input.has-error {
      border-color: #ef4444;
      box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
    }

    .attome-dialog-input-error {
      display: block;
      margin-top: 6px;
      font-size: 12px;
      color: #f87171;
    }

    .attome-dialog-details {
      margin: -6px 0 16px;
      padding: 10px 12px;
      background: rgba(0, 0, 0, 0.35);
      border-radius: 7px;
      border: 1px solid var(--color-border, rgba(255, 255, 255, 0.08));
      max-height: 120px;
      overflow-y: auto;
    }

    .attome-dialog-details pre {
      margin: 0;
      font-size: 11px;
      color: var(--color-text-secondary, #cbd5e1);
      white-space: pre-wrap;
      word-break: break-all;
      font-family: ui-monospace, monospace;
    }

    .attome-dialog-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 10px;
    }

    .attome-dialog-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 500;
      border-radius: 7px;
      border: 1px solid transparent;
      cursor: pointer;
      transition: background-color 0.15s, border-color 0.15s, opacity 0.15s, transform 0.1s;
      outline: none;
    }

    .attome-dialog-btn:active {
      transform: scale(0.98);
    }

    .attome-dialog-btn:disabled {
      opacity: 0.45;
      cursor: not-allowed;
      transform: none;
    }

    .attome-dialog-btn-secondary {
      background: rgba(255, 255, 255, 0.07);
      border-color: var(--color-border, rgba(255, 255, 255, 0.1));
      color: var(--color-text-secondary, #cbd5e1);
    }

    .attome-dialog-btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.12);
      color: var(--color-text-primary, #ffffff);
    }

    .attome-dialog-btn-primary {
      background: var(--color-accent, #5D5CDE);
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(93, 92, 222, 0.35);
    }

    .attome-dialog-btn-primary:hover:not(:disabled) {
      background: var(--color-accent-hover, #4e4dc7);
      box-shadow: 0 3px 12px rgba(93, 92, 222, 0.45);
    }

    .attome-dialog-btn-danger {
      background: #dc2626;
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(220, 38, 38, 0.35);
    }

    .attome-dialog-btn-danger:hover:not(:disabled) {
      background: #b91c1c;
      box-shadow: 0 3px 12px rgba(220, 38, 38, 0.45);
    }
  `],
})
export class DialogHostComponent {
  private readonly dialogService = inject(DialogService);
  readonly lang = inject(LangService);

  /** Stable ids: exactly one dialog is open at a time. */
  readonly TITLE_ID   = 'attome-dialog-title';
  readonly MESSAGE_ID = 'attome-dialog-message';
  readonly INPUT_ID   = 'attome-dialog-prompt-input';
  readonly ERROR_ID   = 'attome-dialog-prompt-error';

  readonly state = this.dialogService.state;
  readonly cardRef           = viewChild<ElementRef<HTMLElement>>('card');
  readonly promptInputRef    = viewChild<ElementRef<HTMLInputElement>>('promptInput');
  readonly confirmBtnRef     = viewChild<ElementRef<HTMLButtonElement>>('confirmBtn');
  readonly errorCloseBtnRef  = viewChild<ElementRef<HTMLButtonElement>>('errorCloseBtn');

  /** NGB-4.3 fixes the reactivity; the signal keeps the template honest now. */
  readonly promptValue = signal('');
  readonly promptValidationMessage = signal<string | null>(null);

  private releaseTrap: (() => void) | null = null;
  private modalHandle: ModalHandle | null = null;

  readonly isDanger = computed(() => {
    const s = this.state();
    return s?.kind === 'confirm' && s.options.variant === 'danger';
  });

  constructor() {
    effect(onCleanup => {
      const s = this.state();
      if (!s) return;

      if (s.kind === 'prompt') {
        this.promptValue.set(s.options.value ?? '');
        this.promptValidationMessage.set(null);
      }

      // NGB-4.3 — register this dialog as the top-most modal so Escape is
      // answered once, by the surface the user is actually looking at.
      this.modalHandle ??= pushModal();

      // The view is not laid out until after this effect's tick, so focus and
      // the trap are installed on the next macrotask (as before NGB-3.2).
      const timer = setTimeout(() => {
        const card = this.cardRef()?.nativeElement;
        if (card) {
          this.releaseTrap?.();
          this.releaseTrap = trapFocus(card);
        }

        if (s.kind === 'prompt') {
          const inputEl = this.promptInputRef()?.nativeElement;
          if (inputEl) {
            inputEl.focus();
            if (s.options.selectStem) {
              const val = inputEl.value;
              const lastDot = val.lastIndexOf('.');
              // Only select stem if dot is not the first char and dot exists
              if (lastDot > 0) {
                inputEl.setSelectionRange(0, lastDot);
              } else {
                inputEl.select();
              }
            } else {
              inputEl.select();
            }
          }
        } else if (s.kind === 'confirm') {
          this.confirmBtnRef()?.nativeElement?.focus();
        } else if (s.kind === 'error') {
          this.errorCloseBtnRef()?.nativeElement?.focus();
        }
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

  getConfirmIcon(variant?: string, customIcon?: string): string {
    if (customIcon) return customIcon;
    if (variant === 'danger') return 'las la-trash-alt';
    if (variant === 'warning') return 'las la-exclamation-triangle';
    return 'las la-question-circle';
  }

  /** NGB-4.3 — only the top-most modal answers Escape. */
  onEscape(): void {
    if (!this.state()) return;
    if (this.modalHandle && !this.modalHandle.isTop()) return;
    this.dialogService.close();
  }

  onBackdropClick(event: MouseEvent): void {
    if ((event.target as HTMLElement).classList.contains('attome-dialog-backdrop')) {
      this.dialogService.close();
    }
  }

  onConfirm(): void {
    const s = this.state();
    if (s && s.kind === 'confirm') {
      s.resolve(true);
    }
  }

  onCancel(): void {
    this.dialogService.close();
  }

  onErrorClose(): void {
    const s = this.state();
    if (s && s.kind === 'error') {
      s.resolve();
    }
  }

  onInputChange(event: Event): void {
    const target = event.target as HTMLInputElement;
    this.promptValue.set(target.value);
    this.validatePrompt();
  }

  validatePrompt(): void {
    const s = this.state();
    if (!s || s.kind !== 'prompt') return;
    const val = this.promptValue().trim();
    if (!val) {
      // NGB-3.3 — was the hardcoded literal 'Value cannot be empty.'
      this.promptValidationMessage.set(this.lang.translate('dialog.emptyValue'));
      return;
    }
    if (s.options.validator) {
      const err = s.options.validator(val);
      this.promptValidationMessage.set(err);
      return;
    }
    this.promptValidationMessage.set(null);
  }

  isPromptSubmittable(): boolean {
    const s = this.state();
    if (!s || s.kind !== 'prompt') return false;
    const val = this.promptValue().trim();
    if (!val) return false;
    if (this.promptValidationMessage()) return false;
    return true;
  }

  onSubmitPrompt(): void {
    const s = this.state();
    if (!s || s.kind !== 'prompt') return;
    this.validatePrompt();
    if (!this.isPromptSubmittable()) return;
    s.resolve(this.promptValue().trim());
  }
}
