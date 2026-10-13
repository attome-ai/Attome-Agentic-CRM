import { ChangeDetectionStrategy, Component, ElementRef, inject, input, signal, viewChild } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';

@Component({
  selector: 'base-forgot-password-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  templateUrl: './forgot-password-page.component.html',
  styleUrl: '../account-forms.css',
})
export class ForgotPasswordPageComponent {
  private readonly auth = inject(AuthService);
  readonly lang          = inject(LangService);

  /**
   * NGB-5.1a — the host's route `data` is bound to this input by
   * `withComponentInputBinding()`, so the page no longer reads
   * `ActivatedRoute.snapshot` (which made a param change invisible to the
   * OnPush template).
   */
  readonly backRoute = input<string>('/login');

  readonly email    = signal('');
  readonly loading  = signal(false);
  readonly sent     = signal(false);
  readonly error    = signal<string | null>(null);

  /** NGB-3.6 — the heading a state change moves focus to. */
  private readonly heading = viewChild<ElementRef<HTMLElement>>('pageHeading');

  submit(): void {
    const email = this.email().trim();
    if (!email) return;

    this.loading.set(true);
    this.error.set(null);
    this.auth.requestPasswordReset({ email }).subscribe({
      // Backend is enumeration-safe: this always resolves the same way
      // regardless of whether the email matched an account.
      next: () => { this.loading.set(false); this.sent.set(true); this.focusHeading(); },
      error: (err: ApiError) => {
        this.loading.set(false);
        // NGB-2.3 — `errorText` keeps the server's field-level text for a
        // `validation` failure and renders `errors.<kind>` in the active
        // language for everything else.
        this.error.set(this.lang.errorText(err));
      },
    });
  }

  /**
   * NGB-3.6 — a keyboard user is not told the state changed unless focus moves
   * to the new heading. The `role="alert"` banner above announces an error on
   * its own.
   */
  private focusHeading(): void {
    setTimeout(() => this.heading()?.nativeElement?.focus(), 0);
  }
}
