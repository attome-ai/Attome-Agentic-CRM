import { ChangeDetectionStrategy, Component, ElementRef, inject, input, signal, viewChild } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';

@Component({
  selector: 'base-reset-password-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  templateUrl: './reset-password-page.component.html',
  styleUrl: '../account-forms.css',
})
export class ResetPasswordPageComponent {
  private readonly auth   = inject(AuthService);
  private readonly route  = inject(ActivatedRoute);
  private readonly router = inject(Router);
  readonly lang            = inject(LangService);

  /** NGB-5.1a — bound from the host route's `data` by `withComponentInputBinding()`. */
  readonly backRoute  = input<string>('/login');
  /** NGB-5.1a — the route to offer once the password is reset. */
  readonly loginRoute = input<string>('/login');
  private readonly token = this.route.snapshot.queryParamMap.get('token');

  /**
   * Bound in the template's `minlength` attribute too — single source of truth
   * for the UI. Mirrors the API's own rule (`attome_auth::password::
   * validate_policy`, 12 characters minimum), which is what actually enforces it.
   */
  readonly minPasswordLength = 12;

  readonly newPassword     = signal('');
  readonly confirmPassword = signal('');
  readonly loading         = signal(false);
  readonly done            = signal(false);
  readonly error           = signal<string | null>(null);

  /** NGB-3.6 — the heading a state change moves focus to. */
  private readonly heading = viewChild<ElementRef<HTMLElement>>('pageHeading');

  submit(): void {
    if (!this.token) {
      this.error.set(this.lang.translate('resetPassword.invalidLink'));
      return;
    }
    if (this.newPassword() !== this.confirmPassword()) {
      this.error.set(this.lang.translate('resetPassword.mismatch'));
      return;
    }

    this.loading.set(true);
    this.error.set(null);
    this.auth.confirmPasswordReset({ token: this.token, new_password: this.newPassword() }).subscribe({
      next: () => {
        this.loading.set(false);
        this.done.set(true);
        // NGB-3.6 — move focus to the new heading so a keyboard user is told.
        setTimeout(() => this.heading()?.nativeElement?.focus(), 0);
      },
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(
          err.kind === 'unauthorized' || err.kind === 'conflict'
            ? this.lang.translate('resetPassword.invalidLink')
            : this.lang.errorText(err), // NGB-2.3
        );
      },
    });
  }
}
