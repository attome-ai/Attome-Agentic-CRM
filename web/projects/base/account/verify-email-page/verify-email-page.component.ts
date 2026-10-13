import { ChangeDetectionStrategy, Component, ElementRef, inject, input, OnInit, signal, viewChild } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AuthService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';

/** Auto-confirms the token in the URL on load — no form, just a status page. */
@Component({
  selector: 'base-verify-email-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  templateUrl: './verify-email-page.component.html',
  styleUrl: '../account-forms.css',
})
export class VerifyEmailPageComponent implements OnInit {
  private readonly auth  = inject(AuthService);
  private readonly route = inject(ActivatedRoute);
  readonly lang           = inject(LangService);

  /** NGB-5.1a — bound from the host route's `data` by `withComponentInputBinding()`. */
  readonly backRoute  = input<string>('/login');
  /** NGB-5.1a — the route to offer once the address is verified. */
  readonly loginRoute = input<string>('/login');

  readonly loading = signal(true);
  readonly done    = signal(false);
  readonly error   = signal<string | null>(null);

  /** NGB-3.6 — the heading/banner a state change moves focus to. */
  private readonly heading = viewChild<ElementRef<HTMLElement>>('pageHeading');

  ngOnInit(): void {
    const token = this.route.snapshot.queryParamMap.get('token');
    if (!token) {
      this.loading.set(false);
      this.error.set(this.lang.translate('verifyEmail.invalidLink'));
      this.focusHeading(); // NGB-3.6
      return;
    }

    this.auth.confirmEmailVerification({ token }).subscribe({
      next: () => {
        this.loading.set(false);
        this.done.set(true);
        this.focusHeading(); // NGB-3.6
      },
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(
          err.kind === 'unauthorized' || err.kind === 'conflict'
            ? this.lang.translate('verifyEmail.invalidLink')
            : this.lang.errorText(err), // NGB-2.3
        );
        this.focusHeading(); // NGB-3.6
      },
    });
  }

  private focusHeading(): void {
    setTimeout(() => this.heading()?.nativeElement?.focus(), 0);
  }
}
