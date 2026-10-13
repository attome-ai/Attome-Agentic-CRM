import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService, ApiError, LangService } from '@attome/base';

@Component({
  selector:   'app-register',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [ReactiveFormsModule, RouterLink],
  template: `
    <div class="auth-page">
      <div class="auth-card">
        <div class="auth-logo">
          <span class="logo-mark">A</span>
          <h1>Attome</h1>
        </div>

        @if (mode() === 'disabled') {
          <h2>Registration is closed</h2>
          <p class="subtitle">
            This deployment doesn't accept self-service sign-ups. Ask your
            administrator to create an account for you.
          </p>
          <p class="auth-link">
            Already have an account? <a routerLink="/xrm/login">Sign in</a>
          </p>
        } @else {
          <h2>Create account</h2>
          <p class="subtitle">
            {{ mode() === 'invite' ? 'Finish setting up the account you were invited to.' : 'Get started for free' }}
          </p>

          <form [formGroup]="form" (ngSubmit)="submit()">
            <div class="field">
              <label for="email">Email</label>
              <input id="email" type="email" formControlName="email"
                     placeholder="you@example.com" autocomplete="email" />
            </div>

            <div class="field">
              <label for="password">Password</label>
              <input id="password" type="password" formControlName="password"
                     placeholder="Min 12 characters" autocomplete="new-password" />
            </div>

            @if (mode() === 'invite') {
              <div class="field">
                <label for="invitation_token">Invitation code</label>
                <input id="invitation_token" type="text" formControlName="invitation_token"
                       placeholder="Paste the code from your invitation email" />
              </div>
            }

            @if (error()) {
              <p class="error-msg">{{ error() }}</p>
            }

            <button type="submit" class="btn-submit" [disabled]="loading()">
              {{ loading() ? 'Creating account…' : 'Create account' }}
            </button>
          </form>

          <p class="auth-link">
            Already have an account? <a routerLink="/xrm/login">Sign in</a>
          </p>
        }
      </div>
    </div>
  `,
  styles: [`@import '../auth-shared.css';`],
})
export class RegisterComponent implements OnInit {
  private readonly auth   = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route  = inject(ActivatedRoute);
  private readonly fb     = inject(FormBuilder);
  private readonly lang   = inject(LangService);

  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  /**
   * P-registration-gating (D-128) — defaults to `'public'` so the form
   * renders immediately rather than flashing "closed" while the config
   * fetch is in flight; corrected as soon as `getRegistrationConfig`
   * resolves. A deployment with registration actually disabled still gets
   * a 403 from the backend on submit even if this briefly showed the form.
   */
  readonly mode = signal<'public' | 'invite' | 'disabled'>('public');

  readonly form = this.fb.group({
    email:            ['', [Validators.required, Validators.email]],
    // Mirrors attome_auth::password::validate_policy (12 characters minimum,
    // 128 bytes maximum). The API is authoritative: it counts bytes, so a
    // multi-byte password under 128 characters can still be rejected there.
    password:         ['', [Validators.required, Validators.minLength(12), Validators.maxLength(128)]],
    invitation_token: [''],
  });

  ngOnInit(): void {
    this.auth.getRegistrationConfig().subscribe({
      next: cfg => {
        this.mode.set(cfg.mode);
        if (cfg.mode === 'invite') {
          const token = this.route.snapshot.queryParamMap.get('invitation_token');
          if (token) this.form.patchValue({ invitation_token: token });
        }
      },
      // Fail open to 'public' on a config-fetch error — worst case the
      // backend still rejects the submit with the real 403; this only
      // controls what the page renders while offline/erroring.
      error: () => this.mode.set('public'),
    });
  }

  submit(): void {
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.loading.set(true);
    this.error.set(null);

    const { email, password, invitation_token } = this.form.value;
    this.auth.register({
      email:    email!,
      password: password!,
      ...(this.mode() === 'invite' && invitation_token ? { invitation_token } : {}),
    }).subscribe({
      next: () => this.router.navigateByUrl('/dashboard'),
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(
          err.status === 409 ? this.lang.translate('register.emailTaken') :
          err.status === 403 ? this.lang.translate('register.invalidInvitation') :
          err.message,
        );
      },
    });
  }
}
