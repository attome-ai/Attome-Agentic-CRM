import {
  ChangeDetectionStrategy, AfterViewInit, Component, OnInit, computed, inject, signal,
} from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import {
  ApiError,
  AuthService,
  LangService,
  MfaEnrollResponse,
  OidcProviderInfo,
  PASSKEY_BROWSER,
  ThemeService,
  consumeReturnUrl,
  initGoogleIdentityOnce,
  isMfaChallenge,
  isPasskeyCancelled,
  type GoogleIdentityGlobal,
} from '@attome/base';
import { solvePow } from './pow';

declare const google: GoogleIdentityGlobal;

type Stage = 'credentials' | 'mfa-code' | 'mfa-grace' | 'mfa-enroll';

/** Q5-T10: Arabic-Indic and Persian digits as ASCII, so a code typed on an
 *  Arabic keyboard is sent as the digits it shows (the server accepts both). */
export function asciiDigits(text: string): string {
  return text.replace(/[\u0660-\u0669\u06F0-\u06F9]/g, d => {
    const code = d.charCodeAt(0);
    return String(code >= 0x06F0 ? code - 0x06F0 : code - 0x0660);
  });
}

const DAY_MS = 86_400_000;

@Component({
  selector:   'app-login',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [ReactiveFormsModule, RouterLink],
  template: `
    <div class="login-page">
      <div class="bg-shape shape-1"></div>
      <div class="bg-shape shape-2"></div>
      <div class="login-card">
        <a routerLink="/" class="back-link" aria-label="Back to website">← Back</a>
        <div class="card-content">
        <div class="logo-mark">
          <svg width="40" height="40" viewBox="0 0 28 28" fill="none" aria-hidden="true">
            <rect width="28" height="28" rx="7" fill="var(--color-accent)"/>
            <path d="M7 20L14 8L21 20" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M9.5 16H18.5" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
          </svg>
        </div>

        @if (stage() === 'credentials') {
          <h1 class="page-title">XRM Access</h1>
          <p class="page-subtitle">Sign in to the Attome Enterprise Platform</p>

          @if (oidcProviders().length > 0) {
            <div class="provider-list">
              @for (provider of oidcProviders(); track provider.key) {
                <button type="button" class="btn-provider" (click)="signInWithOidc(provider.key)">
                  Sign in with {{ provider.display_name }}
                </button>
              }
            </div>
          }

          @if (hasGoogleAuth()) {
            <div [id]="googleBtnId" class="google-btn-slot"></div>
          }

          @if (passkeysSupported) {
            <button type="button" class="btn-provider" (click)="signInWithPasskey()" [disabled]="loading()" data-testid="passkey-sign-in">
              {{ t('xrmLogin.passkeySignIn') }}
            </button>
          }

          @if (hasEnterpriseProviders()) {
            <div class="auth-divider"><span>or use your password</span></div>
          }

          <form [formGroup]="form" (ngSubmit)="submit()">
            <div class="field">
              <label for="email">Email</label>
              <input id="email" type="email" formControlName="email"
                     placeholder="you@example.com" autocomplete="email"
                     [attr.aria-invalid]="showFieldError('email') || null"
                     [attr.aria-describedby]="showFieldError('email') ? 'email-error' : null" />
              @if (showFieldError('email')) {
                <p class="field-error" id="email-error">
                  {{ form.controls.email.hasError('required')
                       ? 'Email is required.'
                       : 'Enter a valid email address, e.g. you@example.com.' }}
                </p>
              }
            </div>

            @if (askPassword()) {
            <div class="field">
              <label for="password">Password</label>
              <input id="password" type="password" formControlName="password"
                     placeholder="••••••••" autocomplete="current-password"
                     [attr.aria-invalid]="showFieldError('password') || null"
                     [attr.aria-describedby]="showFieldError('password') ? 'password-error' : null" />
              @if (showFieldError('password')) {
                <p class="field-error" id="password-error">Password is required.</p>
              }
            </div>
            @if (emailChecked()) {
              <p class="auth-link"><button type="button" class="btn-link" (click)="otherEmail()" data-testid="other-email">{{ t('xrmLogin.otherEmail') }}</button></p>
            }
            }

            @if (error()) {
              <p class="error-msg">{{ error() }}</p>
            }

            <button type="submit" class="btn-submit" [disabled]="loading()">
              @if (askPassword()) {
                {{ loading() ? 'Signing in…' : 'Sign in' }}
              } @else {
                {{ loading() ? t('xrmLogin.checkingEmail') : t('xrmLogin.continue') }}
              }
            </button>
          </form>

          <p class="auth-link">
            <a routerLink="/forgot-password">Forgot your password?</a>
          </p>
          @if (registrationOpen()) {
            <p class="auth-link">
              Don't have an account? <a routerLink="/register">Register</a>
            </p>
          }
        }

        @if (stage() === 'mfa-code') {
          <h2>Two-factor verification</h2>
          <p class="subtitle">
            {{ useRecoveryCode() ? 'Enter one of your unused recovery codes.' : 'Enter the 6-digit code from your authenticator app.' }}
          </p>

          <form [formGroup]="codeForm" (ngSubmit)="submitMfaCode()">
            <div class="field">
              <label for="mfa-code">{{ useRecoveryCode() ? 'Recovery code' : 'Authentication code' }}</label>
              <input id="mfa-code" type="text" formControlName="code" autocomplete="one-time-code"
                     [placeholder]="useRecoveryCode() ? 'XXXX-XXXX' : '123456'"
                     [attr.aria-invalid]="showCodeError() || null"
                     [attr.aria-describedby]="showCodeError() ? 'mfa-code-error' : null" />
              @if (showCodeError()) {
                <p class="field-error" id="mfa-code-error">
                  {{ useRecoveryCode() ? 'Enter a recovery code.' : 'Enter your authentication code.' }}
                </p>
              }
            </div>
            @if (rememberAllowed() && !useRecoveryCode()) {
              <label class="checkbox-row">
                <input type="checkbox" [checked]="rememberDevice()" (change)="onRemember($event)" data-testid="remember-device" />
                {{ t('xrmLogin.rememberDevice') }}
              </label>
            }

            @if (error()) {
              <p class="error-msg">{{ error() }}</p>
            }

            <button type="submit" class="btn-submit" [disabled]="loading()">
              {{ loading() ? 'Verifying…' : 'Verify' }}
            </button>
          </form>

          @if (passkeyOffered()) {
            <p class="auth-link">
              <button type="button" class="link-button" (click)="useMfaPasskey()" [disabled]="loading()" data-testid="mfa-passkey">
                {{ t('xrmLogin.passkeyUse') }}
              </button>
            </p>
          }
          <p class="auth-link">
            <button type="button" class="link-button" (click)="toggleRecoveryCode()">
              {{ useRecoveryCode() ? 'Use my authenticator app instead' : 'Use a recovery code instead' }}
            </button>
          </p>
          <p class="auth-link">
            <button type="button" class="link-button" (click)="startOver()">Back to sign in</button>
          </p>
        }

        @if (stage() === 'mfa-grace') {
          <h2>{{ t('xrmLogin.graceTitle') }}</h2>
          <p class="subtitle">{{ t('xrmLogin.graceIntro') }}</p>
          @if (error()) {
            <p class="error-msg">{{ error() }}</p>
          }
          <button type="button" class="btn-submit" (click)="setUpNow()" [disabled]="loading()" data-testid="grace-now">
            {{ t('xrmLogin.setUpNow') }}
          </button>
          <p class="auth-link">
            <button type="button" class="link-button" (click)="later()" [disabled]="loading()" data-testid="grace-later">
              {{ laterLabel() }}
            </button>
          </p>
        }

        @if (stage() === 'mfa-enroll') {
          @if (recoveryCodes(); as codes) {
            <h2>Save your recovery codes</h2>
            <p class="subtitle">
              Each code can be used once if you lose access to your authenticator app. Store them somewhere safe — they won't be shown again.
            </p>

            <ul class="recovery-codes">
              @for (code of codes; track code) {
                <li>{{ code }}</li>
              }
            </ul>

            <button type="button" class="btn-submit" (click)="continueToDashboard()">Continue</button>
          } @else {
            <h2>Set up two-factor authentication</h2>
            <p class="subtitle">Your organization requires a second factor. Scan this into an authenticator app (Google Authenticator, 1Password, Authy…), or enter the key manually.</p>

            @if (enrollInfo(); as info) {
              <div class="mfa-secret">{{ info.secret_base32 }}</div>
              <p class="auth-link"><a [href]="info.otpauth_uri">Open in authenticator app</a></p>
            }

            <form [formGroup]="codeForm" (ngSubmit)="submitEnrollConfirm()">
              <div class="field">
                <label for="enroll-code">Authentication code</label>
                <input id="enroll-code" type="text" formControlName="code" autocomplete="one-time-code" placeholder="123456"
                       [attr.aria-invalid]="showCodeError() || null"
                       [attr.aria-describedby]="showCodeError() ? 'enroll-code-error' : null" />
                @if (showCodeError()) {
                  <p class="field-error" id="enroll-code-error">Enter your authentication code.</p>
                }
              </div>

              @if (error()) {
                <p class="error-msg">{{ error() }}</p>
              }

              <button type="submit" class="btn-submit" [disabled]="loading()">
                {{ loading() ? 'Confirming…' : 'Confirm' }}
              </button>
            </form>
          }
        }
        </div>
      </div>
    </div>
  `,
  styles: [`
    @import '../auth-shared.css';

    .login-page {
      min-height: 100vh; width: 100%; box-sizing: border-box; padding: 20px;
      display: flex; align-items: center; justify-content: center;
      position: relative; overflow: hidden; background: var(--color-bg);
    }
    .bg-shape { position: absolute; filter: blur(80px); opacity: .25; pointer-events: none; }
    .shape-1 { top: -100px; inset-inline-start: -100px; width: 400px; height: 400px; background: radial-gradient(circle, var(--color-accent), transparent 70%); }
    .shape-2 { inset-inline-end: -100px; bottom: -100px; width: 500px; height: 500px; background: radial-gradient(circle, var(--color-primary), transparent 70%); }
    .login-card {
      position: relative; z-index: 1; width: 100%; max-width: 440px;
      box-sizing: border-box; padding: 40px; border-radius: 24px;
      background: var(--color-bg-alt); border: 1px solid var(--color-border);
      box-shadow: 0 25px 50px -12px var(--color-card-shadow);
    }
    .back-link { display: inline-flex; margin-bottom: 20px; color: var(--color-text-secondary); text-decoration: none; font-size: 14px; }
    .back-link:hover { color: var(--color-text-primary); }
    .card-content { display: flex; flex-direction: column; align-items: center; text-align: center; }
    .logo-mark { width: auto; height: auto; border-radius: 0; background: none; margin-bottom: 20px; }
    .page-title { color: var(--color-text-primary); font-size: 28px; margin: 0 0 8px; }
    .page-subtitle { color: var(--color-text-secondary); font-size: 15px; margin: 0 0 32px; }
    form { width: 100%; text-align: start; }
    h2, label { color: var(--color-text-primary); }
    .subtitle, .auth-link { color: var(--color-text-secondary); }
    input { color: var(--color-text-primary); background: var(--color-bg); border-color: var(--color-border); }
    .btn-submit { background: var(--color-accent); }

    /* Paints its own light background for the same reason .error-msg does in
       auth-shared.css: this page renders over --color-bg, which is dark in one
       theme and light in the other, and a bare red-on-transparent fails the
       axe color-contrast gate in one of them. */
    .field-error {
      color: #dc2626;
      background: #fef2f2;
      border: 1px solid #fecaca;
      border-radius: 6px;
      padding: 6px 10px;
      font-size: 12px;
      margin: 0;
    }

    .link-button {
      background: none;
      border: none;
      padding: 0;
      /* Indigo-600, matching auth-shared.css's .auth-link a — indigo-500 is
         4.46:1 on white and fails WCAG AA for normal text. */
      color: #4f46e5;
      font-weight: 500;
      font-size: 13px;
      cursor: pointer;
      font-family: inherit;
    }

    .provider-list { display: grid; gap: 8px; margin-bottom: 10px; }
    .btn-provider {
      width: 100%; min-height: 42px; border: 1px solid #d1d5db;
      border-radius: 8px; background: var(--color-bg); color: var(--color-text-primary);
      font: inherit; font-weight: 600; cursor: pointer;
    }
    .google-btn-slot { min-height: 42px; margin-bottom: 10px; }
    .auth-divider {
      display: flex; align-items: center; gap: 10px; margin: 16px 0;
      color: var(--color-text-secondary); font-size: 12px;
    }
    .auth-divider::before, .auth-divider::after {
      content: ''; height: 1px; background: var(--color-border); flex: 1;
    }

    .mfa-secret {
      font-family: ui-monospace, monospace;
      font-size: 14px;
      letter-spacing: 0.5px;
      background: #f3f4f6;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 10px 14px;
      margin-bottom: 12px;
      word-break: break-all;
      text-align: center;
    }

    .recovery-codes {
      list-style: none;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      font-family: ui-monospace, monospace;
      font-size: 14px;
      background: #f3f4f6;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 14px;
      margin: 0 0 20px;
    }
  `],
})
export class LoginComponent implements OnInit, AfterViewInit {
  private readonly auth   = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route  = inject(ActivatedRoute);
  private readonly fb     = inject(FormBuilder);
  private readonly theme  = inject(ThemeService);
  private readonly lang   = inject(LangService);
  private readonly passkeys = inject(PASSKEY_BROWSER);

  /** Q6-T2: this browser can use passkeys. */
  readonly passkeysSupported = this.passkeys.supported();
  /** Q6-T2: the person has a passkey for the second factor. */
  readonly passkeyOffered = signal(false);

  readonly stage           = signal<Stage>('credentials');
  readonly loading         = signal(false);
  readonly error           = signal<string | null>(null);
  readonly useRecoveryCode = signal(false);
  readonly enrollInfo      = signal<MfaEnrollResponse | null>(null);
  readonly recoveryCodes   = signal<string[] | null>(null);
  /**
   * P-registration-gating (D-128) — defaults to `true` so the link doesn't
   * flash in-and-out while the config fetch is in flight; corrected to
   * `false` if this deployment has registration disabled.
   */
  readonly registrationOpen = signal(true);
  readonly googleClientId = signal<string | null>(null);
  readonly oidcProviders = signal<OidcProviderInfo[]>([]);
  readonly hasGoogleAuth = computed(() => this.googleClientId() !== null);
  readonly hasEnterpriseProviders = computed(() =>
    this.hasGoogleAuth() || this.oidcProviders().length > 0,
  );
  readonly googleBtnId = 'attome-xrm-google-btn';
  /**
   * Q1-T14: email first. With sign-in providers configured, the email is
   * asked for alone; a verified domain sends the person to their provider
   * (`POST /api/v1/auth/oidc/discover`), any other address goes on to the
   * password. A failed lookup also goes on to the password, so nobody is
   * locked out by it.
   */
  readonly emailChecked = signal(false);
  /** Q5-T10: the grace period's end, when enrolling may still be put off. */
  readonly graceUntil = signal<string | null>(null);
  readonly graceDaysLeft = computed(() => {
    const until = this.graceUntil();
    return until ? Math.max(1, Math.ceil((Date.parse(until) - Date.now()) / DAY_MS)) : 0;
  });
  /** Q5-T10: the server allows remembering this browser after the code. */
  readonly rememberAllowed = signal(false);
  readonly rememberDevice = signal(false);
  readonly askPassword = computed(() => this.emailChecked() || this.oidcProviders().length === 0);

  private pendingToken = '';
  private googleScriptLoaded = false;

  ngOnInit(): void {
    this.auth.getRegistrationConfig().subscribe({
      next:  cfg => this.registrationOpen.set(cfg.mode !== 'disabled'),
      error: () => this.registrationOpen.set(true),
    });
  }

  ngAfterViewInit(): void {
    this.auth.getOidcProviders().subscribe({
      next: providers => this.oidcProviders.set(providers),
      error: () => this.oidcProviders.set([]),
    });
    this.auth.getGoogleConfig().subscribe({
      next: cfg => {
        this.googleClientId.set(cfg.client_id);
        if (cfg.client_id) this.loadGoogleScript();
      },
      error: () => this.googleClientId.set(null),
    });
  }

  signInWithOidc(providerKey: string): void { this.auth.loginWithOidc(providerKey); }

  private loadGoogleScript(): void {
    if (typeof google !== 'undefined') {
      this.googleScriptLoaded = true;
      setTimeout(() => this.initGoogle(), 0);
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => { this.googleScriptLoaded = true; this.initGoogle(); };
    script.onerror = () => this.error.set('Failed to load Google Sign-In. Please refresh.');
    document.head.appendChild(script);
  }

  private initGoogle(): void {
    const clientId = this.googleClientId();
    if (typeof google === 'undefined' || !clientId) return;
    initGoogleIdentityOnce({
      client_id: clientId,
      callback: response => this.handleGoogleCredential(response),
      auto_select: false,
      cancel_on_tap_outside: false,
    });
    this.renderGoogleButton();
  }

  private renderGoogleButton(): void {
    if (!this.googleScriptLoaded || typeof google === 'undefined') return;
    const element = document.getElementById(this.googleBtnId);
    if (!element) return;
    element.innerHTML = '';
    google.accounts.id.renderButton(element, {
      theme: this.theme.isDark() ? 'filled_black' : 'outline',
      size: 'large', width: element.offsetWidth || 360, type: 'standard',
      shape: 'rectangular', text: 'signin_with', logo_alignment: 'left',
    });
  }

  private handleGoogleCredential(response: { credential: string }): void {
    if (!response.credential) return;
    // Fired from outside Angular by the Google SDK. No `NgZone.run()` re-entry
    // under zoneless — the signal writes below schedule the refresh themselves.
    this.loading.set(true);
    this.error.set(null);
    this.auth.loginWithGoogle({ credential: response.credential }).subscribe({
      next: () => this.goHome(),
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(err.status === 401 ? this.lang.translate('xrmLogin.googleError') : this.lang.errorText(err));
        setTimeout(() => this.renderGoogleButton(), 0);
      },
    });
  }

  readonly form = this.fb.group({
    email:    ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });

  readonly codeForm = this.fb.group({
    code: ['', Validators.required],
  });

  /**
   * Gates the inline field messages on a real submit attempt: nothing nags the
   * operator while they are still typing, and the first click of the submit
   * button explains itself. Without it the handlers' `if (invalid) { … return; }`
   * guard is silent, and a malformed email makes "Sign in" look like a dead
   * button — no request, no message, nothing in the console.
   */
  readonly submitAttempted = signal(false);

  showFieldError(name: 'email' | 'password'): boolean {
    return this.submitAttempted() && this.form.controls[name].invalid;
  }

  showCodeError(): boolean {
    return this.submitAttempted() && this.codeForm.controls.code.invalid;
  }

  t(key: string): string {
    return this.lang.translate(key);
  }

  otherEmail(): void {
    this.emailChecked.set(false);
    this.form.controls.password.reset('');
    this.error.set(null);
  }

  private discover(): void {
    this.loading.set(true);
    this.error.set(null);
    this.auth.discoverOidc(this.form.value.email!).subscribe({
      next: res => {
        if (res.provider) { this.signInWithOidc(res.provider); return; }
        this.loading.set(false);
        this.emailChecked.set(true);
      },
      error: () => { this.loading.set(false); this.emailChecked.set(true); },
    });
  }

  submit(): void {
    this.submitAttempted.set(true);
    if (!this.askPassword()) {
      if (this.form.controls.email.invalid) { this.form.controls.email.markAsTouched(); return; }
      this.submitAttempted.set(false);
      this.discover();
      return;
    }
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.submitAttempted.set(false);
    this.loading.set(true);
    this.error.set(null);
    this.signIn(null);
  }

  /**
   * Q20-T3: a `429` may mean this address is being asked for a challenge
   * after a password spray. When proof-of-work is the challenge in force the
   * server hands one out; it is solved in a Web Worker and the sign-in is
   * sent once more with the answer. Otherwise the `429` is shown as is.
   */
  private answerChallenge(err: ApiError): void {
    this.auth.getPowChallenge().subscribe({
      next: challenge => {
        this.error.set(this.lang.translate('xrmLogin.checkingBrowser'));
        this.solveInWorker(challenge.nonce, challenge.difficulty).then(
          answer => { this.error.set(null); this.signIn(`${challenge.challenge}:${answer}`); },
          () => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
        );
      },
      error: () => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  private solveInWorker(nonce: string, difficulty: number): Promise<string> {
    if (typeof Worker === 'undefined') return solvePow(nonce, difficulty);
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./pow.worker', import.meta.url), { type: 'module' });
      worker.onmessage = ({ data }: MessageEvent<{ answer: string | null }>) => {
        worker.terminate();
        if (data.answer) resolve(data.answer); else reject(new Error('unsolved'));
      };
      worker.onerror = event => { worker.terminate(); reject(event); };
      worker.postMessage({ nonce, difficulty });
    });
  }

  private signIn(captchaToken: string | null): void {
    const { email, password } = this.form.value;
    this.auth.login({ email: email!, password: password!, captcha_token: captchaToken }).subscribe({
      next: res => {
        if (!isMfaChallenge(res)) {
          this.goHome();
          return;
        }
        this.pendingToken = res.pending_token;
        if (res.mfa === 'required') {
          this.loading.set(false);
          this.rememberAllowed.set(res.remember_device === true);
          this.passkeyOffered.set(res.passkey === true && this.passkeysSupported);
          this.stage.set('mfa-code');
          return;
        }
        // Q5-T10: within the grace period the person may set it up now or later.
        if (res.grace_until && Date.parse(res.grace_until) > Date.now()) {
          this.loading.set(false);
          this.graceUntil.set(res.grace_until);
          this.stage.set('mfa-grace');
          return;
        }
        // 'enrollment_required' — mfa_policy=required and this account isn't
        // enrolled yet; start forced enrollment before any session exists.
        this.auth.startMfaEnrollment({ pending_token: res.pending_token }).subscribe({
          next: info => {
            this.loading.set(false);
            this.enrollInfo.set(info);
            this.stage.set('mfa-enroll');
          },
          error: (err: ApiError) => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
        });
      },
      error: (err: ApiError) => {
        if (err.status === 429 && captchaToken === null) {
          this.answerChallenge(err);
          return;
        }
        this.loading.set(false);
        this.error.set(err.status === 401 ? this.lang.translate('xrmLogin.invalidCredentials') : this.lang.errorText(err));
      },
    });
  }

  submitMfaCode(): void {
    this.submitAttempted.set(true);
    if (this.codeForm.invalid) { this.codeForm.markAllAsTouched(); return; }
    this.submitAttempted.set(false);
    this.loading.set(true);
    this.error.set(null);

    const code = asciiDigits(this.codeForm.value.code!.trim());
    const remember = this.rememberAllowed() && this.rememberDevice();
    const req$ = this.useRecoveryCode()
      ? this.auth.verifyMfaRecovery({ pending_token: this.pendingToken, code })
      : this.auth.verifyMfa({ pending_token: this.pendingToken, code, ...(remember ? { remember: true } : {}) });

    req$.subscribe({
      next: () => this.goHome(),
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(err.status === 401 ? this.lang.translate('xrmLogin.invalidCode') : this.lang.errorText(err));
      },
    });
  }

  /**
   * Q6-T2: a passkey alone. A role must allow it (403 says so); a cancelled
   * browser prompt leaves the page as it was.
   */
  signInWithPasskey(): void {
    this.loading.set(true);
    this.error.set(null);
    this.auth.signInWithPasskey().subscribe({
      next: () => this.goHome(),
      error: (err: unknown) => this.passkeyFailed(err),
    });
  }

  /** Q6-T2: the person's passkey as the second factor. */
  useMfaPasskey(): void {
    this.loading.set(true);
    this.error.set(null);
    const remember = this.rememberAllowed() && this.rememberDevice();
    this.auth.verifyMfaPasskey(this.pendingToken, remember).subscribe({
      next: () => this.goHome(),
      error: (err: unknown) => this.passkeyFailed(err),
    });
  }

  private passkeyFailed(err: unknown): void {
    this.loading.set(false);
    if (isPasskeyCancelled(err)) return;
    const api = err as ApiError;
    if (api?.status === 403) {
      this.error.set(this.lang.translate('xrmLogin.passkeyNotAllowed'));
    } else if (api?.status === 401 || !api?.kind) {
      this.error.set(this.lang.translate('xrmLogin.passkeyFailed'));
    } else {
      this.error.set(this.lang.errorText(api));
    }
  }

  submitEnrollConfirm(): void {
    this.submitAttempted.set(true);
    if (this.codeForm.invalid) { this.codeForm.markAllAsTouched(); return; }
    this.submitAttempted.set(false);
    this.loading.set(true);
    this.error.set(null);

    const code = asciiDigits(this.codeForm.value.code!.trim());
    this.auth.confirmMfaEnrollment({ pending_token: this.pendingToken, code }).subscribe({
      next:  res => { this.loading.set(false); this.recoveryCodes.set(res.recovery_codes); },
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(err.status === 401 ? this.lang.translate('xrmLogin.invalidCode') : this.lang.errorText(err));
      },
    });
  }

  onRemember(event: Event): void {
    this.rememberDevice.set((event.target as HTMLInputElement).checked);
  }

  laterLabel(): string {
    return this.lang.translate('xrmLogin.later', { days: this.graceDaysLeft() });
  }

  /** Q5-T10: enrol now, from the grace prompt. */
  setUpNow(): void {
    this.loading.set(true);
    this.error.set(null);
    this.auth.startMfaEnrollment({ pending_token: this.pendingToken }).subscribe({
      next: info => {
        this.loading.set(false);
        this.enrollInfo.set(info);
        this.stage.set('mfa-enroll');
      },
      error: (err: ApiError) => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  /** Q5-T10: put enrolling off and sign in. */
  later(): void {
    this.loading.set(true);
    this.error.set(null);
    this.auth.postponeMfa(this.pendingToken).subscribe({
      next: () => this.goHome(),
      error: (err: ApiError) => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  toggleRecoveryCode(): void {
    this.useRecoveryCode.update(v => !v);
    this.codeForm.reset();
    this.submitAttempted.set(false);
    this.error.set(null);
  }

  startOver(): void {
    this.pendingToken = '';
    this.useRecoveryCode.set(false);
    this.passkeyOffered.set(false);
    this.submitAttempted.set(false);
    this.error.set(null);
    this.codeForm.reset();
    this.form.reset();
    this.stage.set('credentials');
  }

  continueToDashboard(): void {
    this.goHome();
  }

  /** NGB-1.3 / OD-5: a deep link survives sign-in, but only as a same-origin path. */
  private goHome(): void {
    this.router.navigateByUrl(consumeReturnUrl(this.route, '/xrm/dashboard'));
  }
}
