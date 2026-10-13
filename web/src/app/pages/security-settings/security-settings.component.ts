import {
  ChangeDetectionStrategy, AfterViewInit, Component, OnInit, computed, inject, signal,
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import {
  ApiError,
  ApiKeyCreated,
  AuthService,
  CreateApiKeyRequest,
  IdentityLinkInfo,
  LangService,
  OidcProviderInfo,
  TranslatePipe,
  initGoogleIdentityOnce,
  type GoogleIdentityGlobal,
} from '@attome/base';
import { StepUpService, type StepUpPendingAction } from '@attome/base/step-up';

declare const google: GoogleIdentityGlobal;

/** One row rendered per configured provider, combining the provider directory with any existing link. */
interface ProviderRow {
  key: string;
  displayName: string;
  protocol: 'oidc';
  linkedEmail: string | null;
}

type Banner = { kind: 'success' | 'conflict' | 'error'; message: string } | null;

/** The backend's hardcoded return target for linking and federated step-up. */
const SETTINGS_PATH = '/settings/security';

/**
 * P-federation-linking-policy §4.3(a) — self-service "link an identity" page.
 * The backend hardcodes its post-linking redirect to exactly `/settings/security`
 * (`crates/server/src/auth.rs`'s `identity_link_oidc_callback`), so this
 * route's path is not a free choice.
 *
 * Google's row (below the OIDC `providers()` list) is wired separately —
 * unlike OIDC, Google's credential arrives synchronously from the GSI SDK
 * already loaded on the page (no redirect/callback round trip), and it links
 * via `core_systemuser.google_sub` directly rather than `core_user_identity`,
 * so its "already linked" state comes from `identity_links()`'s synthetic
 * `provider_key: "google"` entry instead of the OIDC provider directory.
 *
 * D-510 (attome-auth 2.1d): linking and API-key creation need a fresh step-up.
 * OIDC linking starts with a browser navigation, so `link` checks the
 * elevation read endpoint first and prompts when needed; Google linking and
 * API-key creation go through `StepUpService.run`. A federated step-up returns
 * here with `?step_up=<operation>` (or `?step_up_error=1`), and an unelevated
 * link start with `?reauth_required=identity_link`. `reauth_required` is never
 * treated as a signed-out session.
 *
 * Not build/browser-verified in this session — see D-170 in DECISIONS.md
 * (no Angular tooling available; Node/npm in this sandbox are too old for
 * `ng build`/`ng serve` per this repo's own memory notes).
 */
@Component({
  selector:   'app-security-settings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <div class="page">
      <div class="card">
        <h2>Sign-in methods</h2>
        <p class="subtitle">Connect an external identity provider to sign in without a password.</p>

        @if (banner(); as b) {
          <p [class]="'banner banner-' + b.kind">{{ b.message }}</p>
        }

        @if (loading()) {
          <p class="state-msg">Loading your sign-in methods…</p>
        } @else {
          @if (error()) {
            <p class="banner banner-error">{{ error() }}</p>
          }

          @if (providers().length === 0 && !hasGoogleAuth()) {
            <p class="state-msg">No external identity providers are configured for this deployment.</p>
          } @else {
            <ul class="provider-list">
              @for (p of providers(); track p.key + p.protocol) {
                <li class="provider-row">
                  <div class="provider-info">
                    <span class="provider-name">{{ p.displayName }}</span>
                    <span class="provider-protocol">{{ p.protocol.toUpperCase() }}</span>
                  </div>
                  @if (p.linkedEmail; as email) {
                    <span class="badge badge-linked">Linked · {{ email }}</span>
                  } @else {
                    <button type="button" class="btn-secondary" (click)="link(p)">Link</button>
                  }
                </li>
              }

              @if (hasGoogleAuth()) {
                <li class="provider-row">
                  <div class="provider-info">
                    <span class="provider-name">Google</span>
                    <span class="provider-protocol">GOOGLE</span>
                  </div>
                  @if (googleLinkedEmail(); as email) {
                    <span class="badge badge-linked">Linked · {{ email }}</span>
                  } @else {
                    <div class="google-btn-wrapper" [id]="googleBtnId"></div>
                  }
                </li>
              }
            </ul>
          }
        }
      </div>

      <section class="card" aria-labelledby="api-keys-title">
        <h2 id="api-keys-title">{{ 'securitySettings.apiKey.title' | translate }}</h2>
        <p class="subtitle">{{ 'securitySettings.apiKey.subtitle' | translate }}</p>

        @if (createdKey(); as key) {
          <div class="secret-box" role="status">
            <p class="secret-title">{{ 'securitySettings.apiKey.createdTitle' | translate }}</p>
            <p class="secret-warning">{{ 'securitySettings.apiKey.copyNow' | translate }}</p>
            <dl class="secret-values">
              <dt>{{ 'securitySettings.apiKey.publicKeyLabel' | translate }}</dt>
              <dd><code>{{ key.public_key }}</code></dd>
              <dt>{{ 'securitySettings.apiKey.secretLabel' | translate }}</dt>
              <dd><code class="secret-value">{{ key.secret }}</code></dd>
            </dl>
            <button type="button" class="btn-secondary" (click)="dismissCreatedKey()">
              {{ 'securitySettings.apiKey.dismiss' | translate }}
            </button>
          </div>
        }

        <form class="api-key-form" (submit)="$event.preventDefault(); createApiKey()">
          <label class="field-label" for="api-key-name">{{ 'securitySettings.apiKey.nameLabel' | translate }}</label>
          <input
            id="api-key-name"
            class="field-input"
            type="text"
            maxlength="200"
            autocomplete="off"
            [value]="apiKeyName()"
            [disabled]="apiKeyBusy()"
            (input)="apiKeyName.set(inputValue($event))"
          />
          <label class="field-label" for="api-key-expiry">{{ 'securitySettings.apiKey.expiryLabel' | translate }}</label>
          <input
            id="api-key-expiry"
            class="field-input"
            type="number"
            min="1"
            step="1"
            inputmode="numeric"
            [value]="apiKeyExpiry()"
            [disabled]="apiKeyBusy()"
            (input)="apiKeyExpiry.set(inputValue($event))"
          />
          @if (apiKeyError(); as message) {
            <p class="banner banner-error" role="alert">{{ message }}</p>
          }
          <button type="submit" class="btn-primary" [disabled]="apiKeyBusy()">
            {{ (apiKeyBusy() ? 'securitySettings.apiKey.creating' : 'securitySettings.apiKey.create') | translate }}
          </button>
        </form>
      </section>
    </div>
  `,
  styles: [`
    .page {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 24px;
      background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
      padding: 48px 24px;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 560px;
      box-sizing: border-box;
      box-shadow: 0 20px 60px rgba(0,0,0,0.2);
    }
    h2 { font-size: 20px; font-weight: 700; color: #111827; margin: 0 0 4px; }
    .subtitle { color: #6b7280; font-size: 14px; margin: 0 0 20px; }
    .state-msg { color: #6b7280; font-size: 14px; }
    .banner {
      font-size: 13px;
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 16px;
    }
    .banner-success { color: #166534; background: #f0fdf4; border: 1px solid #bbf7d0; }
    .banner-conflict, .banner-error { color: #dc2626; background: #fef2f2; border: 1px solid #fecaca; }
    .provider-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
    .provider-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 12px 16px;
    }
    .provider-info { display: flex; flex-direction: column; gap: 2px; }
    .provider-name { font-size: 14px; font-weight: 600; color: #111827; }
    .provider-protocol { font-size: 11px; letter-spacing: 0.04em; color: #9ca3af; }
    .badge-linked {
      font-size: 12px;
      font-weight: 500;
      color: #166534;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 999px;
      padding: 4px 10px;
    }
    .btn-secondary {
      padding: 8px 16px;
      border-radius: 6px;
      border: 1px solid #d1d5db;
      background: transparent;
      color: #374151;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
    }
    .btn-secondary:hover { background: #f3f4f6; }
    .btn-primary {
      align-self: flex-start;
      padding: 8px 16px;
      border-radius: 6px;
      border: 1px solid #4f46e5;
      background: #4f46e5;
      color: #fff;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
    }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .google-btn-wrapper { min-width: 200px; min-height: 40px; }
    .api-key-form { display: flex; flex-direction: column; gap: 6px; }
    .field-label { font-size: 13px; font-weight: 500; color: #374151; margin-top: 6px; }
    .field-input {
      padding: 8px 12px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      font-size: 14px;
    }
    .secret-box {
      border: 1px solid #fcd34d;
      background: #fffbeb;
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 16px;
    }
    .secret-title { font-size: 14px; font-weight: 600; color: #111827; margin: 0 0 4px; }
    .secret-warning { font-size: 13px; color: #92400e; margin: 0 0 10px; }
    .secret-values { margin: 0 0 12px; font-size: 13px; }
    .secret-values dt { color: #6b7280; margin-top: 6px; }
    .secret-values dd { margin: 2px 0 0; word-break: break-all; }
    .secret-value { user-select: all; }
  `],
})
export class SecuritySettingsComponent implements OnInit, AfterViewInit {
  private readonly auth   = inject(AuthService);
  private readonly route  = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly lang   = inject(LangService);
  private readonly stepUp = inject(StepUpService);

  readonly loading  = signal(true);
  readonly error    = signal<string | null>(null);
  readonly banner   = signal<Banner>(null);
  readonly providers = signal<ProviderRow[]>([]);

  readonly googleBtnId       = 'attome-security-google-btn';
  readonly googleClientId    = signal<string | null>(null);
  readonly googleLinkedEmail = signal<string | null>(null);
  readonly hasGoogleAuth     = computed(() => this.googleClientId() !== null);

  // Self-service API-key creation (2.1d, user decision). `createdKey` holds the
  // one-time secret only until the user dismisses it; nothing persists it.
  readonly apiKeyName   = signal('');
  readonly apiKeyExpiry = signal('');
  readonly apiKeyBusy   = signal(false);
  readonly apiKeyError  = signal<string | null>(null);
  readonly createdKey   = signal<ApiKeyCreated | null>(null);

  private googleScriptLoaded = false;

  ngOnInit(): void {
    this.readRedirectBanner();
    this.loadProviders();
  }

  ngAfterViewInit(): void {
    this.loadGoogleConfig();
  }

  /**
   * The linking callback (`crates/server/src/auth.rs`) redirects back here with
   * exactly one of these three query params — same pattern as
   * `LoginPageComponent`'s `oidc_error` handling
   * (`@attome/base`'s `login-page.component.ts`). D-510 adds three more: the
   * federated step-up outcome (`step_up=<operation>`, `step_up_error=1`) and
   * the unelevated link-start marker (`reauth_required=identity_link`). Every
   * one of them is stripped so a refresh never replays it.
   */
  private readRedirectBanner(): void {
    const params = this.route.snapshot.queryParamMap;
    const stepUpOperation = params.get('step_up');
    let handled = true;
    if (params.has('identity_linked')) {
      this.banner.set({ kind: 'success', message: 'Identity linked. You can now sign in with this provider.' });
    } else if (params.has('identity_link_conflict')) {
      this.banner.set({ kind: 'conflict', message: 'That identity is already linked to a different account.' });
    } else if (params.has('identity_link_error')) {
      this.banner.set({ kind: 'error', message: 'Linking failed. Please try again.' });
    } else if (params.has('step_up_error')) {
      // Nothing was performed, and nothing stored is re-offered later.
      this.stepUp.consumePendingReturn();
      this.showError('securitySettings.stepUpError');
    } else if (stepUpOperation) {
      this.resumeAfterStepUp(stepUpOperation);
    } else if (params.get('reauth_required') === 'identity_link') {
      this.promptIdentityLinkStepUp();
    } else {
      handled = false;
    }
    if (handled) {
      this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
    }
  }

  /**
   * Back from a federated step-up. The query param is only a hint: elevation
   * is confirmed through the read endpoint before anything continues. A
   * pending link resumes its navigation (a GET the server guards again); a
   * pending API-key creation is only re-offered, never replayed as a POST.
   */
  private resumeAfterStepUp(operation: string): void {
    const stored = this.stepUp.consumePendingReturn();
    const pending = stored?.operation === operation ? stored : null;

    this.stepUp.status(operation).subscribe({
      next: status => {
        if (!status.elevated) {
          this.showError('securitySettings.stepUpExpired');
          return;
        }
        if (pending && pending.returnUrl.split(/[?#]/)[0] !== SETTINGS_PATH) {
          this.router.navigateByUrl(pending.returnUrl);
          return;
        }
        const action = pending?.pendingAction;
        if (operation === 'identity_link' && action?.kind === 'link') {
          const protocol = action['protocol'];
          const key = action['key'];
          if (protocol === 'oidc' && typeof key === 'string' && key.length > 0) {
            this.navigateToLink(key);
            return;
          }
        }
        if (operation === 'api_key_create' && action?.kind === 'api_key_create') {
          if (typeof action['name'] === 'string') this.apiKeyName.set(action['name']);
          if (typeof action['expiresInDays'] === 'number') this.apiKeyExpiry.set(String(action['expiresInDays']));
          this.showSuccess('securitySettings.apiKey.ready');
          return;
        }
        this.showSuccess('securitySettings.stepUpComplete');
      },
      error: () => this.showError('securitySettings.stepUpCheckFailed'),
    });
  }

  /** The link start redirected here because the session was not elevated. */
  private promptIdentityLinkStepUp(): void {
    this.stepUp.status('identity_link').subscribe({
      next: status => {
        if (status.elevated) {
          this.showSuccess('securitySettings.stepUpComplete');
          return;
        }
        this.stepUp.elevate('identity_link', status.acceptable_factors, { returnUrl: SETTINGS_PATH })
          .then(verified => { if (verified) this.showSuccess('securitySettings.stepUpComplete'); });
      },
      error: () => this.showError('securitySettings.stepUpCheckFailed'),
    });
  }

  private loadProviders(): void {
    this.loading.set(true);
    this.error.set(null);

    let oidc: OidcProviderInfo[] = [];
    let links: IdentityLinkInfo[] = [];
    let pending = 2;
    const done = () => {
      pending -= 1;
      if (pending > 0) return;
      const linkedByKey = new Map(links.map(l => [l.provider_key, l.email]));
      const rows: ProviderRow[] = oidc.map(p => ({
        key: p.key, displayName: p.display_name, protocol: 'oidc' as const, linkedEmail: linkedByKey.get(p.key) ?? null,
      }));
      this.providers.set(rows);
      this.googleLinkedEmail.set(linkedByKey.get('google') ?? null);
      this.loading.set(false);
    };

    // The OIDC provider directory fails soft to [] (same posture as
    // LoginPageComponent — a deployment may have no OIDC provider configured).
    this.auth.getOidcProviders().subscribe({
      next: res => { oidc = res; done(); },
      error: () => done(),
    });
    // Unlike the provider directories, a failure here is a real error (the
    // caller is authenticated — a 401 here would mean the session expired
    // mid-page-load) — surfaced, not swallowed.
    this.auth.getIdentityLinks().subscribe({
      next: res => { links = res; done(); },
      error: (err: ApiError) => { this.error.set(this.lang.errorText(err)); done(); },
    });
  }

  /**
   * Checks elevation before the browser navigation: the start route would
   * otherwise bounce straight back with `reauth_required`. Navigates at once
   * when elevated, and after a successful step-up otherwise. A federated
   * step-up leaves the page, so the link is stored as the pending action.
   */
  link(p: ProviderRow): void {
    this.stepUp.status('identity_link').subscribe({
      next: status => {
        if (status.elevated) {
          this.navigateToLink(p.key);
          return;
        }
        this.stepUp.elevate('identity_link', status.acceptable_factors, {
          returnUrl:     SETTINGS_PATH,
          pendingAction: { kind: 'link', protocol: p.protocol, key: p.key },
        }).then(verified => { if (verified) this.navigateToLink(p.key); });
      },
      error: () => this.showError('securitySettings.stepUpCheckFailed'),
    });
  }

  private navigateToLink(key: string): void {
    this.auth.linkOidcIdentity(key);
  }

  // ── API keys (D-510 `api_key_create`) ──────────────────────────────────────

  createApiKey(): void {
    if (this.apiKeyBusy()) return;
    const name = this.apiKeyName().trim();
    if (!name) {
      this.apiKeyError.set(this.lang.translate('securitySettings.apiKey.nameRequired'));
      return;
    }
    const expiryText = this.apiKeyExpiry().trim();
    let expiresInDays: number | null = null;
    if (expiryText) {
      const days = Number(expiryText);
      if (!Number.isInteger(days) || days <= 0) {
        this.apiKeyError.set(this.lang.translate('securitySettings.apiKey.expiryInvalid'));
        return;
      }
      expiresInDays = days;
    }

    const body: CreateApiKeyRequest = expiresInDays === null ? { name } : { name, expires_in_days: expiresInDays };
    const pendingAction: StepUpPendingAction = { kind: 'api_key_create', name, expiresInDays };
    this.apiKeyBusy.set(true);
    this.apiKeyError.set(null);
    this.createdKey.set(null);

    this.stepUp.run('api_key_create', () => this.auth.createApiKey(body), { returnUrl: SETTINGS_PATH, pendingAction })
      .subscribe({
        next: created => {
          this.apiKeyBusy.set(false);
          this.createdKey.set(created);
          this.apiKeyName.set('');
          this.apiKeyExpiry.set('');
        },
        error: (err: ApiError) => {
          this.apiKeyBusy.set(false);
          // A cancelled or failed step-up surfaces as the original
          // reauth_required error: the key was simply not created.
          this.apiKeyError.set(
            err.kind === 'reauth_required' || !err.message
              ? this.lang.translate('securitySettings.apiKey.notCreated')
              : err.message,
          );
        },
      });
  }

  dismissCreatedKey(): void {
    this.createdKey.set(null);
  }

  inputValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  private showSuccess(key: string): void {
    this.banner.set({ kind: 'success', message: this.lang.translate(key) });
  }

  private showError(key: string): void {
    this.banner.set({ kind: 'error', message: this.lang.translate(key) });
  }

  // ── Google (P-federation-linking-policy §4.3(a) extended) ──────────────────

  private loadGoogleConfig(): void {
    this.auth.getGoogleConfig().subscribe({
      next: cfg => {
        this.googleClientId.set(cfg.client_id);
        if (cfg.client_id) this.loadGoogleScript();
      },
      // Same "just render no button" handling as an OIDC directory fetch failure.
      error: () => this.googleClientId.set(null),
    });
  }

  private loadGoogleScript(): void {
    if (typeof google !== 'undefined') {
      this.googleScriptLoaded = true;
      // Cached script path: runs synchronously, ahead of Angular flushing the
      // @if-gated button div into the DOM — defer a tick, same reasoning as
      // LoginPageComponent's identical comment.
      setTimeout(() => this.initGoogle(), 0);
      return;
    }
    const s = document.createElement('script');
    s.src   = 'https://accounts.google.com/gsi/client';
    s.async = true;
    s.defer = true;
    s.onload  = () => { this.googleScriptLoaded = true; this.initGoogle(); };
    s.onerror = () => this.error.set('Failed to load Google Sign-In. Please refresh.');
    document.head.appendChild(s);
  }

  private initGoogle(): void {
    const clientId = this.googleClientId();
    if (typeof google === 'undefined' || !clientId) return;
    // Registers this component's link callback as the active one — see
    // google-identity.ts's doc comment for why this is safe even though
    // login-page/auth-modal already called this once with a login callback.
    initGoogleIdentityOnce({
      client_id:             clientId,
      callback:              (r: { credential: string }) => this.handleGoogleCredential(r),
      auto_select:           false,
      cancel_on_tap_outside: false,
    });
    this.renderGoogleButton();
  }

  private renderGoogleButton(): void {
    if (!this.googleScriptLoaded || typeof google === 'undefined') return;
    const el = document.getElementById(this.googleBtnId);
    if (!el) return;
    el.innerHTML = '';
    google.accounts.id.renderButton(el, {
      theme:          'outline',
      size:           'large',
      width:          el.offsetWidth || 240,
      type:           'standard',
      shape:          'rectangular',
      text:           'signin_with',
      logo_alignment: 'left',
    });
  }

  /**
   * Google's credential cannot survive a page load, so a federated step-up
   * here only returns with a "you can continue" banner; the user signs in with
   * Google again. A local step-up retries the link once.
   */
  private handleGoogleCredential(r: { credential: string }): void {
    if (!r.credential) return;
    this.stepUp.run('identity_link', () => this.auth.linkGoogleIdentity(r.credential), { returnUrl: SETTINGS_PATH })
      .subscribe({
        next: () => {
          this.banner.set({ kind: 'success', message: 'Google linked. You can now sign in with it.' });
          this.loadProviders();
        },
        error: (err: ApiError) => {
          if (err.kind === 'reauth_required') {
            this.showError('securitySettings.stepUpError');
          } else {
            // NGB-2.3: translated text only; the server's English prose never reaches the banner.
            const kind = err.status === 409 ? 'conflict' : 'error';
            const key = kind === 'conflict' ? 'securitySettings.googleLinkConflict' : 'securitySettings.googleLinkError';
            this.banner.set({ kind, message: this.lang.translate(key) });
          }
          setTimeout(() => this.renderGoogleButton(), 0);
        },
      });
  }
}
