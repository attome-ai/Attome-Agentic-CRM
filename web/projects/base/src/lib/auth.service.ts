import { computed, inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, catchError, map, of, shareReplay, tap } from 'rxjs';
import { ApiService } from './api.service';
import { ConditionalCache } from './conditional-cache';
import { ATTOME_CONFIG } from './config';
import {
  Ack,
  ApiKeyCreated,
  AuthResponse,
  CreateApiKeyRequest,
  GoogleAuthRequest,
  GoogleConfigInfo,
  IdentityLinkInfo,
  LoginRequest,
  MfaChallenge,
  MfaEnrollResponse,
  MfaPendingConfirmResponse,
  MfaPendingEnrollBody,
  MfaRecoveryCodes,
  MfaStatus,
  MfaVerifyBody,
  OidcProviderInfo,
  RegisterRequest,
  RegistrationConfigInfo,
  ResetConfirmBody,
  ResetRequestBody,
  Session,
  SessionInfo,
  VerifyEmailConfirmBody,
  isMfaChallenge,
} from './types';

/** Q20-T3: a proof-of-work challenge (`GET /api/v1/auth/challenge`). */
export interface PowChallenge {
  challenge:  string;
  nonce:      string;
  difficulty: number;
  /** Unix seconds. */
  expires_at: number;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api    = inject(ApiService);
  private readonly conditional = inject(ConditionalCache);
  private readonly router = inject(Router);
  private readonly config = inject(ATTOME_CONFIG);

  // ── Signals ───────────────────────────────────────────────────────────────

  // P-session-refresh-hardening (D-129): in-memory only, resolved from the
  // server via `bootstrapSession()` — never a client-side marker (localStorage
  // or otherwise). Starts `null` (logged out) until bootstrap resolves.
  private readonly _session = signal<Session | null>(null);

  readonly session    = this._session.asReadonly();
  readonly isLoggedIn = computed(() => this._session()?.loggedIn === true);
  readonly userId     = computed(() => this._session()?.userId ?? null);

  // The single session bootstrap of this page load, shared by `provide.ts`'s
  // app initializer (which starts it) and `authGuard` (which awaits it), so
  // there is exactly one `GET /auth/session` no matter which runs first.
  private sessionBootstrap: Observable<Session | null> | null = null;

  // ── Methods ───────────────────────────────────────────────────────────────

  register(req: RegisterRequest): Observable<AuthResponse> {
    return this.api.post<AuthResponse>('/api/v1/auth/register', req).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /**
   * P2.8 step 7 (D-069) — a correct password no longer always mints a
   * session: check `isMfaChallenge(res)` before assuming `res.user_id`. On a
   * challenge, no cookies were set — the caller must continue via
   * `verifyMfa`/`verifyMfaRecovery` or `startMfaEnrollment`/`confirmMfaEnrollment`.
   */
  login(req: LoginRequest): Observable<AuthResponse | MfaChallenge> {
    return this.api.post<AuthResponse | MfaChallenge>('/api/v1/auth/login', req).pipe(
      tap(res => { if (!isMfaChallenge(res)) this.setSession(res.user_id); }),
    );
  }

  /** Completes an `MfaChallenge` (`mfa: 'required'`) with a live TOTP code. */
  verifyMfa(req: MfaVerifyBody): Observable<AuthResponse> {
    return this.api.post<AuthResponse>('/api/v1/auth/mfa/verify', req).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /** Same as `verifyMfa` but via a single-use recovery code. */
  verifyMfaRecovery(req: MfaVerifyBody): Observable<AuthResponse> {
    return this.api.post<AuthResponse>('/api/v1/auth/mfa/verify-recovery', req).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /** Completes an `MfaChallenge` (`mfa: 'enrollment_required'`) — forced first-time enrollment. */
  startMfaEnrollment(req: MfaPendingEnrollBody): Observable<MfaEnrollResponse> {
    return this.api.post<MfaEnrollResponse>('/api/v1/auth/mfa/pending-enroll', req);
  }

  /** Confirms forced enrollment with the first live TOTP code — issues the session. */
  confirmMfaEnrollment(req: MfaVerifyBody): Observable<MfaPendingConfirmResponse> {
    return this.api.post<MfaPendingConfirmResponse>('/api/v1/auth/mfa/pending-confirm', req).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /** Self-service (session-gated): whether the current account has MFA enrolled. */
  getMfaStatus(): Observable<MfaStatus> {
    return this.api.get<MfaStatus>('/api/v1/auth/mfa/status');
  }

  /** Self-service: starts (or restarts) enrollment — returns the QR/secret to render. */
  enrollMfa(): Observable<MfaEnrollResponse> {
    return this.api.post<MfaEnrollResponse>('/api/v1/auth/mfa/enroll', {});
  }

  /** Self-service: confirms enrollment with the first live code — returns the one-time recovery-code batch. */
  confirmMfa(code: string): Observable<MfaRecoveryCodes> {
    return this.api.post<MfaRecoveryCodes>('/api/v1/auth/mfa/confirm', { code });
  }

  /** Self-service: turns MFA off — requires a live TOTP or recovery code as proof of possession. */
  disableMfa(code: string): Observable<Ack> {
    return this.api.post<Ack>('/api/v1/auth/mfa/disable', { code });
  }

  /** Self-service: invalidates the whole recovery-code batch and issues a fresh one. */
  regenerateMfaRecoveryCodes(code: string): Observable<MfaRecoveryCodes> {
    return this.api.post<MfaRecoveryCodes>('/api/v1/auth/mfa/recovery-codes/regenerate', { code });
  }

  loginWithGoogle(req: GoogleAuthRequest): Observable<AuthResponse> {
    return this.api.post<AuthResponse>('/api/v1/auth/google', req).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /** P-frontend-baseline step 5 — the Google Sign-In button renders only if `client_id` is non-null; no client id baked into config. */
  getGoogleConfig(): Observable<GoogleConfigInfo> {
    return this.api.get<GoogleConfigInfo>('/api/v1/auth/google/config');
  }

  /** P2.8 step 5 — provider buttons render from this list; no client id baked into config. */
  getOidcProviders(): Observable<OidcProviderInfo[]> {
    return this.api.get<OidcProviderInfo[]>('/api/v1/auth/oidc/providers');
  }

  /** P-registration-gating (D-128) — the register page/login page's sign-up link consult this to decide whether to render at all. */
  getRegistrationConfig(): Observable<RegistrationConfigInfo> {
    return this.api.get<RegistrationConfigInfo>('/api/v1/auth/register/config');
  }

  /**
   * Q20-T3: a proof-of-work challenge, when that is the challenge in force
   * (a 404 otherwise). Solve it and send `{challenge}:{answer}` as the
   * sign-in's `captcha_token`.
   */
  getPowChallenge(): Observable<PowChallenge> {
    return this.api.get<PowChallenge>('/api/v1/auth/challenge');
  }

  /**
   * Full top-level navigation to the IdP, not an XHR — the authorization-code
   * flow is a browser redirect round-trip; the callback sets session cookies
   * and redirects back here, so there is nothing for this method to return.
   */
  loginWithOidc(providerKey: string): void {
    window.location.href = `${this.config.apiUrl}/api/v1/auth/oidc/${encodeURIComponent(providerKey)}/login`;
  }

  /** P-federation-linking-policy §4.3(a) — self-service: which providers are already linked to the logged-in account. */
  getIdentityLinks(): Observable<IdentityLinkInfo[]> {
    return this.api.get<IdentityLinkInfo[]>('/api/v1/auth/identity-links');
  }

  /**
   * P-federation-linking-policy §4.3(a) — starts the session-gated linking
   * flow for an OIDC provider. Full top-level navigation, same reasoning as
   * `loginWithOidc`: this is a protected route (unlike `/oidc/{provider}/login`),
   * so it only works while a session cookie is already attached, and the
   * callback lands back on `/settings/security` with a `identity_linked=1`/
   * `identity_link_conflict=1`/`identity_link_error=1` query param.
   */
  linkOidcIdentity(providerKey: string): void {
    window.location.href = `${this.config.apiUrl}/api/v1/auth/identity-link/oidc/${encodeURIComponent(providerKey)}`;
  }

  /**
   * P-federation-linking-policy §4.3(a) extended to Google — unlike
   * `linkOidcIdentity` (full-page redirect through an IdP),
   * Google's credential arrives synchronously from the GSI SDK already
   * running on this page, so this is a direct POST, not a navigation. Session-
   * gated (`/api/v1/auth/identity-link/google`, not the `/api/v1/auth/google`
   * login endpoint) — links to the caller's own already-authenticated
   * account; the backend rejects a credential whose email doesn't match it.
   */
  linkGoogleIdentity(credential: string): Observable<void> {
    return this.api.post<void>('/api/v1/auth/identity-link/google', { credential });
  }

  /**
   * Self-service API-key creation for the logged-in account. Guarded by a
   * step-up (D-510, operation `api_key_create`): without one it fails with
   * `kind: 'reauth_required'`, so call it through `StepUpService.run`. The
   * response's `secret` is shown once and can never be read again.
   */
  createApiKey(req: CreateApiKeyRequest): Observable<ApiKeyCreated> {
    return this.api.post<ApiKeyCreated>('/api/v1/auth/api-keys', req);
  }

  /**
   * NGB-F1. The local session is cleared and the redirect happens **only**
   * once the server has confirmed the cookies are gone — a 500, a 401 or a
   * dropped connection leaves the caller signed in and rethrows the sanitised
   * `ApiError` untouched, so the caller can say "sign-out failed; you are
   * still signed in" and offer a retry. Never swallow it: on a shared machine
   * a silently failed sign-out walks away with a live session.
   */
  logout(): Observable<void> {
    return this.api.post<void>('/api/v1/auth/logout', {}).pipe(
      tap(() => {
        this.clearSession();
        this.router.navigate([this.config.loginRoute ?? '/login']);
      }),
    );
  }

  /**
   * Idempotent, shared handle on this page load's one session bootstrap.
   * The first caller starts `GET /api/v1/auth/session`; every later caller
   * gets the same result replayed (`shareReplay(1)`) — including after it
   * has already completed, so a guard running long after bootstrap resolved
   * emits immediately instead of issuing a second round trip.
   *
   * Read `isLoggedIn()`/`session()` after this emits rather than using the
   * emitted value: a login that happened *after* bootstrap has updated the
   * signals, but the replayed value is still bootstrap's original answer.
   */
  sessionReady(): Observable<Session | null> {
    this.sessionBootstrap ??= this.bootstrapSession().pipe(shareReplay(1));
    return this.sessionBootstrap;
  }

  /**
   * P-session-refresh-hardening (D-129) — the sole source of "am I logged
   * in" truth. Resolves the in-memory session from the server, never from a
   * client-side marker. A failure (no live session cookie) is an expected,
   * non-error outcome — resolves `null`, doesn't throw.
   *
   * Prefer `sessionReady()`, which de-duplicates this across the app
   * initializer and every guard. Call this directly only to force a fresh
   * re-read of server-side session state.
   */
  bootstrapSession(): Observable<Session | null> {
    return this.api.get<SessionInfo>('/api/v1/auth/session').pipe(
      map(res => {
        const session: Session = { userId: res.user_id, loggedIn: true };
        this._session.set(session);
        return session;
      }),
      catchError(() => {
        this._session.set(null);
        return of(null);
      }),
    );
  }

  /**
   * Rotates the refresh cookie and mints a new access token
   * (P-session-refresh-hardening, D-129). Called by `authInterceptor`'s
   * coordinated single-flight refresh on a 401 — feature code should never
   * call this directly.
   */
  refreshSession(): Observable<AuthResponse> {
    return this.api.post<AuthResponse>('/api/v1/auth/refresh', {}).pipe(
      tap(res => this.setSession(res.user_id)),
    );
  }

  /**
   * Sets the in-memory session directly without a round trip — e.g. a
   * component that already knows the user id from a response body it
   * handled itself. Rare: most flows should rely on `setSession` (internal,
   * via a `tap` on the relevant API call) or `bootstrapSession` instead.
   */
  restoreSession(userId: string): void {
    this.setSession(userId);
  }

  /**
   * Always resolves with `{ ok: true }` regardless of whether `email`
   * matched an account (backend is enumeration-safe — never branch UI
   * behavior on this beyond "request sent").
   */
  requestPasswordReset(req: ResetRequestBody): Observable<Ack> {
    return this.api.post<Ack>('/api/v1/auth/reset-request', req);
  }

  confirmPasswordReset(req: ResetConfirmBody): Observable<Ack> {
    return this.api.post<Ack>('/api/v1/auth/reset-confirm', req);
  }

  confirmEmailVerification(req: VerifyEmailConfirmBody): Observable<Ack> {
    return this.api.post<Ack>('/api/v1/auth/verify-email/confirm', req);
  }

  clearSession(): void {
    this._session.set(null);
    // AA7-T11: no remembered answer outlives the user it was fetched for.
    this.conditional.clear();
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private setSession(userId: string): void {
    this._session.set({ userId, loggedIn: true });
  }
}
