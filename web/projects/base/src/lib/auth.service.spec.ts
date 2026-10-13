import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthService } from './auth.service';
import { ATTOME_CONFIG } from './config';
import type { ApiError } from './types';

describe('AuthService', () => {
  let httpMock: HttpTestingController;
  let navigateSpy: ReturnType<typeof vi.fn>;

  function setUp(config: { portalKey?: string; loginRoute?: string } = {}) {
    navigateSpy = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865', ...config } },
        { provide: Router, useValue: { navigate: navigateSpy } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    return TestBed.inject(AuthService);
  }

  afterEach(() => {
    httpMock?.verify();
  });

  it('starts logged out with no session and no API call', () => {
    const auth = setUp();
    expect(auth.isLoggedIn()).toBe(false);
    expect(auth.userId()).toBeNull();
  });

  // ── sessionReady (non-blocking bootstrap; D-129's wait moved to authGuard) ─

  it('sessionReady() issues exactly one GET /auth/session across many callers', () => {
    const auth = setUp();
    auth.sessionReady().subscribe();
    auth.sessionReady().subscribe();
    // One request only — the app initializer and every guard share it.
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/session')
      .flush({ user_id: 'user-boot', email: 'boot@example.com' });

    let late: unknown = 'not-set';
    auth.sessionReady().subscribe(res => { late = res; });
    // A caller arriving after it resolved replays, rather than re-requesting.
    httpMock.expectNone('http://localhost:7865/api/v1/auth/session');
    expect(late).toEqual({ userId: 'user-boot', loggedIn: true });
  });

  it('sessionReady() does not emit until the server has answered', () => {
    const auth = setUp();
    let emitted = false;
    auth.sessionReady().subscribe(() => { emitted = true; });

    const req = httpMock.expectOne('http://localhost:7865/api/v1/auth/session');
    // The guard must not be able to decide "logged out" on an in-flight
    // bootstrap — that is exactly the redirect-to-login bug a non-blocking
    // app initializer would otherwise introduce for a logged-in deep link.
    expect(emitted).toBe(false);
    expect(auth.isLoggedIn()).toBe(false);

    req.flush({ user_id: 'user-boot', email: 'boot@example.com' });
    expect(emitted).toBe(true);
    expect(auth.isLoggedIn()).toBe(true);
  });

  it('sessionReady() emits (logged out) rather than erroring when the backend is unreachable', () => {
    const auth = setUp();
    let resolved: unknown = 'not-set';
    let errored = false;
    auth.sessionReady().subscribe({
      next: res => { resolved = res; },
      error: () => { errored = true; },
    });
    // status 0 — connection refused, i.e. the backend is not running at all.
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/session')
      .error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });

    expect(errored).toBe(false);
    expect(resolved).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
  });

  // ── bootstrapSession (P-session-refresh-hardening, D-129) ──────────────────

  it('bootstrapSession() sets the session from a successful GET /auth/session', () => {
    const auth = setUp();
    let resolved: unknown;
    auth.bootstrapSession().subscribe(res => { resolved = res; });
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/session')
      .flush({ user_id: 'user-boot', email: 'boot@example.com' });

    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-boot');
    expect(resolved).toEqual({ userId: 'user-boot', loggedIn: true });
  });

  it('bootstrapSession() resolves null and stays logged out on a 401 (no live session cookie)', () => {
    const auth = setUp();
    let resolved: unknown = 'not-set';
    let errored = false;
    auth.bootstrapSession().subscribe({
      next: res => { resolved = res; },
      error: () => { errored = true; },
    });
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/session')
      .flush({ error: 'unauthorized', message: 'no session' }, { status: 401, statusText: 'Unauthorized' });

    expect(errored).toBe(false);
    expect(resolved).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
    expect(auth.userId()).toBeNull();
  });

  // ── refreshSession (P-session-refresh-hardening, D-129) ────────────────────

  it('refreshSession() sets the session on a successful POST /auth/refresh', () => {
    const auth = setUp();
    auth.refreshSession().subscribe();
    httpMock.expectOne('http://localhost:7865/api/v1/auth/refresh').flush({ user_id: 'user-refreshed' });

    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-refreshed');
  });

  // ── Existing credential flows ───────────────────────────────────────────────

  it('login() sets the session signal', () => {
    const auth = setUp();
    auth.login({ email: 'a@b.com', password: 'x' }).subscribe();
    httpMock.expectOne('http://localhost:7865/api/v1/auth/login').flush({ user_id: 'user-789' });

    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-789');
  });

  it('login() resolves an MFA challenge without setting a session', () => {
    const auth = setUp();
    auth.login({ email: 'a@b.com', password: 'x' }).subscribe();
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/login')
      .flush({ mfa: 'required', pending_token: 'tok-abc' });

    expect(auth.isLoggedIn()).toBe(false);
  });

  it('verifyMfa() sets the session on a successful TOTP check', () => {
    const auth = setUp();
    auth.verifyMfa({ pending_token: 'tok-abc', code: '123456' }).subscribe();
    httpMock.expectOne('http://localhost:7865/api/v1/auth/mfa/verify').flush({ user_id: 'user-mfa' });

    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-mfa');
  });

  it('confirmMfaEnrollment() sets the session and returns recovery codes', () => {
    const auth = setUp();
    auth.confirmMfaEnrollment({ pending_token: 'tok-abc', code: '123456' }).subscribe();
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/mfa/pending-confirm')
      .flush({ user_id: 'user-new', recovery_codes: ['AAAA-BBBB'] });

    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-new');
  });

  it('logout() clears the session and navigates to the default login route', () => {
    const auth = setUp();
    auth.restoreSession('user-1');

    auth.logout().subscribe();
    httpMock.expectOne('http://localhost:7865/api/v1/auth/logout').flush(null);

    expect(auth.isLoggedIn()).toBe(false);
    expect(auth.userId()).toBeNull();
    expect(navigateSpy).toHaveBeenCalledWith(['/login']);
  });

  it('logout() navigates to a configured loginRoute', () => {
    const auth = setUp({ loginRoute: '/signin' });
    auth.restoreSession('user-1');

    auth.logout().subscribe();
    httpMock.expectOne('http://localhost:7865/api/v1/auth/logout').flush(null);

    expect(navigateSpy).toHaveBeenCalledWith(['/signin']);
  });

  // NGB-F1 — a failed sign-out must never look like a successful one: the
  // session stays live, the router does not move, and the caller gets the
  // sanitised ApiError so it can show "sign-out failed; you are still signed
  // in" and offer a retry.
  it('logout() failure keeps the session and rethrows the ApiError', async () => {
    const auth = setUp();
    auth.restoreSession('user-1');

    const settled = firstValueFrom(auth.logout()).catch((e: ApiError) => e);
    httpMock
      .expectOne('http://localhost:7865/api/v1/auth/logout')
      .flush({ error: 'internal_error', message: 'boom' }, { status: 500, statusText: 'Error' });

    const error = await settled;
    expect(error).toMatchObject({ status: 500, kind: 'internal' });
    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.userId()).toBe('user-1');
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('clearSession() clears state without an API call', () => {
    const auth = setUp();
    auth.restoreSession('user-1');
    auth.clearSession();
    expect(auth.isLoggedIn()).toBe(false);
  });
});
