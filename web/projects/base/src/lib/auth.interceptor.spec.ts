import { TestBed } from '@angular/core/testing';
import { HttpClient, HttpErrorResponse, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { ATTOME_CONFIG } from './config';

const BASE = 'http://localhost:7865';

describe('authInterceptor (P-session-refresh-hardening, D-129)', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let navigateSpy: ReturnType<typeof vi.fn>;

  function setUp() {
    navigateSpy = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: BASE } },
        { provide: Router, useValue: { navigate: navigateSpy, url: '/current' } },
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
  }

  afterEach(() => {
    httpMock?.verify();
  });

  it('coordinates exactly one refresh for two concurrent 401s and retries both idempotent GETs', () => {
    setUp();
    const results: unknown[] = [];
    http.get(`${BASE}/api/v1/a`).subscribe(res => results.push(res));
    http.get(`${BASE}/api/v1/b`).subscribe(res => results.push(res));

    httpMock
      .expectOne(`${BASE}/api/v1/a`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    httpMock
      .expectOne(`${BASE}/api/v1/b`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    // Exactly one refresh call for both 401s — httpMock.expectOne() itself
    // asserts there is no more than one matching pending request.
    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });

    // Both original GETs are retried once the shared refresh resolves.
    httpMock.expectOne(`${BASE}/api/v1/a`).flush({ ok: 'a' });
    httpMock.expectOne(`${BASE}/api/v1/b`).flush({ ok: 'b' });

    expect(results).toEqual([{ ok: 'a' }, { ok: 'b' }]);
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('leaves a portal keyword path 401 to the page: no refresh, no navigation', () => {
    setUp();
    let error: unknown;
    http.get(`${BASE}/acme/api/v1/records/forum_thread`).subscribe({ error: err => { error = err; } });
    httpMock
      .expectOne(`${BASE}/acme/api/v1/records/forum_thread`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    httpMock.expectNone(`${BASE}/api/v1/auth/refresh`);
    expect((error as { status: number }).status).toBe(401);
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('does not auto-retry a non-idempotent POST after refresh — surfaces the original 401', () => {
    setUp();
    let error: unknown;
    http.post(`${BASE}/api/v1/items`, { name: 'x' }).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/items`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    // The refresh still runs (a later request may benefit from it) — only
    // the non-idempotent POST itself is not resubmitted automatically.
    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });

    expect(error).toBeTruthy();
    expect((error as { status: number }).status).toBe(401);
  });

  // NGB-2.5 / OD-4b — the server replays the stored response for the same
  // `x-idempotency-key`, so a keyed write is safe to repeat after a refresh;
  // an unkeyed one still is not (the test above).
  it('retries a keyed POST once after a refresh', () => {
    setUp();
    let result: unknown;
    http.post(`${BASE}/api/v1/items`, { name: 'x' }, { headers: { 'x-idempotency-key': 'k-1' } })
      .subscribe(res => { result = res; });

    httpMock
      .expectOne(`${BASE}/api/v1/items`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });

    const retried = httpMock.expectOne(`${BASE}/api/v1/items`);
    expect(retried.request.method).toBe('POST');
    expect(retried.request.headers.get('x-idempotency-key')).toBe('k-1');
    retried.flush({ ok: true });

    expect(result).toEqual({ ok: true });
  });

  it('clears the session and navigates to login when the refresh itself fails', () => {
    setUp();
    let error: unknown;
    http.get(`${BASE}/api/v1/a`).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/a`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/refresh`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect(error).toBeTruthy();
    expect(navigateSpy).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/current' } });
  });

  it('does not attempt a refresh for a 401 from a credential endpoint (login)', () => {
    setUp();
    let error: unknown;
    http.post(`${BASE}/api/v1/auth/login`, {}).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/login`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect(error).toBeTruthy();
    // httpMock.verify() in afterEach fails the test if a /auth/refresh call
    // was made here — this assertion is enforced by that, not inline.
  });

  // Regression test: bootstrapSession() previously could not recover from an
  // expired access cookie because every /api/v1/auth/* URL (including
  // /auth/session itself) was excluded from refresh-and-retry, so a valid
  // refresh session was reported as logged out on reload.
  it('refreshes and retries a 401 from /auth/session (bootstrapSession) — not a credential endpoint', () => {
    setUp();
    let result: unknown;
    http.get(`${BASE}/api/v1/auth/session`).subscribe(res => { result = res; });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/session`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(`${BASE}/api/v1/auth/session`).flush({ user_id: 'user-1' });

    expect(result).toEqual({ user_id: 'user-1' });
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  // Regression test: an anonymous visitor loading any public page (landing,
  // /login, /register, ...) triggers bootstrapSession() -> GET /auth/session
  // -> expected 401 (no session cookie) -> refresh attempt -> refresh 401s too
  // (no refresh cookie either, since they were never logged in). That used to
  // unconditionally force-navigate to `loginRoute`, hijacking every anonymous
  // page load into a redirect (e.g. always bouncing /login to /xrm/login).
  it('does not navigate when bootstrapSession\'s 401 survives a failed refresh (anonymous visitor)', () => {
    setUp();
    let error: unknown;
    http.get(`${BASE}/api/v1/auth/session`).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/session`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/refresh`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect(error).toBeTruthy();
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('refreshes and retries a 401 from a session-gated MFA self-service GET (mfa/status)', () => {
    setUp();
    let result: unknown;
    http.get(`${BASE}/api/v1/auth/mfa/status`).subscribe(res => { result = res; });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/mfa/status`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(`${BASE}/api/v1/auth/mfa/status`).flush({ enrolled: true });

    expect(result).toEqual({ enrolled: true });
  });

  it('still excludes /auth/mfa/verify (credential endpoint) from refresh-and-retry', () => {
    setUp();
    let error: unknown;
    http.post(`${BASE}/api/v1/auth/mfa/verify`, {}).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/mfa/verify`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect(error).toBeTruthy();
    // httpMock.verify() in afterEach fails the test if a /auth/refresh call was made here.
  });

  // D-510 rule 9: reauth_required is a step-up prompt, never an expired session.
  describe('reauth_required (D-510)', () => {
    const REAUTH = {
      error: 'reauth_required',
      message: 're-authentication is required for this operation',
      operation: 'api_key_create',
      acceptable_factors: ['password'],
    };

    it.each(['POST', 'GET'])('rethrows a reauth_required 401 on %s untouched: no refresh, no retry, no sign-out', method => {
      setUp();
      const auth = TestBed.inject(AuthService);
      auth.restoreSession('user-1');
      const clearSpy = vi.spyOn(auth, 'clearSession');
      const url = `${BASE}/api/v1/auth/api-keys`;
      let error: unknown;
      const req$ = method === 'POST' ? http.post(url, { name: 'k' }) : http.get(url);
      req$.subscribe({ error: err => { error = err; } });

      httpMock.expectOne(url).flush(REAUTH, { status: 401, statusText: 'Unauthorized' });

      expect(error).toBeInstanceOf(HttpErrorResponse);
      expect((error as HttpErrorResponse).status).toBe(401);
      expect((error as HttpErrorResponse).error).toEqual(REAUTH);
      expect(navigateSpy).not.toHaveBeenCalled();
      expect(clearSpy).not.toHaveBeenCalled();
      expect(auth.userId()).toBe('user-1');
      // httpMock.verify() in afterEach fails the test on any /auth/refresh or retry.
    });

    it('still refreshes a plain unauthorized 401 on the same route', () => {
      setUp();
      const url = `${BASE}/api/v1/auth/step-up/identity_link`;
      let result: unknown;
      http.get(url).subscribe(res => { result = res; });

      httpMock.expectOne(url).flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
      httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
      httpMock.expectOne(url).flush({ elevated: true });

      expect(result).toEqual({ elevated: true });
    });
  });

  it('passes through a non-401 error untouched, with no refresh attempt', () => {
    setUp();
    let error: unknown;
    http.get(`${BASE}/api/v1/a`).subscribe({
      error: err => { error = err; },
    });

    httpMock
      .expectOne(`${BASE}/api/v1/a`)
      .flush({ error: 'internal_error' }, { status: 500, statusText: 'Internal Server Error' });

    expect((error as { status: number }).status).toBe(500);
  });

  // ── Third-party origins: the object store's presigned URLs (D-144) ────────
  //
  // Regression guard. Crediting these is what broke every file upload: the
  // browser will not accept RustFS's wildcard `Access-Control-Allow-Origin: *`
  // on a credentialed request, so the preflight failed and the PUT never ran.
  // See `isAppRequest`'s comment in auth.interceptor.ts.
  const STORE = 'http://127.0.0.1:9000';

  it('does not attach credentials to a presigned object-store URL', () => {
    setUp();
    http.put(`${STORE}/attomebase/_quarantine/x.png?X-Amz-Signature=abc`, new Blob(['x']))
      .subscribe();

    const req = httpMock.expectOne(r => r.url.startsWith(STORE));
    expect(req.request.withCredentials).toBe(false);
    req.flush(null);
  });

  it('still attaches credentials to its own API origin', () => {
    setUp();
    http.get(`${BASE}/api/v1/a`).subscribe();

    const req = httpMock.expectOne(`${BASE}/api/v1/a`);
    expect(req.request.withCredentials).toBe(true);
    req.flush({ ok: 'a' });
  });

  it('treats a relative URL as its own origin and credentials it', () => {
    setUp();
    http.get('/api/v1/a').subscribe();

    const req = httpMock.expectOne('/api/v1/a');
    expect(req.request.withCredentials).toBe(true);
    req.flush({ ok: 'a' });
  });

  it('does not refresh-and-retry a 401 from the object store', () => {
    setUp();
    let error: unknown;
    http.get(`${STORE}/attomebase/x.png`).subscribe({ error: err => { error = err; } });

    httpMock
      .expectOne(`${STORE}/attomebase/x.png`)
      .flush({ error: 'denied' }, { status: 401, statusText: 'Unauthorized' });

    expect((error as { status: number }).status).toBe(401);
    expect(navigateSpy).not.toHaveBeenCalled();
    // httpMock.verify() in afterEach fails the test if a /auth/refresh ran here.
  });

  // NGB-P.6, flipped by NGB-1.4. `isCredentialEndpoint` matched with
  // `url.includes(path)`, so `/api/v1/auth/google/config` (a public config
  // GET, no credential involved) matched the `/api/v1/auth/google` login
  // endpoint and a 401 there was never refreshed.
  it('NGB-F4 a 401 from /auth/google/config refreshes', () => {
    setUp();
    let result: unknown;
    http.get(`${BASE}/api/v1/auth/google/config`).subscribe(res => { result = res; });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/google/config`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(`${BASE}/api/v1/auth/google/config`).flush({ client_id: null });

    expect(result).toEqual({ client_id: null });
  });

  it('NGB-F4 a 401 from /auth/register/config refreshes too', () => {
    setUp();
    let result: unknown;
    http.get(`${BASE}/api/v1/auth/register/config`).subscribe(res => { result = res; });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/register/config`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(`${BASE}/api/v1/auth/register/config`).flush({ mode: 'public' });

    expect(result).toEqual({ mode: 'public' });
  });

  // NGB-1.4 — matching the pathname, not a substring: a query string that
  // happens to contain the login path must not turn an ordinary GET into a
  // credential endpoint.
  it('NGB-F4 ignores a query string that contains a credential path', () => {
    setUp();
    const url = `${BASE}/api/v1/things?next=/api/v1/auth/login`;
    let result: unknown;
    http.get(url).subscribe(res => { result = res; });

    httpMock.expectOne(url).flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(url).flush({ ok: true });

    expect(result).toEqual({ ok: true });
  });

  it('NGB-F4 still refuses to refresh the exact credential endpoint with a query string', () => {
    setUp();
    let error: unknown;
    http.post(`${BASE}/api/v1/auth/login?next=/x`, {}).subscribe({ error: err => { error = err; } });

    httpMock
      .expectOne(`${BASE}/api/v1/auth/login?next=/x`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect((error as { status: number }).status).toBe(401);
    // httpMock.verify() in afterEach fails the test if a /auth/refresh ran here.
  });

  // NGB-F5 (D-129): single-flight state belongs to an injector, not to the
  // module. Two app instances in one page — or two TestBed injectors in one
  // `isolate: false` spec run — are two independent sessions, and a shared
  // module-global would make the second one wait on the first one's refresh.
  describe('per-injector single-flight refresh (NGB-F5)', () => {
    function configure() {
      TestBed.resetTestingModule();
      navigateSpy = vi.fn();
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withInterceptors([authInterceptor])),
          provideHttpClientTesting(),
          { provide: ATTOME_CONFIG, useValue: { apiUrl: BASE } },
          { provide: Router, useValue: { navigate: navigateSpy, url: '/current' } },
        ],
      });
      return {
        http: TestBed.inject(HttpClient),
        mock: TestBed.inject(HttpTestingController),
      };
    }

    const expired = { error: 'unauthorized' }, status401 = { status: 401, statusText: 'Unauthorized' };

    it('a second injector starts its own refresh instead of joining the first', () => {
      const a = configure();
      a.http.get(`${BASE}/api/v1/a`).subscribe();
      a.mock.expectOne(`${BASE}/api/v1/a`).flush(expired, status401);
      const aRefresh = a.mock.expectOne(`${BASE}/api/v1/auth/refresh`); // left in flight

      const b = configure();
      b.http.get(`${BASE}/api/v1/b`).subscribe();
      b.mock.expectOne(`${BASE}/api/v1/b`).flush(expired, status401);

      // The second injector's own refresh — a module-global would replay the
      // first injector's in-flight observable and issue no request here.
      b.mock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-b' });
      b.mock.expectOne(`${BASE}/api/v1/b`).flush({ ok: 'b' });
      b.mock.verify();

      aRefresh.flush({ user_id: 'user-a' });
      a.mock.expectOne(`${BASE}/api/v1/a`).flush({ ok: 'a' });
      a.mock.verify();
    });
  });
});
