import { APP_INITIALIZER } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { provideAttomeBase } from './provide';
import { AuthService } from './auth.service';

/**
 * NGB-6.1a — the session bootstrap D-129 requires, without the first-paint
 * stall it used to cause. The initializer may only *start* the one
 * `GET /api/v1/auth/session`; resolving it is the guard's (or any
 * subscriber's) job, and every subscriber shares that same round trip.
 */
describe('provideAttomeBase', () => {
  const BASE = 'http://localhost:7865';
  const SESSION_URL = `${BASE}/api/v1/auth/session`;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideAttomeBase({ apiUrl: BASE, portalKey: 'xrm', loginRoute: '/xrm/login' }),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    localStorage.clear();
  });

  function runInitializers(): (() => unknown)[] {
    const initializers = TestBed.inject(APP_INITIALIZER) as (() => unknown)[];
    expect(initializers.length).toBeGreaterThan(0);
    // Angular invokes each initializer inside an injection context; these use
    // `inject()`, so the manual call has to provide one too.
    for (const run of initializers) TestBed.runInInjectionContext(run);
    return initializers;
  }

  it('starts the session bootstrap from an initializer without resolving it', () => {
    runInitializers();

    // In flight — and no subscriber has been handed a session yet.
    const request = httpMock.expectOne(SESSION_URL);
    expect(TestBed.inject(AuthService).isLoggedIn()).toBe(false);

    request.flush({ user_id: 'user-1', email: 'user@example.com' });

    expect(TestBed.inject(AuthService).isLoggedIn()).toBe(true);
  });

  it('shares the one round trip with a later subscriber', () => {
    runInitializers();
    httpMock.expectOne(SESSION_URL).flush({ user_id: 'user-1', email: 'user@example.com' });

    let observed: unknown = 'not-set';
    TestBed.inject(AuthService).sessionReady().subscribe(session => { observed = session; });

    httpMock.expectNone(SESSION_URL);
    expect(observed).not.toBe('not-set');
  });
});
