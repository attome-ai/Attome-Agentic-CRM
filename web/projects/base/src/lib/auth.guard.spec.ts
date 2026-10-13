import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { authGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { ATTOME_CONFIG } from './config';

/**
 * The app initializer no longer blocks the first paint on
 * `GET /auth/session`, so this guard is now the thing that guarantees D-129's
 * invariant: no authorization decision from a client-side marker, and none
 * before the server has answered. These tests pin that down — above all that
 * an in-flight bootstrap does not read as "logged out".
 */
describe('authGuard', () => {
  let httpMock: HttpTestingController;
  const SESSION_URL = 'http://localhost:7865/api/v1/auth/session';

  function setUp(config: { loginRoute?: string } = {}) {
    const createUrlTree = vi.fn((commands: unknown[], extras?: unknown) => ({ commands, extras }));
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865', ...config } },
        { provide: Router, useValue: { createUrlTree } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    return { auth: TestBed.inject(AuthService), createUrlTree };
  }

  afterEach(() => {
    httpMock?.verify();
  });

  it('waits for the in-flight bootstrap instead of redirecting a logged-in deep link to login', () => {
    const { auth, createUrlTree } = setUp({ loginRoute: '/xrm/login' });
    let result: unknown = 'not-set';

    const returned = TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/settings/security' } as RouterStateSnapshot),
    ) as Observable<unknown>;
    returned.subscribe(r => { result = r; });

    // Bootstrap has not answered yet: the guard must not have decided.
    const req = httpMock.expectOne(SESSION_URL);
    expect(result).toBe('not-set');
    expect(createUrlTree).not.toHaveBeenCalled();

    req.flush({ user_id: 'user-boot', email: 'boot@example.com' });

    expect(result).toBe(true);
    expect(createUrlTree).not.toHaveBeenCalled();
    expect(auth.isLoggedIn()).toBe(true);
  });

  it('redirects to loginRoute with returnUrl once the server confirms no session', () => {
    const { createUrlTree } = setUp({ loginRoute: '/xrm/login' });
    let result: unknown = 'not-set';

    const returned = TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/settings/security' } as RouterStateSnapshot),
    ) as Observable<unknown>;
    returned.subscribe(r => { result = r; });

    httpMock
      .expectOne(SESSION_URL)
      .flush({ error: 'unauthorized', message: 'no session' }, { status: 401, statusText: 'Unauthorized' });

    expect(result).not.toBe(true);
    expect(createUrlTree).toHaveBeenCalledWith(['/xrm/login'], {
      queryParams: { returnUrl: '/settings/security' },
    });
  });

  it('redirects rather than hanging when the backend is unreachable', () => {
    const { createUrlTree } = setUp({ loginRoute: '/xrm/login' });
    let result: unknown = 'not-set';

    const returned = TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/xrm/dashboard' } as RouterStateSnapshot),
    ) as Observable<unknown>;
    returned.subscribe(r => { result = r; });

    httpMock
      .expectOne(SESSION_URL)
      .error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });

    expect(result).not.toBe(true);
    expect(createUrlTree).toHaveBeenCalledWith(['/xrm/login'], {
      queryParams: { returnUrl: '/xrm/dashboard' },
    });
  });

  it('defaults to /login when the config sets no loginRoute', () => {
    const { createUrlTree } = setUp();
    (TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/x' } as RouterStateSnapshot),
    ) as Observable<unknown>).subscribe();

    httpMock
      .expectOne(SESSION_URL)
      .flush({ error: 'unauthorized', message: 'no session' }, { status: 401, statusText: 'Unauthorized' });

    expect(createUrlTree).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/x' } });
  });

  it('reuses the bootstrap already started by the app initializer', () => {
    const { auth } = setUp();
    auth.sessionReady().subscribe();               // what provide.ts's initializer does
    httpMock.expectOne(SESSION_URL).flush({ user_id: 'u', email: 'u@example.com' });

    let result: unknown = 'not-set';
    (TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/x' } as RouterStateSnapshot),
    ) as Observable<unknown>).subscribe(r => { result = r; });

    // No second round trip, and the guard resolves synchronously.
    httpMock.expectNone(SESSION_URL);
    expect(result).toBe(true);
  });
});
