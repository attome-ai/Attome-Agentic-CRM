import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, authInterceptor, ATTOME_CONFIG } from '@attome/base';
import { STEP_UP_NAVIGATE, StepUpService, isSafeReturnUrl } from './step-up.service';

/**
 * D-510 step-up UX (attome-auth 2.1d). Runs under the real `authInterceptor`, so
 * `httpMock.verify()` also proves a `reauth_required` 401 never triggers a
 * refresh, and the router stub proves it never navigates to login.
 */

const BASE = 'http://localhost:7865';
const KEYS_PATH = '/api/v1/auth/api-keys';
const KEYS = `${BASE}${KEYS_PATH}`;
const start  = (operation: string) => `${BASE}/api/v1/auth/step-up/${operation}`;
const verify = (operation: string) => `${start(operation)}/verify`;
const UNAUTHORIZED = { status: 401, statusText: 'Unauthorized' };
const CREATED = { status: 201, statusText: 'Created' };

const settle = () => new Promise<void>(resolve => setTimeout(resolve, 0));

function reauth(operation: string, factors: string[]) {
  return {
    error: 'reauth_required',
    message: 're-authentication is required for this operation',
    operation,
    acceptable_factors: factors,
    request_id: 'req-1',
  };
}

interface Outcome {
  values:    unknown[];
  error:     unknown;
  completed: boolean;
}

describe('StepUpService (D-510)', () => {
  let service: StepUpService;
  let api: ApiService;
  let httpMock: HttpTestingController;
  let navigate: ReturnType<typeof vi.fn>;
  let routerNavigate: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    TestBed.resetTestingModule();
    navigate = vi.fn();
    routerNavigate = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG,    useValue: { apiUrl: BASE } },
        { provide: Router,           useValue: { navigate: routerNavigate, url: '/settings/security?tab=keys' } },
        { provide: STEP_UP_NAVIGATE, useValue: navigate },
      ],
    });
    service  = TestBed.inject(StepUpService);
    api      = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
    sessionStorage.clear();
  });

  afterEach(() => {
    httpMock.verify();
    expect(routerNavigate).not.toHaveBeenCalled();
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  function createKey(): Outcome {
    const outcome: Outcome = { values: [], error: undefined, completed: false };
    service.run('api_key_create', () => api.post(KEYS_PATH, { name: 'k' })).subscribe({
      next:     v => outcome.values.push(v),
      error:    e => { outcome.error = e; },
      complete: () => { outcome.completed = true; },
    });
    return outcome;
  }

  function answerStart(operation: string, challengeId: string): void {
    const req = httpMock.expectOne(start(operation));
    expect(req.request.method).toBe('POST');
    req.flush(
      { challenge_id: challengeId, operation, acceptable_factors: ['password'], expires_in_secs: 300 },
      CREATED,
    );
  }

  it('reads the elevation endpoint for an operation', () => {
    let status: unknown;
    service.status('identity_link').subscribe(s => { status = s; });
    const req = httpMock.expectOne(start('identity_link'));
    expect(req.request.method).toBe('GET');
    req.flush({ operation: 'identity_link', elevated: false, elevated_until: null, acceptable_factors: ['totp'] });
    expect(status).toMatchObject({ elevated: false, acceptable_factors: ['totp'] });
  });

  it.each([
    ['password',      'correct horse battery staple'],
    ['totp',          '123456'],
    ['recovery_code', 'abcd-efgh-ijkl'],
  ] as const)('completes a %s step-up and retries the original request exactly once', async (factor, credential) => {
    const outcome = createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['totp', 'recovery_code', 'password']), UNAUTHORIZED);

    expect(service.prompt()).toMatchObject({
      operation: 'api_key_create',
      localFactors: ['totp', 'recovery_code', 'password'],
      federated: false,
      enrollmentRequired: false,
      busy: false,
      error: null,
    });

    service.submit(factor, credential);
    expect(service.prompt()?.busy).toBe(true);
    answerStart('api_key_create', 'c-1');
    const verifyReq = httpMock.expectOne(verify('api_key_create'));
    expect(verifyReq.request.body).toEqual({ challenge_id: 'c-1', factor, credential });
    verifyReq.flush({ operation: 'api_key_create', elevated_until: '2026-09-15T12:15:00Z' });
    expect(service.prompt()).toBeNull();

    await settle();
    httpMock.expectOne(KEYS).flush({ id: 'k1', secret: 'atk_sec_x' }, CREATED);

    expect(outcome.values).toEqual([{ id: 'k1', secret: 'atk_sec_x' }]);
    expect(outcome.completed).toBe(true);
    expect(outcome.error).toBeUndefined();
  });

  it('errors with the original ApiError and never retries when the prompt is cancelled', async () => {
    const outcome = createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);

    service.cancel();
    await settle();

    expect(service.prompt()).toBeNull();
    expect(outcome.error).toMatchObject({
      status: 401, kind: 'reauth_required', operation: 'api_key_create', acceptableFactors: ['password'],
    });
    expect(outcome.values).toEqual([]);
    httpMock.expectNone(KEYS);
  });

  it('shows an error after a refused verify, does not retry, and starts a fresh challenge for the next attempt', async () => {
    const outcome = createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);

    service.submit('password', 'wrong');
    answerStart('api_key_create', 'c-1');
    httpMock.expectOne(verify('api_key_create')).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);

    await settle();
    expect(service.prompt()).toMatchObject({ busy: false, error: 'stepUp.failed' });
    httpMock.expectNone(KEYS);
    expect(outcome.values).toEqual([]);
    expect(outcome.error).toBeUndefined();

    service.submit('password', 'right');
    answerStart('api_key_create', 'c-2');
    const verifyReq = httpMock.expectOne(verify('api_key_create'));
    expect(verifyReq.request.body).toEqual({ challenge_id: 'c-2', factor: 'password', credential: 'right' });
    verifyReq.flush({ operation: 'api_key_create', elevated_until: '2026-09-15T12:15:00Z' });

    await settle();
    httpMock.expectOne(KEYS).flush({ id: 'k1' }, CREATED);
    expect(outcome.values).toEqual([{ id: 'k1' }]);
    expect(outcome.completed).toBe(true);
  });

  it('never loops: a retry that is refused again errors without a second prompt', async () => {
    const outcome = createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);
    service.submit('password', 'right');
    answerStart('api_key_create', 'c-1');
    httpMock.expectOne(verify('api_key_create')).flush({ operation: 'api_key_create', elevated_until: 'x' });

    await settle();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);

    expect(service.prompt()).toBeNull();
    expect(outcome.error).toMatchObject({ kind: 'reauth_required' });
  });

  it('sends no credential when the prompt is cancelled while its challenge is starting', () => {
    createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['password']), UNAUTHORIZED);
    service.submit('password', 'pw');
    service.cancel();
    answerStart('api_key_create', 'c-1');
    httpMock.expectNone(verify('api_key_create'));
  });

  it('shows the enrollment message for totp_enrollment_required and starts no challenge', async () => {
    const outcome = createKey();
    httpMock.expectOne(KEYS).flush(reauth('api_key_create', ['totp_enrollment_required']), UNAUTHORIZED);

    expect(service.prompt()).toMatchObject({ enrollmentRequired: true, localFactors: [], federated: false });
    service.submit('totp', '123456');
    httpMock.expectNone(start('api_key_create'));

    service.cancel();
    await settle();
    expect(outcome.error).toMatchObject({ kind: 'reauth_required' });
  });

  it('passes other errors, and a reauth_required for another operation, straight through', () => {
    let forbidden: unknown;
    service.run('api_key_create', () => api.post(KEYS_PATH, {})).subscribe({ error: e => { forbidden = e; } });
    httpMock.expectOne(KEYS).flush({ error: 'forbidden', message: 'no' }, { status: 403, statusText: 'Forbidden' });
    expect(forbidden).toMatchObject({ kind: 'forbidden' });

    let other: unknown;
    service.run('api_key_create', () => api.post(KEYS_PATH, {})).subscribe({ error: e => { other = e; } });
    httpMock.expectOne(KEYS).flush(reauth('identity_link', ['password']), UNAUTHORIZED);
    expect(other).toMatchObject({ kind: 'reauth_required', operation: 'identity_link' });
    expect(service.prompt()).toBeNull();
  });

  it('resolves elevate with false on cancel and true on a verified step-up', async () => {
    const cancelled = service.elevate('identity_link', ['password']);
    service.cancel();
    await expect(cancelled).resolves.toBe(false);

    const verified = service.elevate('identity_link', ['password']);
    service.submit('password', 'pw');
    answerStart('identity_link', 'c-1');
    httpMock.expectOne(verify('identity_link')).flush({ operation: 'identity_link', elevated_until: 'x' });
    await expect(verified).resolves.toBe(true);
  });

  it('lists only linked OIDC providers, stores the pending return and navigates to the federated start', () => {
    service.elevate('identity_link', ['totp', 'federated'], {
      returnUrl: '/settings/security',
      pendingAction: { kind: 'link', protocol: 'oidc', key: 'adfs' },
    });
    expect(service.prompt()).toMatchObject({ federated: true, providersLoading: true, localFactors: ['totp'] });

    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([
      { provider_key: 'okta',   email: 'a@example.com', linked_at: '2026-08-01T00:00:00Z' },
      { provider_key: 'google', email: 'a@gmail.com',   linked_at: null },
    ]);
    httpMock.expectOne(`${BASE}/api/v1/auth/oidc/providers`).flush([
      { key: 'okta', display_name: 'Okta' }, { key: 'unlinked', display_name: 'Other' },
    ]);

    const providers = service.prompt()!.providers;
    expect(providers).toEqual([
      { key: 'okta', displayName: 'Okta', protocol: 'oidc' },
    ]);
    expect(service.prompt()!.providersLoading).toBe(false);

    service.startFederated(providers[0]);
    answerStart('identity_link', 'c-9 /x');

    expect(navigate).toHaveBeenCalledWith(
      `${BASE}/api/v1/auth/step-up/identity_link/oidc/okta?challenge_id=c-9%20%2Fx`,
    );
    expect(service.consumePendingReturn()).toEqual({
      operation: 'identity_link',
      returnUrl: '/settings/security',
      pendingAction: { kind: 'link', protocol: 'oidc', key: 'adfs' },
    });
    // Read-and-clear.
    expect(service.consumePendingReturn()).toBeNull();
  });

  it('defaults the federated return to the current route and ignores a provider it did not list', () => {
    service.elevate('api_key_create', ['federated']);
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([{ provider_key: 'okta', email: 'a', linked_at: null }]);
    httpMock.expectOne(`${BASE}/api/v1/auth/oidc/providers`).flush([{ key: 'okta', display_name: 'Okta' }]);

    service.startFederated({ key: 'evil', displayName: 'Evil', protocol: 'oidc' });
    httpMock.expectNone(start('api_key_create'));

    service.startFederated(service.prompt()!.providers[0]);
    answerStart('api_key_create', 'c-1');
    expect(navigate).toHaveBeenCalledWith(`${BASE}/api/v1/auth/step-up/api_key_create/oidc/okta?challenge_id=c-1`);
    expect(service.consumePendingReturn()).toEqual({
      operation: 'api_key_create', returnUrl: '/settings/security?tab=keys',
    });
  });

  it('rejects stored state whose returnUrl is not a same-origin relative path', () => {
    for (const returnUrl of ['//evil.example/x', 'https://evil.example', '/\\evil.example', 'settings', '/a\nb']) {
      sessionStorage.setItem('attome-step-up-pending', JSON.stringify({ operation: 'identity_link', returnUrl }));
      expect(service.consumePendingReturn()).toBeNull();
    }
    sessionStorage.setItem('attome-step-up-pending', '{not json');
    expect(service.consumePendingReturn()).toBeNull();
    expect(isSafeReturnUrl('/settings/security?step_up=1')).toBe(true);
  });

  it('treats unavailable storage as no pending state', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied'); });
    expect(service.consumePendingReturn()).toBeNull();
  });

  // NGB-1.6 — the pending key is namespaced by `portalKey`, and the
  // un-namespaced key it replaces is still read once so a federated step-up
  // that started before the change still returns to its action.
  describe('portal-scoped pending state (NGB-1.6)', () => {
    let portal: StepUpService;
    let portalHttp: HttpTestingController;

    beforeEach(() => {
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withInterceptors([authInterceptor])),
          provideHttpClientTesting(),
          { provide: ATTOME_CONFIG,    useValue: { apiUrl: BASE, portalKey: 'myportal' } },
          { provide: Router,           useValue: { navigate: routerNavigate, url: '/portal' } },
          { provide: STEP_UP_NAVIGATE, useValue: navigate },
        ],
      });
      portal    = TestBed.inject(StepUpService);
      portalHttp = TestBed.inject(HttpTestingController);
      sessionStorage.clear();
    });

    afterEach(() => {
      portalHttp.verify();
      sessionStorage.clear();
    });

    it('reads a pending state stored under the portal key, then the legacy key once', () => {
      sessionStorage.setItem(
        'myportal-step-up-pending',
        JSON.stringify({ operation: 'api_key_create', returnUrl: '/portal?tab=keys' }),
      );
      expect(portal.consumePendingReturn()).toEqual({
        operation: 'api_key_create', returnUrl: '/portal?tab=keys',
      });

      sessionStorage.setItem(
        'attome-step-up-pending',
        JSON.stringify({ operation: 'identity_link', returnUrl: '/portal/legacy' }),
      );
      expect(portal.consumePendingReturn()).toEqual({
        operation: 'identity_link', returnUrl: '/portal/legacy',
      });
      expect(sessionStorage.getItem('attome-step-up-pending')).toBeNull();
    });
  });
});
