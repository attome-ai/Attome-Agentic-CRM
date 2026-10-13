import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';
import {
  ATTOME_CONFIG,
  ApiError,
  AuthService,
  IdentityLinkInfo,
  LangService,
  authInterceptor,
} from '@attome/base';
import { STEP_UP_NAVIGATE, StepUpService } from '@attome/base/step-up';
import { Observable, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecuritySettingsComponent } from './security-settings.component';

/**
 * Self-service identity linking (P-federation-linking-policy §4.3(a)). Two
 * halves are covered here: the start side (which AuthService entry point a row
 * dispatches to) and the callback side (the query params the backend
 * redirects back to `/settings/security` with), plus the session-expiry path
 * that any authenticated screen inherits from `authInterceptor` (D-129).
 *
 * D-510 (attome-auth 2.1d) adds the step-up side: the link pre-check, the
 * federated step-up return markers, and API-key creation. `reauth_required`
 * must never behave like an expired session.
 */

// See login.component.spec.ts — the first TestBed fixture in a file runs past
// vitest's 5s default on a cold worker.
vi.setConfig({ testTimeout: 30_000 });

const BASE = 'http://localhost:7865';
const SETTINGS = '/settings/security';

function apiError(status: number, message = 'server said no'): ApiError {
  return { status, message, kind: status === 409 ? 'conflict' : 'internal' };
}

function reauthBody(operation: string, factors: string[]) {
  return {
    error: 'reauth_required',
    message: 're-authentication is required for this operation',
    operation,
    acceptable_factors: factors,
    request_id: 'req-1',
  };
}

const settle = () => new Promise<void>(resolve => setTimeout(resolve, 0));

function authStub(overrides: Record<string, unknown> = {}) {
  return {
    getOidcProviders:   vi.fn((): Observable<unknown> => of([])),
    getIdentityLinks:   vi.fn((): Observable<unknown> => of([])),
    getGoogleConfig:    vi.fn((): Observable<unknown> => of({ client_id: null })),
    linkOidcIdentity:   vi.fn(),
    linkGoogleIdentity: vi.fn((): Observable<unknown> => of(undefined)),
    createApiKey:       vi.fn((): Observable<unknown> => of({ id: 'k1', public_key: 'atk_pub_1', secret: 'atk_sec_1' })),
    ...overrides,
  };
}

function elevation(elevated: boolean, factors: string[] = ['password']) {
  return { operation: 'identity_link', elevated, elevated_until: elevated ? '2026-09-15T12:05:00Z' : null, acceptable_factors: factors };
}

function stepUpStub(overrides: Record<string, unknown> = {}) {
  return {
    status:               vi.fn((): Observable<unknown> => of(elevation(true))),
    elevate:              vi.fn((): Promise<boolean> => Promise.resolve(true)),
    run:                  vi.fn(<T>(_operation: string, request: () => Observable<T>) => request()),
    consumePendingReturn: vi.fn((): unknown => null),
    ...overrides,
  };
}

/**
 * The GSI SDK delivers Google's credential by invoking the component's own
 * callback — there is no DOM affordance to click, so the tests enter through
 * the same private handler the SDK does.
 */
function deliverGoogleCredential(component: SecuritySettingsComponent, credential: string): void {
  (component as unknown as { handleGoogleCredential(r: { credential: string }): void })
    .handleGoogleCredential({ credential });
}

interface Mounted {
  fixture:       ComponentFixture<SecuritySettingsComponent>;
  component:     SecuritySettingsComponent;
  auth:          ReturnType<typeof authStub>;
  stepUp:        ReturnType<typeof stepUpStub>;
  navigate:      ReturnType<typeof vi.fn>;
  navigateByUrl: ReturnType<typeof vi.fn>;
}

function mount(
  queryParams: Record<string, string> = {},
  overrides: Record<string, unknown> = {},
  stepUpOverrides: Record<string, unknown> = {},
): Mounted {
  const auth          = authStub(overrides);
  const stepUp        = stepUpStub(stepUpOverrides);
  const navigate      = vi.fn().mockResolvedValue(true);
  const navigateByUrl = vi.fn().mockResolvedValue(true);

  TestBed.configureTestingModule({
    imports: [SecuritySettingsComponent],
    providers: [
      { provide: AuthService,    useValue: auth },
      { provide: StepUpService,  useValue: stepUp },
      { provide: Router,         useValue: { navigate, navigateByUrl, url: SETTINGS } },
      { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(queryParams) } } },
      { provide: LangService,    useValue: { translate: (key: string) => key, errorText: (e: ApiError) => `errors.${e.kind}` } },
    ],
  });

  const fixture = TestBed.createComponent(SecuritySettingsComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, auth, stepUp, navigate, navigateByUrl };
}

describe('SecuritySettingsComponent identity-link start', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('merges the provider directory with the links the account already has', () => {
    const links: IdentityLinkInfo[] = [
      { provider_key: 'okta', email: 'operator@example.com', linked_at: '2026-08-01T00:00:00Z' },
    ];
    const { fixture, component } = mount({}, {
      getOidcProviders: vi.fn(() => of([
        { key: 'okta', display_name: 'Okta' },
        { key: 'entra', display_name: 'Entra' },
      ])),
      getIdentityLinks: vi.fn(() => of(links)),
    });

    expect(component.loading()).toBe(false);
    expect(component.providers()).toEqual([
      { key: 'okta', displayName: 'Okta', protocol: 'oidc', linkedEmail: 'operator@example.com' },
      { key: 'entra', displayName: 'Entra', protocol: 'oidc', linkedEmail: null },
    ]);

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('operator@example.com');
    // The unlinked row offers the action; the linked one does not.
    expect(fixture.nativeElement.querySelectorAll('.provider-row button.btn-secondary').length).toBe(1);
  });

  it('dispatches the row to the OIDC link endpoint once the session is elevated', () => {
    const { component, auth, stepUp } = mount({}, {
      getOidcProviders: vi.fn(() => of([{ key: 'okta', display_name: 'Okta' }])),
    });

    const [oidcRow] = component.providers();
    component.link(oidcRow);

    expect(stepUp.status).toHaveBeenCalledWith('identity_link');
    expect(stepUp.elevate).not.toHaveBeenCalled();
    expect(auth.linkOidcIdentity).toHaveBeenCalledWith('okta');
  });

  it('prompts before navigating when not elevated, and navigates only after the step-up succeeds', async () => {
    let finishStepUp!: (verified: boolean) => void;
    const { component, auth, stepUp } = mount({}, {
      getOidcProviders: vi.fn(() => of([{ key: 'okta', display_name: 'Okta' }])),
    }, {
      status:  vi.fn(() => of(elevation(false, ['password', 'federated']))),
      elevate: vi.fn(() => new Promise<boolean>(resolve => { finishStepUp = resolve; })),
    });

    component.link(component.providers()[0]);

    expect(stepUp.elevate).toHaveBeenCalledWith('identity_link', ['password', 'federated'], {
      returnUrl: SETTINGS,
      pendingAction: { kind: 'link', protocol: 'oidc', key: 'okta' },
    });
    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();

    finishStepUp(true);
    await settle();
    expect(auth.linkOidcIdentity).toHaveBeenCalledWith('okta');
  });

  it('does not navigate when the step-up is cancelled', async () => {
    const { component, auth } = mount({}, {
      getOidcProviders: vi.fn(() => of([{ key: 'okta', display_name: 'Okta' }])),
    }, {
      status:  vi.fn(() => of(elevation(false))),
      elevate: vi.fn(() => Promise.resolve(false)),
    });

    component.link(component.providers()[0]);
    await settle();

    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();
  });

  it('renders the Google row from the synthetic link entry rather than the provider directory', () => {
    const { component } = mount({}, {
      getGoogleConfig:  vi.fn(() => of({ client_id: 'google-client-id' })),
      getIdentityLinks: vi.fn(() => of([
        { provider_key: 'google', email: 'operator@gmail.com', linked_at: null },
      ] as IdentityLinkInfo[])),
    });

    expect(component.hasGoogleAuth()).toBe(true);
    expect(component.googleLinkedEmail()).toBe('operator@gmail.com');
    // Google is not an entry in the OIDC directory.
    expect(component.providers()).toEqual([]);
  });

  it('fails soft on a provider directory but surfaces a failed identity-links read', () => {
    const { component } = mount({}, {
      getOidcProviders: vi.fn(() => throwError(() => apiError(404, 'oidc not configured'))),
      getIdentityLinks: vi.fn(() => throwError(() => apiError(500, 'links unavailable'))),
    });

    expect(component.loading()).toBe(false);
    expect(component.providers()).toEqual([]);
    // NGB-2.3: translated by kind, never the server's prose.
    expect(component.error()).toBe('errors.internal');
  });

  it('reports a Google link conflict distinctly from an ordinary failure', () => {
    const { component } = mount({}, {
      getGoogleConfig:    vi.fn(() => of({ client_id: 'google-client-id' })),
      linkGoogleIdentity: vi.fn(() => throwError(() => apiError(409, 'already linked elsewhere'))),
    });

    deliverGoogleCredential(component, 'jwt-from-gsi');

    expect(component.banner()).toEqual({ kind: 'conflict', message: 'securitySettings.googleLinkConflict' });
  });

  it('links Google through the step-up service and reloads the linked providers afterwards', () => {
    const { component, auth, stepUp } = mount({}, {
      getGoogleConfig: vi.fn(() => of({ client_id: 'google-client-id' })),
    });

    expect(auth.getIdentityLinks).toHaveBeenCalledTimes(1);

    deliverGoogleCredential(component, 'jwt-from-gsi');

    expect(stepUp.run).toHaveBeenCalledWith('identity_link', expect.any(Function), { returnUrl: SETTINGS });
    expect(auth.linkGoogleIdentity).toHaveBeenCalledWith('jwt-from-gsi');
    expect(component.banner()?.kind).toBe('success');
    expect(auth.getIdentityLinks).toHaveBeenCalledTimes(2);
  });
});

describe('SecuritySettingsComponent identity-link callback', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  // The backend hardcodes this redirect target and carries the outcome in
  // exactly one of three query params (crates/server/src/auth.rs).
  it.each([
    ['identity_linked',          'success'],
    ['identity_link_conflict',   'conflict'],
    ['identity_link_error',      'error'],
  ])('turns ?%s into a %s banner and strips it from the URL', (param, kind) => {
    const { component, navigate } = mount({ [param]: '1' });

    expect(component.banner()?.kind).toBe(kind);
    expect(component.banner()?.message).toBeTruthy();
    // Re-showing the banner on refresh (or on a back-navigation) would be wrong.
    expect(navigate).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
  });

  it('shows no banner and leaves the URL alone on an ordinary visit', () => {
    const { component, navigate, stepUp } = mount();

    expect(component.banner()).toBeNull();
    expect(navigate).not.toHaveBeenCalled();
    expect(stepUp.consumePendingReturn).not.toHaveBeenCalled();
  });
});

describe('SecuritySettingsComponent federated step-up return (D-510)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  const strip = expect.objectContaining({ queryParams: {}, replaceUrl: true });

  it('confirms elevation, then continues a stored pending link navigation', () => {
    const { auth, stepUp, navigate } = mount({ step_up: 'identity_link' }, {}, {
      consumePendingReturn: vi.fn(() => ({
        operation: 'identity_link', returnUrl: SETTINGS,
        pendingAction: { kind: 'link', protocol: 'oidc', key: 'adfs' },
      })),
    });

    expect(stepUp.status).toHaveBeenCalledWith('identity_link');
    expect(auth.linkOidcIdentity).toHaveBeenCalledWith('adfs');
    expect(navigate).toHaveBeenCalledWith([], strip);
  });

  it('continues nothing when the read endpoint says the session is not elevated', () => {
    const { component, auth } = mount({ step_up: 'identity_link' }, {}, {
      status: vi.fn(() => of(elevation(false))),
      consumePendingReturn: vi.fn(() => ({
        operation: 'identity_link', returnUrl: SETTINGS,
        pendingAction: { kind: 'link', protocol: 'oidc', key: 'okta' },
      })),
    });

    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();
    expect(component.banner()).toEqual({ kind: 'error', message: 'securitySettings.stepUpExpired' });
  });

  it('ignores a pending action stored for a different operation', () => {
    const { component, auth } = mount({ step_up: 'identity_link' }, {}, {
      consumePendingReturn: vi.fn(() => ({
        operation: 'api_key_create', returnUrl: SETTINGS,
        pendingAction: { kind: 'link', protocol: 'oidc', key: 'okta' },
      })),
    });

    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();
    expect(component.banner()).toEqual({ kind: 'success', message: 'securitySettings.stepUpComplete' });
  });

  it('re-offers a pending API-key creation without replaying the POST', () => {
    const { component, auth } = mount({ step_up: 'api_key_create' }, {}, {
      consumePendingReturn: vi.fn(() => ({
        operation: 'api_key_create', returnUrl: SETTINGS,
        pendingAction: { kind: 'api_key_create', name: 'ci-bot', expiresInDays: 30 },
      })),
    });

    expect(auth.createApiKey).not.toHaveBeenCalled();
    expect(component.apiKeyName()).toBe('ci-bot');
    expect(component.apiKeyExpiry()).toBe('30');
    expect(component.banner()).toEqual({ kind: 'success', message: 'securitySettings.apiKey.ready' });
  });

  it('returns to a different stored returnUrl instead of acting here', () => {
    const { auth, navigateByUrl } = mount({ step_up: 'identity_link' }, {}, {
      consumePendingReturn: vi.fn(() => ({
        operation: 'identity_link', returnUrl: '/xrm/home',
        pendingAction: { kind: 'link', protocol: 'oidc', key: 'okta' },
      })),
    });

    expect(navigateByUrl).toHaveBeenCalledWith('/xrm/home');
    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();
  });

  it('shows an error on ?step_up_error=1, performs nothing and drops the stored state', () => {
    const { component, auth, stepUp, navigate } = mount({ step_up_error: '1' });

    expect(component.banner()).toEqual({ kind: 'error', message: 'securitySettings.stepUpError' });
    expect(stepUp.consumePendingReturn).toHaveBeenCalled();
    expect(stepUp.status).not.toHaveBeenCalled();
    expect(auth.linkOidcIdentity).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith([], strip);
  });

  it('opens the step-up prompt on ?reauth_required=identity_link', async () => {
    const { component, stepUp, navigate } = mount({ reauth_required: 'identity_link' }, {}, {
      status: vi.fn(() => of(elevation(false, ['totp', 'federated']))),
    });

    expect(stepUp.elevate).toHaveBeenCalledWith('identity_link', ['totp', 'federated'], { returnUrl: SETTINGS });
    expect(navigate).toHaveBeenCalledWith([], strip);
    await settle();
    expect(component.banner()).toEqual({ kind: 'success', message: 'securitySettings.stepUpComplete' });
  });
});

describe('SecuritySettingsComponent API-key creation', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('validates the name and expiry before sending anything', () => {
    const { component, auth, stepUp } = mount();

    component.createApiKey();
    expect(component.apiKeyError()).toBe('securitySettings.apiKey.nameRequired');

    component.apiKeyName.set('ci');
    component.apiKeyExpiry.set('0');
    component.createApiKey();
    expect(component.apiKeyError()).toBe('securitySettings.apiKey.expiryInvalid');

    expect(stepUp.run).not.toHaveBeenCalled();
    expect(auth.createApiKey).not.toHaveBeenCalled();
  });

  it('creates through the step-up service with the pending action for a federated return', () => {
    const { component, auth, stepUp } = mount();
    component.apiKeyName.set('  ci  ');
    component.apiKeyExpiry.set('30');

    component.createApiKey();

    expect(stepUp.run).toHaveBeenCalledWith('api_key_create', expect.any(Function), {
      returnUrl: SETTINGS,
      pendingAction: { kind: 'api_key_create', name: 'ci', expiresInDays: 30 },
    });
    expect(auth.createApiKey).toHaveBeenCalledWith({ name: 'ci', expires_in_days: 30 });
    expect(component.createdKey()?.secret).toBe('atk_sec_1');
  });

  it('reports a cancelled step-up as "not created"', () => {
    const { component } = mount({}, {}, {
      run: vi.fn(() => throwError(() => ({
        status: 401, kind: 'reauth_required', message: 're-authentication is required', operation: 'api_key_create',
      } satisfies ApiError))),
    });
    component.apiKeyName.set('ci');

    component.createApiKey();

    expect(component.apiKeyBusy()).toBe(false);
    expect(component.createdKey()).toBeNull();
    expect(component.apiKeyError()).toBe('securitySettings.apiKey.notCreated');
  });
});

describe('SecuritySettingsComponent with the real interceptor (D-129, D-510)', () => {
  let httpMock: HttpTestingController;
  let navigate: ReturnType<typeof vi.fn>;

  function mountWithRealHttp(): ComponentFixture<SecuritySettingsComponent> {
    navigate = vi.fn().mockResolvedValue(true);
    TestBed.configureTestingModule({
      imports: [SecuritySettingsComponent],
      providers: [
        // The real interceptor, AuthService and StepUpService — this is the
        // wiring an authenticated host-app screen actually runs under.
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG,    useValue: { apiUrl: BASE, portalKey: 'xrm', loginRoute: '/xrm/login' } },
        { provide: Router,           useValue: { navigate, url: SETTINGS } },
        { provide: ActivatedRoute,   useValue: { snapshot: { queryParamMap: convertToParamMap({}) } } },
        { provide: LangService,      useValue: { translate: (key: string) => key, errorText: (e: ApiError) => `errors.${e.kind}` } },
        { provide: STEP_UP_NAVIGATE, useValue: vi.fn() },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(SecuritySettingsComponent);
    fixture.detectChanges();
    return fixture;
  }

  /** The fail-soft directory read and the Google config, which are not what these tests are about. */
  function flushSideRequests(): void {
    httpMock.expectOne(`${BASE}/api/v1/auth/oidc/providers`).flush([]);
    httpMock.expectOne(`${BASE}/api/v1/auth/google/config`).flush({ client_id: null });
  }

  /** Answers the prompt's local step-up: a fresh challenge, then a successful verify. */
  function passStepUp(operation: string, factor: 'password' | 'totp', credential: string): void {
    TestBed.inject(StepUpService).submit(factor, credential);
    httpMock.expectOne(`${BASE}/api/v1/auth/step-up/${operation}`)
      .flush({ challenge_id: 'c-1', operation, acceptable_factors: [factor], expires_in_secs: 300 },
        { status: 201, statusText: 'Created' });
    const verifyReq = httpMock.expectOne(`${BASE}/api/v1/auth/step-up/${operation}/verify`);
    expect(verifyReq.request.body).toEqual({ challenge_id: 'c-1', factor, credential });
    verifyReq.flush({ operation, elevated_until: '2026-09-15T12:15:00Z' });
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  afterEach(() => {
    httpMock?.verify();
  });

  it('refreshes and replays the identity-links read when the access cookie expired mid-load', () => {
    const fixture = mountWithRealHttp();
    const component = fixture.componentInstance;

    flushSideRequests();
    httpMock
      .expectOne(`${BASE}/api/v1/auth/identity-links`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    // One refresh, then the same GET again — expectOne() also asserts the
    // interceptor did not fan out a second refresh.
    httpMock.expectOne(`${BASE}/api/v1/auth/refresh`).flush({ user_id: 'user-1' });
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([
      { provider_key: 'okta', email: 'operator@example.com', linked_at: '2026-08-01T00:00:00Z' },
    ]);

    expect(TestBed.inject(AuthService).userId()).toBe('user-1');
    expect(component.loading()).toBe(false);
    expect(component.error()).toBeNull();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('clears the session and returns to the XRM login when the refresh itself fails', () => {
    const fixture = mountWithRealHttp();
    const component = fixture.componentInstance;

    flushSideRequests();
    httpMock
      .expectOne(`${BASE}/api/v1/auth/identity-links`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    httpMock
      .expectOne(`${BASE}/api/v1/auth/refresh`)
      .flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    expect(TestBed.inject(AuthService).userId()).toBeNull();
    // `loginRoute` comes from this app's provideAttomeBase config, not the
    // library default — an XRM operator must land back on /xrm/login.
    expect(navigate).toHaveBeenCalledWith(
      ['/xrm/login'],
      { queryParams: { returnUrl: '/settings/security' } },
    );
    // The screen stops loading rather than spinning behind the redirect.
    expect(component.loading()).toBe(false);
    expect(component.error()).toBeTruthy();
  });

  it('prompts on a reauth_required Google link and retries the link once, never signing out', async () => {
    const fixture = mountWithRealHttp();
    const component = fixture.componentInstance;
    const auth = TestBed.inject(AuthService);
    auth.restoreSession('user-1');
    flushSideRequests();
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([]);

    deliverGoogleCredential(component, 'jwt-from-gsi');
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-link/google`)
      .flush(reauthBody('identity_link', ['totp', 'recovery_code']), { status: 401, statusText: 'Unauthorized' });

    // No refresh (httpMock.verify), no sign-out, no login navigation.
    expect(auth.userId()).toBe('user-1');
    expect(navigate).not.toHaveBeenCalled();
    expect(TestBed.inject(StepUpService).prompt()).toMatchObject({
      operation: 'identity_link', localFactors: ['totp', 'recovery_code'],
    });

    passStepUp('identity_link', 'totp', '123456');
    await settle();

    const retry = httpMock.expectOne(`${BASE}/api/v1/auth/identity-link/google`);
    expect(retry.request.body).toEqual({ credential: 'jwt-from-gsi' });
    retry.flush(null);

    httpMock.expectOne(`${BASE}/api/v1/auth/oidc/providers`).flush([]);
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([]);

    expect(component.banner()?.kind).toBe('success');
    expect(auth.userId()).toBe('user-1');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('creates an API key after a password step-up and shows the secret exactly once', async () => {
    const fixture = mountWithRealHttp();
    const component = fixture.componentInstance;
    const auth = TestBed.inject(AuthService);
    auth.restoreSession('user-1');
    flushSideRequests();
    httpMock.expectOne(`${BASE}/api/v1/auth/identity-links`).flush([]);

    component.apiKeyName.set('ci');
    component.apiKeyExpiry.set('30');
    component.createApiKey();

    const first = httpMock.expectOne(`${BASE}/api/v1/auth/api-keys`);
    expect(first.request.body).toEqual({ name: 'ci', expires_in_days: 30 });
    first.flush(reauthBody('api_key_create', ['password']), { status: 401, statusText: 'Unauthorized' });
    expect(auth.userId()).toBe('user-1');

    passStepUp('api_key_create', 'password', 'correct horse');
    await settle();

    httpMock.expectOne(`${BASE}/api/v1/auth/api-keys`).flush({
      id: '0190a000-0000-7000-8000-000000000001', name: 'ci',
      public_key: 'atk_pub_ci', secret: 'atk_sec_only_once',
      created_at: '2026-09-15T12:00:00Z', expires_at: '2026-10-15T12:00:00Z',
    }, { status: 201, statusText: 'Created' });
    fixture.detectChanges();

    const text = fixture.nativeElement.textContent as string;
    expect(text.split('atk_sec_only_once').length - 1).toBe(1);
    expect(text).toContain('securitySettings.apiKey.copyNow');
    expect(component.apiKeyName()).toBe('');
    expect(navigate).not.toHaveBeenCalled();

    component.dismissCreatedKey();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).not.toContain('atk_sec_only_once');
  });
});
