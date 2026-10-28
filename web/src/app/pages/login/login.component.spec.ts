import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import {
  ApiError,
  AuthService,
  LangService,
  MfaChallenge,
  ThemeService,
} from '@attome/base';
import { Observable, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LoginComponent } from './login.component';

/**
 * The XRM sign-in screen's MFA branch (D-069): a correct password does not
 * always mint a session, so `submit()` has three outcomes — straight to the
 * dashboard, a TOTP/recovery challenge, or forced first-time enrollment — and
 * the pending token that carries the operator between them never touches a
 * cookie. These pin the branch selection and the pending-token plumbing.
 */

// The first fixture in a file pays for TestBed compiling a component that pulls
// in @attome/base, which alone runs past vitest's 5s default on a cold worker.
vi.setConfig({ testTimeout: 30_000 });

const CHALLENGE_REQUIRED: MfaChallenge = { mfa: 'required', pending_token: 'pending-1' };
const CHALLENGE_ENROLL:   MfaChallenge = { mfa: 'enrollment_required', pending_token: 'pending-2' };

function apiError(status: number, message = 'server said no'): ApiError {
  return { status, message, kind: status === 401 ? 'unauthorized' : 'internal' };
}

/** Every AuthService call the login screen can make, all succeeding by default. */
function authStub(overrides: Record<string, unknown> = {}) {
  return {
    getRegistrationConfig: vi.fn(() => of({ mode: 'public' as const })),
    getOidcProviders:      vi.fn(() => of([])),
    getGoogleConfig:       vi.fn(() => of({ client_id: null })),
    login:                 vi.fn((): Observable<unknown> => of({ user_id: 'user-1' })),
    verifyMfa:             vi.fn((): Observable<unknown> => of({ user_id: 'user-1' })),
    verifyMfaRecovery:     vi.fn((): Observable<unknown> => of({ user_id: 'user-1' })),
    startMfaEnrollment:    vi.fn((): Observable<unknown> =>
      of({ secret_base32: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/attome' })),
    confirmMfaEnrollment:  vi.fn((): Observable<unknown> =>
      of({ user_id: 'user-1', recovery_codes: ['AAAA-1111', 'BBBB-2222'] })),
    ...overrides,
  };
}

interface Mounted {
  fixture:   ComponentFixture<LoginComponent>;
  component: LoginComponent;
  auth:      ReturnType<typeof authStub>;
  navigate:  ReturnType<typeof vi.fn>;
}

function configure(overrides: Record<string, unknown> = {}): ReturnType<typeof authStub> {
  const auth = authStub(overrides);
  TestBed.configureTestingModule({
    imports: [LoginComponent],
    providers: [
      // A real router: the template renders `routerLink` on the back/forgot/
      // register links, which resolves ActivatedRoute on render.
      provideRouter([]),
      { provide: AuthService,  useValue: auth },
      { provide: ThemeService, useValue: { isDark: () => false } },
      // Identity translation — an assertion on the key proves which message
      // branch ran without pinning the English copy.
      { provide: LangService,  useValue: { translate: (key: string) => key, errorText: (e: ApiError) => `errors.${e.kind}` } },
    ],
  });
  return auth;
}

function create(auth: ReturnType<typeof authStub>): Mounted {
  const fixture  = TestBed.createComponent(LoginComponent);
  const navigate = vi.fn().mockResolvedValue(true);
  vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockImplementation(navigate);
  fixture.detectChanges();

  return { fixture, component: fixture.componentInstance, auth, navigate };
}

function mount(overrides: Record<string, unknown> = {}): Mounted {
  return create(configure(overrides));
}

/** Mounts after a real navigation that carries `?returnUrl=`, as the guard leaves it. */
async function mountWithReturnUrl(returnUrl: string): Promise<Mounted> {
  const auth = configure();
  await TestBed.inject(Router).navigateByUrl(`/?returnUrl=${encodeURIComponent(returnUrl)}`);
  return create(auth);
}

/** Fills the credential form and submits it. */
function signIn(component: LoginComponent): void {
  component.form.setValue({ email: 'operator@example.com', password: 'correct horse' });
  component.submit();
}

function text(fixture: ComponentFixture<LoginComponent>): string {
  return fixture.nativeElement.textContent as string;
}

describe('LoginComponent MFA challenge', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('does not call the API when the credential form is incomplete', () => {
    const { component, auth } = mount();

    component.form.setValue({ email: 'not-an-email', password: '' });
    component.submit();

    expect(auth.login).not.toHaveBeenCalled();
    expect(component.form.touched).toBe(true);
    expect(component.loading()).toBe(false);
  });

  // Regression: `submit()`'s invalid-form guard used to return silently, so a
  // malformed email made "Sign in" look like a dead button — no request, no
  // message, nothing in the console.
  it('tells the operator why the submit was rejected', () => {
    const { fixture, component } = mount();

    component.form.setValue({ email: 'fwef', password: 'secret' });
    component.submit();
    fixture.detectChanges();

    const message = fixture.nativeElement.querySelector('#email-error') as HTMLElement | null;
    expect(message?.textContent).toContain('valid email');
    expect(fixture.nativeElement.querySelector('#email').getAttribute('aria-invalid')).toBe('true');
    expect(fixture.nativeElement.querySelector('#password-error')).toBeNull();
  });

  it('goes straight to the dashboard when no second factor is required', () => {
    const { component, navigate } = mount();

    signIn(component);

    expect(component.stage()).toBe('credentials');
    expect(navigate).toHaveBeenCalledWith('/xrm/dashboard');
  });

  it('NGB-1.3 returns to a same-origin deep link after sign-in', async () => {
    const { component, navigate } = await mountWithReturnUrl('/xrm/entity/x?id=1');

    signIn(component);

    expect(navigate).toHaveBeenCalledWith('/xrm/entity/x?id=1');
  });

  it('NGB-1.3 ignores an off-origin returnUrl and lands on the dashboard', async () => {
    const { component, navigate } = await mountWithReturnUrl('//evil.example/phish');

    signIn(component);

    expect(navigate).toHaveBeenCalledWith('/xrm/dashboard');
  });

  it('maps a 401 from login to the invalid-credentials message', () => {
    const { component, navigate } = mount({
      login: vi.fn(() => throwError(() => apiError(401))),
    });

    signIn(component);

    expect(component.error()).toBe('xrmLogin.invalidCredentials');
    expect(component.loading()).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows the code form and mints no session when the challenge is `required`', () => {
    const { fixture, component, navigate } = mount({
      login: vi.fn(() => of(CHALLENGE_REQUIRED)),
    });

    signIn(component);
    fixture.detectChanges();

    expect(component.stage()).toBe('mfa-code');
    expect(component.loading()).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('#mfa-code')).toBeTruthy();
  });

  it('verifies with the pending token carried over from the login response', () => {
    const { component, auth, navigate } = mount({
      login: vi.fn(() => of(CHALLENGE_REQUIRED)),
    });

    signIn(component);
    component.codeForm.setValue({ code: '123456' });
    component.submitMfaCode();

    expect(auth.verifyMfa).toHaveBeenCalledWith({ pending_token: 'pending-1', code: '123456' });
    expect(auth.verifyMfaRecovery).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith('/xrm/dashboard');
  });

  it('sends a recovery code to the recovery endpoint instead, and clears the typed code on the switch', () => {
    const { component, auth } = mount({
      login: vi.fn(() => of(CHALLENGE_REQUIRED)),
    });

    signIn(component);
    component.codeForm.setValue({ code: '123456' });
    component.toggleRecoveryCode();

    expect(component.useRecoveryCode()).toBe(true);
    expect(component.codeForm.value.code).toBeFalsy();

    component.codeForm.setValue({ code: 'AAAA-1111' });
    component.submitMfaCode();

    expect(auth.verifyMfaRecovery).toHaveBeenCalledWith({ pending_token: 'pending-1', code: 'AAAA-1111' });
    expect(auth.verifyMfa).not.toHaveBeenCalled();
  });

  it('keeps the operator on the code stage after a rejected code', () => {
    const { component, navigate } = mount({
      login:     vi.fn(() => of(CHALLENGE_REQUIRED)),
      verifyMfa: vi.fn(() => throwError(() => apiError(401))),
    });

    signIn(component);
    component.codeForm.setValue({ code: '000000' });
    component.submitMfaCode();

    expect(component.stage()).toBe('mfa-code');
    expect(component.error()).toBe('xrmLogin.invalidCode');
    expect(component.loading()).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('drops the pending challenge when the operator backs out to sign-in', () => {
    const { fixture, component, auth } = mount({
      login: vi.fn(() => of(CHALLENGE_REQUIRED)),
    });

    signIn(component);
    component.codeForm.setValue({ code: '123456' });
    component.toggleRecoveryCode();
    component.startOver();
    fixture.detectChanges();

    expect(component.stage()).toBe('credentials');
    expect(component.useRecoveryCode()).toBe(false);
    expect(component.error()).toBeNull();
    expect(component.form.value.email).toBeFalsy();
    expect(fixture.nativeElement.querySelector('#mfa-code')).toBeNull();

    // The stale token is gone: a code submitted after backing out cannot
    // resume the abandoned challenge.
    component.codeForm.setValue({ code: '123456' });
    component.submitMfaCode();
    expect(auth.verifyMfa).toHaveBeenCalledWith({ pending_token: '', code: '123456' });
  });
});

describe('LoginComponent forced MFA enrollment', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('starts enrollment with the challenge token and renders the secret to scan', () => {
    const { fixture, component, auth, navigate } = mount({
      login: vi.fn(() => of(CHALLENGE_ENROLL)),
    });

    signIn(component);
    fixture.detectChanges();

    expect(auth.startMfaEnrollment).toHaveBeenCalledWith({ pending_token: 'pending-2' });
    expect(component.stage()).toBe('mfa-enroll');
    expect(component.enrollInfo()?.secret_base32).toBe('JBSWY3DPEHPK3PXP');
    expect(component.loading()).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
    expect(text(fixture)).toContain('JBSWY3DPEHPK3PXP');
  });

  it('surfaces a failure to start enrollment instead of stranding the operator on a spinner', () => {
    const { component } = mount({
      login:              vi.fn(() => of(CHALLENGE_ENROLL)),
      startMfaEnrollment: vi.fn(() => throwError(() => apiError(500, 'enrollment unavailable'))),
    });

    signIn(component);

    // NGB-2.3: a non-actionable kind shows the translated message, never server prose.
    expect(component.error()).toBe('errors.internal');
    expect(component.loading()).toBe(false);
    expect(component.stage()).toBe('credentials');
  });

  it('shows the one-time recovery codes and waits for acknowledgement before navigating', () => {
    const { fixture, component, auth, navigate } = mount({
      login: vi.fn(() => of(CHALLENGE_ENROLL)),
    });

    signIn(component);
    component.codeForm.setValue({ code: '123456' });
    component.submitEnrollConfirm();
    fixture.detectChanges();

    expect(auth.confirmMfaEnrollment).toHaveBeenCalledWith({ pending_token: 'pending-2', code: '123456' });
    expect(component.recoveryCodes()).toEqual(['AAAA-1111', 'BBBB-2222']);
    // The codes are shown exactly once — navigating away automatically would
    // lose them.
    expect(navigate).not.toHaveBeenCalled();
    expect(text(fixture)).toContain('AAAA-1111');

    component.continueToDashboard();
    expect(navigate).toHaveBeenCalledWith('/xrm/dashboard');
  });

  it('keeps the enrollment form up when the first code is rejected', () => {
    const { component } = mount({
      login:                vi.fn(() => of(CHALLENGE_ENROLL)),
      confirmMfaEnrollment: vi.fn(() => throwError(() => apiError(401))),
    });

    signIn(component);
    component.codeForm.setValue({ code: '000000' });
    component.submitEnrollConfirm();

    expect(component.stage()).toBe('mfa-enroll');
    expect(component.recoveryCodes()).toBeNull();
    expect(component.error()).toBe('xrmLogin.invalidCode');
  });
});

describe('LoginComponent password-spray challenge (Q20-T3)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('solves a proof-of-work challenge after a 429 and signs in with the answer', async () => {
    const login = vi.fn()
      .mockReturnValueOnce(throwError(() => apiError(429)))
      .mockReturnValue(of({ user_id: 'user-1' }));
    const getPowChallenge = vi.fn(() =>
      of({ challenge: 'payload.signature', nonce: '00ff', difficulty: 1, expires_at: 0 }));
    const { component } = mount({ login, getPowChallenge });

    signIn(component);

    await vi.waitFor(() => expect(login).toHaveBeenCalledTimes(2));
    expect(getPowChallenge).toHaveBeenCalledTimes(1);
    const retried = login.mock.calls[1][0] as { captcha_token: string };
    expect(retried.captcha_token).toMatch(/^payload\.signature:\d+$/);
  });

  it('shows the 429 when no proof-of-work challenge is in force', () => {
    const { component } = mount({
      login:           vi.fn(() => throwError(() => apiError(429))),
      getPowChallenge: vi.fn(() => throwError(() => apiError(404))),
    });

    signIn(component);

    expect(component.error()).toBe('errors.internal');
    expect(component.loading()).toBe(false);
  });
});

describe('LoginComponent email first (Q1-T14)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  const providers = [{ key: 'corp', display_name: 'Corp' }];

  it('asks for the email alone and sends a verified domain to its provider', () => {
    const { component, auth } = mount({
      getOidcProviders: vi.fn(() => of(providers)),
      discoverOidc:     vi.fn(() => of({ provider: 'corp' })),
      loginWithOidc:    vi.fn(),
    });
    expect(component.askPassword()).toBe(false);
    component.form.controls.email.setValue('person@corp.example');
    component.submit();
    expect(auth['discoverOidc']).toHaveBeenCalledWith('person@corp.example');
    expect(auth['loginWithOidc']).toHaveBeenCalledWith('corp');
    expect(auth.login).not.toHaveBeenCalled();
  });

  it('goes on to the password for any other address, even when the lookup fails', () => {
    const { component, auth } = mount({
      getOidcProviders: vi.fn(() => of(providers)),
      discoverOidc:     vi.fn(() => throwError(() => apiError(500))),
    });
    component.form.controls.email.setValue('someone@elsewhere.example');
    component.submit();
    expect(component.askPassword()).toBe(true);
    expect(auth.login).not.toHaveBeenCalled();
    component.form.controls.password.setValue('correct horse');
    component.submit();
    expect(auth.login).toHaveBeenCalledTimes(1);
  });
});
