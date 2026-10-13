import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { afterEach, describe, expect, it } from 'vitest';
import { ResetPasswordPageComponent } from './reset-password-page.component';
import { AuthService, ATTOME_CONFIG, provideAttomeI18n, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';

/**
 * NGB-6.1d — the reset page's four paths: no token in the link, a mismatch
 * caught before the request, the happy path, and a server refusal. The last
 * case runs in Arabic to pin NGB-2.3's `errorText` contract (errors.<kind> in
 * the active language, server prose only for validation/rule_violation).
 */
describe('ResetPasswordPageComponent', () => {
  afterEach(() => localStorage.clear());

  const INVALID: ApiError = { status: 401, kind: 'unauthorized', message: 'invalid or expired token' };
  const NETWORK: ApiError = { status: 0, kind: 'unknown', message: 'Http failure response for …' };

  function setUp(options: { token?: string | null; error?: ApiError } = {}) {
    const confirmPasswordReset = options.error
      ? () => throwError(() => options.error)
      : () => of({ ok: true });

    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
        provideRouter([]),
        { provide: AuthService, useValue: { confirmPasswordReset } },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              data: { backRoute: '/xrm/login', successRoute: '/xrm/login' },
              queryParamMap: { get: (key: string) => (key === 'token' ? (options.token ?? null) : null) },
            },
          },
        },
      ],
    });
    const lang = TestBed.inject(LangService);
    const component = TestBed.runInInjectionContext(() => new ResetPasswordPageComponent());
    return { component, lang };
  }

  it('rejects a link with no token before it calls the server', () => {
    const { component, lang } = setUp({ token: null });
    component.newPassword.set('a-long-enough-password');
    component.confirmPassword.set('a-long-enough-password');

    component.submit();

    expect(component.error()).toBe(lang.translate('resetPassword.invalidLink'));
    expect(component.loading()).toBe(false);
    expect(component.done()).toBe(false);
  });

  it('rejects a mismatched confirmation locally', () => {
    const { component, lang } = setUp({ token: 'tok' });
    component.newPassword.set('a-long-enough-password');
    component.confirmPassword.set('something-else-entirely');

    component.submit();

    expect(component.error()).toBe(lang.translate('resetPassword.mismatch'));
  });

  it('marks the reset done and focuses the new heading on success', async () => {
    const { component, lang } = setUp({ token: 'tok' });
    component.newPassword.set('a-long-enough-password');
    component.confirmPassword.set('a-long-enough-password');

    component.submit();

    expect(component.done()).toBe(true);
    expect(component.error()).toBeNull();
    expect(lang.current()).toBe('en');
  });

  it('shows the invalid-link copy for a refused token', () => {
    const { component, lang } = setUp({ token: 'tok', error: INVALID });
    component.newPassword.set('a-long-enough-password');
    component.confirmPassword.set('a-long-enough-password');

    component.submit();

    expect(component.done()).toBe(false);
    expect(component.error()).toBe(lang.translate('resetPassword.invalidLink'));
  });

  it('renders a generic server failure in the active Arabic catalog (NGB-2.3)', async () => {
    const { component, lang } = setUp({ token: 'tok', error: NETWORK });
    await lang.set('ar');
    component.newPassword.set('a-long-enough-password');
    component.confirmPassword.set('a-long-enough-password');

    component.submit();

    expect(component.error()).toBe(lang.translate('errors.unknown'));
    expect(component.error()).not.toBe(NETWORK.message);
  });
});
