import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { afterEach, describe, expect, it } from 'vitest';
import { VerifyEmailPageComponent } from './verify-email-page.component';
import { AuthService, ATTOME_CONFIG, provideAttomeI18n, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';

/**
 * NGB-6.1d — the verify page auto-confirms on load, so its four paths are
 * "no token", "confirmed", "token refused", and a generic failure (asserted in
 * Arabic, per NGB-2.3). Focus movement is part of the contract: the page
 * changing state is the only thing a keyboard or screen-reader user hears.
 *
 * The fixture is created by the test, not by `setUp`: `TestBed.createComponent`
 * runs the first change detection here, so `ngOnInit` reads the language that
 * is active at creation time.
 */
describe('VerifyEmailPageComponent', () => {
  afterEach(() => localStorage.clear());

  const INVALID: ApiError = { status: 401, kind: 'unauthorized', message: 'invalid or expired token' };
  const NETWORK: ApiError = { status: 0, kind: 'unknown', message: 'Http failure response for …' };

  function setUp(options: { token?: string | null; error?: ApiError } = {}) {
    const confirmEmailVerification = options.error
      ? () => throwError(() => options.error)
      : () => of({ ok: true });

    TestBed.configureTestingModule({
      imports: [VerifyEmailPageComponent],
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
        provideRouter([]),
        { provide: AuthService, useValue: { confirmEmailVerification } },
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
    return {
      lang,
      create: () => {
        const fixture = TestBed.createComponent(VerifyEmailPageComponent);
        fixture.detectChanges();
        return { fixture, component: fixture.componentInstance };
      },
    };
  }

  const settle = () => new Promise(resolve => setTimeout(resolve, 5));

  it('reports an invalid link when the URL carries no token, and focuses the banner', async () => {
    const { create } = setUp({ token: null });
    const { fixture, component } = create();
    await settle();
    fixture.detectChanges();

    expect(component.loading()).toBe(false);
    expect(component.done()).toBe(false);
    expect(component.error()).toBe(component.lang.translate('verifyEmail.invalidLink'));

    const banner = fixture.nativeElement.querySelector('.error-banner') as HTMLElement;
    expect(banner.getAttribute('role')).toBe('alert');
    expect(banner.getAttribute('tabindex')).toBe('-1');
    expect(document.activeElement).toBe(banner);
  });

  it('confirms the token, shows the success heading and focuses it', async () => {
    const { create } = setUp({ token: 'tok' });
    const { fixture, component } = create();
    await settle();
    fixture.detectChanges();

    expect(component.loading()).toBe(false);
    expect(component.done()).toBe(true);
    expect(component.error()).toBeNull();
    const heading = fixture.nativeElement.querySelector('.page-title') as HTMLElement;
    expect(heading.textContent).toContain('Email verified');
    expect(document.activeElement).toBe(heading);
  });

  it('shows the invalid-link copy when the server refuses the token', async () => {
    const { create } = setUp({ token: 'tok', error: INVALID });
    const { component } = create();
    await settle();

    expect(component.done()).toBe(false);
    expect(component.error()).toBe(component.lang.translate('verifyEmail.invalidLink'));
  });

  it('renders a generic failure in the active Arabic catalog (NGB-2.3)', async () => {
    const { create, lang } = setUp({ token: 'tok', error: NETWORK });
    await lang.set('ar');
    expect(lang.current()).toBe('ar');
    const { component } = create();
    await settle();

    expect(component.error()).toBe(lang.translate('errors.unknown'));
    expect(component.error()).not.toBe(NETWORK.message);
  });
});
