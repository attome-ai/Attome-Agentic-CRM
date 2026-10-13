import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { afterEach, describe, expect, it } from 'vitest';
import { ForgotPasswordPageComponent } from './forgot-password-page.component';
import { AuthService, ATTOME_CONFIG, provideAttomeI18n, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';

/**
 * NGB-P.3 / NGB-F6, flipped by NGB-2.3. `handleError` always set `message`, so
 * every `err.message ?? lang.translate(…)` fallback in the account pages was
 * dead code: an Arabic user got the server's English prose (or, once the
 * default message became empty, a bare empty banner). The call sites now go
 * through `LangService.errorText`, which renders `errors.<kind>` in the active
 * language and keeps server text only for `validation` and `rule_violation`.
 */
describe('ForgotPasswordPageComponent', () => {
  afterEach(() => localStorage.clear());

  /** The English server message ApiService produces for a refused connection. */
  const NETWORK_ERROR: ApiError = {
    status: 0,
    kind: 'unknown',
    message: 'Http failure response for http://localhost:7865/api/v1/auth/reset-request: 0 Unknown Error',
  };

  function setUp(error: ApiError = NETWORK_ERROR) {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
        { provide: AuthService, useValue: { requestPasswordReset: () => throwError(() => error) } },
        { provide: ActivatedRoute, useValue: { snapshot: { data: {} } } },
      ],
    });
    const lang = TestBed.inject(LangService);
    const component = TestBed.runInInjectionContext(() => new ForgotPasswordPageComponent());
    return { component, lang };
  }

  it('NGB-F6 a network failure shows the Arabic error', async () => {
    const { component, lang } = setUp();
    await lang.set('ar');
    expect(lang.current()).toBe('ar');

    component.email.set('user@example.com');
    component.submit();

    expect(component.error()).toBe(lang.translate('errors.unknown'));
  });

  // NGB-3.6 — decorative SVGs are hidden from assistive tech, and the success
  // state moves focus to the new heading so a keyboard user is told.
  it('hides its decorative icons and focuses the new heading (NGB-3.6)', async () => {
    TestBed.configureTestingModule({
      imports: [ForgotPasswordPageComponent],
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
        provideRouter([]),
        { provide: AuthService, useValue: { requestPasswordReset: () => of({ ok: true }) } },
      ],
    });
    const fixture = TestBed.createComponent(ForgotPasswordPageComponent);
    fixture.detectChanges();

    const svgs = Array.from(fixture.nativeElement.querySelectorAll('svg')) as SVGElement[];
    expect(svgs.length).toBeGreaterThan(0);
    for (const svg of svgs) {
      expect(svg.getAttribute('aria-hidden')).toBe('true');
    }

    fixture.componentInstance.email.set('user@example.com');
    fixture.componentInstance.submit();
    fixture.detectChanges();
    await new Promise(resolve => setTimeout(resolve, 5));
    fixture.detectChanges();

    const heading = fixture.nativeElement.querySelector('.page-title') as HTMLElement;
    expect(heading.textContent).toContain('Check your inbox');
    expect(heading.getAttribute('tabindex')).toBe('-1');
    expect(document.activeElement).toBe(heading);
  });

  it('renders the server text for a validation error, which is field-level and actionable', async () => {
    const { component, lang } = setUp({
      status: 422,
      kind: 'validation',
      code: 'validation_error',
      message: 'email: must be a valid address',
    });
    await lang.set('ar');

    component.email.set('nope');
    component.submit();

    expect(component.error()).toBe('email: must be a valid address');
  });
});
