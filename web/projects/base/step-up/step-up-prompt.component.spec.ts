import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, LangService, pushModal } from '@attome/base';
import { StepUpPromptComponent } from './step-up-prompt.component';
import { STEP_UP_NAVIGATE, StepUpService } from './step-up.service';

vi.setConfig({ testTimeout: 30_000 });

const BASE = 'http://localhost:7865';

describe('StepUpPromptComponent', () => {
  let fixture: ComponentFixture<StepUpPromptComponent>;
  let service: StepUpService;
  let httpMock: HttpTestingController;

  function mount(): HTMLElement {
    TestBed.configureTestingModule({
      imports: [StepUpPromptComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG,    useValue: { apiUrl: BASE } },
        { provide: Router,           useValue: { navigate: vi.fn(), url: '/' } },
        { provide: STEP_UP_NAVIGATE, useValue: vi.fn() },
        { provide: LangService,      useValue: { translate: (key: string) => key } },
      ],
    });
    service  = TestBed.inject(StepUpService);
    httpMock = TestBed.inject(HttpTestingController);
    fixture  = TestBed.createComponent(StepUpPromptComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function credentialInput(el: HTMLElement): HTMLInputElement {
    return el.querySelector<HTMLInputElement>('#attome-step-up-credential')!;
  }

  afterEach(() => {
    httpMock?.verify();
    TestBed.resetTestingModule();
  });

  it('renders nothing while no prompt is open', () => {
    const el = mount();
    expect(el.querySelector('[role="dialog"]')).toBeNull();
  });

  it('masks a password and marks TOTP and recovery codes as one-time codes, each with a label', () => {
    const el = mount();
    service.elevate('api_key_create', ['password', 'totp', 'recovery_code']);
    fixture.detectChanges();

    const dialog = el.querySelector('[role="dialog"]')!;
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(el.querySelector('label[for="attome-step-up-credential"]')).not.toBeNull();
    expect(credentialInput(el).type).toBe('password');

    const radios = el.querySelectorAll<HTMLInputElement>('input[type="radio"]');
    expect(radios.length).toBe(3);

    radios[1].checked = true;
    radios[1].dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(credentialInput(el).type).toBe('text');
    expect(credentialInput(el).getAttribute('inputmode')).toBe('numeric');
    expect(credentialInput(el).getAttribute('autocomplete')).toBe('one-time-code');

    radios[2].checked = true;
    radios[2].dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(credentialInput(el).type).toBe('text');
    expect(credentialInput(el).getAttribute('autocomplete')).toBe('one-time-code');
    expect(credentialInput(el).getAttribute('inputmode')).toBeNull();
  });

  it('submits the typed credential through the service, then closes', async () => {
    const el = mount();
    const verified = service.elevate('identity_link', ['password']);
    fixture.detectChanges();

    const input = credentialInput(el);
    input.value = 'pw';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    fixture.detectChanges();

    httpMock.expectOne(`${BASE}/api/v1/auth/step-up/identity_link`)
      .flush({ challenge_id: 'c-1', operation: 'identity_link', acceptable_factors: ['password'], expires_in_secs: 300 });
    const verifyReq = httpMock.expectOne(`${BASE}/api/v1/auth/step-up/identity_link/verify`);
    expect(verifyReq.request.body).toEqual({ challenge_id: 'c-1', factor: 'password', credential: 'pw' });
    verifyReq.flush({ operation: 'identity_link', elevated_until: '2026-09-15T12:05:00Z' });

    await expect(verified).resolves.toBe(true);
    fixture.detectChanges();
    expect(el.querySelector('[role="dialog"]')).toBeNull();
  });

  it('shows the generic failure text after a refused verify and keeps the prompt open', () => {
    const el = mount();
    service.elevate('identity_link', ['password']);
    fixture.detectChanges();
    service.submit('password', 'wrong');
    httpMock.expectOne(`${BASE}/api/v1/auth/step-up/identity_link`)
      .flush({ challenge_id: 'c-1', operation: 'identity_link', acceptable_factors: ['password'], expires_in_secs: 300 });
    httpMock.expectOne(`${BASE}/api/v1/auth/step-up/identity_link/verify`)
      .flush({ error: 'reauth_required', message: 'x', operation: 'identity_link', acceptable_factors: ['password'] },
        { status: 401, statusText: 'Unauthorized' });
    fixture.detectChanges();

    expect(el.querySelector('[role="alert"]')?.textContent).toContain('stepUp.failed');
    expect(el.querySelector('[role="dialog"]')).not.toBeNull();
  });

  it('shows the enrollment message with no credential input for totp_enrollment_required', () => {
    const el = mount();
    service.elevate('api_key_create', ['totp_enrollment_required']);
    fixture.detectChanges();

    expect(el.textContent).toContain('stepUp.enrollmentRequired');
    expect(credentialInput(el)).toBeNull();
  });

  it('cancels on Escape', async () => {
    mount();
    const result = service.elevate('identity_link', ['password']);
    fixture.detectChanges();

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(result).resolves.toBe(false);
  });

  it('does not answer Escape while it is not the top-most modal (NGB-4.3)', async () => {
    mount();
    const result = service.elevate('identity_link', ['password']);
    fixture.detectChanges();

    const above = pushModal();
    try {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
      fixture.detectChanges();
      expect(service.prompt()).not.toBeNull();
    } finally {
      above.release();
    }

    // The host binding, not a direct call: this is the path a real Escape takes.
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(result).resolves.toBe(false);
  });
});
