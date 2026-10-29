import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, PASSKEY_BROWSER } from '@attome/base';
import { STEP_UP_NAVIGATE, StepUpService } from './step-up.service';

/** Q6-T1: a passkey answers the step-up prompt. */

const BASE = 'http://localhost:7865';
const START = `${BASE}/api/v1/auth/step-up/passkey_manage/passkey`;
const VERIFY = `${START}/verify`;
const settle = () => new Promise<void>(resolve => setTimeout(resolve, 0));

describe('StepUpService passkey (Q6-T1)', () => {
  let service: StepUpService;
  let httpMock: HttpTestingController;
  let browser: { supported: () => boolean; create: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };

  function setUp(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG,    useValue: { apiUrl: BASE } },
        { provide: Router,           useValue: { navigate: vi.fn(), url: '/settings/security' } },
        { provide: STEP_UP_NAVIGATE, useValue: vi.fn() },
        { provide: PASSKEY_BROWSER,  useValue: browser },
      ],
    });
    service  = TestBed.inject(StepUpService);
    httpMock = TestBed.inject(HttpTestingController);
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    browser = { supported: () => true, create: vi.fn(), get: vi.fn().mockResolvedValue({ id: 'cred' }) };
  });

  afterEach(() => httpMock.verify());

  it('offers a passkey the account has, beside its other factors', () => {
    setUp();
    void service.elevate('passkey_manage', ['password', 'passkey']);
    expect(service.prompt()?.passkey).toBe(true);
    expect(service.prompt()?.localFactors).toEqual(['password']);
    expect(service.prompt()?.enrollmentRequired).toBe(false);
  });

  it('lets a passkey alone answer, and offers none in a browser without passkeys', () => {
    setUp();
    void service.elevate('passkey_manage', ['passkey']);
    expect(service.prompt()?.passkey).toBe(true);
    expect(service.prompt()?.enrollmentRequired).toBe(false);

    TestBed.resetTestingModule();
    browser = { ...browser, supported: () => false };
    setUp();
    void service.elevate('passkey_manage', ['passkey']);
    expect(service.prompt()?.passkey).toBe(false);
    expect(service.prompt()?.enrollmentRequired).toBe(true);
  });

  it('verifies with the browser assertion', async () => {
    setUp();
    const verified = service.elevate('passkey_manage', ['passkey']);
    service.submitPasskey();
    httpMock.expectOne(START).flush({ options: { challenge: 'abc' } });
    await settle();
    expect(browser.get).toHaveBeenCalledWith({ challenge: 'abc' });
    const req = httpMock.expectOne(VERIFY);
    expect(req.request.body).toEqual({ response: { id: 'cred' } });
    req.flush({ operation: 'passkey_manage', elevated_until: 'x' });
    await expect(verified).resolves.toBe(true);
  });

  it('keeps the prompt open with no error when the browser prompt is cancelled', async () => {
    browser.get.mockRejectedValue(Object.assign(new Error('no'), { name: 'NotAllowedError' }));
    setUp();
    void service.elevate('passkey_manage', ['passkey']);
    service.submitPasskey();
    httpMock.expectOne(START).flush({ options: { challenge: 'abc' } });
    await settle();
    expect(service.prompt()?.busy).toBe(false);
    expect(service.prompt()?.error).toBeNull();
  });

  it('shows the generic failure when the server refuses the assertion', async () => {
    setUp();
    void service.elevate('passkey_manage', ['passkey']);
    service.submitPasskey();
    httpMock.expectOne(START).flush({ options: { challenge: 'abc' } });
    await settle();
    httpMock.expectOne(VERIFY).flush(
      { error: 'reauth_required', message: 'no', operation: 'passkey_manage', acceptable_factors: ['passkey'] },
      { status: 401, statusText: 'Unauthorized' },
    );
    expect(service.prompt()?.error).toBe('stepUp.failed');
  });
});
