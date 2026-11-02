import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DEVICE_ID_KEY, DeviceSecurityService, mustUnlock, needsPrivacy } from './device-security.service';

const g = globalThis as unknown as { Capacitor?: unknown };

/** A service whose sign-out is recorded instead of leaving the page. */
class Recording extends DeviceSecurityService {
  signedOutCalls = 0;
  protected override signedOut(): void {
    this.signedOutCalls += 1;
  }
}

function setup(): { service: Recording; http: HttpTestingController } {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), Recording],
  });
  return { service: TestBed.inject(Recording), http: TestBed.inject(HttpTestingController) };
}

afterEach(() => {
  delete g.Capacitor;
  localStorage.clear();
  vi.restoreAllMocks();
  TestBed.resetTestingModule();
});

describe('DeviceSecurityService (B17-T5)', () => {
  it('wipe clears storage and signs out', async () => {
    const { service, http } = setup();
    localStorage.setItem(DEVICE_ID_KEY, 'd1');
    localStorage.setItem('xrm-offline', 'records');
    const done = service.checkWipe();
    http.expectOne('/api/v1/devices/me/d1').flush({ wipe: true });
    await vi.waitFor(() => http.expectOne('/api/v1/devices/me/d1/wiped').flush({}));
    await vi.waitFor(() => http.expectOne('/api/v1/auth/logout').flush({}));
    expect(await done).toBe(true);
    expect(localStorage.getItem('xrm-offline')).toBeNull();
    expect(service.signedOutCalls).toBe(1);
  });

  it('no wipe keeps everything', async () => {
    const { service, http } = setup();
    localStorage.setItem(DEVICE_ID_KEY, 'd1');
    const done = service.checkWipe();
    http.expectOne('/api/v1/devices/me/d1').flush({ wipe: false });
    expect(await done).toBe(false);
    expect(localStorage.getItem(DEVICE_ID_KEY)).toBe('d1');
    expect(service.signedOutCalls).toBe(0);
  });

  it('privacy screen on for sensitive entity', async () => {
    const enable = vi.fn(async () => undefined);
    const disable = vi.fn(async () => undefined);
    g.Capacitor = { isNativePlatform: () => true, Plugins: { PrivacyScreen: { enable, disable } } };
    const { service } = setup();
    await service.privacyFor([{ is_sensitive: false }, { is_sensitive: true }]);
    expect(enable).toHaveBeenCalledOnce();
    await service.privacyFor([{ is_sensitive: false }]);
    expect(disable).toHaveBeenCalledOnce();
    expect(needsPrivacy([])).toBe(false);
  });

  it('a resume after the timeout asks to unlock', async () => {
    const authenticate = vi.fn(async () => undefined);
    g.Capacitor = { isNativePlatform: () => true, Plugins: { BiometricAuth: { authenticate } } };
    const { service } = setup();
    service.onPause(0);
    expect(await service.onResume(10 * 60 * 1000)).toBe(true);
    expect(authenticate).toHaveBeenCalledOnce();
    expect(mustUnlock(60_000)).toBe(false);
  });
});
