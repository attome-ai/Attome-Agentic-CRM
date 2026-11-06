import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import { DeviceSecurityService, ManagedConfigService, NativeService } from '@attome/base/native';
import { DeviceLockComponent } from './device-lock.component';

// B17-T5 — the host app starts device security only inside the phone shell:
// the MDM's lock timeout is applied, the phone is registered once signed in
// and checked for a wipe, and a refused unlock covers the app.
describe('DeviceLockComponent', () => {
  const loggedIn = signal(false);
  let security: {
    locked: ReturnType<typeof signal<boolean>>;
    start: ReturnType<typeof vi.fn>;
    appVersion: ReturnType<typeof vi.fn>;
    register: ReturnType<typeof vi.fn>;
    checkWipe: ReturnType<typeof vi.fn>;
    unlock: ReturnType<typeof vi.fn>;
    copyBlocked: ReturnType<typeof signal<boolean>>;
    refusesCopy: ReturnType<typeof vi.fn>;
  };

  function setUp(native: boolean, lockMinutes: number | null = null, blockCopy = false) {
    loggedIn.set(false);
    security = {
      locked: signal(false),
      start: vi.fn(),
      appVersion: vi.fn(async () => '1.2.3'),
      register: vi.fn(async () => 'device-1'),
      checkWipe: vi.fn(async () => false),
      unlock: vi.fn(async () => undefined),
      copyBlocked: signal(false),
      refusesCopy: vi.fn(() => true),
    };
    TestBed.configureTestingModule({
      imports: [DeviceLockComponent],
      providers: [
        { provide: DeviceSecurityService, useValue: security },
        {
          provide: ManagedConfigService,
          useValue: {
            get: async () => ({ deployment_url: null, block_copy: blockCopy, lock_timeout_minutes: lockMinutes }),
          },
        },
        { provide: NativeService, useValue: { isNative: () => native } },
        { provide: AuthService, useValue: { isLoggedIn: loggedIn } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(DeviceLockComponent);
    fixture.detectChanges();
    return fixture;
  }

  const settle = () => new Promise(resolve => setTimeout(resolve));

  it('does nothing in a browser', async () => {
    const fixture = setUp(false);
    loggedIn.set(true);
    TestBed.flushEffects();
    await settle();
    expect(security.start).not.toHaveBeenCalled();
    expect(security.register).not.toHaveBeenCalled();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-device-lock]')).toBeNull();
  });

  it("applies the MDM's lock timeout and registers once signed in", async () => {
    setUp(true, 2);
    await settle();
    expect(security.start).toHaveBeenCalledWith(120_000);
    expect(security.register).not.toHaveBeenCalled();
    loggedIn.set(true);
    TestBed.flushEffects();
    await settle();
    expect(security.register).toHaveBeenCalledWith('1.2.3');
    expect(security.checkWipe).toHaveBeenCalled();
    loggedIn.set(false);
    TestBed.flushEffects();
    loggedIn.set(true);
    TestBed.flushEffects();
    await settle();
    expect(security.register).toHaveBeenCalledTimes(1);
  });

  it('covers the app while locked and asks again on Unlock', async () => {
    const fixture = setUp(true);
    await settle();
    security.locked.set(true);
    fixture.detectChanges();
    const button = (fixture.nativeElement as HTMLElement).querySelector('[data-device-unlock]') as HTMLButtonElement;
    expect(button).not.toBeNull();
    button.click();
    expect(security.unlock).toHaveBeenCalled();
  });

  it("applies the MDM's copy block to sensitive fields", async () => {
    setUp(true, null, true);
    await settle();
    expect(security.copyBlocked()).toBe(true);
    const copy = new Event('copy', { cancelable: true });
    document.dispatchEvent(copy);
    expect(security.refusesCopy).toHaveBeenCalled();
    expect(copy.defaultPrevented).toBe(true);
  });
});
