import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

/** The parts of the native bridge's plugins this service uses. */
interface SecurityPlugins {
  BiometricAuth?: { authenticate(options: Record<string, unknown>): Promise<void> };
  PrivacyScreen?: { enable(): Promise<void>; disable(): Promise<void> };
  Preferences?: { clear(): Promise<void> };
  App?: {
    addListener(
      event: 'appStateChange',
      handler: (state: { isActive: boolean }) => void,
    ): Promise<{ remove(): Promise<void> }> | { remove(): Promise<void> };
    getInfo?(): Promise<{ version?: string }>;
  };
}

/** Where the device id is kept. */
export const DEVICE_ID_KEY = 'attome.device-id';
/** The lock timeout when the person has not set one. */
export const DEFAULT_LOCK_MS = 5 * 60 * 1000;

/** Whether a resume after `awayMs` in the background must unlock first. Pure. */
export function mustUnlock(awayMs: number, lockMs = DEFAULT_LOCK_MS): boolean {
  return awayMs > lockMs;
}

/** Whether a screen showing `attributes` must hide from screenshots. Pure. */
export function needsPrivacy(attributes: readonly { is_sensitive?: boolean }[]): boolean {
  return attributes.some(a => a.is_sensitive === true);
}

/**
 * B17-T5 — the phone app's device security, through the shell's native
 * bridge (`window.Capacitor`, as `NativeService`): it registers the device
 * once after sign-in (`POST /api/v1/devices`, the id kept), asks for the
 * fingerprint, face or device PIN on a resume after the lock timeout, checks
 * on every resume whether an administrator asked to wipe the device
 * (`GET /api/v1/devices/me/{id}`) and then clears every local store, reports
 * it (`.../wiped`) and signs out, and turns the privacy screen on while a
 * sensitive record is shown. In a browser there is no bridge: no lock and no
 * privacy screen, while registration and the wipe check still work.
 */
@Injectable({ providedIn: 'root' })
export class DeviceSecurityService {
  private readonly http = inject(HttpClient);
  private backgroundAt: number | null = null;
  private lockMs = DEFAULT_LOCK_MS;
  private listening = false;

  /** Whether the app's content is covered until the person unlocks. */
  readonly locked = signal(false);

  /**
   * Starts following the shell's pause and resume (the `App` plugin's
   * `appStateChange`) with `lockMs` as the lock timeout (an MDM's
   * `lock_timeout_minutes`, or the default). Once per app run; nothing in a
   * browser. While locked, every resume asks to unlock again, however short
   * the time away.
   */
  start(lockMs = DEFAULT_LOCK_MS): void {
    this.lockMs = lockMs > 0 ? lockMs : DEFAULT_LOCK_MS;
    const app = this.plugins()?.App;
    if (!app || this.listening) return;
    this.listening = true;
    void app.addListener('appStateChange', state => {
      if (!state.isActive) {
        this.onPause();
        return;
      }
      if (this.locked()) {
        void this.unlock();
        return;
      }
      void this.onResume(Date.now(), this.lockMs).then(shown => this.locked.set(!shown));
    });
  }

  /** The shell's own version, for registration; `unknown` without one. */
  async appVersion(): Promise<string> {
    try {
      return (await this.plugins()?.App?.getInfo?.())?.version || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Asks for the fingerprint, face or device PIN again after a refused
   * unlock; the wipe check follows a good one.
   */
  async unlock(): Promise<void> {
    const biometric = this.plugins()?.BiometricAuth;
    if (biometric) {
      try {
        await biometric.authenticate({ reason: 'Unlock Attome', allowDeviceCredential: true });
      } catch {
        this.locked.set(true);
        return;
      }
    }
    this.locked.set(false);
    await this.checkWipe();
  }

  /** The bridge's plugins, inside the shell. */
  protected plugins(): SecurityPlugins | undefined {
    const bridge = (globalThis as { Capacitor?: { isNativePlatform?: () => boolean; Plugins?: SecurityPlugins } })
      .Capacitor;
    return bridge?.isNativePlatform?.() ? bridge.Plugins : undefined;
  }

  /** The device id this app was given, if any. */
  deviceId(): string | null {
    try {
      return localStorage.getItem(DEVICE_ID_KEY);
    } catch {
      return null;
    }
  }

  /** Registers (or refreshes) this device after sign-in; its id. */
  async register(appVersion: string, appKind: 'standard' | 'branded' | 'pwa' = 'standard'): Promise<string> {
    const platform = this.plugins() ? (/iphone|ipad/i.test(navigator.userAgent) ? 'ios' : 'android') : 'web';
    const answer = await firstValueFrom(
      this.http.post<{ id: string }>('/api/v1/devices', {
        id: this.deviceId(),
        platform,
        app_kind: this.plugins() ? appKind : 'pwa',
        app_version: appVersion,
      }),
    );
    try {
      localStorage.setItem(DEVICE_ID_KEY, answer.id);
    } catch {
      // Not kept: the next sign-in registers again.
    }
    return answer.id;
  }

  /** The app went to the background. */
  onPause(now = Date.now()): void {
    this.backgroundAt = now;
  }

  /**
   * The app came back: unlock first when it was away longer than `lockMs`,
   * then the wipe check. Whether the content may show.
   */
  async onResume(now = Date.now(), lockMs = DEFAULT_LOCK_MS): Promise<boolean> {
    const away = this.backgroundAt === null ? 0 : now - this.backgroundAt;
    this.backgroundAt = null;
    if (mustUnlock(away, lockMs)) {
      const biometric = this.plugins()?.BiometricAuth;
      if (biometric) {
        try {
          await biometric.authenticate({ reason: 'Unlock Attome', allowDeviceCredential: true });
        } catch {
          return false;
        }
      }
    }
    await this.checkWipe();
    return true;
  }

  /** Wipes this device when an administrator asked; whether it did. */
  async checkWipe(): Promise<boolean> {
    const id = this.deviceId();
    if (!id) return false;
    let status: { wipe: boolean };
    try {
      status = await firstValueFrom(this.http.get<{ wipe: boolean }>(`/api/v1/devices/me/${id}`));
    } catch {
      return false;
    }
    if (!status.wipe) return false;
    await this.clearLocalData();
    try {
      await firstValueFrom(this.http.post(`/api/v1/devices/me/${id}/wiped`, {}));
    } catch {
      // The server asks again on the next resume; the data is gone already.
    }
    try {
      await firstValueFrom(this.http.post('/api/v1/auth/logout', {}));
    } catch {
      // Signed out locally below either way.
    }
    this.signedOut();
    return true;
  }

  /** Clears IndexedDB, Cache Storage, local storage and Preferences. */
  protected async clearLocalData(): Promise<void> {
    const idb = globalThis.indexedDB as (IDBFactory & { databases?: () => Promise<{ name?: string }[]> }) | undefined;
    if (idb?.databases) {
      for (const db of await idb.databases()) {
        if (db.name) idb.deleteDatabase(db.name);
      }
    }
    const caches = (globalThis as { caches?: CacheStorage }).caches;
    if (caches) {
      for (const key of await caches.keys()) await caches.delete(key);
    }
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // Storage may be blocked; nothing was kept there then.
    }
    await this.plugins()?.Preferences?.clear();
  }

  /** After a wipe: back to the start, signed out. */
  protected signedOut(): void {
    location.assign('/');
  }

  /** Hides the screen from screenshots and the task switcher, or shows it again. */
  async privacy(on: boolean): Promise<void> {
    const screen = this.plugins()?.PrivacyScreen;
    if (!screen) return;
    await (on ? screen.enable() : screen.disable());
  }

  /** The privacy screen for a record showing `attributes`. */
  async privacyFor(attributes: readonly { is_sensitive?: boolean }[]): Promise<void> {
    await this.privacy(needsPrivacy(attributes));
  }
}
