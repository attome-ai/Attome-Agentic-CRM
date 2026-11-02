import { Injectable } from '@angular/core';

/** The managed configuration keys the app reads. */
export interface ManagedConfig {
  /** Opens this deployment directly; the connect page is skipped. */
  deployment_url: string | null;
  /** Disables copying sensitive fields to the clipboard. */
  block_copy: boolean;
  /** The lock timeout, overriding the person's. */
  lock_timeout_minutes: number | null;
}

/** The parts of a managed-configuration plugin the service uses. */
interface ManagedPlugin {
  getString(options: { key: string }): Promise<{ value: string | null }>;
  getBoolean?(options: { key: string }): Promise<{ value: boolean | null }>;
  getNumber?(options: { key: string }): Promise<{ value: number | null }>;
}

/** A managed deployment address worth opening: https only. Pure. */
export function managedAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' ? url.origin : null;
  } catch {
    return null;
  }
}

/**
 * B17-T9 — what an MDM (Intune and others) pushes to the phone app: Android's
 * restrictions or iOS's `com.apple.configuration.managed`, read through the
 * shell's managed-configuration plugin over the native bridge
 * (`ManagedConfigurations`). `deployment_url` opens that deployment and skips
 * the connect page (`mobile/www/connect.js` reads the same key),
 * `block_copy` turns off copying sensitive fields, and
 * `lock_timeout_minutes` sets the lock timeout. In a browser, or without
 * the plugin, nothing is managed.
 */
@Injectable({ providedIn: 'root' })
export class ManagedConfigService {
  protected plugin(): ManagedPlugin | undefined {
    const bridge = (globalThis as {
      Capacitor?: { isNativePlatform?: () => boolean; Plugins?: { ManagedConfigurations?: ManagedPlugin } };
    }).Capacitor;
    return bridge?.isNativePlatform?.() ? bridge.Plugins?.ManagedConfigurations : undefined;
  }

  /** The managed configuration, with nothing managed as the default. */
  async get(): Promise<ManagedConfig> {
    const plugin = this.plugin();
    const none: ManagedConfig = { deployment_url: null, block_copy: false, lock_timeout_minutes: null };
    if (!plugin) return none;
    try {
      const url = await plugin.getString({ key: 'deployment_url' });
      const copy = plugin.getBoolean ? await plugin.getBoolean({ key: 'block_copy' }) : { value: null };
      const lock = plugin.getNumber ? await plugin.getNumber({ key: 'lock_timeout_minutes' }) : { value: null };
      return {
        deployment_url: managedAddress(url.value),
        block_copy: copy.value === true,
        lock_timeout_minutes: typeof lock.value === 'number' && lock.value > 0 ? lock.value : null,
      };
    } catch {
      return none;
    }
  }
}
