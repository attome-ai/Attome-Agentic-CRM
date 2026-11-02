import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';

/** A notification's data as J12 sends it to a phone: only where to go. */
interface PushData {
  route?: string;
}

/** The parts of the shell's `PushNotifications` plugin the service uses. */
interface PushPlugin {
  requestPermissions(): Promise<{ receive: string }>;
  register(): Promise<void>;
  unregister?(): Promise<void>;
  addListener(
    event: 'registration' | 'pushNotificationActionPerformed',
    handler: (event: never) => void,
  ): Promise<{ remove(): Promise<void> }> | { remove(): Promise<void> };
}

/** Where the push subscription id is kept. */
export const PUSH_SUBSCRIPTION_KEY = 'attome.push-subscription';

/** The approval request a notification's route opens, if it is one. Pure. */
export function approvalIdOf(route: string | undefined): string | null {
  const match = /^\/xrm\/approvals\/requests\/([0-9a-f-]{36})(?:[/?#]|$)/i.exec(route ?? '');
  return match ? match[1] : null;
}

/** Whether a route is one of the app's own (never another site). Pure. */
export function isAppRoute(route: string | undefined): route is string {
  return !!route && route.startsWith('/') && !route.startsWith('//');
}

/**
 * B17-T8 — push notifications in the phone app. After sign-in it asks for
 * permission once, registers the shell's push token with J12
 * (`POST /api/v1/push/subscriptions`, with the device id from B17-T4) and
 * keeps the subscription id. A notification carries only a route: tapping it
 * opens that route in the app, under the person's own session, so nothing is
 * shown that their access does not allow. The `approve` action decides the
 * approval the route names through the ordinary decide route, which checks
 * the person's permission again. Signing out removes the subscription. In a
 * browser there is no bridge and this does nothing (browsers use Web Push).
 */
@Injectable({ providedIn: 'root' })
export class PushService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  /** The shell's push plugin, inside the shell. */
  protected plugin(): PushPlugin | undefined {
    const bridge = (globalThis as {
      Capacitor?: { isNativePlatform?: () => boolean; Plugins?: { PushNotifications?: PushPlugin } };
    }).Capacitor;
    return bridge?.isNativePlatform?.() ? bridge.Plugins?.PushNotifications : undefined;
  }

  /** Asks once, registers the token with J12, and listens for taps. */
  async start(deviceId: string | null, platform: 'ios' | 'android'): Promise<boolean> {
    const push = this.plugin();
    if (!push) return false;
    const permission = await push.requestPermissions();
    if (permission.receive !== 'granted') return false;
    await push.addListener('registration', ((token: { value: string }) => {
      void this.subscribe(token.value, deviceId, platform);
    }) as (event: never) => void);
    await push.addListener('pushNotificationActionPerformed', ((action: {
      actionId: string;
      notification: { data?: PushData };
    }) => {
      void this.onAction(action.actionId, action.notification.data ?? {});
    }) as (event: never) => void);
    await push.register();
    return true;
  }

  /** Sends the token to J12 and keeps the subscription id. */
  async subscribe(token: string, deviceId: string | null, platform: 'ios' | 'android'): Promise<void> {
    const answer = await firstValueFrom(
      this.http.post<{ id: string }>('/api/v1/push/subscriptions', { platform, token, device_id: deviceId }),
    );
    try {
      localStorage.setItem(PUSH_SUBSCRIPTION_KEY, answer.id);
    } catch {
      // Not kept: the subscription stays until the provider reports it gone.
    }
  }

  /** A tap or an action button on a notification. */
  async onAction(actionId: string, data: PushData): Promise<void> {
    const approval = approvalIdOf(data.route);
    if (actionId === 'approve' && approval) {
      const detail = await firstValueFrom(
        this.http.get<{ row_version: number }>(`/api/v1/approvals/${approval}`),
      );
      await firstValueFrom(
        this.http.post(`/api/v1/approvals/${approval}/decide`, {
          decision: 'approve',
          row_version: detail.row_version,
        }),
      );
      return;
    }
    if (isAppRoute(data.route)) {
      await this.router.navigateByUrl(data.route);
    }
  }

  /** On sign-out: the subscription goes, and the shell stops receiving. */
  async stop(): Promise<void> {
    let id: string | null;
    try {
      id = localStorage.getItem(PUSH_SUBSCRIPTION_KEY);
      localStorage.removeItem(PUSH_SUBSCRIPTION_KEY);
    } catch {
      id = null;
    }
    if (id) {
      try {
        await firstValueFrom(this.http.delete(`/api/v1/push/subscriptions/${id}`));
      } catch {
        // Already gone on the server.
      }
    }
    await this.plugin()?.unregister?.();
  }
}
