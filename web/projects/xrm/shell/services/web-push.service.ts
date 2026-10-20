import { inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { SwPush } from '@angular/service-worker';
import { ApiService } from '@attome/base';
import { firstValueFrom } from 'rxjs';

/** Where this browser keeps the id of its push address, to remove it later. */
const ADDRESS_KEY = 'attome-push-address';

/** `GET /api/v1/push/vapid-public-key`. */
interface VapidKey {
  public_key: string;
}

/** The `navigator` badge calls, where the browser has them. */
interface BadgeNavigator {
  setAppBadge?: (count?: number) => Promise<void>;
  clearAppBadge?: () => Promise<void>;
}

/**
 * B19-T2 — browser push and the app badge. `enable` asks the browser for a
 * push subscription under the server's VAPID key (J12) and registers it as
 * this person's push address (`POST /api/v1/push/subscriptions`); `disable`
 * removes it. A push the person taps opens its record: the service worker
 * does that while the app is closed, and `watchClicks` while it is open.
 * `setBadge` shows the unread count on the installed app's icon.
 *
 * Without a service worker (a development build, an unsupported browser)
 * `supported` is false and nothing is asked.
 */
@Injectable({ providedIn: 'root' })
export class WebPushService {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly sw = inject(SwPush, { optional: true });

  /** Whether this browser has a push address registered. */
  readonly enabled = signal(this.storedAddress() !== null);
  private watching = false;

  get supported(): boolean {
    return !!this.sw?.isEnabled && typeof Notification !== 'undefined';
  }

  /** Asks for permission and registers this browser; false when refused or unsupported. */
  async enable(): Promise<boolean> {
    if (!this.supported || !this.sw) return false;
    const key = await firstValueFrom(this.api.get<VapidKey>('/api/v1/push/vapid-public-key'));
    const subscription = await this.sw.requestSubscription({ serverPublicKey: key.public_key });
    const json = subscription.toJSON();
    const address = await firstValueFrom(this.api.post<{ id: string }>('/api/v1/push/subscriptions', {
      platform: 'web',
      endpoint: json.endpoint,
      p256dh: json.keys?.['p256dh'],
      auth: json.keys?.['auth'],
    }));
    try { localStorage.setItem(ADDRESS_KEY, address.id); } catch { /* private mode: nothing to remember */ }
    this.enabled.set(true);
    return true;
  }

  /** Removes this browser's push address and its subscription. */
  async disable(): Promise<void> {
    const id = this.storedAddress();
    if (id) {
      await firstValueFrom(this.api.delete(`/api/v1/push/subscriptions/${encodeURIComponent(id)}`)).catch(() => undefined);
    }
    try { localStorage.removeItem(ADDRESS_KEY); } catch { /* nothing stored */ }
    await this.sw?.unsubscribe().catch(() => undefined);
    this.enabled.set(false);
  }

  /** Opens a tapped push's record while the app is open (once). */
  watchClicks(): void {
    if (this.watching || !this.sw?.isEnabled) return;
    this.watching = true;
    this.sw.notificationClicks.subscribe(({ notification }) => {
      const data = notification.data as { route?: unknown } | undefined;
      // An app path only: never another site, and never `//host` (protocol-relative).
      const route = data?.route;
      if (typeof route === 'string' && route.startsWith('/') && !route.startsWith('//')) {
        void this.router.navigateByUrl(route);
      }
    });
  }

  /** The installed app's icon badge: the count, or none at zero. */
  setBadge(count: number): void {
    const nav = (typeof navigator === 'undefined' ? {} : navigator) as BadgeNavigator;
    if (count > 0) void nav.setAppBadge?.(count).catch(() => undefined);
    else void nav.clearAppBadge?.().catch(() => undefined);
  }

  private storedAddress(): string | null {
    try { return localStorage.getItem(ADDRESS_KEY); } catch { return null; }
  }
}
