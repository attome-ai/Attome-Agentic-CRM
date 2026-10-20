import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { SwPush } from '@angular/service-worker';
import { ApiService } from '@attome/base';
import { of, Subject } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { WebPushService } from './web-push.service';

describe('WebPushService (B19-T2)', () => {
  afterEach(() => {
    localStorage.clear();
    vi.unstubAllGlobals();
  });

  function setUp(swEnabled = true) {
    // jsdom has no Notification; a browser that can push does.
    vi.stubGlobal('Notification', class {});
    const clicks = new Subject<{ action: string; notification: NotificationOptions & { title: string } }>();
    const sw = {
      isEnabled: swEnabled,
      requestSubscription: vi.fn(async () => ({
        toJSON: () => ({ endpoint: 'https://push.example/abc', keys: { p256dh: 'pk', auth: 'au' } }),
      })),
      unsubscribe: vi.fn(async () => undefined),
      notificationClicks: clicks,
    };
    const api = {
      get: vi.fn(() => of({ public_key: 'vapid-key' })),
      post: vi.fn(() => of({ id: 'addr-1' })),
      delete: vi.fn(() => of(undefined)),
    };
    const router = { navigateByUrl: vi.fn(async () => true) };
    TestBed.configureTestingModule({
      providers: [
        { provide: SwPush, useValue: sw },
        { provide: ApiService, useValue: api },
        { provide: Router, useValue: router },
      ],
    });
    return { push: TestBed.inject(WebPushService), sw, api, router, clicks };
  }

  it('subscribes under the server key and registers the address', async () => {
    const { push, sw, api } = setUp();
    expect(await push.enable()).toBe(true);
    expect(sw.requestSubscription).toHaveBeenCalledWith({ serverPublicKey: 'vapid-key' });
    expect(api.post).toHaveBeenCalledWith('/api/v1/push/subscriptions', {
      platform: 'web', endpoint: 'https://push.example/abc', p256dh: 'pk', auth: 'au',
    });
    expect(push.enabled()).toBe(true);
    expect(localStorage.getItem('attome-push-address')).toBe('addr-1');
  });

  it('removes the address and the subscription', async () => {
    const { push, sw, api } = setUp();
    await push.enable();
    await push.disable();
    expect(api.delete).toHaveBeenCalledWith('/api/v1/push/subscriptions/addr-1');
    expect(sw.unsubscribe).toHaveBeenCalled();
    expect(push.enabled()).toBe(false);
  });

  it('asks nothing without a service worker', async () => {
    const { push, sw, api } = setUp(false);
    expect(push.supported).toBe(false);
    expect(await push.enable()).toBe(false);
    expect(sw.requestSubscription).not.toHaveBeenCalled();
    expect(api.get).not.toHaveBeenCalled();
  });

  it('opens a tapped push inside the app, never an outside address', () => {
    const { push, router, clicks } = setUp();
    push.watchClicks();
    clicks.next({ action: '', notification: { title: 't', data: { route: '/xrm/entity/ticket/form/1' } } });
    clicks.next({ action: '', notification: { title: 't', data: { route: 'https://evil.example' } } });
    expect(router.navigateByUrl).toHaveBeenCalledTimes(1);
    expect(router.navigateByUrl).toHaveBeenCalledWith('/xrm/entity/ticket/form/1');
  });

  it('sets and clears the app badge', () => {
    const { push } = setUp();
    const nav = navigator as Navigator & { setAppBadge?: unknown; clearAppBadge?: unknown };
    const set = vi.fn(async () => undefined);
    const clear = vi.fn(async () => undefined);
    Object.assign(nav, { setAppBadge: set, clearAppBadge: clear });
    push.setBadge(3);
    push.setBadge(0);
    expect(set).toHaveBeenCalledWith(3);
    expect(clear).toHaveBeenCalled();
  });
});
