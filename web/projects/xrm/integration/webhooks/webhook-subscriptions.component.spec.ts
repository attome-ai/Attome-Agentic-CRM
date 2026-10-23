import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import {
  SubscriptionDetail, SubscriptionItem, WebhookSubscriptionsComponent, createBody, replayFrom,
} from './webhook-subscriptions.component';

const ITEM: SubscriptionItem = {
  id: 's-1', name: 'ERP', kind: 'webhook', is_active: true, target_url: 'https://erp.test.local/hook',
  owner_ref: 'u-1', created_at: '2026-10-23T08:00:00Z',
};
const DETAIL: SubscriptionDetail = {
  ...ITEM, payload_shape: 'changes', ordered: true, paused_at: null, paused_reason: null,
  target_auth_header: null, row_version: 3,
};

describe('WebhookSubscriptionsComponent (M13-T4)', () => {
  function create() {
    const get = vi.fn((url: string) => {
      if (url.endsWith('/deliveries')) {
        return of({ items: [{
          id: 'd-1', event_id: 'e-1', event_entity_logicalname: 'account', event_operation: 'update',
          status: 'delivered', attempts: 1, last_error: null, response_status: 200,
          last_attempted_at: '2026-10-23T09:00:00Z', created_at: '2026-10-23T09:00:00Z',
        }] });
      }
      return url.endsWith('/s-1') ? of(DETAIL) : of({ items: [ITEM] });
    });
    const post = vi.fn((url: string, _body: unknown) =>
      of(url.endsWith('/replay') ? { queued: 4 } : { id: 's-2', webhook_secret: 'ab', webhook_secret_standard: 'whsec_q' }));
    const patch = vi.fn(() => of(DETAIL));
    TestBed.configureTestingModule({
      imports: [WebhookSubscriptionsComponent],
      providers: [
        { provide: ApiService, useValue: { get, post, patch } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(WebhookSubscriptionsComponent);
    fixture.detectChanges();
    return { fixture, get, post, patch };
  }

  it('lists webhook subscriptions and shows a selected one with its delivery log', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/events/subscriptions', { kind: 'webhook', page_size: '200' });
    fixture.componentInstance.select(ITEM);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-detail]')).not.toBeNull();
    expect(el.querySelector('[data-delivery="d-1"]')?.textContent).toContain('delivered');
  });

  it('sends a test event and replays from a time', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.select(ITEM);
    c.sendTest();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/events/subscriptions/s-1/test', {});
    c.replayAt = '2026-10-20T08:00';
    c.replay();
    const [url, body] = post.mock.calls[post.mock.calls.length - 1];
    expect(url).toBe('/api/v1/admin/events/subscriptions/s-1/replay');
    expect(typeof (body as { from: string }).from).toBe('string');
  });

  it('creates a subscription and shows its secret once', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.startNew();
    c.draft = { name: 'Billing', target_url: 'https://billing.test.local', owner_ref: 'u-1',
      payload_shape: 'id', ordered: false, is_active: true };
    c.save();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/events/subscriptions', expect.objectContaining({
      name: 'Billing', kind: 'webhook', payload_shape: 'id',
    }));
    expect(c.created()?.webhook_secret_standard).toBe('whsec_q');
  });

  it('refuses a draft without a name, an http target or an owner', () => {
    const draft = { name: 'x', target_url: 'ftp://x', owner_ref: 'u', payload_shape: 'full' as const,
      ordered: false, is_active: true };
    expect(createBody(draft)).toBeNull();
    expect(createBody({ ...draft, target_url: 'https://x' })).not.toBeNull();
    expect(replayFrom('')).toBeNull();
    expect(replayFrom('not a date')).toBeNull();
  });
});
