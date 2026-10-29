import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OfferToastComponent, currentOffer, secondsLeft, type WorkOffer } from './offer-toast.component';

const offer = (id: string, expires: string, status = 'offered'): WorkOffer => ({
  id, item_id: `i-${id}`, queue_id: 'q1', channel: 'chat', status, offered_at: '2026-10-27T10:00:00Z',
  expires_at: expires, record_entity: 'service_ticket', record_id: `t-${id}`,
});

describe('work offer toast (J10-T2)', () => {
  const now = Date.parse('2026-10-27T10:00:10Z');

  it('counts down to the offer\'s expiry and shows the soonest open one', () => {
    expect(secondsLeft('2026-10-27T10:00:30Z', now)).toBe(20);
    expect(secondsLeft('2026-10-27T10:00:05Z', now)).toBe(0);
    expect(secondsLeft('not a time', now)).toBe(0);
    const shown = currentOffer([
      offer('late', '2026-10-27T10:00:40Z'),
      offer('soon', '2026-10-27T10:00:20Z'),
      offer('gone', '2026-10-27T10:00:01Z'),
      offer('taken', '2026-10-27T10:00:15Z', 'accepted'),
    ], now);
    expect(shown?.id).toBe('soon');
    expect(currentOffer([], now)).toBeNull();
  });

  function create(offers: WorkOffer[]) {
    const get = vi.fn(() => of({ items: offers, total: offers.length, page: 1, page_size: 50 }));
    const post = vi.fn((url: string) => of({ ...offers[0], status: url.endsWith('/accept') ? 'accepted' : 'declined' }));
    TestBed.configureTestingModule({
      imports: [OfferToastComponent],
      providers: [
        { provide: ApiService, useValue: { getBackground: get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: signal(false), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(OfferToastComponent);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, get, post };
  }

  it('accepting takes the offer and opens its record as a session', () => {
    const expires = new Date(Date.now() + 25_000).toISOString();
    const { fixture, cmp, el, post } = create([offer('o1', expires)]);
    expect(el.querySelector('[data-offer="o1"]')).not.toBeNull();
    const opened = vi.fn();
    cmp.accepted.subscribe(opened);
    (el.querySelector('[data-testid="offer-accept"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/queue-offers/o1/accept', {});
    expect(opened).toHaveBeenCalledWith({ entity: 'service_ticket', recordId: 't-o1', title: 'serviceOffer.channel.chat' });
    expect(el.querySelector('[data-offer]')).toBeNull();
  });

  it('declining passes the offer on', () => {
    const expires = new Date(Date.now() + 25_000).toISOString();
    const { fixture, el, post } = create([offer('o2', expires)]);
    (el.querySelector('[data-testid="offer-decline"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/queue-offers/o2/decline', {});
    expect(el.querySelector('[data-offer]')).toBeNull();
  });
});
