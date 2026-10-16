import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ActiveBan, RateLimitBansComponent, minutesLeft } from './rate-limit-bans.component';

const BANS: ActiveBan[] = [
  { bucket: 'ip:203.0.113.9', category: 'auth', seconds_left: 610 },
  { bucket: 'user:0190-a', category: null, seconds_left: 20 },
];

describe('RateLimitBansComponent (Q20-T5)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: BANS }));
    const del = vi.fn((_: string) => of(undefined));
    TestBed.configureTestingModule({
      imports: [RateLimitBansComponent],
      providers: [
        { provide: ApiService, useValue: { get, delete: del } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(RateLimitBansComponent);
    fixture.detectChanges();
    return { fixture, get, del };
  }

  it('lists bans and lifts one by its bucket', () => {
    const { fixture, get, del } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/rate-limits/bans');
    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll('li[data-bucket]');
    expect(rows.length).toBe(2);
    fixture.componentInstance.lift(BANS[0]);
    expect(del).toHaveBeenCalledWith('/api/v1/admin/rate-limits/bans/ip%3A203.0.113.9');
  });

  it('shows whole minutes left', () => {
    expect(minutesLeft(BANS[0])).toBe(11);
    expect(minutesLeft(BANS[1])).toBe(1);
  });
});
