import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ChangeFeedService } from '@attome/xrm/core/admin/data';

import { ChangeConsumersComponent, lagText } from './change-consumers.component';

describe('ChangeConsumersComponent (L7-T7)', () => {
  it('lists consumers with an expired chip', () => {
    const listConsumers = vi.fn(() => of({ items: [
      {
        consumer: 'attome-search/index', kind: 'internal', status: 'active', lag_events: 0,
        lag_seconds: 0, last_read_at: '2026-10-15T08:00:00Z', last_event_at: null, max_lag_hours: 720,
      },
      {
        consumer: 'webhook:erp', kind: 'external', status: 'expired', lag_events: 4200,
        lag_seconds: 700_000, last_read_at: '2026-10-01T08:00:00Z', last_event_at: null, max_lag_hours: 168,
      },
    ] }));
    TestBed.configureTestingModule({
      imports: [ChangeConsumersComponent],
      providers: [
        { provide: ChangeFeedService, useValue: { listConsumers } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(ChangeConsumersComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-consumer]').length).toBe(2);
    const expired = el.querySelector('[data-consumer="webhook:erp"] .cc-chip');
    expect(expired?.classList.contains('cc-expired')).toBe(true);
    expect(el.querySelector('[data-consumer="webhook:erp"]')?.textContent).toContain('8 d');
  });

  it('writes lag in the largest whole unit', () => {
    expect(lagText(0)).toBe('0 s');
    expect(lagText(59)).toBe('59 s');
    expect(lagText(600)).toBe('10 min');
    expect(lagText(7200)).toBe('2 h');
    expect(lagText(172_800)).toBe('2 d');
  });
});
