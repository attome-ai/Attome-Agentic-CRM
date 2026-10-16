import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ConsumerHealth, EventsMonitorComponent, isLagging, lagText } from './events-monitor.component';

const CONSUMERS: ConsumerHealth[] = [
  {
    consumer: 'attome-search/index', kind: 'internal', status: 'active', lag_events: 0, lag_seconds: 2,
    last_read_at: '2026-10-16T08:00:00Z', last_event_at: '2026-10-16T08:00:00Z', max_lag_hours: 720,
  },
  {
    consumer: 'attome-workflow/entry', kind: 'internal', status: 'active', lag_events: 40, lag_seconds: 900,
    last_read_at: '2026-10-16T07:45:00Z', last_event_at: '2026-10-16T07:45:00Z', max_lag_hours: 720,
  },
];

describe('EventsMonitorComponent (Y7-T6)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: CONSUMERS }));
    TestBed.configureTestingModule({
      imports: [EventsMonitorComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(EventsMonitorComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('lists consumers with the lagging one first and flagged', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/change-feed/consumers');
    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr');
    expect(rows[0].getAttribute('data-consumer')).toBe('attome-workflow/entry');
    expect(rows[0].classList.contains('em-lagging')).toBe(true);
    expect(rows[1].classList.contains('em-lagging')).toBe(false);
  });

  it('formats lag and flags past five minutes', () => {
    expect(lagText(45)).toBe('45s');
    expect(lagText(900)).toBe('15m');
    expect(lagText(7200)).toBe('2h');
    expect(isLagging(CONSUMERS[0])).toBe(false);
    expect(isLagging(CONSUMERS[1])).toBe(true);
    expect(isLagging({ ...CONSUMERS[0], status: 'expired' })).toBe(true);
  });
});
