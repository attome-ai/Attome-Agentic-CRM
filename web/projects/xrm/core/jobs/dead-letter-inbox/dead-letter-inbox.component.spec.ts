import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import {
  DeadLetterGroup, DeadLetterInboxComponent, DeadLetterItem, trend, validRate,
} from './dead-letter-inbox.component';

const NOW = Date.parse('2026-10-23T12:00:00Z');

const GROUPS: DeadLetterGroup[] = [
  {
    cause_group: 'webhook:sub-1:timeout', source: 'webhook', step: 'sub-1', error_kind: 'timeout',
    count: 12, first_seen: '2026-10-20T08:00:00Z', last_seen: '2026-10-23T11:30:00Z',
    sample_message: 'webhook delivery timed out',
  },
];

const ITEMS: DeadLetterItem[] = [
  {
    source: 'webhook', id: 'd-1', step: 'sub-1', error_kind: 'timeout', cause_group: 'webhook:sub-1:timeout',
    message: 'webhook delivery timed out', first_seen: '2026-10-23T11:30:00Z', attempts: 8, payload_ref: null,
  },
];

describe('DeadLetterInboxComponent (M5-T3)', () => {
  function create() {
    const get = vi.fn((url: string) => of({ items: url.endsWith('/groups') ? GROUPS : ITEMS, total: 1 }));
    const post = vi.fn((_url: string, _body: unknown) =>
      of({ preview: { outcome: 'replayed', reason: null }, job_id: 'j-1', queued: 11, rate_per_minute: 30 }));
    TestBed.configureTestingModule({
      imports: [DeadLetterInboxComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(DeadLetterInboxComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists groups with their count', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/dead-letters/groups', { page_size: '200' });
    const row: HTMLElement | null = fixture.nativeElement.querySelector('[data-group="webhook:sub-1:timeout"]');
    expect(row?.textContent).toContain('12');
    expect(row?.textContent).toContain('deadLetterInbox.sources.webhook');
  });

  it('replays a group at the chosen rate', () => {
    const { fixture, post } = create();
    const component = fixture.componentInstance;
    component.rate = 30;
    component.replayGroup(GROUPS[0]);
    expect(post).toHaveBeenCalledWith('/api/v1/admin/dead-letters/groups/replay', {
      cause_group: 'webhook:sub-1:timeout', rate_per_minute: 30,
    });
    expect(component.notice()).toContain('11');
  });

  it('refuses an out-of-range rate without calling the API', () => {
    const { fixture, post } = create();
    const component = fixture.componentInstance;
    component.rate = 0;
    component.replayGroup(GROUPS[0]);
    expect(post).not.toHaveBeenCalled();
    expect(component.error()).not.toBeNull();
  });

  it('opens a group and discards an item only with a reason', () => {
    const { fixture, get, post } = create();
    const component = fixture.componentInstance;
    component.toggle(GROUPS[0]);
    expect(get).toHaveBeenCalledWith('/api/v1/admin/dead-letters', {
      group: 'webhook:sub-1:timeout', page_size: '200',
    });
    component.startDiscard(ITEMS[0]);
    component.reason = '   ';
    component.discard(ITEMS[0]);
    expect(post).not.toHaveBeenCalled();
    component.reason = 'endpoint retired';
    component.discard(ITEMS[0]);
    expect(post).toHaveBeenCalledWith('/api/v1/admin/dead-letters/webhook/d-1/discard', {
      reason: 'endpoint retired',
    });
  });

  it('marks a group new, active or quiet', () => {
    expect(trend(GROUPS[0], NOW)).toBe('active');
    expect(trend({ ...GROUPS[0], first_seen: '2026-10-23T06:00:00Z' }, NOW)).toBe('new');
    expect(trend({ ...GROUPS[0], last_seen: '2026-10-22T06:00:00Z' }, NOW)).toBe('quiet');
    expect(validRate(60)).toBe(60);
    expect(validRate(601)).toBeNull();
    expect(validRate(1.5)).toBeNull();
  });
});
