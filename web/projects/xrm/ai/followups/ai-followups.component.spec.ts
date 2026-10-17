import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiFollowupItem, AiFollowupsComponent, ageInDays } from './ai-followups.component';

const ITEMS: AiFollowupItem[] = [
  {
    id: 'f1', rule_id: 'r1', entity: 'opportunity', record_id: 'o1', reason: 'stalled_deal',
    status: 'open', window_start: '2026-10-12', created_at: '2026-10-14T08:00:00Z', row_version: 4,
  },
  {
    id: 'f2', rule_id: 'r1', entity: 'task', record_id: 't1', reason: 'overdue_task',
    status: 'reminded', window_start: '2026-10-12', created_at: '2026-10-16T08:00:00Z', row_version: 2,
  },
];

describe('AiFollowupsComponent (AI4-T7)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: ITEMS, total: 2, page: 1, page_size: 100 }));
    const post = vi.fn(() => of(undefined));
    TestBed.configureTestingModule({
      imports: [AiFollowupsComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(AiFollowupsComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists my open follow-ups with a link to each record', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/ai/follow-ups?page=1&page_size=100');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('li[data-item]').length).toBe(2);
    expect(el.textContent).toContain('aiFollowups.reason.stalled_deal');
    expect(el.querySelector('li[data-item="f1"] a')?.getAttribute('href')).toContain('id=o1');
  });

  it('dismisses with the row version as If-Match', () => {
    const { fixture, post } = create();
    fixture.componentInstance.dismiss(ITEMS[0]);
    expect(post).toHaveBeenCalledWith('/api/v1/ai/follow-ups/f1/dismiss', {}, { ifMatch: 4 });
  });

  it('counts whole days', () => {
    expect(ageInDays('2026-10-14T08:00:00Z', new Date('2026-10-17T09:00:00Z'))).toBe(3);
    expect(ageInDays('2026-10-18T08:00:00Z', new Date('2026-10-17T09:00:00Z'))).toBe(0);
  });
});
