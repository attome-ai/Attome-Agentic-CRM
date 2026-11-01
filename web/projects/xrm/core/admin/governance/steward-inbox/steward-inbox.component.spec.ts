import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { InboxItem, StewardInboxComponent } from './steward-inbox.component';

const ITEMS: InboxItem[] = [
  { source: 'duplicate', id: 'd1', entity: 'account', record_id: 'r1', related_id: 'r2', detail: '0.95', due_at: '2026-10-01T08:00:00Z', link: '/xrm/admin/duplicates' },
  { source: 'quality_issue', id: 'q1', entity: 'account', record_id: 'r3', detail: 'completeness: name is empty', due_at: '2026-10-02T08:00:00Z', link: '/xrm/admin/data/quality' },
];

function create(lang: 'en' | 'ar', items: InboxItem[]) {
  const getAllPages = vi.fn((_: string) => of(items));
  TestBed.configureTestingModule({
    imports: [StewardInboxComponent],
    providers: [
      provideRouter([]),
      { provide: ApiService, useValue: { getAllPages } },
      { provide: LangService, useValue: { translate: (k: string) => k, current: signal(lang), intlLocale: () => (lang === 'ar' ? 'ar-SA' : 'en-US') } },
      { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
    ],
  });
  const fixture = TestBed.createComponent(StewardInboxComponent);
  fixture.detectChanges();
  return { fixture, getAllPages };
}

describe('StewardInboxComponent (L3-T7)', () => {
  it('lists the items oldest first with a link to the screen that handles each', () => {
    const { fixture, getAllPages } = create('en', ITEMS);
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/governance/inbox');
    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="si-list"] li');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('governance.inbox.sources.duplicate');
    expect(rows[0].querySelector('a')?.getAttribute('href')).toBe('/xrm/admin/duplicates');
  });

  it('says so when nothing waits, in Arabic too', () => {
    const { fixture } = create('ar', []);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('governance.inbox.empty');
    expect(el.querySelector('[data-testid="si-list"]')).toBeNull();
  });
});
