import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { SdkService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OnCallPage, OncallPagesComponent } from './oncall-pages.component';
import { sdkFromApi } from '../../testing/sdk-from-api';

const PAGES: OnCallPage[] = [
  { id: 'p1', ticket_id: 't1', subject: 'Major incident: payments down', paged_at: '2026-11-01T10:00:00Z', acknowledged_at: null },
  { id: 'p0', ticket_id: 't0', subject: 'Major incident: mail delayed', paged_at: '2026-10-30T10:00:00Z', acknowledged_at: '2026-10-30T10:05:00Z' },
];

describe('OncallPagesComponent (H7-T2)', () => {
  it('acknowledges an open page from the list', () => {
    const get = vi.fn((_: string, _params?: unknown) => of({ items: PAGES }));
    const post = vi.fn((_: string, _body: unknown) => of({ ...PAGES[0], acknowledged_at: '2026-11-01T10:02:00Z' }));
    TestBed.configureTestingModule({
      imports: [OncallPagesComponent],
      providers: [
        { provide: SdkService, useValue: sdkFromApi({ get, post }) },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('ar'), intlLocale: () => 'ar-SA' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(OncallPagesComponent);
    fixture.componentRef.setInput('focus', 'p1');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const items = el.querySelectorAll('[data-testid="op-list"] li');
    expect(items.length).toBe(2);
    expect(items[0].classList.contains('op-focus')).toBe(true);
    const button = items[0].querySelector('button') as HTMLButtonElement;
    button.click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/service/oncall/pages/p1/acknowledge', {});
    expect(el.querySelectorAll('[data-testid="op-list"] button').length).toBe(0);
    expect(el.textContent).toContain('oncallCalendar.pages.acknowledged');
  });
});
