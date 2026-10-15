import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DeployEvent, DeploysComponent, durationSeconds } from './deploys.component';

const EVENTS: DeployEvent[] = [
  {
    id: 'a', node: 'web-1:7865', version: '2.0.1', kind: 'drain', started_by: 'ops',
    started_at: '2026-10-15T08:00:00Z', finished_at: '2026-10-15T08:00:12Z', failed_requests: 3,
  },
  {
    id: 'b', node: 'web-1:7865', version: '2.0.1', kind: 'start', started_by: null,
    started_at: '2026-10-15T08:01:00Z', finished_at: '2026-10-15T08:01:04Z', failed_requests: null,
  },
];

describe('DeploysComponent (AB7-T9)', () => {
  function create() {
    const get = vi.fn((path: string) => of({ items: path.endsWith('/deploys') ? EVENTS : [] }));
    TestBed.configureTestingModule({
      imports: [DeploysComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(DeploysComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('highlights deploy with failed requests', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/deploys');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-deploy="a"]')?.classList.contains('dp-failed')).toBe(true);
    expect(el.querySelector('[data-deploy="b"]')?.classList.contains('dp-failed')).toBe(false);
    expect(el.querySelector('[data-deploy="a"]')?.textContent).toContain('12 s');
  });

  it('a running step has no duration', () => {
    expect(durationSeconds({ ...EVENTS[0], finished_at: null })).toBeNull();
    expect(durationSeconds(EVENTS[1])).toBe(4);
  });
});
