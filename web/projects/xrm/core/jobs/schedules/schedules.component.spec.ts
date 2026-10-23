import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ScheduleItem, SchedulesComponent, quietWindowsOf } from './schedules.component';

const ITEMS: ScheduleItem[] = [
  {
    kind: 'flow', id: 'd-1:trigger', name: 'Nightly renewals', owner: 'sara', schedule: '0 2 * * *',
    next_run_at: '2026-10-24T02:00:00Z', last_run_at: '2026-10-23T02:00:00Z', last_result: 'started',
    paused: false, can_pause: true,
  },
  {
    kind: 'platform', id: 'dead-letter-sweep', name: 'dead-letter-sweep', owner: null, schedule: 'every 3600 s',
    next_run_at: '2026-10-23T12:00:00Z', last_run_at: null, last_result: null, paused: false, can_pause: false,
  },
];

describe('SchedulesComponent (M12-T3)', () => {
  function create() {
    const get = vi.fn((url: string) => of(url.endsWith('/schedules')
      ? { items: ITEMS, total: 2 }
      : { items: [{ key: 'jobs.quiet_windows', value: [{ start: '08:00', end: '18:00' }] }] }));
    const post = vi.fn((_url: string, _body: unknown) => of({}));
    const put = vi.fn((_url: string, _body: unknown) => of({}));
    TestBed.configureTestingModule({
      imports: [SchedulesComponent],
      providers: [
        { provide: ApiService, useValue: { get, post, put } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(SchedulesComponent);
    fixture.detectChanges();
    return { fixture, get, post, put };
  }

  it('lists every schedule with its owner', () => {
    const { fixture } = create();
    const flow: HTMLElement | null = fixture.nativeElement.querySelector('[data-schedule="flow:d-1:trigger"]');
    expect(flow?.textContent).toContain('Nightly renewals');
    expect(flow?.textContent).toContain('sara');
    expect(fixture.nativeElement.querySelector('[data-schedule="platform:dead-letter-sweep"]')).not.toBeNull();
  });

  it('offers no pause for a platform scheduler', () => {
    const { fixture } = create();
    const platform: HTMLElement = fixture.nativeElement.querySelector('[data-schedule="platform:dead-letter-sweep"]');
    expect(platform.querySelector('.sc-pause')).toBeNull();
    expect(platform.textContent).toContain('schedules.readOnly');
  });

  it('pauses a flow schedule', () => {
    const { fixture, post } = create();
    fixture.componentInstance.setPaused(ITEMS[0], true);
    expect(post).toHaveBeenCalledWith('/api/v1/admin/schedules/flow/d-1%3Atrigger/pause', {});
    expect(fixture.componentInstance.items()[0].paused).toBe(true);
  });

  it('filters by kind', () => {
    const { fixture } = create();
    fixture.componentInstance.kind.set('platform');
    expect(fixture.componentInstance.shown().map(s => s.kind)).toEqual(['platform']);
  });

  it('saves the quiet windows as a deployment setting', () => {
    const { fixture, put } = create();
    expect(fixture.componentInstance.windows()).toEqual([{ start: '08:00', end: '18:00' }]);
    fixture.componentInstance.addWindow();
    fixture.componentInstance.saveWindows();
    expect(put).toHaveBeenCalledWith('/api/v1/admin/settings/jobs.quiet_windows', {
      scope: 'deployment', scope_ref: null, value: [{ start: '08:00', end: '18:00' }, { start: '08:00', end: '18:00' }],
    });
  });

  it('reads only well-formed windows', () => {
    expect(quietWindowsOf([{ start: '23:00', end: '01:00' }, { start: '25:00', end: '01:00' }, 'x'])).toEqual([
      { start: '23:00', end: '01:00' },
    ]);
    expect(quietWindowsOf(null)).toEqual([]);
  });
});
