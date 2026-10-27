import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService, LiveChannel, UserPreferencesService } from '@attome/base';
import { of, Subject, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WorkforceApiService } from '../workforce-api.service';
import type { AssignmentView } from '../workforce-api.service';
import { addDays, dayKey, MyScheduleComponent, scheduleByDay } from './my-schedule.component';

function shift(id: string, start: string, end: string): AssignmentView {
  return { id, start_at: start, end_at: end, activity: 'work', booking_id: null, row_version: 1, user_id: 'me' };
}

describe('MyScheduleComponent (G17-T14)', () => {
  let api: Record<string, ReturnType<typeof vi.fn>>;
  let live: { watch: ReturnType<typeof vi.fn>; records: Subject<unknown>; notifications: Subject<number> };

  beforeEach(() => {
    api = {
      mySchedule: vi.fn(() => of([
        shift('a', '2026-11-02T13:00:00Z', '2026-11-02T21:00:00Z'),
        shift('b', '2026-11-01T05:00:00Z', '2026-11-01T13:00:00Z'),
      ])),
      openOffers: vi.fn(() => of([
        { id: 'o-1', kind: 'overtime', status: 'sent', start_at: '2026-11-01T14:00:00Z', end_at: '2026-11-01T16:00:00Z', people: 1, reason: null },
      ])),
      users: vi.fn(() => of([{ id: 'u-2', label: 'Sara' }])),
      giveAway: vi.fn(() => of({ swap_id: 's-1', status: 'requested', waiting_because: 'needs approval' })),
      acceptOffer: vi.fn(() => throwError(() => ({ status: 409, kind: 'conflict', message: 'taken' }))),
    };
    live = { watch: vi.fn(() => () => undefined), records: new Subject(), notifications: new Subject<number>() };
    TestBed.configureTestingModule({
      imports: [MyScheduleComponent],
      providers: [
        provideRouter([]),
        { provide: WorkforceApiService, useValue: api },
        { provide: LiveChannel, useValue: live },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US', current: () => 'en',
            translate: (k: string, p?: Record<string, unknown>) => (p ? `${k} ${JSON.stringify(p)}` : k),
            errorText: (e: { message: string }) => e.message,
          },
        },
        {
          provide: UserPreferencesService,
          useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null },
        },
      ],
    });
  });

  afterEach(() => {
    document.documentElement.removeAttribute('dir');
  });

  function render(dir: 'ltr' | 'rtl') {
    document.documentElement.setAttribute('dir', dir);
    const fixture = TestBed.createComponent(MyScheduleComponent);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('lists the shifts by day, in time order, and the open offers', () => {
    const { el } = render('ltr');
    const days = [...el.querySelectorAll('[data-day]')].map(d => d.getAttribute('data-day'));
    expect(days).toEqual(['2026-11-01', '2026-11-02']);
    expect(el.querySelector('[data-offer="o-1"]')?.textContent).toContain('xrm.workforce.me.overtime');
    expect(el.querySelector('[data-leave-link]')?.getAttribute('href')).toBe('/xrm/entity/leave_request/form');
  });

  it('gives a shift to a colleague and says when it waits for approval', () => {
    const { el, fixture, cmp } = render('rtl');
    (el.querySelector('[data-give="b"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const select = el.querySelector('[data-give-to]') as HTMLSelectElement;
    select.value = 'u-2';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    (el.querySelector('[data-give-confirm]') as HTMLButtonElement).click();
    expect(api['giveAway']).toHaveBeenCalledWith('b', 'u-2', null);
    expect(cmp.notice()).toBe('xrm.workforce.me.giveWaiting');
  });

  it('says an offer was taken by someone else', () => {
    const { el, cmp } = render('rtl');
    (el.querySelector('[data-accept="o-1"]') as HTMLButtonElement).click();
    expect(api['acceptOffer']).toHaveBeenCalledWith('o-1');
    expect(cmp.error()).toBe('xrm.workforce.me.taken');
  });

  it('reloads when a notification or a watched record arrives', () => {
    render('ltr');
    expect(live.watch).toHaveBeenCalledWith('wfm_assignment');
    expect(live.watch).toHaveBeenCalledWith('wfm_offer');
    const before = api['mySchedule'].mock.calls.length;
    live.notifications.next(3);
    live.records.next({ changes: [] });
    expect(api['mySchedule'].mock.calls.length).toBe(before + 2);
  });

  it('renders the same in right-to-left at 360 px', () => {
    const { el } = render('rtl');
    el.style.inlineSize = '360px';
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
    expect(el.querySelectorAll('[data-shift]').length).toBe(2);
    expect(el.querySelector('[data-accept="o-1"]')).not.toBeNull();
  });

  it('groups by the person\'s day and counts days purely', () => {
    expect(dayKey('2026-11-01T22:30:00Z', 'Asia/Riyadh')).toBe('2026-11-02');
    expect(dayKey('2026-11-01T22:30:00Z', 'UTC')).toBe('2026-11-01');
    expect(scheduleByDay([shift('x', '2026-11-01T22:30:00Z', '2026-11-02T02:00:00Z')], 'Asia/Riyadh')[0].day).toBe('2026-11-02');
    expect(addDays(new Date('2026-12-30T10:00:00Z'), 3)).toBe('2027-01-02');
  });
});
