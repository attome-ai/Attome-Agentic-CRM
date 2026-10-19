import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BookManageComponent } from './booking-manage.component';
import { BookPageComponent } from './booking-page.component';
import { groupByDay, meetingTime, timeZones } from './booking';

const page = {
  name: 'Intro call',
  description: null,
  duration_minutes: 30,
  meeting_type: 'video',
  video_provider: 'teams',
  location: null,
  slots: [
    { start: '2026-11-03T06:00:00Z', end: '2026-11-03T06:30:00Z' },
    { start: '2026-11-02T06:30:00Z', end: '2026-11-02T07:00:00Z' },
    { start: '2026-11-02T06:00:00Z', end: '2026-11-02T06:30:00Z' },
  ],
};

const lang = {
  translate: (k: string) => k, current: () => 'en', isRtl: () => false, intlLocale: () => 'en-GB', toggle: vi.fn(),
};

describe('booking helpers (D20-T2)', () => {
  it('groups slots by the day they start on, in the reader\'s time zone', () => {
    const days = groupByDay(page.slots, 'en-GB', 'Asia/Riyadh');
    expect(days.map(d => d.key)).toEqual(['2026-11-02', '2026-11-03']);
    expect(days[0].slots.map(s => s.label)).toEqual(['09:00', '09:30']);
    expect(days[0].label).toContain('2 November');
    // Late UTC evening is the next day in Riyadh.
    expect(groupByDay([{ start: '2026-11-02T22:00:00Z', end: '2026-11-02T22:30:00Z' }], 'en-GB', 'Asia/Riyadh')[0].key)
      .toBe('2026-11-03');
    expect(meetingTime('2026-11-02T06:00:00Z', '2026-11-02T06:30:00Z', 'en-GB', 'Asia/Riyadh')).toContain('09:30');
    expect(timeZones('Asia/Riyadh', ['Africa/Cairo', 'Asia/Riyadh', 'Europe/London']))
      .toEqual(['Asia/Riyadh', 'Africa/Cairo', 'Europe/London']);
  });

  it('shows Arabic times right to left in the chosen zone', () => {
    const ar = groupByDay(page.slots, 'ar-SA-u-nu-latn', 'Asia/Riyadh');
    expect(ar[0].slots[0].label).toMatch(/9:00|09:00/);
    expect(ar[0].label).not.toBe(groupByDay(page.slots, 'en-GB', 'Asia/Riyadh')[0].label);
  });
});

describe('BookPageComponent (D20-T2)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = {
      get: vi.fn((path: string) => (path === '/api/v1/auth/challenge'
        ? throwError(() => ({ status: 404 }))
        : of(page))),
      post: vi.fn(() => of({ booking_id: 'b1', start: page.slots[2].start, end: page.slots[2].end, manage_token: 't' })),
    };
    TestBed.configureTestingModule({
      imports: [BookPageComponent, BookManageComponent],
      providers: [{ provide: ApiService, useValue: api }, { provide: LangService, useValue: lang }],
    });
  });

  it('lists the free times and books the chosen one', async () => {
    const fixture = TestBed.createComponent(BookPageComponent);
    fixture.componentRef.setInput('slug', 'intro');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/booking/intro');
    expect(el.querySelectorAll('[data-testid="book-slot"]').length).toBe(3);

    const cmp = fixture.componentInstance;
    cmp.choose(page.slots[2].start);
    cmp.name = 'Sara';
    cmp.email = 'sara@example.sa';
    await cmp.book();
    expect(api.post).toHaveBeenCalledWith('/api/v1/booking/intro', expect.objectContaining({
      start: '2026-11-02T06:00:00Z', name: 'Sara', email: 'sara@example.sa', captcha_token: undefined,
    }));
    expect(cmp.stage()).toBe('booked');
  });

  it('says the meeting type, and re-labels the times when the visitor picks another zone', () => {
    const fixture = TestBed.createComponent(BookPageComponent);
    fixture.componentRef.setInput('slug', 'intro');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="book-type"]')?.textContent).toContain('book.meetingType.video');
    expect(el.querySelector('[data-testid="book-type"]')?.textContent).toContain('book.provider.teams');
    const cmp = fixture.componentInstance;
    cmp.zone.set('Asia/Riyadh');
    fixture.detectChanges();
    expect(cmp.days()[0].slots[0].label).toBe('09:00');
    cmp.zone.set('Europe/London');
    fixture.detectChanges();
    expect(cmp.days()[0].slots[0].label).toBe('06:00');
  });

  it('lays the page out right to left in Arabic', () => {
    TestBed.overrideProvider(LangService, { useValue: { ...lang, current: () => 'ar', isRtl: () => true, intlLocale: () => 'ar' } });
    const fixture = TestBed.createComponent(BookPageComponent);
    fixture.componentRef.setInput('slug', 'intro');
    fixture.detectChanges();
    const main = (fixture.nativeElement as HTMLElement).querySelector('main');
    expect(main?.getAttribute('dir')).toBe('rtl');
    expect(main?.getAttribute('lang')).toBe('ar');
  });

  it('shows the remaining times when someone booked it first', async () => {
    api.post.mockReturnValue(throwError(() => ({ status: 409 })));
    const fixture = TestBed.createComponent(BookPageComponent);
    fixture.componentRef.setInput('slug', 'intro');
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    cmp.choose(page.slots[0].start);
    cmp.name = 'Sara';
    cmp.email = 'sara@example.sa';
    await cmp.book();
    expect(cmp.stage()).toBe('taken');
    expect(cmp.chosen()).toBeNull();
    expect(api.get.mock.calls.filter(c => c[0] === '/api/v1/booking/intro').length).toBe(2);
  });

  it('manage link cancels the booking', () => {
    api.get.mockImplementation(() => of({
      page_name: 'Intro call', slug: 'intro', start: page.slots[0].start, end: page.slots[0].end, status: 'booked',
    }));
    api.post.mockReturnValue(of({
      page_name: 'Intro call', slug: 'intro', start: page.slots[0].start, end: page.slots[0].end, status: 'cancelled',
    }));
    const fixture = TestBed.createComponent(BookManageComponent);
    fixture.componentRef.setInput('token', 'abc.def');
    fixture.detectChanges();
    fixture.componentInstance.cancel();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/booking/manage/abc.def/cancel', {});
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="manage-cancelled"]')).not.toBeNull();
  });
});
