import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { LocalDatePipe, localeTag } from './local-date.pipe';
import { UserPreferencesService } from './user-preferences.service';
import { ATTOME_CONFIG } from './config';
import { provideAttomeI18n } from './provide';

describe('LocalDatePipe', () => {
  afterEach(() => localStorage.clear());

  // A fixed instant so the formatted output is deterministic regardless of
  // the machine running the test: 2026-08-27T12:00:00Z.
  const instant = '2026-08-27T12:00:00Z';

  function setUp() {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
      ],
    });
    const prefs = TestBed.inject(UserPreferencesService);
    const pipe = TestBed.runInInjectionContext(() => new LocalDatePipe());
    return { pipe, prefs };
  }

  it('formats using the browser timezone when no viewer preference is set', () => {
    const { pipe } = setUp();
    const withoutPref = pipe.transform(instant, { hour: 'numeric', timeZone: 'UTC' });
    // Same call with an explicit UTC option must always read 12 (noon).
    expect(withoutPref).toContain('12');
  });

  it('uses the viewer\'s stored timezone preference when the caller passes no timeZone option', () => {
    const { pipe, prefs } = setUp();
    prefs.setTimezone('Asia/Dubai'); // UTC+4
    const formatted = pipe.transform(instant, { hour: 'numeric', hourCycle: 'h23' });
    expect(formatted).toContain('16'); // 12:00 UTC -> 16:00 in Asia/Dubai
  });

  it('an explicit caller-supplied timeZone always wins over the stored preference', () => {
    const { pipe, prefs } = setUp();
    prefs.setTimezone('Asia/Dubai');
    const formatted = pipe.transform(instant, { hour: 'numeric', hourCycle: 'h23', timeZone: 'UTC' });
    expect(formatted).toContain('12');
  });

  // NGB-P.4, flipped by NGB-1.8. `new Date('not-a-date')` is an Invalid Date
  // and `Intl.DateTimeFormat.format` threw RangeError on it; an unknown IANA
  // zone in the same constructor threw RangeError too. One bad value (or one
  // bad stored timezone) broke every date view for that user.
  it('NGB-F26 an invalid value or timezone does not throw', () => {
    const { pipe, prefs } = setUp();
    expect(pipe.transform('not-a-date')).toBe('');
    prefs.setTimezone('Not/AZone');
    expect(pipe.transform(instant)).toBeTruthy();
  });

  // OD-11 — a missing value renders '' exactly as Angular's DatePipe does for
  // `null`, rather than Intl's epoch (the old code rendered 1970 for null).
  it('NGB-F26 renders an empty string for null, undefined and the empty string', () => {
    const { pipe } = setUp();
    expect(pipe.transform(null)).toBe('');
    expect(pipe.transform(undefined)).toBe('');
    expect(pipe.transform('')).toBe('');
    expect(pipe.transform(new Date(Number.NaN))).toBe('');
  });

  // A caller-supplied unusable zone must not throw either — it falls back to
  // the browser's own zone.
  it('NGB-F26 falls back to the browser zone for a caller-supplied unusable timeZone', () => {
    const { pipe } = setUp();
    const formatted = pipe.transform(instant, { hour: 'numeric', hourCycle: 'h23', timeZone: 'Not/AZone' });
    expect(formatted).toBeTruthy();
    expect(formatted).not.toBe('');
  });

  it('AG1-T8 shows the Umm al-Qura date for a Hijri viewer, with Arabic digits when asked', () => {
    const { pipe, prefs } = setUp();
    const ramadan = '2026-02-18T12:00:00Z'; // 1 Ramadan 1447
    const opts: Intl.DateTimeFormatOptions = { timeZone: 'UTC', year: 'numeric', month: 'numeric', day: 'numeric' };
    prefs.setCalendar('hijri');
    expect(pipe.transform(ramadan, opts)).toContain('1447');
    prefs.setDigits('arab');
    expect(pipe.transform(ramadan, opts)).toContain('١٤٤٧');
    prefs.setDigits('latn');
    prefs.setCalendar('both');
    const both = pipe.transform(ramadan, opts);
    expect(both).toContain('2026');
    expect(both).toContain('1447');
    // An attribute's own display calendar wins over the viewer's.
    expect(pipe.transform(ramadan, opts, 'gregorian')).not.toContain('1447');
  });

  it('localeTag adds only the extensions the viewer chose', () => {
    expect(localeTag('en-US', null, null)).toBe('en-US');
    expect(localeTag('ar-SA', 'hijri', 'arab')).toBe('ar-SA-u-ca-islamic-umalqura-nu-arab');
    expect(localeTag('ar-SA-u-nu-latn', 'gregorian', null)).toBe('ar-SA-u-ca-gregory');
  });

  it('setTimezone(null) clears the preference back to browser-default behavior', () => {
    const { pipe, prefs } = setUp();
    prefs.setTimezone('Asia/Dubai');
    prefs.setTimezone(null);
    expect(prefs.timezone()).toBeNull();
    const formatted = pipe.transform(instant, { hour: 'numeric', hourCycle: 'h23', timeZone: 'UTC' });
    expect(formatted).toContain('12');
  });
});
