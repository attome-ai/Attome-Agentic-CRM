import { describe, expect, it } from 'vitest';
import { formatHijri, fromHijri, hijriMonthName, toHijri } from './hijri';

describe('hijri', () => {
  it('reads the Umm al-Qura date of known days', () => {
    expect(toHijri('2026-02-18')).toEqual({ year: 1447, month: 9, day: 1 });
    expect(toHijri('2025-06-26')).toEqual({ year: 1447, month: 1, day: 1 });
    expect(toHijri('2025-03-30')).toEqual({ year: 1446, month: 10, day: 1 });
  });

  it('finds the Gregorian day of a Hijri date and refuses one that does not exist', () => {
    expect(fromHijri({ year: 1447, month: 9, day: 1 })).toBe('2026-02-18');
    expect(fromHijri({ year: 1446, month: 10, day: 1 })).toBe('2025-03-30');
    expect(fromHijri({ year: 1447, month: 13, day: 1 })).toBeNull();
    expect(fromHijri({ year: 1447, month: 1, day: 0 })).toBeNull();
  });

  it('round-trips every day of a year', () => {
    let day = new Date('2025-06-26T00:00:00Z');
    for (let i = 0; i < 360; i++) {
      const iso = day.toISOString().slice(0, 10);
      const hijri = toHijri(iso);
      expect(hijri).not.toBeNull();
      expect(fromHijri(hijri!)).toBe(iso);
      day = new Date(day.getTime() + 86_400_000);
    }
  });

  it('follows the published table where ICU does not', () => {
    expect(toHijri('1979-11-20')).toEqual({ year: 1400, month: 1, day: 1 });
    expect(toHijri('1937-03-12')).toBeNull();
    expect(toHijri('2077-11-17')).toBeNull();
  });

  it('formats with Arabic-Indic digits for Arabic or when asked', () => {
    const ramadan = { year: 1447, month: 9, day: 1 };
    expect(formatHijri(ramadan, 'en', null)).toBe('1 Ramadan 1447 AH');
    expect(formatHijri(ramadan, 'ar', null)).toBe('١ رمضان ١٤٤٧ هـ');
    expect(formatHijri(ramadan, 'ar', 'latn')).toBe('1 رمضان 1447 هـ');
  });

  it('names months in both languages', () => {
    expect(hijriMonthName(9, 'ar')).toBe('رمضان');
    expect(hijriMonthName(9, 'en')).toBe('Ramadan');
    expect(hijriMonthName(13, 'en')).toBe('');
  });
});
