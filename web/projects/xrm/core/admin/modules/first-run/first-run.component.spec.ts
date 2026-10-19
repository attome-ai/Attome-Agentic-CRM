import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { FirstRunComponent, RegionSetupView, SETUP_URL, countryName, initialCountry } from './first-run.component';

const VIEW: RegionSetupView = {
  country: null,
  pack_available: true,
  countries: [
    { code: 'AE', name: 'United Arab Emirates', name_ar: 'الإمارات', currency_code: 'AED',
      time_zone: 'Asia/Dubai', default_date_calendar: 'gregorian', week_start: 'mon' },
    { code: 'SA', name: 'Saudi Arabia', name_ar: 'السعودية', currency_code: 'SAR',
      time_zone: 'Asia/Riyadh', default_date_calendar: 'both', week_start: 'sun' },
  ],
};

describe('FirstRunComponent (X12-T3)', () => {
  function create(view: RegionSetupView = VIEW, lang = 'ar') {
    const get = vi.fn((_: string) => of(view));
    const post = vi.fn((_: string, body: { country: string }) =>
      of({ ...view, country: body.country }));
    const set = vi.fn(() => Promise.resolve());
    TestBed.configureTestingModule({
      imports: [FirstRunComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal(lang), set } },
      ],
    });
    const fixture = TestBed.createComponent(FirstRunComponent);
    fixture.detectChanges();
    return { fixture, get, post, set };
  }

  it('starts on Saudi Arabia, in Arabic, with its default calendar', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith(SETUP_URL);
    const c = fixture.componentInstance;
    expect(c.country()).toBe('SA');
    expect(c.language()).toBe('ar');
    expect(c.calendar()).toBe('both');
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[data-country="SA"] .fr-name')!.textContent).toContain('السعودية');
  });

  it('saves the picked country, language and calendar and switches the language', () => {
    const { fixture, post, set } = create();
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLInputElement>('[data-country="AE"] input')!.click();
    root.querySelector<HTMLInputElement>('[data-language="en"] input')!.click();
    fixture.detectChanges();
    expect(fixture.componentInstance.calendar()).toBe('gregorian');
    root.querySelector<HTMLButtonElement>('button[type="submit"]')!.click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith(SETUP_URL, { country: 'AE', language: 'en', calendar: 'gregorian' });
    expect(set).toHaveBeenCalledWith('en');
    expect(root.querySelector('[data-done]')).not.toBeNull();
  });

  it('says so when the regions pack is missing, and offers nothing to save', () => {
    const { fixture } = create({ country: null, pack_available: false, countries: [] });
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[data-no-pack]')).not.toBeNull();
    expect(root.querySelector('button[type="submit"]')).toBeNull();
  });

  it('keeps the deployment country and names countries per language', () => {
    expect(initialCountry({ ...VIEW, country: 'AE' })).toBe('AE');
    expect(initialCountry({ ...VIEW, country: 'XX' })).toBe('SA');
    expect(initialCountry({ country: null, pack_available: true, countries: [] })).toBeNull();
    expect(countryName(VIEW.countries[1], 'en')).toBe('Saudi Arabia');
    expect(countryName({ ...VIEW.countries[1], name_ar: null }, 'ar')).toBe('Saudi Arabia');
  });
});
