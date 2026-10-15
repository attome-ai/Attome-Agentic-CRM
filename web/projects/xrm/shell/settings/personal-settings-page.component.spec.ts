import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, ThemeService, UserPreferencesService } from '@attome/base';
import { Observable, of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { PersonalSettingsPageComponent, labelKey, optionKey } from './personal-settings-page.component';
import { PersonalSettingsService, REDUCED_MOTION_CLASS, SIMPLE_MODE_CLASS, TEXT_LARGE_CLASS } from './personal-settings.service';

const ITEMS = [
  { key: 'core.locale', value: 'en-US', source: 'default' },
  { key: 'core.calendar', value: 'gregorian', source: 'default' },
  { key: 'core.digits', value: 'latn', source: 'default' },
  { key: 'core.time_zone', value: 'Asia/Dubai', source: 'organization' },
  { key: 'core.theme', value: 'auto', source: 'default' },
  { key: 'core.text_size', value: 'normal', source: 'default' },
  { key: 'core.reduced_motion', value: false, source: 'default' },
];

class StubApi {
  puts: { path: string; body: unknown }[] = [];
  get(): Observable<unknown> { return of({ items: ITEMS }); }
  put(path: string, body: { value: unknown }): Observable<unknown> {
    this.puts.push({ path, body });
    return of({ key: path.split('/').pop(), value: body.value, source: 'user' });
  }
}

function setup() {
  const api = new StubApi();
  const lang = { current: signal('en'), set: vi.fn(async () => undefined), translate: (k: string) => k, intlLocale: signal('en-US') };
  const theme = { mode: signal('auto'), setMode: vi.fn() };
  TestBed.configureTestingModule({
    imports: [PersonalSettingsPageComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: lang },
      { provide: ThemeService, useValue: theme },
    ],
  });
  const fixture = TestBed.createComponent(PersonalSettingsPageComponent);
  fixture.detectChanges();
  return {
    fixture, api, lang, theme,
    component: fixture.componentInstance,
    prefs: TestBed.inject(UserPreferencesService),
    svc: TestBed.inject(PersonalSettingsService),
  };
}

describe('PersonalSettingsPageComponent', () => {
  it('applies a value set by the organization, and leaves unchosen ones to the language', () => {
    const { prefs, lang } = setup();
    expect(prefs.timezone()).toBe('Asia/Dubai');
    expect(prefs.calendar()).toBeNull();
    expect(lang.set).not.toHaveBeenCalled();
  });

  it('saves a calendar choice and applies it at once', () => {
    const { component, api, prefs } = setup();
    component.save('core.calendar', 'hijri');
    expect(api.puts[0]).toEqual({ path: '/api/v1/settings/me/core.calendar', body: { value: 'hijri' } });
    expect(prefs.calendar()).toBe('hijri');
  });

  it('switches the language without a reload', () => {
    const { component, lang } = setup();
    component.save('core.locale', 'ar-SA');
    expect(lang.set).toHaveBeenCalledWith('ar');
  });

  it('turns on large text and reduced motion on the document', () => {
    const { component } = setup();
    component.save('core.text_size', 'large');
    component.save('core.reduced_motion', true);
    expect(document.documentElement.classList.contains(TEXT_LARGE_CLASS)).toBe(true);
    expect(document.documentElement.classList.contains(REDUCED_MOTION_CLASS)).toBe(true);
  });

  it('simple mode hides the advanced actions (AK6-T2)', () => {
    const { component } = setup();
    component.save('core.simple_mode', true);
    expect(document.documentElement.classList.contains(SIMPLE_MODE_CLASS)).toBe(true);
    component.save('core.simple_mode', false);
    expect(document.documentElement.classList.contains(SIMPLE_MODE_CLASS)).toBe(false);
  });

  it('names labels and options from the catalogue', () => {
    expect(labelKey('core.time_zone')).toBe('settingsPage.time_zone');
    expect(optionKey('en-US')).toBe('settingsPage.option.en_US');
  });
});
