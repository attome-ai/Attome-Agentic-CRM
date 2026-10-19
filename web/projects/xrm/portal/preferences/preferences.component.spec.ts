import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Preferences, PreferencesComponent, toggledPreferences } from './preferences.component';

const PREFS: Preferences = {
  purposes: [
    {
      key: 'newsletter',
      description: 'Monthly newsletter',
      channels: [
        { channel: 'email', granted: true },
        { channel: 'sms', granted: null },
      ],
    },
  ],
};

describe('PreferencesComponent', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
  let lang: { translate: (k: string) => string; current: ReturnType<typeof signal>; isRtl: () => boolean; toggle: ReturnType<typeof vi.fn> };

  function setup(token: string | null) {
    api = { get: vi.fn(), post: vi.fn() };
    lang = { translate: (k: string) => k, current: signal('en'), isRtl: () => false, toggle: vi.fn() };
    TestBed.configureTestingModule({
      imports: [PreferencesComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: lang },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParamMap: convertToParamMap(token ? { token } : {}) } },
        },
      ],
    });
  }

  function render() {
    const fixture = TestBed.createComponent(PreferencesComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(id: string) =>
      el.querySelector<T>(`[data-testid="${id}"]`);
    return { fixture, el, q };
  }

  beforeEach(() => TestBed.resetTestingModule());

  it('sends only what changed', () => {
    expect(toggledPreferences(PREFS, { 'newsletter|email': true, 'newsletter|sms': false })).toEqual([]);
    expect(toggledPreferences(PREFS, { 'newsletter|email': false, 'newsletter|sms': true })).toEqual([
      { purpose_key: 'newsletter', channel: 'email', grant: false },
      { purpose_key: 'newsletter', channel: 'sms', grant: true },
    ]);
  });

  it('loads the preferences for the link\'s token and saves a change', () => {
    setup('tok-1');
    api.get.mockReturnValue(of(PREFS));
    const updated: Preferences = {
      purposes: [{ ...PREFS.purposes[0], channels: [{ channel: 'email', granted: false }, { channel: 'sms', granted: null }] }],
    };
    api.post.mockReturnValue(of(updated));
    const { fixture, q } = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/consents/preferences', { token: 'tok-1' });
    const email = q<HTMLInputElement>('pref-newsletter-email')!;
    expect(email.checked).toBe(true);
    expect(q<HTMLButtonElement>('pref-save')!.disabled).toBe(true);

    email.checked = false;
    email.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    q('pref-save')!.click();
    fixture.detectChanges();

    expect(api.post).toHaveBeenCalledWith('/api/v1/consents/preferences', {
      token: 'tok-1',
      changes: [{ purpose_key: 'newsletter', channel: 'email', grant: false }],
    });
    expect(q('pref-saved')?.textContent).toContain('consentPreferences.saved');
    expect(q<HTMLInputElement>('pref-newsletter-email')!.checked).toBe(false);
  });

  it('shows a message, not data, for a missing or refused link', () => {
    setup(null);
    expect(render().q('pref-invalid')).not.toBeNull();
    TestBed.resetTestingModule();
    setup('expired');
    api.get.mockReturnValue(throwError(() => ({ kind: 'not_found' })));
    const { q } = render();
    expect(q('pref-invalid')?.textContent).toContain('consentPreferences.invalidLink');
    expect(q('pref-purpose')).toBeNull();
  });

  it('switches language from the page', () => {
    setup('tok-1');
    api.get.mockReturnValue(of(PREFS));
    const { q } = render();
    q('pref-lang')!.click();
    expect(lang.toggle).toHaveBeenCalled();
  });
});
