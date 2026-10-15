import { ApplicationInitStatus } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { DOCUMENT } from '@angular/common';
import { TRANSLOCO_TRANSPILER, TranslocoService } from '@jsverse/transloco';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FIRST_RENDER_BOOT_TIMEOUT_MS, LangService } from './lang.service';
import { ATTOME_CONFIG } from './config';
import { provideAttomeI18n } from './provide';
import { CATALOG_LOAD } from './i18n/catalogs';
import { LazyMessageFormatTranspiler } from './i18n/lazy-messageformat.transpiler';
import { DEFAULT_LANGUAGES, LanguageDef, fallbackChain } from './i18n/languages';

describe('LangService', () => {
  afterEach(() => localStorage.clear());

  function setUp(portalKey?: string) {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865', portalKey } },
        provideAttomeI18n(),
      ],
    });
    return TestBed.inject(LangService);
  }

  it('defaults to English, LTR, with no stored preference', () => {
    const lang = setUp();
    expect(lang.current()).toBe('en');
    expect(lang.isRtl()).toBe(false);
    expect(TestBed.inject(DOCUMENT).documentElement.dir).toBe('ltr');
  });

  it('restores a stored "ar" preference under the default portal key', async () => {
    localStorage.setItem('attome-lang', 'ar');
    const lang = setUp();
    await lang.ready;
    expect(lang.current()).toBe('ar');
    expect(lang.isRtl()).toBe(true);
  });

  it('namespaces the storage key by portalKey', async () => {
    localStorage.setItem('myportal-lang', 'ar');
    const lang = setUp('myportal');
    await lang.ready;
    expect(lang.current()).toBe('ar');
  });

  // The Arabic catalog is a lazy chunk. provideAttomeI18n()'s app initializer
  // awaits it when Arabic is the saved language, so by the time Angular renders
  // anything the UI is already Arabic — no English flash.
  it('the app initializer loads the Arabic catalog before first render when ar is saved', async () => {
    localStorage.setItem('attome-lang', 'ar');
    const lang = setUp();
    await TestBed.inject(ApplicationInitStatus).donePromise;
    expect(lang.current()).toBe('ar');
    expect(TestBed.inject(TranslocoService).getTranslation('ar')).toBeTruthy();
    expect(lang.translate('auth.back')).toBe('رجوع');
    expect(TestBed.inject(DOCUMENT).documentElement.dir).toBe('rtl');
  });

  it('English is registered synchronously — no await needed for an English session', () => {
    const lang = setUp();
    expect(lang.translate('auth.back')).toBe('Back');
    const settled = lang.set('en');
    expect(lang.current()).toBe('en');
    expect(lang.translate('auth.back')).toBe('Back');
    return settled;
  });

  it('switching to ar loads the Arabic catalog on demand, then translates', async () => {
    const lang = setUp();
    const transloco = TestBed.inject(TranslocoService);
    expect(Object.keys(transloco.getTranslation('ar') ?? {})).toEqual([]);
    await lang.set('ar');
    expect(lang.current()).toBe('ar');
    expect(lang.translate('auth.back')).toBe('رجوع');
    // A second switch finds the catalog registered and applies synchronously.
    void lang.set('en');
    expect(lang.current()).toBe('en');
    void lang.set('ar');
    expect(lang.current()).toBe('ar');
  });

  it('the latest request wins when an older one is still loading', async () => {
    const lang = setUp();
    const toAr = lang.set('ar');
    await lang.set('en');
    await toAr;
    expect(lang.current()).toBe('en');
    expect(localStorage.getItem('attome-lang')).toBe('en');
  });

  it('set() updates the signal, persists, and flips dir/lang on the document', async () => {
    const lang = setUp();
    await lang.set('ar');

    expect(lang.current()).toBe('ar');
    expect(lang.isRtl()).toBe(true);
    expect(localStorage.getItem('attome-lang')).toBe('ar');
    const doc = TestBed.inject(DOCUMENT);
    expect(doc.documentElement.dir).toBe('rtl');
    expect(doc.documentElement.lang).toBe('ar');
  });

  it('toggle() flips between en and ar', async () => {
    const lang = setUp();
    expect(lang.current()).toBe('en');
    await lang.toggle();
    expect(lang.current()).toBe('ar');
    await lang.toggle();
    expect(lang.current()).toBe('en');
  });

  it('translate() resolves a catalog key in the active language', async () => {
    const lang = setUp();
    expect(lang.translate('auth.back')).toBe('Back');
    await lang.set('ar');
    expect(lang.translate('auth.back')).toBe('رجوع');
  });

  // Awaits the transpiler because the messageformat plugin now arrives in its
  // own chunk rather than the initial bundle — see
  // i18n/lazy-messageformat.transpiler.ts.
  it('translate() resolves an ICU plural with the given params', async () => {
    const lang = setUp();
    await (TestBed.inject(TRANSLOCO_TRANSPILER) as LazyMessageFormatTranspiler).ready;
    expect(lang.translate('resetPassword.minLength', { count: 8 })).toBe('Minimum 8 characters');
  });

  // NGB-1.9 / NGB-F27 / D-668 — the first render must not wait on a chunk that
  // never arrives. A stalled Arabic load used to hold an Arabic user on a blank
  // page indefinitely; past the deadline the app paints in English.
  describe('boot deadline (NGB-1.9 / D-668)', () => {
    function setUpWithLoader(load: (lang: string) => Promise<never | Record<string, unknown>>) {
      TestBed.configureTestingModule({
        providers: [
          { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
          provideAttomeI18n(),
          { provide: CATALOG_LOAD, useValue: load },
        ],
      });
      return TestBed.inject(LangService);
    }

    it('ready resolves in English when the Arabic chunk never settles', async () => {
      vi.useFakeTimers();
      try {
        localStorage.setItem('attome-lang', 'ar');
        const lang = setUpWithLoader(() => new Promise(() => { /* never settles */ }));
        expect(lang.current()).toBe('en');

        await vi.advanceTimersByTimeAsync(FIRST_RENDER_BOOT_TIMEOUT_MS);
        await expect(lang.ready).resolves.toBeUndefined();
        expect(lang.current()).toBe('en');
      } finally {
        vi.useRealTimers();
      }
    });

    it('applies Arabic when the stalled chunk finally arrives', async () => {
      vi.useFakeTimers();
      try {
        localStorage.setItem('attome-lang', 'ar');
        let arrive!: (catalog: Record<string, unknown>) => void;
        const stalled = new Promise<Record<string, unknown>>(resolve => { arrive = resolve; });
        const lang = setUpWithLoader(() => stalled as Promise<Record<string, unknown>>);
        expect(lang.current()).toBe('en');

        await vi.advanceTimersByTimeAsync(FIRST_RENDER_BOOT_TIMEOUT_MS);
        await lang.ready;
        expect(lang.current()).toBe('en');

        arrive({ auth: { back: 'رجوع' } });
        await vi.advanceTimersByTimeAsync(0);
        expect(lang.current()).toBe('ar');
        expect(lang.translate('auth.back')).toBe('رجوع');
      } finally {
        vi.useRealTimers();
      }
    });

    it('does not apply the late Arabic catalog after the user switched away', async () => {
      vi.useFakeTimers();
      try {
        localStorage.setItem('attome-lang', 'ar');
        let arrive!: (catalog: Record<string, unknown>) => void;
        const stalled = new Promise<Record<string, unknown>>(resolve => { arrive = resolve; });
        const lang = setUpWithLoader(() => stalled as Promise<Record<string, unknown>>);

        await vi.advanceTimersByTimeAsync(FIRST_RENDER_BOOT_TIMEOUT_MS);
        await lang.ready;
        await lang.set('en');
        expect(lang.current()).toBe('en');

        arrive({ auth: { back: 'رجوع' } });
        await vi.advanceTimersByTimeAsync(0);
        expect(lang.current()).toBe('en');
      } finally {
        vi.useRealTimers();
      }
    });
  });

  // NGB-2.3 / OD-8 — one place turns a failed API call into user-visible text.
  describe('errorText (NGB-2.3)', () => {
    it('renders the catalog text for every kind whose prose is not actionable', () => {
      const lang = setUp();
      expect(lang.errorText({ kind: 'not_found', message: 'server prose' })).toBe(lang.translate('errors.not_found'));
      expect(lang.errorText({ kind: 'unavailable', message: 'server prose' })).toBe(lang.translate('errors.unavailable'));
      expect(lang.errorText({ kind: 'rate_limited', message: '' })).toBe(lang.translate('errors.rate_limited'));
      expect(lang.errorText(undefined)).toBe(lang.translate('errors.unknown'));
    });

    it('keeps the server text for validation and rule_violation', () => {
      const lang = setUp();
      expect(lang.errorText({ kind: 'validation', message: 'email: must be a valid address' }))
        .toBe('email: must be a valid address');
      expect(lang.errorText({ kind: 'rule_violation', message: 'rule violation: stage required' }))
        .toBe('rule violation: stage required');
      // ...and falls back to the catalog when the server sent none.
      expect(lang.errorText({ kind: 'validation', message: '' })).toBe(lang.translate('errors.validation'));
    });

    it('renders the Arabic catalog text once the language is ar', async () => {
      const lang = setUp();
      await lang.set('ar');
      expect(lang.errorText({ kind: 'forbidden', message: 'forbidden' })).toBe('ليس لديك صلاحية للقيام بذلك.');
    });

    it('resolves a client-synthesised code to its own catalog entry (NGB-3.3)', async () => {
      const lang = setUp();
      const enText = lang.translate('errors.too_many_pages');
      expect(enText).not.toBe('errors.too_many_pages');
      expect(lang.errorText({ kind: 'validation', message: '', code: 'too_many_pages' })).toBe(enText);

      await lang.set('ar');
      const arText = lang.translate('errors.too_many_pages');
      expect(arText).not.toBe(enText);
      expect(lang.errorText({ kind: 'validation', message: '', code: 'too_many_pages' })).toBe(arText);
    });
  });

  // NGB-3.5 / OD-10 — an ar-missing key renders English rather than its own raw
  // key, and a key no catalog defines warns exactly once.
  describe('missing-key handling (NGB-3.5)', () => {
    it('renders the English text for a key missing from Arabic', async () => {
      const lang = setUp();
      // An en-only key registered at runtime; the committed catalogs stay
      // key-for-key identical (the parity test above enforces that).
      TestBed.inject(TranslocoService).setTranslation({ enOnlyProbe: 'English only' }, 'en', { merge: true });
      await lang.set('ar');
      expect(lang.current()).toBe('ar');
      expect(lang.translate('enOnlyProbe')).toBe('English only');
    });

    it('warns once per key that no catalog defines', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => { /* captured */ });
      try {
        const lang = setUp();
        await lang.set('ar');
        lang.translate('nope.not.a.key');
        lang.translate('nope.not.a.key');
        const forKey = warn.mock.calls.filter(call => String(call[0]).includes('nope.not.a.key'));
        expect(forKey.length).toBe(1);
      } finally {
        warn.mockRestore();
      }
    });
  });

  // NGB-P.1's passing half (NGB-F13): LangService's own storage read is already
  // guarded, so a blocked store leaves it in English rather than throwing out of
  // the constructor. NGB-1.6 gives ThemeService the same shape.
  it('falls back to English when the storage read is blocked', () => {
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    });
    const lang = setUp();
    expect(lang.current()).toBe('en');
    expect(lang.isRtl()).toBe(false);
    expect(getItem).toHaveBeenCalledWith('attome-lang');
    getItem.mockRestore();
  });
});

describe('LangService with more languages (B20-T1)', () => {
  afterEach(() => localStorage.clear());

  const languages: LanguageDef[] = [
    ...DEFAULT_LANGUAGES,
    { code: 'ar-SA', dir: 'rtl', intl: 'ar-SA', label: 'AR-SA', load: () => Promise.resolve({ auth: { back: 'عودة' } }) },
    { code: 'fr', dir: 'ltr', intl: 'fr-FR', label: 'FR', load: () => Promise.resolve({ auth: { back: 'Retour' } }) },
  ];

  function setUp() {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(languages),
      ],
    });
    return TestBed.inject(LangService);
  }

  it('a chain runs from the most specific language to English', () => {
    expect(fallbackChain('ar-SA', languages)).toEqual(['ar-SA', 'ar', 'en']);
    expect(fallbackChain('fr', languages)).toEqual(['fr', 'en']);
    expect(fallbackChain('fr-CA', languages)).toEqual(['fr-CA', 'fr', 'en']);
    expect(fallbackChain('x', [{ code: 'x', dir: 'ltr', intl: 'x', label: 'X', fallback: ['fr'] }, ...languages]))
      .toEqual(['x', 'fr', 'en']);
  });

  it('a third language loads, and a key it lacks falls back to English', async () => {
    const lang = setUp();
    const english = lang.translate('dialog.cancel');
    await lang.set('fr');
    expect(lang.current()).toBe('fr');
    expect(lang.translate('auth.back')).toBe('Retour');
    expect(lang.translate('dialog.cancel')).toBe(english);
    expect(lang.isRtl()).toBe(false);
    expect(lang.intlLocale()).toBe('fr-FR');
    const root = TestBed.inject(DOCUMENT).documentElement;
    expect(root.lang).toBe('fr');
    expect(root.dir).toBe('ltr');
  });

  it('a regional language falls back to its base language before English', async () => {
    const lang = setUp();
    await lang.set('ar-SA');
    expect(lang.translate('auth.back')).toBe('عودة');
    expect(lang.translate('dialog.cancel')).toBe('إلغاء');
    expect(lang.isRtl()).toBe(true);
    expect(TestBed.inject(DOCUMENT).documentElement.dir).toBe('rtl');
  });

  it('restores a saved third language at startup', async () => {
    localStorage.setItem('attome-lang', 'fr');
    const lang = setUp();
    await lang.ready;
    expect(lang.current()).toBe('fr');
  });

  it('toggle() walks the configured languages in order', async () => {
    const lang = setUp();
    await lang.toggle();
    expect(lang.current()).toBe('ar');
    await lang.toggle();
    expect(lang.current()).toBe('ar-SA');
    await lang.toggle();
    expect(lang.current()).toBe('fr');
    await lang.toggle();
    expect(lang.current()).toBe('en');
  });

  it('ignores a language that is not configured', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const lang = setUp();
    await lang.set('de');
    expect(lang.current()).toBe('en');
    expect(error).toHaveBeenCalled();
    error.mockRestore();
  });
});
