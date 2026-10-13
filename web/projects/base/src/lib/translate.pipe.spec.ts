import { TestBed } from '@angular/core/testing';
import { TRANSLOCO_TRANSPILER } from '@jsverse/transloco';
import { afterEach, describe, expect, it } from 'vitest';
import { TranslatePipe } from './translate.pipe';
import { LangService } from './lang.service';
import { ATTOME_CONFIG } from './config';
import { provideAttomeI18n } from './provide';
import { LazyMessageFormatTranspiler } from './i18n/lazy-messageformat.transpiler';

describe('TranslatePipe', () => {
  afterEach(() => localStorage.clear());

  function setUp() {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
      ],
    });
    const lang = TestBed.inject(LangService);
    const pipe = TestBed.runInInjectionContext(() => new TranslatePipe());
    const transpiler = TestBed.inject(TRANSLOCO_TRANSPILER) as LazyMessageFormatTranspiler;
    return { pipe, lang, transpiler };
  }

  it('resolves the English string for a catalog key while the language is en', () => {
    const { pipe } = setUp();
    expect(pipe.transform('auth.back')).toBe('Back');
  });

  it('resolves the Arabic string once the language is switched to ar', async () => {
    const { pipe, lang } = setUp();
    await lang.set('ar');
    expect(pipe.transform('auth.back')).toBe('رجوع');
  });

  // ICU formatting is transpiled by the messageformat plugin, which now loads
  // from its own chunk (lazy-messageformat.transpiler.ts) instead of the
  // initial bundle — so these await the swap rather than assuming it has
  // already happened, the way application rendering does not.
  it('passes ICU params through to the catalog once the messageformat chunk loads', async () => {
    const { pipe, transpiler } = setUp();
    await transpiler.ready;
    expect(pipe.transform('resetPassword.minLength', { count: 1 })).toBe('Minimum 1 character');
    expect(pipe.transform('resetPassword.minLength', { count: 8 })).toBe('Minimum 8 characters');
  });

  it('applies the active language to ICU output', async () => {
    const { pipe, lang, transpiler } = setUp();
    await transpiler.ready;
    await lang.set('ar');
    expect(pipe.transform('resetPassword.minLength', { count: 8 })).toContain('8');
  });

  // The documented cost of deferring the plugin: an ICU key resolved in the
  // window before the chunk lands falls back to DefaultTranspiler, which has no
  // plural support and returns the raw source. Pinned so that window's
  // behaviour is a known quantity rather than a surprise in production.
  it('falls back to the raw ICU source before the chunk has loaded', () => {
    const { pipe } = setUp();
    expect(pipe.transform('resetPassword.minLength', { count: 1 })).toContain('plural');
  });

  // Non-ICU interpolation must not wait for the chunk — it is DefaultTranspiler
  // behaviour, which this transpiler extends and serves synchronously.
  it('resolves a plain key synchronously, with no chunk loaded', () => {
    const { pipe } = setUp();
    expect(pipe.transform('auth.back')).toBe('Back');
  });
});
