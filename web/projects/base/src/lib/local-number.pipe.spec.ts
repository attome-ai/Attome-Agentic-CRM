import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { LocalNumberPipe } from './local-number.pipe';
import { LangService } from './lang.service';
import { ATTOME_CONFIG } from './config';
import { provideAttomeI18n } from './provide';

describe('LocalNumberPipe', () => {
  afterEach(() => localStorage.clear());

  function setUp() {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
      ],
    });
    const lang = TestBed.inject(LangService);
    const pipe = TestBed.runInInjectionContext(() => new LocalNumberPipe());
    return { pipe, lang };
  }

  it('formats with the en-US grouping while the language is en', () => {
    const { pipe } = setUp();
    expect(pipe.transform(1234)).toBe('1,234');
  });

  it('formats with Arabic-Indic digits once the language is switched to ar', async () => {
    const { pipe, lang } = setUp();
    await lang.set('ar');
    // '1234' in Arabic-Indic digits. Bare 'ar' resolves to Western digits
    // under current CLDR/ICU data — LangService.intlLocale() maps it to
    // 'ar-SA', the region-qualified locale that gets the 'arab' numbering
    // system by default.
    expect(pipe.transform(1234)).toBe('١٬٢٣٤');
  });

  it('forwards Intl.NumberFormatOptions', () => {
    const { pipe } = setUp();
    expect(pipe.transform(0.5, { style: 'percent' })).toBe('50%');
  });
});
