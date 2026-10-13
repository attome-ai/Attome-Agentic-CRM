import { TestBed } from '@angular/core/testing';
import { TRANSLOCO_CONFIG, translocoConfig } from '@jsverse/transloco';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LazyMessageFormatTranspiler } from './lazy-messageformat.transpiler';

/**
 * NGB-6.1b — the ICU plugin is deferred, so the interesting behaviour is the
 * window before it lands: everything that uses plain `{{param}}` interpolation
 * must keep working, an ICU key falls back to its raw source, and the active
 * language set during that window is replayed to the plugin on arrival.
 *
 * The plugin module is faked so the assertions can name exactly what the
 * delegate received rather than depending on MessageFormat's own output.
 */
const calls = vi.hoisted(() => ({ onLangChanged: [] as string[], constructed: 0 }));

vi.mock('@jsverse/transloco-messageformat', () => ({
  MessageFormatTranspiler: class {
    constructor(_config: unknown) {
      calls.constructed++;
    }
    onLangChanged(lang: string): void {
      calls.onLangChanged.push(lang);
    }
    transpile(params: { value: string }): string {
      return 'MF:' + params.value;
    }
  },
}));

describe('LazyMessageFormatTranspiler', () => {
  const ICU = '{count, plural, one {# item} other {# items}}';

  beforeEach(() => {
    calls.onLangChanged = [];
    calls.constructed = 0;
    TestBed.configureTestingModule({
      providers: [
        {
          provide: TRANSLOCO_CONFIG,
          useValue: translocoConfig({ availableLangs: ['en', 'ar'], defaultLang: 'en', fallbackLang: 'en' }),
        },
      ],
    });
  });

  function make(): LazyMessageFormatTranspiler {
    return TestBed.runInInjectionContext(
      () => new LazyMessageFormatTranspiler({ locales: ['en', 'ar'], biDiSupport: true }),
    ) as LazyMessageFormatTranspiler;
  }

  it('interpolates plain params synchronously and leaves ICU raw until the chunk lands', async () => {
    const transpiler = make();

    // Before `ready`: DefaultTranspiler handles `{{param}}`, and an ICU
    // skeleton is passed through untouched — the documented brief window.
    expect(transpiler.transpile({ key: 'greet', value: 'Hi {{name}}', params: { name: 'Ada' }, translation: {} }))
      .toBe('Hi Ada');
    expect(transpiler.transpile({ key: 'k', value: ICU, params: { count: 1 }, translation: {} })).toBe(ICU);

    await transpiler.ready;

    expect(transpiler.transpile({ key: 'k', value: ICU, params: { count: 1 }, translation: {} })).toBe('MF:' + ICU);
    expect(calls.constructed).toBe(1);
  });

  it('replays the active language to a plugin that arrives later', async () => {
    const transpiler = make();

    transpiler.onLangChanged('ar');   // synchronous, before the dynamic import resolves
    await transpiler.ready;

    expect(calls.onLangChanged).toEqual(['ar']);
  });

  it('forwards later language switches to the live plugin', async () => {
    const transpiler = make();
    await transpiler.ready;

    transpiler.onLangChanged('en');

    expect(calls.onLangChanged).toContain('en');
  });
});
