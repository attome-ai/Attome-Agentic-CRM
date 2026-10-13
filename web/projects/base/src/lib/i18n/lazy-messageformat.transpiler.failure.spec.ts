import { TestBed } from '@angular/core/testing';
import { TRANSLOCO_CONFIG, translocoConfig } from '@jsverse/transloco';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LazyMessageFormatTranspiler } from './lazy-messageformat.transpiler';

/**
 * NGB-6.1b, failure half. The chunk is a dynamic `import()`, so it can fail
 * (offline, a stale hash after a deploy). The contract is: `ready` rejects for
 * anyone awaiting it, a single console warning is emitted rather than an
 * unhandled rejection, and rendering keeps working with the raw source.
 *
 * This lives in its own file because `vi.mock` is file-scoped and must make
 * the plugin import throw for the whole file.
 */
vi.mock('@jsverse/transloco-messageformat', () => ({
  // A module that resolves but cannot be instantiated is the same failure the
  // loader sees for a chunk that 404s after a deploy: `loadPlugin` rejects.
  MessageFormatTranspiler: class {
    constructor() {
      throw new Error('simulated chunk failure');
    }
  },
}));

describe('LazyMessageFormatTranspiler — failed ICU chunk', () => {
  afterEach(() => vi.restoreAllMocks());

  function make(): LazyMessageFormatTranspiler {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: TRANSLOCO_CONFIG,
          useValue: translocoConfig({ availableLangs: ['en', 'ar'], defaultLang: 'en', fallbackLang: 'en' }),
        },
      ],
    });
    return TestBed.runInInjectionContext(
      () => new LazyMessageFormatTranspiler({ locales: ['en', 'ar'], biDiSupport: true }),
    ) as LazyMessageFormatTranspiler;
  }

  it('warns once and keeps serving raw messages instead of rejecting the render', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const transpiler = make();

    await expect(transpiler.ready).rejects.toThrow('simulated chunk failure');
    expect(warn).toHaveBeenCalledTimes(1);

    const raw = '{count, plural, other {# items}}';
    expect(transpiler.transpile({ key: 'k', value: raw, params: { count: 2 }, translation: {} })).toBe(raw);
  });
});
