import { InjectionToken, inject } from '@angular/core';
import type { Translation } from '@jsverse/transloco';
import { en } from './en.catalog';
import { ATTOME_LANGUAGES, DEFAULT_LANGUAGES, LanguageDef } from './languages';

/**
 * Where each language's catalog comes from (P-i18n-a11y §4.1: bundled JS, no
 * HTTP/assets round trip).
 *
 * English is the default and fallback language, so it stays in the initial
 * bundle and is available synchronously. Arabic lives in its own entry point,
 * `@attome/base/i18n-ar`, and is `import()`ed on first use: bundled eagerly it
 * was ~119 KB of every visitor's first load, and it grew with every new key.
 */
export const EAGER_CATALOGS: Readonly<Record<string, Translation>> = { en };

/**
 * The catalog loader as an injected seam. `provideAttomeI18n()`'s first-render
 * guarantee has to bound how long it waits on a chunk that may never arrive
 * (NGB-1.9 / D-668), and a spec cannot stall a real `import()`. Same shape as
 * `STEP_UP_NAVIGATE`: the production value is the real function, a test (or an
 * embedding host) can replace it.
 */
export const CATALOG_LOAD = new InjectionToken<(lang: string) => Promise<Translation>>(
  'ATTOME_CATALOG_LOAD',
  {
    providedIn: 'root',
    factory: () => {
      const languages = inject(ATTOME_LANGUAGES);
      return (lang: string) => loadCatalog(lang, languages);
    },
  },
);

const pending = new Map<string, Promise<Translation>>();

/**
 * Resolves `lang`'s catalog. The dynamic import is memoised, so every caller
 * (LangService, the Transloco loader) shares one chunk request and receives the
 * same catalog object. A failed load is not memoised: the next call retries.
 * An unknown language resolves to an empty catalog, as the loader always did.
 * B20-T1: a configured language other than English and Arabic loads through
 * its own `load`.
 */
export function loadCatalog(
  lang: string,
  languages: readonly LanguageDef[] = DEFAULT_LANGUAGES,
): Promise<Translation> {
  const eager = EAGER_CATALOGS[lang];
  if (eager) return Promise.resolve(eager);
  const own = languages.find(l => l.code === lang)?.load;
  if (lang !== 'ar' && !own) return Promise.resolve({});

  let load = pending.get(lang);
  if (!load) {
    load = own ? own() : import('@attome/base/i18n-ar').then(m => m.ar as Translation);
    load.catch(() => pending.delete(lang));
    pending.set(lang, load);
  }
  return load;
}
