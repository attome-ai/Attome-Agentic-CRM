import { InjectionToken } from '@angular/core';
import type { Translation } from '@jsverse/transloco';

/**
 * B20-T1: one language the interface can be shown in.
 *
 * `code` is a BCP 47 tag (`en`, `ar`, `ar-SA`, `fr`). A key the language's own
 * catalogue lacks resolves through its fallback chain: `fallback` when given,
 * otherwise the tag's shorter forms (`ar-SA` falls back to `ar`), and always
 * English last.
 */
export interface LanguageDef {
  readonly code: string;
  readonly dir: 'ltr' | 'rtl';
  /** For Intl.NumberFormat/DateTimeFormat, e.g. `ar-SA` so digits follow the region. */
  readonly intl: string;
  /** The language's name in itself, shown in the language picker. */
  readonly label: string;
  readonly fallback?: readonly string[];
  /** Where this language's base catalogue comes from; English and Arabic ship with the product. */
  readonly load?: () => Promise<Translation>;
}

/** The languages the product ships with. */
export const DEFAULT_LANGUAGES: readonly LanguageDef[] = [
  { code: 'en', dir: 'ltr', intl: 'en-US', label: 'EN' },
  { code: 'ar', dir: 'rtl', intl: 'ar-SA', label: 'AR' },
];

/** The configured languages; `provideAttomeI18n(languages)` sets it. */
export const ATTOME_LANGUAGES = new InjectionToken<readonly LanguageDef[]>('ATTOME_LANGUAGES', {
  providedIn: 'root',
  factory: () => DEFAULT_LANGUAGES,
});

/** The language every chain ends in, and whose catalogue is always loaded. */
export const BASE_LANGUAGE = 'en';

/**
 * `code` followed by the languages it falls back to, most specific first,
 * ending in English. Only configured languages (and English) appear.
 */
export function fallbackChain(code: string, languages: readonly LanguageDef[]): string[] {
  const known = new Set(languages.map(l => l.code));
  const def = languages.find(l => l.code === code);
  const parts = code.split('-');
  const parents = def?.fallback ?? parts.slice(1).map((_, i) => parts.slice(0, parts.length - 1 - i).join('-'));
  const chain: string[] = [code];
  for (const parent of parents) {
    if (known.has(parent) && !chain.includes(parent)) chain.push(parent);
  }
  if (!chain.includes(BASE_LANGUAGE)) chain.push(BASE_LANGUAGE);
  return chain;
}
