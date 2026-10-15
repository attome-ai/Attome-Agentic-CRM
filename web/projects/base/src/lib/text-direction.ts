/**
 * B21-T2: Arabic and English side by side. A value reads in its own
 * direction (an English name in an Arabic screen stays left to right), and
 * client-side sorts follow the reader's language: `Intl.Collator('ar')` puts
 * Arabic letters in alphabet order and ignores tatweel and diacritics the way
 * an Arabic reader expects.
 */

/** Hebrew, Arabic, Syriac, Thaana, NKo and the Arabic presentation forms. */
const RTL_CHAR = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/;
/** Latin, Greek and Cyrillic letters. */
const LTR_CHAR = /[A-Za-z\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]/;

/**
 * The direction `value` reads in, from its first strong character (the
 * Unicode bidi rule `dir="auto"` applies); `auto` when it has none, such as a
 * number or an empty value.
 */
export function textDirection(value: string | null | undefined): 'rtl' | 'ltr' | 'auto' {
  for (const ch of value ?? '') {
    if (RTL_CHAR.test(ch)) return 'rtl';
    if (LTR_CHAR.test(ch)) return 'ltr';
  }
  return 'auto';
}

const collators = new Map<string, Intl.Collator>();

/**
 * The collator for `locale` (a BCP-47 tag such as `LangService.intlLocale()`),
 * kept per locale: base letters only, so case and accents do not split
 * equal names, and numbers in order (`item 2` before `item 10`).
 */
export function textCollator(locale?: string): Intl.Collator {
  const key = locale ?? '';
  let collator = collators.get(key);
  if (!collator) {
    collator = new Intl.Collator(locale || undefined, { sensitivity: 'base', numeric: true });
    collators.set(key, collator);
  }
  return collator;
}

/** Compares two values for a client-side sort in `locale`'s order. */
export function compareText(a: string | null | undefined, b: string | null | undefined, locale?: string): number {
  return textCollator(locale).compare(a ?? '', b ?? '');
}
