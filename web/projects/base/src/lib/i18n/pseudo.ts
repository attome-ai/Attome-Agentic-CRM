import type { Translation } from '@jsverse/transloco';

/**
 * B20-T2: a pseudo-language for finding interface text that skips the
 * catalogue and layouts that break on longer or right-to-left text. Every
 * catalogue string is accented, padded to 40% longer, bracketed so a cut-off
 * shows, and wrapped in right-to-left marks; anything inside `{…}` (a
 * parameter or an ICU plural) is kept as it is so formatting still works.
 * Text on a screen that does not look like this did not come from the
 * catalogue.
 */
const ACCENTED: Record<string, string> = {
  a: 'á', e: 'é', i: 'í', o: 'ó', u: 'ú', c: 'ç', n: 'ñ', y: 'ý', s: 'š', z: 'ž',
  A: 'Á', E: 'É', I: 'Í', O: 'Ó', U: 'Ú', C: 'Ç', N: 'Ñ', Y: 'Ý', S: 'Š', Z: 'Ž',
};

/** Right-to-left mark. */
export const RLM = '‏';
/** How much longer pseudo text is than the original. */
export const PSEUDO_GROWTH = 0.4;

/** One string in the pseudo-language. */
export function pseudoText(text: string): string {
  let out = '';
  let depth = 0;
  let letters = 0;
  for (const ch of text) {
    if (ch === '{') depth++;
    if (depth === 0) {
      out += ACCENTED[ch] ?? ch;
      if (/\p{L}/u.test(ch)) letters++;
    } else {
      out += ch;
    }
    if (ch === '}' && depth > 0) depth--;
  }
  const pad = '~'.repeat(Math.ceil(letters * PSEUDO_GROWTH));
  return `${RLM}[${out}${pad}]${RLM}`;
}

/** A whole catalogue in the pseudo-language, keys unchanged. */
export function pseudoCatalog(catalog: Translation): Translation {
  const out: Translation = {};
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === 'string') out[key] = pseudoText(value);
    else if (value && typeof value === 'object') out[key] = pseudoCatalog(value as Translation);
    else out[key] = value;
  }
  return out;
}
