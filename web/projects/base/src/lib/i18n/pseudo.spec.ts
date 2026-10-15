import { describe, expect, it } from 'vitest';

import { en } from './en.catalog';
import { PSEUDO_GROWTH, RLM, pseudoCatalog, pseudoText } from './pseudo';

describe('pseudo-language (B20-T2)', () => {
  it('accents, lengthens, brackets and marks a string', () => {
    const text = pseudoText('Save record');
    expect(text.startsWith(`${RLM}[`)).toBe(true);
    expect(text.endsWith(`]${RLM}`)).toBe(true);
    expect(text).toContain('Šávé réçórd');
    expect(text.length).toBeGreaterThanOrEqual(Math.ceil('Save record'.length * (1 + PSEUDO_GROWTH)));
  });

  it('keeps parameters and ICU plurals working', () => {
    expect(pseudoText('Hello {name}')).toContain('{name}');
    const plural = '{count, plural, one {# item} other {# items}}';
    expect(pseudoText(plural)).toContain(plural);
  });

  it('turns every catalogue string and keeps every key', () => {
    const pseudo = pseudoCatalog(en);
    const keys = (catalog: object, prefix = ''): string[] =>
      Object.entries(catalog).flatMap(([k, v]) =>
        v && typeof v === 'object' ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`]);
    expect(keys(pseudo)).toEqual(keys(en));
    const strings = (catalog: object): string[] =>
      Object.values(catalog).flatMap(v => (v && typeof v === 'object' ? strings(v) : typeof v === 'string' ? [v] : []));
    expect(strings(pseudo).every(s => s.startsWith(`${RLM}[`))).toBe(true);
  });
});
