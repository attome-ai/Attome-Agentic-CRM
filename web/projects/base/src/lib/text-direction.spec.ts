import { describe, expect, it } from 'vitest';
import { compareText, textCollator, textDirection } from './text-direction';

describe('textDirection', () => {
  it('reads Arabic right to left and English left to right', () => {
    expect(textDirection('مرحبا')).toBe('rtl');
    expect(textDirection('Hello')).toBe('ltr');
  });

  it('follows the first strong character of a mixed value', () => {
    expect(textDirection('شركة Acme')).toBe('rtl');
    expect(textDirection('Acme شركة')).toBe('ltr');
    expect(textDirection('2026 - تقرير')).toBe('rtl');
  });

  it('is auto without a strong character', () => {
    expect(textDirection('')).toBe('auto');
    expect(textDirection(null)).toBe('auto');
    expect(textDirection('12,345.00')).toBe('auto');
  });
});

describe('compareText', () => {
  it('sorts Arabic in alphabet order', () => {
    const names = ['يوسف', 'باسل', 'أحمد', 'ثامر', 'تامر'];
    expect([...names].sort((a, b) => compareText(a, b, 'ar'))).toEqual(['أحمد', 'باسل', 'تامر', 'ثامر', 'يوسف']);
  });

  it('puts numbers in numeric order and ignores case', () => {
    expect(['item 10', 'item 2'].sort((a, b) => compareText(a, b, 'en'))).toEqual(['item 2', 'item 10']);
    expect(compareText('acme', 'ACME', 'en')).toBe(0);
  });

  it('keeps one collator per locale', () => {
    expect(textCollator('ar')).toBe(textCollator('ar'));
    expect(textCollator('ar')).not.toBe(textCollator('en'));
  });
});
