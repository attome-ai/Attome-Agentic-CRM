import { describe, expect, it } from 'vitest';
import {
  evaluateCondition,
  isSafeHexColor,
  isSafeLinkTarget,
  resolveConditionalColor,
  substitutePlaceholders,
} from './declarative-widget.util';

describe('isSafeHexColor', () => {
  it('accepts #RGB, #RRGGBB, #RRGGBBAA', () => {
    expect(isSafeHexColor('#abc')).toBe(true);
    expect(isSafeHexColor('#aabbcc')).toBe(true);
    expect(isSafeHexColor('#aabbccdd')).toBe(true);
  });

  it('rejects named colors, CSS functions, and anything with extra characters', () => {
    expect(isSafeHexColor('red')).toBe(false);
    expect(isSafeHexColor('rgb(0,0,0)')).toBe(false);
    expect(isSafeHexColor('#aabbcc; background:url(javascript:alert(1))')).toBe(false);
    expect(isSafeHexColor('')).toBe(false);
    expect(isSafeHexColor(null)).toBe(false);
    expect(isSafeHexColor(undefined)).toBe(false);
  });
});

describe('isSafeLinkTarget', () => {
  it('accepts absolute http(s) and site-relative paths', () => {
    expect(isSafeLinkTarget('https://example.com/x')).toBe(true);
    expect(isSafeLinkTarget('http://example.com/x')).toBe(true);
    expect(isSafeLinkTarget('/xrm/invoice/123')).toBe(true);
  });

  it('rejects javascript:, data:, vbscript:, and protocol-relative //host', () => {
    expect(isSafeLinkTarget('javascript:alert(1)')).toBe(false);
    expect(isSafeLinkTarget('JavaScript:alert(1)')).toBe(false);
    expect(isSafeLinkTarget('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(isSafeLinkTarget('vbscript:msgbox(1)')).toBe(false);
    expect(isSafeLinkTarget('//evil.example.com')).toBe(false);
    expect(isSafeLinkTarget('')).toBe(false);
  });
});

describe('substitutePlaceholders', () => {
  it('replaces {field} with the row value', () => {
    expect(substitutePlaceholders('https://example.com/{id}', { id: '42' })).toBe('https://example.com/42');
  });

  it('replaces a missing field with an empty string', () => {
    expect(substitutePlaceholders('https://example.com/{id}', {})).toBe('https://example.com/');
  });

  it('performs plain string substitution — a malicious row value is never interpreted', () => {
    const result = substitutePlaceholders('x={name}', { name: '"><script>alert(1)</script>' });
    expect(result).toBe('x="><script>alert(1)</script>');
  });
});

describe('evaluateCondition', () => {
  it('supports eq/ne/gt/gte/lt/lte on numbers', () => {
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'eq', value: 5 })).toBe(true);
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'ne', value: 5 })).toBe(false);
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'gt', value: 4 })).toBe(true);
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'gte', value: 5 })).toBe(true);
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'lt', value: 6 })).toBe(true);
    expect(evaluateCondition({ n: 5 }, { field: 'n', operator: 'lte', value: 5 })).toBe(true);
  });

  it('supports contains on strings', () => {
    expect(evaluateCondition({ s: 'hello world' }, { field: 's', operator: 'contains', value: 'world' })).toBe(true);
    expect(evaluateCondition({ s: 'hello world' }, { field: 's', operator: 'contains', value: 'xyz' })).toBe(false);
  });

  it('supports is_empty/is_not_empty without needing a value', () => {
    expect(evaluateCondition({ s: '' }, { field: 's', operator: 'is_empty' })).toBe(true);
    expect(evaluateCondition({ s: null }, { field: 's', operator: 'is_empty' })).toBe(true);
    expect(evaluateCondition({ s: 'x' }, { field: 's', operator: 'is_not_empty' })).toBe(true);
  });

  it('never evaluates an expression — it only compares plain values', () => {
    // If this were eval()-based, a field value containing code would run.
    // It cannot, because there is no code path that parses `field`/`value`
    // as anything but a lookup key and a literal to compare against.
    const row = { field: 'field", () => { throw new Error("evaluated") }, "x' };
    expect(() =>
      evaluateCondition(row, { field: 'field', operator: 'eq', value: 'anything' }),
    ).not.toThrow();
  });
});

describe('resolveConditionalColor', () => {
  it('returns the first matching rule color, top to bottom', () => {
    const rules = [
      { when: { field: 'n', operator: 'gt' as const, value: 100 }, color: '#ff0000' },
      { when: { field: 'n', operator: 'gt' as const, value: 0 }, color: '#00ff00' },
    ];
    expect(resolveConditionalColor({ n: 50 }, rules)).toBe('#00ff00');
    expect(resolveConditionalColor({ n: 200 }, rules)).toBe('#ff0000');
  });

  it('returns null when nothing matches', () => {
    const rules = [{ when: { field: 'n', operator: 'gt' as const, value: 100 }, color: '#ff0000' }];
    expect(resolveConditionalColor({ n: 1 }, rules)).toBeNull();
  });

  it('skips a matching rule whose color is not a safe hex value', () => {
    const rules = [{ when: { field: 'n', operator: 'gt' as const, value: 0 }, color: 'red' }];
    expect(resolveConditionalColor({ n: 1 }, rules)).toBeNull();
  });
});
