import { describe, expect, it } from 'vitest';

import { FNC1, isValidGtinCheckDigit, parseGs1 } from './gs1';

describe('GS1 (B16-T2)', () => {
  it('parses 01 10 17 21', () => {
    const raw = `]d2010950110153000317260630` + `10ABC123${FNC1}` + `21SN-9`;
    expect(parseGs1(raw)).toEqual({
      gtin: '09501101530003',
      expiry: '2026-06-30',
      batch: 'ABC123',
      serial: 'SN-9',
    });
  });

  it('expiry day 00 is end of month', () => {
    expect(parseGs1('17280200').expiry).toBe('2028-02-29');
    expect(parseGs1('17270400').expiry).toBe('2027-04-30');
  });

  it('rejects bad check digit', () => {
    expect(isValidGtinCheckDigit('4006381333932')).toBe(false);
    expect(isValidGtinCheckDigit('12345')).toBe(false);
    expect(isValidGtinCheckDigit('40063813339a1')).toBe(false);
  });

  it('accepts EAN-13 4006381333931', () => {
    expect(isValidGtinCheckDigit('4006381333931')).toBe(true);
    expect(isValidGtinCheckDigit('09501101530003')).toBe(true);
    expect(isValidGtinCheckDigit('96385074')).toBe(true);
  });

  it('stops at an identifier it does not know', () => {
    expect(parseGs1('0109501101530003' + '99XYZ')).toEqual({ gtin: '09501101530003' });
  });
});
