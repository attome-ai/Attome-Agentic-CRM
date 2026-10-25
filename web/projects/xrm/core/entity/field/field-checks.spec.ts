import { FormControl } from '@angular/forms';
import { describe, expect, it } from 'vitest';

import type { FieldSchema } from '@attome/xrm';
import { checkFailure, fieldValidators, formatOk, normalizeForFormat } from './field-checks';

function field(partial: Partial<FieldSchema>): FieldSchema {
  return {
    id: 'f', entity_id: 'e', name: 'f', display_name: 'F', field_type: 'text',
    options: null, sort_order: 0, is_required: false, ...partial,
  };
}

const ok = (format: string, raw: string) => formatOk(format, normalizeForFormat(format, raw));

describe('field checks (A3-T7)', () => {
  it('mirrors the server formats after normalising', () => {
    expect(ok('iban', 'sa03 8000 0000 6080 1016 7519')).toBe(true);
    expect(ok('iban', 'SA03 8000 0000 6080 1016 7518')).toBe(false);
    expect(ok('phone', '٠٠٩٦٦٥٠١٢٣٤٥٦٧')).toBe(true);
    expect(ok('phone', '0501234567')).toBe(false);
    expect(ok('saudi_national_id', '١٠٠٠٠٠٠٠٠٨')).toBe(true);
    expect(ok('iqama', '2000000005')).toBe(false);
    expect(ok('uae_emirates_id', '784-1990-1234567-6')).toBe(true);
    expect(ok('email', ' Sara@Example.COM ')).toBe(true);
    expect(ok('percent', '101')).toBe(false);
    expect(ok('duration', 'PT30M')).toBe(true);
    expect(ok('duration', 'PT')).toBe(false);
  });

  it('builds validators from the field metadata and names the failure', () => {
    const iban = new FormControl('', fieldValidators(field({ options: { format: 'iban' } })));
    expect(iban.valid).toBe(true);
    iban.setValue('SA03');
    expect(checkFailure(iban.errors)?.key).toBe('xrmForm.check.format.iban');

    const masked = new FormControl('', fieldValidators(field({ options: { pattern: '[A-Z]{2}[0-9]{3}', mask_description: 'AB123' } })));
    masked.setValue('AB12');
    expect(checkFailure(masked.errors)).toEqual({ key: 'xrmForm.check.pattern', params: { description: 'AB123' } });
    masked.setValue('AB١٢٣');
    expect(masked.valid).toBe(true);

    const amount = new FormControl<number | null>(null, fieldValidators(field({ field_type: 'number', options: { min: 1, max: 10 } })));
    amount.setValue(11);
    expect(checkFailure(amount.errors)?.key).toBe('xrmForm.check.max');

    const required = new FormControl('', fieldValidators(field({ is_required: true })));
    expect(required.hasError('required')).toBe(true);
    expect(checkFailure(required.errors)).toBeNull();
  });
});
