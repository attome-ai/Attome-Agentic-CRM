import { describe, expect, it } from 'vitest';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { STABLE_ERROR_CODES, stableErrorCode } from './admin-http';
import { structureErrorText } from './structure-error-text';

describe('stableErrorCode', () => {
  it('reads version_conflict from the kind', () => {
    expect(stableErrorCode({ kind: 'version_conflict', code: 'version_conflict', message: 'version conflict' }))
      .toBe('version_conflict');
  });

  it('reads the code of a blocked change body from `code`', () => {
    expect(stableErrorCode({ kind: 'conflict', code: 'field_referenced', message: '' })).toBe('field_referenced');
  });

  it('reads the code from a `conflict: <code>: <prose>` message', () => {
    expect(stableErrorCode({
      kind: 'conflict', code: 'conflict',
      message: 'conflict: report_item_decided: this report item is no longer open',
    })).toBe('report_item_decided');
  });

  it('reads the code from a validation message that starts with it', () => {
    expect(stableErrorCode({
      kind: 'validation', code: 'validation_error',
      message: 'conversion_not_defined: no conversion from date to bool',
    })).toBe('conversion_not_defined');
  });

  it('returns null for an unknown failure', () => {
    expect(stableErrorCode({ kind: 'internal', code: 'internal_error', message: 'an internal error occurred' })).toBeNull();
    expect(stableErrorCode(null)).toBeNull();
  });
});

describe('structureErrorText', () => {
  const lang = {
    translate: (key: string) => (key === 'structureErrors.field_busy' ? 'busy text' : key),
    errorText: () => 'generic text',
  };

  it('uses the catalog text for a stable code', () => {
    expect(structureErrorText(lang, { kind: 'conflict', code: 'conflict', message: 'conflict: field_busy: x' }))
      .toBe('busy text');
  });

  it('falls back to LangService.errorText', () => {
    expect(structureErrorText(lang, { kind: 'internal', message: '' })).toBe('generic text');
  });
});

describe('structureErrors catalog', () => {
  it('has an English and an Arabic text for every stable code', () => {
    const en = (xrmEn as unknown as { structureErrors: Record<string, string> }).structureErrors;
    const ar = (xrmAr as unknown as { structureErrors: Record<string, string> }).structureErrors;
    for (const code of STABLE_ERROR_CODES) {
      expect(en[code], `en ${code}`).toBeTruthy();
      expect(ar[code], `ar ${code}`).toBeTruthy();
    }
  });
});
