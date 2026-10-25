import { AbstractControl, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';

import type { FieldSchema } from '@attome/xrm';

/**
 * A3-T7: the checks the server makes on a field, run as the person types so
 * every failure shows before saving. The server stays the authority: these
 * mirror `attome_field::validate` (required, `options.pattern`,
 * `options.format` from A2-T2, a number's `options.min`/`options.max`) and a
 * 422 still lands under each field. Values are checked as the server stores
 * them: Arabic digits as Western ones, identifiers without spaces or dashes.
 */

/** The built-in formats (`attome_field::formats::FORMATS`). */
export const FIELD_FORMATS = [
  'email', 'phone', 'url', 'iban', 'saudi_national_id', 'iqama', 'uae_emirates_id', 'percent', 'duration',
] as const;
export type FieldFormat = (typeof FIELD_FORMATS)[number];

const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AE: 23, BH: 22, DE: 22, EG: 29, FR: 27, GB: 22, IQ: 23, JO: 30,
  KW: 30, LB: 28, NL: 18, OM: 23, PK: 24, QA: 29, SA: 24, TR: 26,
};

/** Arabic-Indic and Eastern Arabic-Indic digits as Western ones. */
export function westernDigits(text: string): string {
  return text
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06f0))
    .replace(/٫/g, '.');
}

/** The value as the server stores it for `format` (`formats::normalize`). */
export function normalizeForFormat(format: string, text: string): string {
  const western = westernDigits(text.trim());
  switch (format) {
    case 'email': return western.toLowerCase();
    case 'phone': {
      const plus = western.startsWith('+');
      let digits = western.replace(/\D/g, '');
      if (plus) return `+${digits}`;
      if (digits.startsWith('00')) digits = `+${digits.slice(2)}`;
      return digits;
    }
    case 'iban': case 'saudi_national_id': case 'iqama': case 'uae_emirates_id':
      return western.replace(/[\s-]/g, '').toUpperCase();
    default: return western;
  }
}

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

function ibanOk(text: string): boolean {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(text)) return false;
  const expected = IBAN_LENGTHS[text.slice(0, 2)];
  if (expected !== undefined && expected !== text.length) return false;
  let remainder = 0;
  for (const c of text.slice(4) + text.slice(0, 4)) {
    const value = c >= 'A' ? c.charCodeAt(0) - 55 : Number(c);
    remainder = (remainder * (value >= 10 ? 100 : 10) + value) % 97;
  }
  return remainder === 1;
}

function durationOk(text: string): boolean {
  const clock = /^(\d+):([0-5]\d)$/.exec(text);
  if (clock) return true;
  const iso = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(text);
  if (!iso) return false;
  const hasTime = text.includes('T');
  const timeParts = iso.slice(5).filter(p => p !== undefined).length;
  if (hasTime && timeParts === 0) return false;
  return iso.slice(1).some(p => p !== undefined);
}

/** Whether `text` (already normalised) is a valid `format` (`formats::check`). */
export function formatOk(format: string, text: string): boolean {
  switch (format) {
    case 'email': {
      const at = text.indexOf('@');
      if (at < 1 || at !== text.lastIndexOf('@') || /\s/.test(text) || text.length > 254) return false;
      const domain = text.slice(at + 1);
      return domain.includes('.') && domain.split('.').every(l => l.length > 0 && !l.startsWith('-') && !l.endsWith('-'));
    }
    case 'phone': return /^\+[1-9]\d{7,14}$/.test(text);
    case 'url': return /^https?:\/\/[^/?#\s]+\S*$/.test(text);
    case 'iban': return ibanOk(text);
    case 'saudi_national_id': return /^1\d{9}$/.test(text) && luhn(text);
    case 'iqama': return /^2\d{9}$/.test(text) && luhn(text);
    case 'uae_emirates_id': return /^784\d{12}$/.test(text) && luhn(text);
    case 'percent': {
      const n = Number(text.replace(/%$/, '').trim());
      return text.trim() !== '' && Number.isFinite(n) && n >= 0 && n <= 100;
    }
    case 'duration': return durationOk(text);
    default: return true;
  }
}

interface CheckedOptions {
  pattern?: string | null;
  mask_description?: string | null;
  format?: string | null;
  min?: number | null;
  max?: number | null;
}

const isBlank = (v: unknown) => v === null || v === undefined || (typeof v === 'string' && v.trim() === '');

/** The validators for one field: required, then its pattern, format or range. */
export function fieldValidators(field: FieldSchema): ValidatorFn[] {
  const validators: ValidatorFn[] = [];
  if (field.is_required) validators.push(Validators.required);
  const opts = (field.options ?? {}) as unknown as CheckedOptions;
  if (field.field_type === 'text') {
    const pattern = opts.pattern?.trim();
    if (pattern) {
      let re: RegExp | null = null;
      try { re = new RegExp(`^(?:${pattern.replace(/^\^/, '').replace(/\$$/, '')})$`, 'u'); } catch { re = null; }
      if (re) {
        const anchored = re;
        validators.push((c: AbstractControl): ValidationErrors | null =>
          isBlank(c.value) || anchored.test(westernDigits(String(c.value).trim()))
            ? null : { pattern: { description: opts.mask_description ?? pattern } });
      }
    }
    const format = opts.format;
    if (format && (FIELD_FORMATS as readonly string[]).includes(format)) {
      validators.push((c: AbstractControl): ValidationErrors | null =>
        isBlank(c.value) || formatOk(format, normalizeForFormat(format, String(c.value)))
          ? null : { format: { format } });
    }
  }
  if (field.field_type === 'number' || field.field_type === 'currency') {
    if (typeof opts.min === 'number') validators.push(Validators.min(opts.min));
    if (typeof opts.max === 'number') validators.push(Validators.max(opts.max));
  }
  return validators;
}

/**
 * The first failing check's message key and parameters, for a control that
 * failed something other than `required` (which the field shows itself).
 */
export function checkFailure(errors: ValidationErrors | null): { key: string; params: Record<string, unknown> } | null {
  if (!errors) return null;
  if (errors['format']) return { key: `xrmForm.check.format.${errors['format'].format}`, params: {} };
  if (errors['pattern']) return { key: 'xrmForm.check.pattern', params: { description: errors['pattern'].description } };
  if (errors['min']) return { key: 'xrmForm.check.min', params: { min: errors['min'].min } };
  if (errors['max']) return { key: 'xrmForm.check.max', params: { max: errors['max'].max } };
  return null;
}
