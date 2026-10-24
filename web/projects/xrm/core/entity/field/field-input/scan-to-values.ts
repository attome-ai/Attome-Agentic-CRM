import { isValidGtinCheckDigit, parseGs1 } from '@attome/base';

/** A field's `options.scan` (`attome_field::ScanOptions`). */
export interface ScanFieldOptions {
  enabled?: boolean;
  formats?: string[];
  gs1_batch_attribute?: string | null;
  gs1_expiry_attribute?: string | null;
  on_unknown?: 'reject' | 'offer_create';
}

/** What a scan puts in the form, or why it is refused. */
export interface ScanFill {
  value?: string;
  /** Other fields of the record to set: GS1 batch and expiry. */
  siblings: Record<string, string>;
  /** A catalog key when the scan is refused. */
  error?: string;
}

const RETAIL = ['ean_13', 'ean_8', 'upc_a', 'upc_e'];

/** Whether a raw scan is a GS1 element string: a GS1 symbology id, or AI 01 first. */
function isGs1(raw: string): boolean {
  return /^\]C1|^\]d2|^\]Q3/.test(raw) || /^01\d{14}/.test(raw.replace(/^\][A-Za-z]\d/, ''));
}

/**
 * B16-T4: the value and sibling fields one scan fills. A GS1 code fills the
 * field with its GTIN and the configured batch and expiry fields with
 * theirs; a retail code (EAN, UPC) must carry a valid check digit; a number
 * field takes digits only. Pure.
 */
export function scanToValues(raw: string, format: string, fieldType: string, scan: ScanFieldOptions | null): ScanFill {
  const siblings: Record<string, string> = {};
  let value = raw.trim();
  let gtinLike = RETAIL.includes(format);
  if (isGs1(raw)) {
    const gs1 = parseGs1(raw);
    if (gs1.gtin) {
      value = gs1.gtin;
      gtinLike = true;
    }
    if (gs1.batch && scan?.gs1_batch_attribute) siblings[scan.gs1_batch_attribute] = gs1.batch;
    if (gs1.expiry && scan?.gs1_expiry_attribute) siblings[scan.gs1_expiry_attribute] = gs1.expiry;
  }
  if (!value) return { siblings: {}, error: 'fieldInput.scan.empty' };
  if (fieldType === 'number' && !/^\d+$/.test(value)) return { siblings: {}, error: 'fieldInput.scan.notANumber' };
  if (gtinLike && !isValidGtinCheckDigit(value)) return { siblings: {}, error: 'fieldInput.scan.badCheckDigit' };
  return { value, siblings };
}
