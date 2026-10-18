/**
 * Currencies whose amounts carry three decimals (ISO 4217 minor units);
 * the Gulf ones the platform bills in first. The server rounds to the same
 * table (`attome_billing::tax::minor_units`).
 */
const THREE_DECIMALS = new Set(['KWD', 'BHD', 'OMR', 'JOD', 'IQD', 'LYD', 'TND']);
/** Currencies with no minor unit. */
const NO_DECIMALS = new Set(['JPY', 'KRW']);

/** How many decimals an amount in `currency` shows. */
export function minorUnits(currency: string): number {
  const code = currency.trim().toUpperCase();
  if (THREE_DECIMALS.has(code)) return 3;
  if (NO_DECIMALS.has(code)) return 0;
  return 2;
}

/**
 * A decimal amount from the API (text, so no float rounding) formatted for
 * `locale` with the currency's minor units. Text that is not a number is
 * returned as it came.
 */
export function formatAmount(amount: string | null | undefined, currency: string, locale: string): string {
  if (amount === null || amount === undefined || amount === '') return '';
  const value = Number(amount);
  if (!Number.isFinite(value)) return amount;
  const digits = minorUnits(currency);
  return new Intl.NumberFormat(locale, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value);
}
