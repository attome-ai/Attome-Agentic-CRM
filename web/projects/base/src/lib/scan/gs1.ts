/**
 * B16-T2: reading a GS1 element string (what a GS1-128, GS1 DataMatrix or
 * GS1 QR code holds) into the fields a scan fills, and checking a GTIN's
 * check digit. Pure: no camera, no decoder.
 *
 * Application identifiers read: `01` GTIN (14 digits), `10` batch (to the
 * next FNC1, ASCII 29), `17` expiry (YYMMDD, returned as YYYY-MM-DD; day `00`
 * means the month's last day) and `21` serial (to the next FNC1). A leading
 * symbology identifier (`]C1`, `]d2`, `]Q3`) is skipped. Reading stops at an
 * identifier it does not know, since it cannot tell where that one ends.
 */
export interface Gs1Fields {
  gtin?: string;
  batch?: string;
  expiry?: string;
  serial?: string;
}

/** The group separator a scanner sends for FNC1. */
export const FNC1 = '\u001d';

/** Reads the element string `raw`. */
export function parseGs1(raw: string): Gs1Fields {
  let rest = raw.replace(/^\][A-Za-z]\d/, '');
  const out: Gs1Fields = {};
  while (rest.length >= 2) {
    if (rest.startsWith(FNC1)) {
      rest = rest.slice(1);
      continue;
    }
    const ai = rest.slice(0, 2);
    rest = rest.slice(2);
    if (ai === '01') {
      out.gtin = rest.slice(0, 14);
      rest = rest.slice(14);
    } else if (ai === '17') {
      out.expiry = gs1Date(rest.slice(0, 6));
      rest = rest.slice(6);
    } else if (ai === '10' || ai === '21') {
      const end = rest.indexOf(FNC1);
      const value = end === -1 ? rest : rest.slice(0, end);
      rest = end === -1 ? '' : rest.slice(end + 1);
      if (ai === '10') out.batch = value;
      else out.serial = value;
    } else {
      break;
    }
  }
  return out;
}

/** `YYMMDD` as `YYYY-MM-DD`; day `00` is the month's last day. Years are 20YY. */
function gs1Date(yymmdd: string): string | undefined {
  if (!/^\d{6}$/.test(yymmdd)) return undefined;
  const year = 2000 + Number(yymmdd.slice(0, 2));
  const month = Number(yymmdd.slice(2, 4));
  let day = Number(yymmdd.slice(4, 6));
  if (month < 1 || month > 12) return undefined;
  if (day === 0) day = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${year}-${pad(month)}-${pad(day)}`;
}

/** The GS1 mod-10 check for an 8, 12, 13 or 14 digit GTIN. */
export function isValidGtinCheckDigit(code: string): boolean {
  if (!/^\d+$/.test(code) || ![8, 12, 13, 14].includes(code.length)) return false;
  const digits = [...code].map(Number);
  const check = digits.pop() as number;
  const sum = digits
    .reverse()
    .reduce((total, digit, i) => total + digit * (i % 2 === 0 ? 3 : 1), 0);
  return (10 - (sum % 10)) % 10 === check;
}
