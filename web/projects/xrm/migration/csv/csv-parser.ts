/**
 * U11 / D-606 — the CSV import's browser-side reader. Pure functions, no
 * Angular, no dependency: bytes -> text (encoding detection) -> rows
 * (RFC 4180). The server never sees the file; it sees staged-import records
 * built from what this returns.
 *
 * - RFC 4180: quoted fields, `""` as an escaped quote, CR/LF/CRLF line ends,
 *   line breaks inside quoted cells. Lenient where Excel is: a quote that
 *   does not open a field is kept as a literal character.
 * - A leading BOM picks the encoding (UTF-8, UTF-16LE/BE) and is dropped.
 * - Without a BOM the bytes are tried as strict UTF-8 first; bytes that are
 *   not valid UTF-8 are an Excel "CSV" export in the machine's ANSI code
 *   page, decoded as Windows-1256 when the result is mostly Arabic and as
 *   Windows-1252 otherwise. The caller can force any of these.
 * - The delimiter is sniffed from `,` `;` and tab.
 * - The data-row cap (Q6: 50,000) stops the parse early instead of reading a
 *   file the import would refuse anyway.
 */

export type CsvEncoding = 'utf-8' | 'utf-16le' | 'utf-16be' | 'windows-1256' | 'windows-1252';
export type CsvDelimiter = ',' | ';' | '\t';

/** Q6 (basic-units-10-10 §7): the v1 row cap, data rows only. */
export const MAX_IMPORT_ROWS = 50_000;

export interface DecodedCsv {
  text: string;
  encoding: CsvEncoding;
  /** True when the encoding came from a byte-order mark. */
  bom: boolean;
}

export function decodeCsvBytes(bytes: Uint8Array, forced?: CsvEncoding): DecodedCsv {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { text: decode(bytes.subarray(3), forced ?? 'utf-8'), encoding: forced ?? 'utf-8', bom: true };
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { text: decode(bytes.subarray(2), forced ?? 'utf-16le'), encoding: forced ?? 'utf-16le', bom: true };
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return { text: decode(bytes.subarray(2), forced ?? 'utf-16be'), encoding: forced ?? 'utf-16be', bom: true };
  }
  if (forced) return { text: decode(bytes, forced), encoding: forced, bom: false };
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), encoding: 'utf-8', bom: false };
  } catch {
    // Not UTF-8: an ANSI code-page export. Arabic Excel writes Windows-1256.
    const arabic = decode(bytes, 'windows-1256');
    const encoding: CsvEncoding = mostlyArabic(arabic) ? 'windows-1256' : 'windows-1252';
    return { text: encoding === 'windows-1256' ? arabic : decode(bytes, encoding), encoding, bom: false };
  }
}

function decode(bytes: Uint8Array, encoding: CsvEncoding): string {
  return new TextDecoder(encoding).decode(bytes);
}

/** More than half of the non-ASCII letters fall in the Arabic block. */
function mostlyArabic(text: string): boolean {
  let arabic = 0;
  let other = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) continue;
    if (code >= 0x0600 && code <= 0x06ff) arabic++;
    else other++;
  }
  return arabic > 0 && arabic >= other;
}

export interface RaggedRow {
  /** 0-based index into `ParsedCsv.rows`. */
  index: number;
  /** The row's number as a spreadsheet shows it (the header is row 1). */
  rowNumber: number;
  expected: number;
  actual: number;
}

export interface ParsedCsv {
  delimiter: CsvDelimiter;
  /** Trimmed, never empty, unique (a repeat gets " (2)", " (3)"...). */
  headers: string[];
  /** Data rows, header excluded, blank lines skipped. */
  rows: string[][];
  /** Spreadsheet row number of each data row (header = 1, blank lines counted). */
  rowNumbers: number[];
  /** Rows whose field count differs from the header's. */
  ragged: RaggedRow[];
  /** More than `maxRows` data rows; parsing stopped at the cap. */
  tooManyRows: boolean;
  /** The file ended inside a quoted field (spreadsheet row where it opened). */
  unterminatedQuoteRow: number | null;
}

export interface ParseOptions {
  delimiter?: CsvDelimiter;
  maxRows?: number;
}

export function parseCsv(text: string, options: ParseOptions = {}): ParsedCsv {
  const delimiter = options.delimiter ?? sniffDelimiter(text);
  const maxRows = options.maxRows ?? MAX_IMPORT_ROWS;
  const records: string[][] = [];
  const recordNumbers: number[] = [];
  let tooManyRows = false;
  const scan = scanRecords(text, delimiter, (fields, recordNumber) => {
    // Blank line: one empty, unquoted field. Skipped, but still counted.
    if (fields.length === 1 && fields[0] === '') return true;
    // `records` holds the header plus the data rows read so far.
    if (records.length > maxRows) {
      tooManyRows = true;
      return false;
    }
    records.push(fields);
    recordNumbers.push(recordNumber);
    return true;
  });

  const headerRow = records.shift() ?? [];
  recordNumbers.shift();
  const headers = uniqueHeaders(headerRow);
  const ragged: RaggedRow[] = [];
  records.forEach((row, index) => {
    if (row.length !== headers.length) {
      ragged.push({ index, rowNumber: recordNumbers[index], expected: headers.length, actual: row.length });
    }
  });
  return {
    delimiter,
    headers,
    rows: records,
    rowNumbers: recordNumbers,
    ragged,
    tooManyRows,
    unterminatedQuoteRow: scan.unterminatedAt,
  };
}

/**
 * Picks the candidate that splits the first few records into the same,
 * largest number of fields. Quote-aware, so a comma inside a quoted cell of a
 * semicolon file does not count.
 */
export function sniffDelimiter(text: string): CsvDelimiter {
  const sample = text.slice(0, 64 * 1024);
  let best: CsvDelimiter = ',';
  let bestScore = -1;
  for (const candidate of [',', ';', '\t'] as CsvDelimiter[]) {
    const counts: number[] = [];
    scanRecords(sample, candidate, fields => {
      if (!(fields.length === 1 && fields[0] === '')) counts.push(fields.length);
      return counts.length < 10;
    });
    // The sample may cut the last record short; judge on the complete ones.
    if (counts.length > 1 && sample.length < text.length) counts.pop();
    const width = counts[0] ?? 1;
    if (width < 2) continue;
    const consistent = counts.filter(c => c === width).length;
    const score = consistent * 1000 + width;
    if (score > bestScore) {
      bestScore = score;
      best = candidate;
    }
  }
  return best;
}

/**
 * The RFC 4180 state machine. Calls `onRecord` per record with its fields and
 * its 1-based record number; `onRecord` returns false to stop.
 */
function scanRecords(
  text: string,
  delimiter: string,
  onRecord: (fields: string[], recordNumber: number) => boolean,
): { unterminatedAt: number | null } {
  let fields: string[] = [];
  let field = '';
  let inQuotes = false;
  let fieldStarted = false; // a quote opens a field only as its first character
  let recordNumber = 1;
  let quoteOpenedAt = 0;
  const n = text.length;
  let i = 0;

  const endRecord = (): boolean => {
    fields.push(field);
    const keepGoing = onRecord(fields, recordNumber);
    recordNumber++;
    fields = [];
    field = '';
    fieldStarted = false;
    return keepGoing;
  };

  while (i < n) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"' && !fieldStarted) {
      inQuotes = true;
      fieldStarted = true;
      quoteOpenedAt = recordNumber;
      i++;
      continue;
    }
    if (c === delimiter) {
      fields.push(field);
      field = '';
      fieldStarted = false;
      i++;
      continue;
    }
    if (c === '\r' || c === '\n') {
      i += c === '\r' && text[i + 1] === '\n' ? 2 : 1;
      if (!endRecord()) return { unterminatedAt: null };
      continue;
    }
    field += c;
    fieldStarted = true;
    i++;
  }
  if (inQuotes) {
    endRecord();
    return { unterminatedAt: quoteOpenedAt };
  }
  // No trailing newline: the last record still counts.
  if (field !== '' || fields.length > 0 || fieldStarted) endRecord();
  return { unterminatedAt: null };
}

function uniqueHeaders(raw: string[]): string[] {
  const seen = new Map<string, number>();
  return raw.map((h, i) => {
    const base = h.trim() || `Column ${i + 1}`;
    const count = (seen.get(base) ?? 0) + 1;
    seen.set(base, count);
    return count === 1 ? base : `${base} (${count})`;
  });
}
