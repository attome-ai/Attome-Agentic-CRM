import type { CsvEncoding } from './csv-parser';
import type { DateFormat, DecimalSeparator, ImportRecord } from './csv-coerce';

/**
 * U11 / D-606 — how a parsed file becomes staged-import requests, and how an
 * import project remembers which file it was.
 */

/** `bulk.rs::MAX_BULK_RECORDS` — the most records one staged import takes. */
export const CHUNK_ROWS = 500;

/**
 * Stays well under the server's default 10 MiB body limit
 * (`app.max_body_size_bytes`), so a chunk of wide rows is split rather than
 * refused as a whole.
 */
export const CHUNK_MAX_BYTES = 6 * 1024 * 1024;

export interface ImportChunk {
  /** 0-based chunk number; the order chunks are linked to the project in. */
  index: number;
  records: ImportRecord[];
}

/**
 * Consecutive records, at most `maxRows` per chunk and at most `maxBytes` of
 * JSON. Deterministic: the same records always give the same chunks, which
 * is what lets a resumed import skip the chunks already staged.
 */
export function chunkRecords(
  records: ImportRecord[],
  maxRows = CHUNK_ROWS,
  maxBytes = CHUNK_MAX_BYTES,
): ImportChunk[] {
  const encoder = new TextEncoder();
  const chunks: ImportChunk[] = [];
  let current: ImportRecord[] = [];
  let bytes = 0;
  for (const record of records) {
    const size = encoder.encode(JSON.stringify({ data: record.data })).length + 1;
    if (current.length > 0 && (current.length >= maxRows || bytes + size > maxBytes)) {
      chunks.push({ index: chunks.length, records: current });
      current = [];
      bytes = 0;
    }
    current.push(record);
    bytes += size;
  }
  if (current.length > 0) chunks.push({ index: chunks.length, records: current });
  return chunks;
}

/** `POST /api/v1/{entity}/staged-import`'s body for one chunk. */
export function chunkBody(chunk: ImportChunk, mappingRef: string, mode: 'stage' | 'dry_run'): object {
  return {
    operation: 'create',
    mapping_ref: mappingRef,
    mode,
    records: chunk.records.map(r => ({ data: r.data })),
  };
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * What an import project records about its file in `source_ref`, so a later
 * resume can check it is being given the same file read the same way.
 */
export interface CsvSourceRef {
  sha256: string;
  rows: number;
  encoding: CsvEncoding;
  dateFormat: DateFormat;
  decimal: DecimalSeparator;
}

const PREFIX = 'csv-import:v1';

export function formatSourceRef(ref: CsvSourceRef): string {
  return `${PREFIX};sha256=${ref.sha256};rows=${ref.rows};encoding=${ref.encoding};date=${ref.dateFormat};decimal=${ref.decimal}`;
}

export function parseSourceRef(value: string | null | undefined): CsvSourceRef | null {
  if (!value?.startsWith(`${PREFIX};`)) return null;
  const parts = new Map(
    value
      .slice(PREFIX.length + 1)
      .split(';')
      .map(p => p.split('=') as [string, string]),
  );
  const sha256 = parts.get('sha256');
  const rows = Number(parts.get('rows'));
  const encoding = parts.get('encoding') as CsvEncoding | undefined;
  const dateFormat = parts.get('date') as DateFormat | undefined;
  const decimal = parts.get('decimal') as DecimalSeparator | undefined;
  if (!sha256 || !Number.isInteger(rows) || !encoding || !dateFormat || !decimal) return null;
  return { sha256, rows, encoding, dateFormat, decimal };
}
