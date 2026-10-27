/**
 * B6-T3: the editable grid's paste and fill, pure. A block copied from
 * Excel arrives as tab-separated text; when its first row names the grid's
 * columns it is mapped by header, otherwise by position from the active
 * cell. Each cell is converted to its column's type, and a cell that does
 * not convert carries an error instead of a value, for the preview. Fill
 * continues a number or date series from two cells, or copies one.
 */
import { CellPos, EditableType, editable, parseCell } from './editable-grid.model';

/** The column facts paste and fill need. */
export interface GridColumn {
  name: string;
  display_name: string;
  type: string;
}

/** One pasted cell, placed. */
export interface PastedCell {
  row: number;
  col: number;
  raw: string;
  /** The converted value; absent when `error` is set. */
  value?: unknown;
  /** `invalid` (does not convert) or `readonly` (the column is not edited in the grid). */
  error?: 'invalid' | 'readonly';
}

/** What a paste would do. */
export interface PastePlan {
  /** Whether the first pasted row was read as headers. */
  byHeader: boolean;
  /** Each pasted column's target column index, or -1 when no column matched its header. */
  targets: number[];
  cells: PastedCell[];
  /** Pasted rows past the grid's last row (not placed). */
  overflowRows: number;
  /** Pasted headers no grid column matched. */
  unmatched: string[];
}

/**
 * Splits tab-separated text as Excel copies it: tabs between cells, a line
 * break between rows, `"` quoting a cell that holds a tab, a line break or
 * a quote (doubled). A trailing line break ends the last row.
 */
export function parseTsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  let atCellStart = true;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
      continue;
    }
    if (c === '"' && atCellStart) { quoted = true; atCellStart = false; continue; }
    if (c === '\t') { row.push(cell); cell = ''; atCellStart = true; continue; }
    if (c === '\r') continue;
    if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; atCellStart = true; continue; }
    cell += c;
    atCellStart = false;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

const norm = (s: string) => s.trim().toLowerCase().replace(/[\s_]+/g, ' ');

/** The column a header names, by display name or logical name; -1 when none. */
export function headerTarget(header: string, columns: GridColumn[]): number {
  const h = norm(header);
  if (!h) return -1;
  return columns.findIndex(c => norm(c.display_name) === h || norm(c.name) === h);
}

/**
 * Where `rows` land and what each cell becomes. The first row is read as
 * headers when at least half of its non-empty cells name a column; then
 * each pasted column goes to the column it names and the data starts on
 * the active row. Otherwise the block is placed from the active cell,
 * column by column; pasted columns past the last grid column are dropped.
 */
export function planPaste(rows: string[][], columns: GridColumn[], at: CellPos, rowCount: number): PastePlan {
  const first = rows[0] ?? [];
  const named = first.filter(h => h.trim() !== '');
  const matches = named.filter(h => headerTarget(h, columns) >= 0).length;
  const byHeader = named.length > 0 && matches * 2 >= named.length;
  const data = byHeader ? rows.slice(1) : rows;
  const width = Math.max(0, ...data.map(r => r.length), byHeader ? first.length : 0);
  const targets = Array.from({ length: width }, (_, i) => {
    if (byHeader) return headerTarget(first[i] ?? '', columns);
    const col = at.col + i;
    return col < columns.length ? col : -1;
  });
  const cells: PastedCell[] = [];
  data.forEach((values, r) => {
    const row = at.row + r;
    if (row >= rowCount) return;
    values.forEach((raw, i) => {
      const col = targets[i];
      if (col === undefined || col < 0) return;
      const column = columns[col];
      if (!editable(column.type)) {
        cells.push({ row, col, raw, error: 'readonly' });
        return;
      }
      const value = parseCell(column.type as EditableType, raw);
      cells.push(value === undefined ? { row, col, raw, error: 'invalid' } : { row, col, raw, value });
    });
  });
  return {
    byHeader,
    targets,
    cells,
    overflowRows: Math.max(0, at.row + data.length - rowCount),
    unmatched: byHeader ? first.filter((h, i) => h.trim() !== '' && targets[i] < 0) : [],
  };
}

const DAY_MS = 86_400_000;

/**
 * The values filling `count` cells after `source` (one or two cells, the
 * last one nearest the fill). Two numbers continue their step; two dates
 * (`yyyy-mm-dd`) continue their step in days; anything else copies the
 * last value.
 */
export function fillValues(source: unknown[], type: string, count: number): unknown[] {
  const last = source[source.length - 1];
  const prev = source.length > 1 ? source[source.length - 2] : undefined;
  if ((type === 'number' || type === 'currency') && typeof last === 'number' && typeof prev === 'number') {
    const step = last - prev;
    return Array.from({ length: count }, (_, i) => round(last + step * (i + 1)));
  }
  if (type === 'date' && isDate(last) && isDate(prev)) {
    const lastMs = Date.parse(`${last}T00:00:00Z`);
    const step = Math.round((lastMs - Date.parse(`${prev}T00:00:00Z`)) / DAY_MS);
    return Array.from({ length: count }, (_, i) =>
      new Date(lastMs + step * (i + 1) * DAY_MS).toISOString().slice(0, 10));
  }
  return Array.from({ length: count }, () => last);
}

function isDate(v: unknown): v is string {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
}

/** Drops float noise (`0.1 + 0.2`) from a filled number. */
function round(n: number): number {
  return Math.round(n * 1e10) / 1e10;
}
