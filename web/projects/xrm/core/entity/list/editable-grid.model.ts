/**
 * B6-T1: the editable grid's pure parts: which columns a cell editor can
 * edit, how a typed value becomes the value saved, and where the keyboard
 * moves the active cell (spreadsheet keys, with left and right swapped in a
 * right-to-left layout).
 */

/** The column types a grid cell edits in place. Lookups, files, images and rich text open the record instead. */
export const EDITABLE_TYPES = ['text', 'number', 'currency', 'date', 'date_time', 'bool', 'choice'] as const;
export type EditableType = (typeof EDITABLE_TYPES)[number];

export function editable(type: string): type is EditableType {
  return (EDITABLE_TYPES as readonly string[]).includes(type);
}

/** A cell position. */
export interface CellPos {
  row: number;
  col: number;
}

/** What a key does to the active cell; `null` when the grid does not handle it. */
export type GridMove =
  | { kind: 'move'; to: CellPos }
  | { kind: 'edit' }
  | { kind: 'commit'; to: CellPos }
  | { kind: 'cancel' };

function clamp(pos: CellPos, rows: number, cols: number): CellPos {
  return { row: Math.max(0, Math.min(rows - 1, pos.row)), col: Math.max(0, Math.min(cols - 1, pos.col)) };
}

/**
 * The spreadsheet keyboard model. While not editing: arrows move (left and
 * right swapped when `rtl`), Tab and Shift+Tab move along the row and wrap
 * to the next or previous row, Enter and F2 start editing. While editing:
 * Enter commits and moves down, Tab commits and moves along, Escape cancels;
 * other keys belong to the editor. Pure.
 */
export function keyMove(
  key: string,
  shift: boolean,
  editing: boolean,
  at: CellPos,
  rows: number,
  cols: number,
  rtl: boolean,
): GridMove | null {
  if (rows === 0 || cols === 0) return null;
  const along = (step: number): CellPos => {
    let col = at.col + step;
    let row = at.row;
    if (col >= cols) { col = 0; row += 1; }
    if (col < 0) { col = cols - 1; row -= 1; }
    return clamp({ row, col }, rows, cols);
  };
  if (editing) {
    if (key === 'Escape') return { kind: 'cancel' };
    if (key === 'Enter') return { kind: 'commit', to: clamp({ row: at.row + (shift ? -1 : 1), col: at.col }, rows, cols) };
    if (key === 'Tab') return { kind: 'commit', to: along(shift ? -1 : 1) };
    return null;
  }
  const forward = rtl ? -1 : 1;
  switch (key) {
    case 'ArrowDown': return { kind: 'move', to: clamp({ row: at.row + 1, col: at.col }, rows, cols) };
    case 'ArrowUp': return { kind: 'move', to: clamp({ row: at.row - 1, col: at.col }, rows, cols) };
    case 'ArrowRight': return { kind: 'move', to: clamp({ row: at.row, col: at.col + forward }, rows, cols) };
    case 'ArrowLeft': return { kind: 'move', to: clamp({ row: at.row, col: at.col - forward }, rows, cols) };
    case 'Home': return { kind: 'move', to: { row: at.row, col: 0 } };
    case 'End': return { kind: 'move', to: { row: at.row, col: cols - 1 } };
    case 'Tab': return { kind: 'move', to: along(shift ? -1 : 1) };
    case 'Enter':
    case 'F2': return { kind: 'edit' };
    default: return null;
  }
}

/**
 * The value saved for what was typed into a `type` cell: a number for a
 * number or currency (empty is `null`), `true`/`false` for yes/no, an ISO
 * moment for a date and time, the text otherwise; `undefined` when the text
 * is not a value of the type. Pure.
 */
export function parseCell(type: EditableType, raw: string): unknown {
  const text = raw.trim();
  switch (type) {
    case 'number':
    case 'currency': {
      if (!text) return null;
      const n = Number(text.replace(/,/g, ''));
      return Number.isFinite(n) ? n : undefined;
    }
    case 'bool':
      return text === 'true' ? true : text === 'false' ? false : null;
    case 'date':
      return text ? (/^\d{4}-\d{2}-\d{2}$/.test(text) ? text : undefined) : null;
    case 'date_time': {
      if (!text) return null;
      const d = new Date(text);
      return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
    }
    default:
      return raw === '' ? null : raw;
  }
}

/** A value as its editor shows it. Pure. */
export function editorText(type: EditableType, value: unknown): string {
  if (value === null || value === undefined) return '';
  if (type === 'date_time' && typeof value === 'string') {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '';
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  if (type === 'date' && typeof value === 'string') return value.slice(0, 10);
  return String(value);
}

/** Whether `next` differs from `current`, as saved values. Pure. */
export function changed(current: unknown, next: unknown): boolean {
  const norm = (v: unknown) => (v === undefined ? null : v);
  return JSON.stringify(norm(current)) !== JSON.stringify(norm(next));
}
