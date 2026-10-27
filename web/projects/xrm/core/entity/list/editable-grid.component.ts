import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { concatMap, from, map, of, catchError, toArray } from 'rxjs';
import { EntityService } from '../services/entity.service';
import type { Col } from './entity-list.component';
import { CellPos, EditableType, changed, editable, editorText, keyMove, parseCell } from './editable-grid.model';
import { PastePlan, PastedCell, fillValues, parseTsv, planPaste } from './grid-paste';
import { EMPTY_STATE, GridState, History, isNewRow, newRow, record, undoLast, withValue } from './grid-undo';

/** One row's outcome of a save. */
export interface RowSave {
  id: string;
  ok: boolean;
  error?: string;
}

/** How many pasted rows the preview shows. */
export const PASTE_PREVIEW_ROWS = 5;

/**
 * B6-T1: the page's records as a spreadsheet. Click a cell, or press F2 or
 * Enter on it, to edit it in place with a compact control for its type
 * (text, number, currency, date, date and time, yes/no, choice); lookups,
 * files and rich text stay read-only here. Arrows, Tab, Enter and Escape
 * move and commit as in a spreadsheet, with left and right swapped in
 * Arabic. A changed cell is marked until it is saved; Save all sends one
 * PATCH per changed row with that row's version (`If-Match`) and
 * `If-Match-Merge: attributes`, so a row someone else changed in other
 * fields still saves and one changed in the same field is refused alone.
 *
 * B6-T3: a block pasted from Excel is previewed (mapped by its header row
 * when it has one, else from the active cell; cells that do not convert are
 * marked) before it fills the cells. Dragging the active cell's corner
 * copies its value down; with Ctrl held it continues the number or date
 * series of the cell above and the active cell. Ctrl+D copies the cell
 * above.
 *
 * B6-T4: Add row appends a row with the entity's new-record defaults
 * (created on save). Undo (Ctrl+Z) takes back the last edit, paste, fill or
 * added row; Discard all takes back the whole unsaved session.
 */
@Component({
  selector: 'xrm-editable-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './editable-grid.component.html',
  styleUrl: './editable-grid.component.css',
})
export class EditableGridComponent {
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly entityName = input.required<string>();
  readonly columns = input.required<Col[]>();
  readonly records = input.required<EntityRecord[]>();

  /** Rows saved (and failed), after Save all. */
  readonly saved = output<RowSave[]>();
  readonly closed = output<void>();

  readonly active = signal<CellPos>({ row: 0, col: 0 });
  readonly editing = signal(false);
  readonly draft = signal('');
  readonly state = signal<GridState>(EMPTY_STATE);
  readonly history = signal<History>({ past: [] });
  readonly errors = signal<Record<string, string>>({});
  readonly saving = signal(false);
  readonly invalid = signal(false);
  readonly addingRow = signal(false);
  /** B6-T3: the paste waiting for its preview to be applied. */
  readonly pastePlan = signal<PastePlan | null>(null);
  /** B6-T3: the row a fill drag reaches, while dragging. */
  readonly fillTo = signal<number | null>(null);
  private fillSeries = false;
  private seq = 0;

  /** Pending values by row id, then field. */
  readonly pending = computed(() => this.state().pending);
  /** The page's records, then the rows added in the grid. */
  readonly rows = computed(() => [...this.records(), ...this.state().added]);
  readonly rtl = computed(() => this.lang.isRtl());
  readonly changedRows = computed(() =>
    new Set([...Object.keys(this.pending()), ...this.state().added.map(r => r.id)]).size);
  readonly changedCells = computed(() => Object.values(this.pending()).reduce((n, p) => n + Object.keys(p).length, 0));
  readonly canUndo = computed(() => this.history().past.length > 0);

  /** The preview's target columns, in pasted order. */
  readonly pasteColumns = computed(() => {
    const plan = this.pastePlan();
    return plan ? [...new Set(plan.targets.filter(t => t >= 0))] : [];
  });
  /** The preview's first rows: per target column, the pasted cell or `null`. */
  readonly pasteRows = computed(() => {
    const plan = this.pastePlan();
    if (!plan) return [];
    const byRow = new Map<number, Map<number, PastedCell>>();
    for (const cell of plan.cells) {
      const cells = byRow.get(cell.row) ?? new Map<number, PastedCell>();
      cells.set(cell.col, cell);
      byRow.set(cell.row, cells);
    }
    return [...byRow.entries()].slice(0, PASTE_PREVIEW_ROWS).map(([row, cells]) => ({
      row,
      cells: this.pasteColumns().map(col => cells.get(col) ?? null),
    }));
  });
  /** The preview's message for a cell that will not be filled. */
  readonly pasteErrorKeys = {
    invalid: 'editableGrid.paste_invalid',
    readonly: 'editableGrid.paste_readonly',
  } as const;
  readonly pasteErrors = computed(() => this.pastePlan()?.cells.filter(c => c.error).length ?? 0);
  readonly pasteValid = computed(() => this.pastePlan()?.cells.filter(c => !c.error).length ?? 0);

  isEditable(col: Col): boolean {
    return editable(col.type);
  }

  isNew(row: EntityRecord): boolean {
    return isNewRow(row.id);
  }

  original(row: EntityRecord, col: Col): unknown {
    return (row.data as Record<string, unknown>)[col.name];
  }

  value(row: EntityRecord, col: Col): unknown {
    const p = this.pending()[row.id];
    return p && col.name in p ? p[col.name] : this.original(row, col);
  }

  isPending(row: EntityRecord, col: Col): boolean {
    const p = this.pending()[row.id];
    return !!p && col.name in p;
  }

  inFill(row: number, col: number): boolean {
    const to = this.fillTo();
    const at = this.active();
    return to !== null && col === at.col && row > at.row && row <= to;
  }

  display(row: EntityRecord, col: Col): string {
    const v = this.value(row, col);
    if (v === null || v === undefined || v === '') return '';
    if (col.type === 'choice') return col.options?.find(o => o.value === v)?.label ?? String(v);
    if (col.type === 'bool') return this.lang.translate(v === true ? 'editableGrid.yes' : 'editableGrid.no');
    if (typeof v === 'object') {
      const name = (v as { name?: unknown }).name;
      return typeof name === 'string' ? name : JSON.stringify(v);
    }
    return String(v);
  }

  /** Applies one batch, recording the state before it for undo; a batch that changes nothing is not recorded. */
  private apply(change: (s: GridState) => GridState): void {
    const before = this.state();
    const after = change(before);
    if (JSON.stringify(after) === JSON.stringify(before)) return;
    this.history.update(h => record(h, before));
    this.state.set(after);
  }

  private setCell(s: GridState, row: EntityRecord, col: Col, next: unknown): GridState {
    return withValue(s, row.id, col.name, next, this.original(row, col), (a, b) => !changed(a, b));
  }

  select(row: number, col: number): void {
    const at = this.active();
    if (at.row === row && at.col === col) return;
    if (this.editing()) this.commit();
    this.active.set({ row, col });
  }

  startEdit(): void {
    const { row, col } = this.active();
    const record = this.rows()[row];
    const column = this.columns()[col];
    if (!record || !column || !editable(column.type)) return;
    this.draft.set(editorText(column.type, this.value(record, column)));
    this.invalid.set(false);
    this.editing.set(true);
  }

  /** Keeps the editor's value as the cell's pending value (or refuses an invalid one). */
  commit(): boolean {
    const { row, col } = this.active();
    const record = this.rows()[row];
    const column = this.columns()[col];
    if (!record || !column || !editable(column.type)) {
      this.editing.set(false);
      return true;
    }
    const next = parseCell(column.type as EditableType, this.draft());
    if (next === undefined) {
      this.invalid.set(true);
      return false;
    }
    this.apply(s => this.setCell(s, record, column, next));
    this.editing.set(false);
    this.invalid.set(false);
    return true;
  }

  onKey(event: KeyboardEvent): void {
    if ((event.ctrlKey || event.metaKey) && !this.editing()) {
      const key = event.key.toLowerCase();
      if (key === 'd') { event.preventDefault(); this.fillFromAbove(); return; }
      if (key === 'z') { event.preventDefault(); this.undo(); return; }
    }
    const move = keyMove(event.key, event.shiftKey, this.editing(), this.active(), this.rows().length,
      this.columns().length, this.rtl());
    if (!move) return;
    event.preventDefault();
    switch (move.kind) {
      case 'edit':
        this.startEdit();
        break;
      case 'cancel':
        this.editing.set(false);
        this.invalid.set(false);
        break;
      case 'commit':
        if (this.commit()) this.active.set(move.to);
        break;
      case 'move':
        this.active.set(move.to);
        break;
    }
  }

  onDraft(event: Event): void {
    const target = event.target as HTMLInputElement | HTMLSelectElement;
    this.draft.set(target instanceof HTMLInputElement && target.type === 'checkbox' ? String(target.checked) : target.value);
  }

  // ── B6-T3: paste and fill ──────────────────────────────────────────────

  onPaste(event: ClipboardEvent): void {
    if (this.editing()) return;
    const text = event.clipboardData?.getData('text/plain') ?? '';
    if (!text.trim()) return;
    event.preventDefault();
    this.previewPaste(text);
  }

  previewPaste(text: string): void {
    this.pastePlan.set(planPaste(parseTsv(text), this.columns(), this.active(), this.rows().length));
  }

  /** Fills the previewed cells that converted; the others are left as they were. */
  applyPaste(): void {
    const plan = this.pastePlan();
    if (!plan) return;
    const rows = this.rows();
    const columns = this.columns();
    this.apply(s => plan.cells
      .filter(c => !c.error)
      .reduce((state, c) => this.setCell(state, rows[c.row], columns[c.col], c.value), s));
    this.pastePlan.set(null);
  }

  cancelPaste(): void {
    this.pastePlan.set(null);
  }

  startFill(event: MouseEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.fillSeries = event.ctrlKey || event.metaKey;
    this.fillTo.set(this.active().row);
  }

  extendFill(row: number): void {
    if (this.fillTo() !== null) this.fillTo.set(Math.max(this.active().row, row));
  }

  endFill(): void {
    const to = this.fillTo();
    this.fillTo.set(null);
    if (to === null) return;
    this.fill(to, this.fillSeries);
  }

  /** Fills the active cell's column down to row `to`: a copy, or with `series` the series of the cell above and the active cell. */
  fill(to: number, series: boolean): void {
    const { row, col } = this.active();
    const rows = this.rows();
    const column = this.columns()[col];
    if (!column || !editable(column.type) || to <= row) return;
    const source = series && row > 0 ? [this.value(rows[row - 1], column), this.value(rows[row], column)]
      : [this.value(rows[row], column)];
    const values = fillValues(source, column.type, Math.min(to, rows.length - 1) - row);
    this.apply(s => values.reduce<GridState>((state, v, i) => this.setCell(state, rows[row + 1 + i], column, v), s));
  }

  /** Ctrl+D: the active cell takes the value of the cell above. */
  fillFromAbove(): void {
    const { row, col } = this.active();
    const column = this.columns()[col];
    const rows = this.rows();
    if (row === 0 || !column || !editable(column.type)) return;
    const above = this.value(rows[row - 1], column);
    this.apply(s => this.setCell(s, rows[row], column, above));
  }

  // ── B6-T4: added rows and undo ─────────────────────────────────────────

  /** Appends a row with the entity's new-record defaults; it is created on save. */
  addRow(): void {
    if (this.addingRow()) return;
    this.addingRow.set(true);
    this.entities.newDefaults(this.entityName()).pipe(catchError(() => of({}))).subscribe(defaults => {
      this.addingRow.set(false);
      this.seq += 1;
      const row = newRow(this.seq, defaults);
      this.apply(s => ({ ...s, added: [...s.added, row] }));
      this.active.set({ row: this.rows().length - 1, col: 0 });
    });
  }

  /** Takes back the last edit, paste, fill or added row. */
  undo(): void {
    const back = undoLast(this.history());
    if (!back) return;
    this.state.set(back.state);
    this.history.set(back.history);
    this.editing.set(false);
    this.clampActive();
  }

  /** Takes back the whole unsaved session. */
  discardAll(): void {
    this.state.set(EMPTY_STATE);
    this.history.set({ past: [] });
    this.errors.set({});
    this.editing.set(false);
    this.pastePlan.set(null);
    this.clampActive();
  }

  private clampActive(): void {
    const last = Math.max(0, this.rows().length - 1);
    if (this.active().row > last) this.active.update(a => ({ ...a, row: last }));
  }

  /** One write per changed or added row, one after another; a refused row keeps its changes and says why. */
  saveAll(): void {
    if (this.editing() && !this.commit()) return;
    const pending = this.pending();
    const rows = this.rows().filter(r => pending[r.id] || isNewRow(r.id));
    if (!rows.length || this.saving()) return;
    this.saving.set(true);
    from(rows).pipe(
      concatMap(r => {
        const write = isNewRow(r.id)
          ? this.entities.create(this.entityName(), { ...(r.data as Record<string, unknown>), ...(pending[r.id] ?? {}) })
          : this.entities.update(this.entityName(), r.id, pending[r.id], r.row_version, { mergeAttributes: true });
        return write.pipe(
          map((): RowSave => ({ id: r.id, ok: true })),
          catchError((e: ApiError) => of<RowSave>({
            id: r.id, ok: false,
            error: e.status === 409 ? this.lang.translate('editableGrid.conflict') : this.lang.errorText(e),
          })),
        );
      }),
      toArray(),
    ).subscribe(outcomes => {
      this.saving.set(false);
      const ok = new Set(outcomes.filter(o => o.ok).map(o => o.id));
      this.state.update(s => ({
        pending: Object.fromEntries(Object.entries(s.pending).filter(([id]) => !ok.has(id))),
        added: s.added.filter(r => !ok.has(r.id)),
      }));
      if (ok.size) this.history.set({ past: [] });
      this.errors.set(Object.fromEntries(outcomes.filter(o => !o.ok).map(o => [o.id, o.error ?? ''])));
      this.clampActive();
      this.saved.emit(outcomes);
    });
  }
}
