import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { concatMap, from, map, of, catchError, toArray } from 'rxjs';
import { EntityService } from '../services/entity.service';
import type { Col } from './entity-list.component';
import { CellPos, EditableType, changed, editable, editorText, keyMove, parseCell } from './editable-grid.model';

/** One row's outcome of a save. */
export interface RowSave {
  id: string;
  ok: boolean;
  error?: string;
}

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
 * Discard all drops every pending change.
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
  /** Pending values by row id, then field. */
  readonly pending = signal<Record<string, Record<string, unknown>>>({});
  readonly errors = signal<Record<string, string>>({});
  readonly saving = signal(false);
  readonly invalid = signal(false);

  readonly rtl = computed(() => this.lang.isRtl());
  readonly changedRows = computed(() => Object.keys(this.pending()).length);
  readonly changedCells = computed(() => Object.values(this.pending()).reduce((n, p) => n + Object.keys(p).length, 0));

  isEditable(col: Col): boolean {
    return editable(col.type);
  }

  value(row: EntityRecord, col: Col): unknown {
    const p = this.pending()[row.id];
    return p && col.name in p ? p[col.name] : (row.data as Record<string, unknown>)[col.name];
  }

  isPending(row: EntityRecord, col: Col): boolean {
    const p = this.pending()[row.id];
    return !!p && col.name in p;
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

  select(row: number, col: number): void {
    const at = this.active();
    if (at.row === row && at.col === col) return;
    if (this.editing()) this.commit();
    this.active.set({ row, col });
  }

  startEdit(): void {
    const { row, col } = this.active();
    const record = this.records()[row];
    const column = this.columns()[col];
    if (!record || !column || !editable(column.type)) return;
    this.draft.set(editorText(column.type, this.value(record, column)));
    this.invalid.set(false);
    this.editing.set(true);
  }

  /** Keeps the editor's value as the cell's pending value (or refuses an invalid one). */
  commit(): boolean {
    const { row, col } = this.active();
    const record = this.records()[row];
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
    const original = (record.data as Record<string, unknown>)[column.name];
    this.pending.update(all => {
      const rowChanges = { ...(all[record.id] ?? {}) };
      if (changed(original, next)) rowChanges[column.name] = next;
      else delete rowChanges[column.name];
      const out = { ...all };
      if (Object.keys(rowChanges).length) out[record.id] = rowChanges;
      else delete out[record.id];
      return out;
    });
    this.editing.set(false);
    this.invalid.set(false);
    return true;
  }

  onKey(event: KeyboardEvent): void {
    const move = keyMove(event.key, event.shiftKey, this.editing(), this.active(), this.records().length,
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

  discardAll(): void {
    this.pending.set({});
    this.errors.set({});
    this.editing.set(false);
  }

  /** One PATCH per changed row, one after another; a refused row keeps its changes and says why. */
  saveAll(): void {
    if (this.editing() && !this.commit()) return;
    const rows = this.records().filter(r => this.pending()[r.id]);
    if (!rows.length || this.saving()) return;
    this.saving.set(true);
    from(rows).pipe(
      concatMap(r => this.entities.update(this.entityName(), r.id, this.pending()[r.id], r.row_version, { mergeAttributes: true }).pipe(
        map((): RowSave => ({ id: r.id, ok: true })),
        catchError((e: ApiError) => of<RowSave>({
          id: r.id, ok: false,
          error: e.status === 409 ? this.lang.translate('editableGrid.conflict') : this.lang.errorText(e),
        })),
      )),
      toArray(),
    ).subscribe(outcomes => {
      this.saving.set(false);
      const ok = new Set(outcomes.filter(o => o.ok).map(o => o.id));
      this.pending.update(all => Object.fromEntries(Object.entries(all).filter(([id]) => !ok.has(id))));
      this.errors.set(Object.fromEntries(outcomes.filter(o => !o.ok).map(o => [o.id, o.error ?? ''])));
      this.saved.emit(outcomes);
    });
  }
}
