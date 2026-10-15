import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, signal, untracked,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import {
  RecordHistoryChange, RecordHistoryField, RecordTimelineService,
} from '../timeline/record-timeline.service';

/** One side of a field change, ready to render. */
export interface HistoryValue {
  /** `null` = the field had no value. */
  text: string | null;
  /** True when `text` is an ISO date/time to format with `localDate`. */
  isDate: boolean;
}

/**
 * The display text for one side of a change, by the field's type: a lookup
 * shows the referenced record's name when the audit captured one, a boolean
 * reads Yes/No, a date is formatted by the template, and everything else
 * prefers the audit's display value over the raw stored one.
 */
export function historyValue(
  field: RecordHistoryField,
  side: 'old' | 'new',
  translate: (key: string) => string,
): HistoryValue {
  const raw = side === 'old' ? field.old_value : field.new_value;
  const display = side === 'old' ? field.old_display_value : field.new_display_value;
  const lookupName = side === 'old' ? field.old_lookup_name : field.new_lookup_name;
  const value = raw ?? null;
  if (value === null || value === '') return { text: null, isDate: false };
  switch (field.field_type) {
    case 'lookup':
      return { text: lookupName || display || value, isDate: false };
    case 'bool':
      if (value === 'true') return { text: translate('recordHistory.yes'), isDate: false };
      if (value === 'false') return { text: translate('recordHistory.no'), isDate: false };
      return { text: value, isDate: false };
    case 'date':
      return { text: value, isDate: !Number.isNaN(Date.parse(value)) };
    default:
      return { text: display || value, isDate: false };
  }
}

/**
 * U6 (basic-units plan, D-601) — a record's change history over
 * `GET /api/v1/{entity}/{id}/history`: one group per change (who, when, what
 * kind of change), each listing its fields as old → new. The server has
 * already dropped every field this caller cannot read and withheld the values
 * of sensitive ones (`masked`); this panel renders what it is given.
 */
@Component({
  selector: 'xrm-record-history-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgTemplateOutlet, TranslatePipe, LocalDatePipe],
  styleUrls: ['./record-history-panel.component.css'],
  templateUrl: './record-history-panel.component.html',
})
export class RecordHistoryPanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();

  private readonly service    = inject(RecordTimelineService);
  private readonly lang       = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly changes    = signal<RecordHistoryChange[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly loading    = signal(false);
  readonly error      = signal(false);

  private generation = 0;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      untracked(() => {
        if (entity && id) this.reload();
      });
    });
  }

  value(field: RecordHistoryField, side: 'old' | 'new'): HistoryValue {
    return historyValue(field, side, key => this.lang.translate(key));
  }

  /** The field's display name, or its column name made readable
   * ('last_login' → 'Last login') when the audit row carries none. */
  fieldLabel(field: RecordHistoryField): string {
    if (field.display_name) return field.display_name;
    const words = field.field_name.replace(/_/g, ' ').trim();
    return words.charAt(0).toUpperCase() + words.slice(1);
  }

  /** B2-T1: what the change was part of, when it was more than one save. */
  groupLabel(change: RecordHistoryChange): string | null {
    const kind = change.group_id.split(':')[0];
    return kind === 'batch' || kind === 'agent' || kind === 'run'
      ? this.lang.translate(`recordHistory.group_${kind}`)
      : null;
  }

  /** True when the change listed just above was made in the same change set. */
  continuesGroup(index: number): boolean {
    const list = this.changes();
    const group = list[index]?.group_id ?? '';
    return index > 0 && !group.startsWith('change:') && list[index - 1].group_id === group;
  }

  operationLabel(change: RecordHistoryChange): string {
    const key = `recordHistory.operations.${change.operation}`;
    const label = this.lang.translate(key);
    return label === key ? change.operation : label;
  }

  reload(): void {
    this.changes.set([]);
    this.nextCursor.set(null);
    this.fetch(null, ++this.generation);
  }

  loadMore(): void {
    const cursor = this.nextCursor();
    if (cursor && !this.loading()) this.fetch(cursor, this.generation);
  }

  private fetch(cursor: string | null, generation: number): void {
    this.loading.set(true);
    this.error.set(false);
    this.service.history(this.entityName(), this.recordId(), cursor)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: page => {
          if (generation !== this.generation) return;
          this.changes.update(list => [...list, ...page.items]);
          this.nextCursor.set(page.next_cursor ?? null);
          this.loading.set(false);
        },
        error: () => {
          if (generation !== this.generation) return;
          this.loading.set(false);
          this.error.set(true);
        },
      });
  }
}
