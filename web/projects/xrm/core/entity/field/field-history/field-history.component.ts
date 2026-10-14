import {
  ChangeDetectionStrategy, Component, ElementRef, inject, input, output, signal,
} from '@angular/core';
import { ApiComponents, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { FieldSchema } from '@attome/xrm';
import { EntityService } from '../../services/entity.service';

type HistoryChange = ApiComponents['schemas']['RecordHistoryChange'];
type HistoryField = ApiComponents['schemas']['RecordHistoryField'];

/** One past value of the field, as the popover lists it. */
export interface FieldHistoryEntry {
  auditId: string;
  changedOn: string;
  who: string | null;
  oldText: string | null;
  newText: string | null;
  /** The stored old value, typed for the form control; absent when masked. */
  restoreValue: unknown;
  masked: boolean;
}

/** The value a field's control takes for a stored history value. */
export function controlValue(fieldType: string | null | undefined, raw: string | null | undefined): unknown {
  if (raw === null || raw === undefined || raw === '') return null;
  switch (fieldType) {
    case 'number':
    case 'currency': {
      const n = Number(raw);
      return Number.isFinite(n) ? n : raw;
    }
    case 'bool':
      return raw === 'true';
    case 'date':
      return raw.slice(0, 10);
    default:
      return raw;
  }
}

/** The entries for one field from a page of the record's history. */
export function entriesFor(changes: readonly HistoryChange[], fieldName: string): FieldHistoryEntry[] {
  const out: FieldHistoryEntry[] = [];
  for (const change of changes) {
    const field: HistoryField | undefined = change.fields.find(f => f.field_name === fieldName);
    if (!field) continue;
    const text = (side: 'old' | 'new') => {
      const raw = side === 'old' ? field.old_value : field.new_value;
      const display = side === 'old' ? field.old_display_value : field.new_display_value;
      const lookup = side === 'old' ? field.old_lookup_name : field.new_lookup_name;
      return lookup || display || raw || null;
    };
    out.push({
      auditId: change.audit_id,
      changedOn: change.changed_on,
      who: change.user_display_name ?? null,
      oldText: field.masked ? null : text('old'),
      newText: field.masked ? null : text('new'),
      restoreValue: field.masked ? undefined : controlValue(field.field_type, field.old_value),
      masked: field.masked,
    });
  }
  return out;
}

/**
 * B2-T3: the clock beside a field's label. It lists the field's past values
 * (who, when, old → new) and puts one back into the form; saving the form
 * then writes it through the ordinary update path, with its row version.
 */
@Component({
  selector: 'attome-field-history',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  host: { '(document:click)': 'onDocumentClick($event)' },
  styleUrls: ['./field-history.component.css'],
  templateUrl: './field-history.component.html',
})
export class FieldHistoryComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();
  readonly field = input.required<FieldSchema>();
  /** The old value the person chose to put back. */
  readonly restored = output<unknown>();

  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);
  private readonly host = inject(ElementRef<HTMLElement>);

  readonly open = signal(false);
  readonly loading = signal(false);
  readonly failed = signal(false);
  readonly entries = signal<FieldHistoryEntry[]>([]);

  toggle(): void {
    const opening = !this.open();
    this.open.set(opening);
    if (!opening) return;
    this.loading.set(true);
    this.failed.set(false);
    this.entities.fieldHistory(this.entityName(), this.recordId(), this.field().name).subscribe({
      next: page => {
        this.entries.set(entriesFor(page.items, this.field().name));
        this.loading.set(false);
      },
      error: () => {
        this.failed.set(true);
        this.loading.set(false);
      },
    });
  }

  restore(entry: FieldHistoryEntry): void {
    if (entry.masked) return;
    this.restored.emit(entry.restoreValue);
    this.open.set(false);
  }

  label(): string {
    return this.lang.translate('fieldInput.historyOf', { field: this.field().display_name || this.field().name });
  }

  onDocumentClick(event: MouseEvent): void {
    if (this.open() && !this.host.nativeElement.contains(event.target as Node)) this.open.set(false);
  }
}
