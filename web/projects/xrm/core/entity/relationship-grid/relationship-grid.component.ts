import {
  ChangeDetectionStrategy, Component, ElementRef, HostListener, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { QueryColumnDef, QueryService } from '@attome/xrm/core/query/data';
import { EntityService, EntityRecordResponse } from '../services/entity.service';
import { entityFormRoute } from '../services/entity-url.utils';

/**
 * M01 Core P3 gap (D-455) — the generic M:M relationship sub-grid: one
 * instance per `EntitySchema.relationships` entry (`getSchema`'s new,
 * previously-always-empty field), driving `/api/v1/{entity}/{id}/related/
 * {relationship}` GET/POST/DELETE. Deliberately NOT `xrm-related-grid`: that
 * component treats its target as an ordinary registered entity reached
 * through generic `/api/v1/{entity}` CRUD (`EntityService.create/delete`),
 * which is exactly the legacy hand-built `_mm_` table shape this mechanism
 * does not use — the physical join table behind a relationship is never
 * entity-registered (see `attome_metadata::provision::relationship`'s doc
 * comment). This component talks to the dedicated link/unlink API instead.
 *
 * Unlike `xrm-related-grid`'s heavy `EntityListComponent` (query/execute +
 * view resolution + column metadata), this renders a plain table from
 * `EntityRecordResponse.data` directly — there is no "view" over a join
 * table's other side to resolve, and `displayValue` below is a best-effort
 * label (first candidate field name found), not the query engine's column
 * projection. A future pass may want a per-relationship configurable
 * display field; this is the pragmatic first cut.
 */
@Component({
  selector: 'xrm-relationship-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['./relationship-grid.component.css'],
  templateUrl: './relationship-grid.component.html',
})
export class RelationshipGridComponent {
  private readonly entitySvc = inject(EntityService);
  private readonly querySvc = inject(QueryService);
  private readonly router = inject(Router);
  private readonly pickerSearchInput = viewChild<ElementRef<HTMLInputElement>>('pickerSearchInput');
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  /** This entity's own name and the current record's id (the "anchor" side
   * of the relationship). */
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();
  /** The relationship's name (`relationship_info.name`). */
  readonly relationship = input.required<string>();
  /** The label to show for this section — `EntitySchema.relationships[].label`. */
  readonly label = input.required<string>();
  /** The other side's entity name — `EntitySchema.relationships[].other_entity`. */
  readonly otherEntity = input.required<string>();
  readonly pageSize = input(10);

  readonly items = signal<EntityRecordResponse[]>([]);
  readonly total = signal(0);
  readonly loading = signal(false);
  readonly error = signal('');

  readonly pickerOpen = signal(false);
  readonly pickerSearch = signal('');
  readonly pickerItems = signal<{ id: string; data: Record<string, unknown> }[]>([]);
  readonly pickerColumns = signal<QueryColumnDef[]>([]);
  readonly pickerLoading = signal(false);
  readonly pickerSaving = signal(false);
  readonly pickerError = signal('');

  readonly linkedIds = computed(() => new Set(this.items().map(i => i.id)));

  constructor() {
    effect(() => {
      // Re-load whenever the anchor record or relationship identity changes.
      this.entityName(); this.recordId(); this.relationship();
      untracked(() => this.refresh());
    });
    effect(() => {
      if (this.pickerOpen()) {
        setTimeout(() => this.pickerSearchInput()?.nativeElement.focus(), 0);
      }
    });
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    if (this.pickerOpen()) this.closePicker();
  }

  refresh(): void {
    this.loading.set(true);
    this.error.set('');
    this.entitySvc.listRelated(this.entityName(), this.recordId(), this.relationship(), 1, this.pageSize())
      .subscribe({
        next: res => {
          this.items.set(res.items);
          this.total.set(res.total);
          this.loading.set(false);
        },
        error: (err: { message?: string }) => {
          this.loading.set(false);
          this.error.set(err?.message || 'Could not load related records.');
        },
      });
  }

  /** Best-effort label for a related row — the first candidate field
   * present, falling back to the record id. */
  displayValue(record: EntityRecordResponse): string {
    const data = record.data as Record<string, unknown>;
    for (const candidate of ['name', 'title', 'user_name', 'email', 'display_name']) {
      const value = data[candidate];
      if (typeof value === 'string' && value.trim()) return value;
    }
    return record.id;
  }

  openRecord(record: EntityRecordResponse): void {
    void this.router.navigate(entityFormRoute(this.otherEntity()), { queryParams: { id: record.id } });
  }

  unlink(record: EntityRecordResponse): void {
    this.entitySvc.unlinkRelated(this.entityName(), this.recordId(), this.relationship(), record.id).subscribe({
      next: () => this.refresh(),
      error: (err: { message?: string }) => this.error.set(err?.message || 'Could not unlink the record.'),
    });
  }

  openPicker(): void {
    this.pickerOpen.set(true);
    this.pickerSearch.set('');
    this.pickerError.set('');
    this.loadPicker('');
  }

  closePicker(): void { this.pickerOpen.set(false); }

  searchPicker(value: string): void {
    this.pickerSearch.set(value);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.loadPicker(value), 250);
  }

  link(id: string): void {
    if (this.pickerSaving()) return;
    this.pickerSaving.set(true);
    this.pickerError.set('');
    this.entitySvc.linkRelated(this.entityName(), this.recordId(), this.relationship(), id).subscribe({
      next: () => {
        this.pickerSaving.set(false);
        this.closePicker();
        this.refresh();
      },
      error: (err: { message?: string }) => {
        this.pickerSaving.set(false);
        this.pickerError.set(err?.message || 'Could not link the record.');
      },
    });
  }

  pickerCell(record: Record<string, unknown>, column: QueryColumnDef): string {
    const value = record[column.name];
    if (value == null) return '';
    return Array.isArray(value) ? value.join(', ') : String(value);
  }

  private loadPicker(search: string): void {
    this.pickerLoading.set(true);
    this.querySvc.execute({
      entity: this.otherEntity(),
      page: 1,
      page_size: 50,
      search,
      include_total: true,
    }).subscribe({
      next: response => {
        this.pickerLoading.set(false);
        const columns = response.data.columns.filter(column => column.is_visible && column.name !== 'id');
        this.pickerColumns.set(columns);
        const linked = this.linkedIds();
        this.pickerItems.set(response.data.records
          .map(data => ({ id: String(data['id'] ?? ''), data }))
          .filter(item => item.id && !linked.has(item.id)));
      },
      error: () => {
        this.pickerLoading.set(false);
        this.pickerColumns.set([]);
        this.pickerItems.set([]);
      },
    });
  }
}
