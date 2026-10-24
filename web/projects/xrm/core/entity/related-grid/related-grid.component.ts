import {
  ChangeDetectionStrategy, Component, ElementRef, HostListener, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { catchError, forkJoin, map, of, switchMap } from 'rxjs';
import { TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { QueryColumnDef, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { EntityService } from '../services/entity.service';
import { EntityListComponent } from '../list/entity-list.component';
import { entityFormRoute } from '../services/entity-url.utils';
import { FeatureFlagsService } from '@attome/xrm/core/admin/data';
import { ContinuousScanDialogComponent } from './continuous-scan-dialog.component';

/** Suffix marking a seeded view as the stable, non-default target for a
 * related-grid/subgrid — see `ensure_secondary_view` call sites named
 * `"{Display} (Related)"` in the backend seeds. A view carrying this suffix
 * is never the entity's `is_default` view, so pinning to it by id keeps a
 * subgrid's contents stable even if an admin later repoints the default view
 * or edits the Active/Inactive queries. */
const RELATED_VIEW_SUFFIX = ' (Related)';

export interface RelatedGridFilter { field: string; value: string; }
export type RelatedGridType = 'records' | 'many_to_one' | 'many_to_many';

export interface RelationshipPickerConfig {
  targetEntityName: string;
  targetField: string;
  displayField: string;
  title?: string;
  /** Saved view controlling the picker columns, order, and fixed view filters. */
  viewId?: string;
}

@Component({
  selector: 'xrm-related-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EntityListComponent, FormsModule, TranslatePipe, ContinuousScanDialogComponent],
  styleUrls: ['./related-grid.component.css'],
  templateUrl: './related-grid.component.html',
})
export class RelatedGridComponent {
  private readonly router = inject(Router);
  private readonly entitySvc = inject(EntityService);
  private readonly querySvc = inject(QueryService);
  private readonly viewSvc = inject(ViewAdminService);
  private readonly flags = inject(FeatureFlagsService);

  // ── B16-T10: continuous scanning into new lines ───────────────────────────
  /** The line entity's field a scan fills: its first text or number field with scanning on. */
  readonly scanField = signal<string | null>(null);
  readonly scanOpen = signal(false);
  /** Shown when creating is allowed, a field scans, and `scan.continuous_enabled` is on. */
  readonly canScan = computed(() =>
    this.allowCreate() && this.scanField() !== null && this.flags.isOn('scan.continuous_enabled'));

  closeScan(): void {
    this.scanOpen.set(false);
  }
  private readonly list = viewChild(EntityListComponent);
  private readonly pickerSearchInput = viewChild<ElementRef<HTMLInputElement>>('pickerSearchInput');
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  /** Resolved id of `entityName()`'s "{Display} (Related)" view, if one is
   * seeded — see `RELATED_VIEW_SUFFIX`. Falls back to null (the entity's
   * default view) when no such view exists, same as before this resolution
   * was added. */
  readonly relatedViewId = signal<string | null>(null);
  readonly effectiveViewId = computed(() => this.viewId() ?? this.relatedViewId());

  constructor() {
    effect(() => {
      if (this.pickerOpen()) {
        setTimeout(() => this.pickerSearchInput()?.nativeElement.focus(), 0);
      }
    });
    effect(() => {
      const entity = this.entityName();
      untracked(() => {
        this.flags.ensureLoaded();
        this.scanField.set(null);
        this.entitySvc.getSchema(entity).pipe(catchError(() => of(null))).subscribe(schema => {
          const f = schema?.fields.find(x => {
            const scan = (x.options as { scan?: { enabled?: boolean } } | null)?.scan;
            return !!scan && scan.enabled !== false && (x.field_type === 'text' || x.field_type === 'number');
          });
          this.scanField.set(f?.name ?? null);
        });
        this.relatedViewId.set(null);
        this.resolveRelatedViewId(entity).subscribe(id => this.relatedViewId.set(id));
      });
    });
  }

  /** Looks up `entity`'s seeded `"… (Related)"` view id, if any. Never throws
   * into the caller — a lookup failure just leaves the grid on the entity's
   * default view, same as today's behavior. */
  private resolveRelatedViewId(entity: string) {
    return this.viewSvc.listAvailable(entity).pipe(
      map(views => views.find(v => v.name.endsWith(RELATED_VIEW_SUFFIX))?.id ?? null),
      catchError(() => of(null)),
    );
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    if (this.pickerOpen()) this.closePicker();
  }

  readonly entityName = input.required<string>();
  readonly filters = input.required<readonly RelatedGridFilter[]>();
  readonly viewId = input<string | null>(null);
  readonly pageSize = input(10);
  readonly relationshipType = input<RelatedGridType>('records');
  readonly picker = input<RelationshipPickerConfig | null>(null);
  readonly allowCreate = input(false);

  readonly pickerOpen = signal(false);
  readonly pickerSearch = signal('');
  readonly pickerItems = signal<{ id: string; data: Record<string, unknown> }[]>([]);
  readonly pickerColumns = signal<QueryColumnDef[]>([]);
  readonly pickerSelection = signal<Set<string>>(new Set());
  readonly pickerLoading = signal(false);
  readonly pickerSaving = signal(false);
  readonly pickerError = signal('');

  readonly relationshipFilter = computed(() => this.filters().map(f => ({
    field: f.field, op: 'eq' as const, value: f.value,
  })));

  createRelatedRecord(): void {
    if (!this.allowCreate()) return;
    const queryParams: Record<string, string> = {};
    for (const f of this.filters()) queryParams[f.field] = f.value;
    void this.router.navigate(entityFormRoute(this.entityName()), { queryParams });
  }

  openRelatedRecord(record: EntityRecord): void {
    void this.router.navigate(entityFormRoute(this.entityName()), { queryParams: { id: record.id } });
  }

  openPicker(): void {
    if (!this.picker()) return;
    this.pickerOpen.set(true);
    this.pickerSelection.set(new Set());
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

  togglePickerItem(id: string): void {
    this.pickerSelection.update(current => {
      const next = new Set(current);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  pickerCell(record: Record<string, unknown>, column: QueryColumnDef): string {
    const value = record[column.name];
    if (value == null) return '';
    return Array.isArray(value) ? value.join(', ') : String(value);
  }

  addRelationships(): void {
    const config = this.picker();
    if (!config || this.pickerSaving()) return;
    const fixed = Object.fromEntries(this.filters().map(f => [f.field, f.value]));
    const requests = [...this.pickerSelection()].map(id =>
      this.entitySvc.create(this.entityName(), { ...fixed, [config.targetField]: id }));
    if (!requests.length) return;
    this.pickerSaving.set(true);
    this.pickerError.set('');
    forkJoin(requests).subscribe({
      next: () => {
        this.pickerSaving.set(false);
        this.closePicker();
        this.list()?.refresh();
      },
      error: err => {
        this.pickerSaving.set(false);
        this.pickerError.set(err?.message || 'Could not add the relationship.');
      },
    });
  }

  removeRelationships(ids: readonly string[]): void {
    if (!ids.length) return;
    forkJoin(ids.map(id => this.entitySvc.delete(this.entityName(), id))).subscribe({
      next: () => {
        this.list()?.clearSelection();
        this.list()?.refresh();
      },
      error: () => this.pickerError.set('Could not remove the relationship.'),
    });
  }

  private loadPicker(search: string): void {
    const config = this.picker();
    if (!config) return;
    this.pickerLoading.set(true);
    // A picker author can pin an explicit view via `RelationshipPickerConfig.
    // viewId`; when they don't, resolve the target entity's own seeded
    // `"… (Related)"` view instead of falling through to `query/execute`'s
    // "whichever view is default right now" resolution — same stability
    // reasoning as `effectiveViewId` above, for the picker's own grid.
    const viewId$ = config.viewId
      ? of(config.viewId)
      : this.resolveRelatedViewId(config.targetEntityName);
    viewId$.pipe(
      switchMap(view_id => this.querySvc.execute({
        entity: config.targetEntityName,
        view_id: view_id ?? undefined,
        page: 1,
        page_size: 50,
        search,
        include_total: true,
      })),
    ).subscribe({
      next: response => {
        this.pickerLoading.set(false);
        const columns = response.data.columns.filter(column => column.is_visible && column.name !== 'id');
        this.pickerColumns.set(columns.length ? columns : [this.fallbackColumn(config)]);
        const linkedIds = new Set(
          (this.list()?.records() ?? []).map(record => String(record.data[config.targetField] ?? '')),
        );
        this.pickerItems.set(response.data.records
          .map(data => ({ id: String(data['id'] ?? ''), data }))
          .filter(item => item.id && !linkedIds.has(item.id)));
      },
      error: () => {
        this.pickerLoading.set(false);
        this.pickerColumns.set([]);
        this.pickerItems.set([]);
      },
    });
  }

  private fallbackColumn(config: RelationshipPickerConfig): QueryColumnDef {
    return {
      name: config.displayField,
      display_name: config.displayField.replaceAll('_', ' '),
      data_type: 'text', is_visible: true, is_sortable: false, is_searchable: true,
      is_clickable: false, route_template: '',
    };
  }
}
