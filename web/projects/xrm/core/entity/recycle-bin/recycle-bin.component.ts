import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { Observable } from 'rxjs';

/** `recycle_bin::DeletedRecord`. */
export interface DeletedRecord {
  id: string;
  label: string | null;
  deleted_at: string | null;
  deleted_by: string | null;
  reason: string | null;
  operation_id: string | null;
  operation_kind: string | null;
}

/** `recycle_bin::BinItem`. */
export interface BinItem {
  entity: string;
  id: string;
}

/** `recycle_bin::BinRestoreFailure`. */
export interface BinRestoreFailure extends BinItem {
  /** `not_found`, `forbidden`, `conflict`, `invalid` or `failed`. */
  code: string;
  /** For `invalid`: the deleted record it points at. */
  parent?: BinItem;
}

/** `recycle_bin::BinRestoreResult`. */
export interface BinRestoreResult {
  restored: number;
  failed: BinRestoreFailure[];
}

/** The failure codes with a message of their own. */
const FAILURE_CODES = new Set(['not_found', 'forbidden', 'conflict', 'invalid']);

/**
 * A18-T9: an entity's recycle bin. The deleted records the caller could read,
 * newest first, with why and in which operation each was deleted; restore a
 * selection, or everything one operation deleted.
 */
@Component({
  selector: 'xrm-recycle-bin',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="rb">
      <header class="rb-head">
        <h2>{{ 'recycleBin.title' | translate }} <span class="rb-entity" dir="ltr">{{ entity() }}</span></h2>
        <button type="button" class="btn btn-primary" [disabled]="selected().size === 0 || busy()" (click)="restoreSelected()">
          {{ 'recycleBin.restoreSelected' | translate: { count: selected().size } }}
        </button>
      </header>
      @if (error(); as message) { <p class="rb-error" role="alert">{{ message }}</p> }
      @if (result(); as r) {
        <p role="status" data-result>{{ 'recycleBin.result' | translate: { restored: r.restored, failed: r.failed.length } }}</p>
        @if (r.failed.length) {
          <ul class="rb-failed">
            @for (f of r.failed; track f.entity + f.id) {
              <li [attr.data-failed]="f.id">
                <span class="rb-failed-name">{{ labelOf(f.id) }}</span>
                @if (f.parent; as parent) {
                  <span>{{ 'recycleBin.failedParent' | translate: { entity: parent.entity } }}</span>
                  <button type="button" class="btn btn-text" [disabled]="busy()" (click)="restoreWithParent(f)"
                          [attr.data-restore-parent]="f.id">
                    {{ 'recycleBin.restoreParentToo' | translate }}
                  </button>
                } @else {
                  <span>{{ failureKey(f.code) | translate }}</span>
                }
              </li>
            }
          </ul>
        }
      }
      @if (records().length === 0) {
        <p class="rb-muted">{{ 'recycleBin.empty' | translate }}</p>
      } @else {
        <table class="rb-table">
          <thead>
            <tr>
              <th scope="col"><span class="rb-sr">{{ 'recycleBin.select' | translate }}</span></th>
              <th scope="col">{{ 'recycleBin.record' | translate }}</th>
              <th scope="col">{{ 'recycleBin.deletedAt' | translate }}</th>
              <th scope="col">{{ 'recycleBin.reason' | translate }}</th>
              <th scope="col">{{ 'recycleBin.operation' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (r of records(); track r.id) {
              <tr [attr.data-record]="r.id">
                <td><input type="checkbox" [checked]="selected().has(r.id)" (change)="toggle(r.id)"
                           [attr.aria-label]="'recycleBin.select' | translate" /></td>
                <td>{{ r.label || r.id }}</td>
                <td>{{ r.deleted_at | localDate }}</td>
                <td dir="auto">{{ r.reason ?? '—' }}</td>
                <td>
                  @if (r.operation_id; as op) {
                    <button type="button" class="btn btn-text" [disabled]="busy()" (click)="restoreOperation(op)"
                            [attr.data-operation]="op">
                      {{ 'recycleBin.restoreOperation' | translate: { count: operationSize(op) } }}
                    </button>
                    <span class="rb-muted">{{ r.operation_kind }}</span>
                  } @else { — }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .rb { display: flex; flex-direction: column; gap: 0.75rem; }
    .rb-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.75rem; }
    .rb-head h2 { margin-block: 0; font-size: 1.25rem; }
    .rb-entity { color: var(--color-text-secondary); font-size: 1rem; }
    .rb-table { border-collapse: collapse; font-size: 0.875rem; }
    .rb-table th, .rb-table td { padding-block: 0.25rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border); }
    .rb-muted { color: var(--color-text-secondary); font-size: 0.875rem; }
    .rb-error { color: var(--color-danger); }
    .rb-failed { margin: 0; padding-inline-start: 1.25rem; display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.875rem; }
    .rb-failed-name { font-weight: 600; margin-inline-end: 0.5rem; }
    .rb-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
  `],
})
export class RecycleBinComponent {
  private readonly api = inject(ApiService);

  /** From the route, `/xrm/bin/:entity`. */
  readonly entity = input.required<string>();
  readonly records = signal<DeletedRecord[]>([]);
  readonly selected = signal<Set<string>>(new Set());
  readonly result = signal<BinRestoreResult | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  private readonly operationSizes = computed(() => {
    const sizes = new Map<string, number>();
    for (const r of this.records()) {
      if (r.operation_id) sizes.set(r.operation_id, (sizes.get(r.operation_id) ?? 0) + 1);
    }
    return sizes;
  });

  constructor() {
    effect(() => this.load(this.entity()));
  }

  load(entity = this.entity()): void {
    this.api.get<{ items: DeletedRecord[] }>(`/api/v1/${encodeURIComponent(entity)}/deleted`, { page: '1', page_size: '100' }).subscribe({
      next: page => { this.records.set(page.items); this.selected.set(new Set()); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  operationSize(operationId: string): number {
    return this.operationSizes().get(operationId) ?? 1;
  }

  toggle(id: string): void {
    const next = new Set(this.selected());
    if (next.has(id)) next.delete(id); else next.add(id);
    this.selected.set(next);
  }

  restoreSelected(): void {
    const entity = this.entity();
    const items = [...this.selected()].map(id => ({ entity, id }));
    this.run(this.api.post<BinRestoreResult>('/api/v1/bin/restore', { items }));
  }

  /**
   * Restores the deleted record a failed restore points at, then the record
   * itself: the route restores items in order.
   */
  restoreWithParent(failure: BinRestoreFailure): void {
    if (!failure.parent) return;
    const items = [failure.parent, { entity: failure.entity, id: failure.id }];
    this.run(this.api.post<BinRestoreResult>('/api/v1/bin/restore', { items }));
  }

  /** The record's name as the bin lists it, else its id. */
  labelOf(id: string): string {
    return this.records().find(r => r.id === id)?.label ?? id;
  }

  /**
   * Why a record could not come back. A unique-value clash says to rename or
   * change the record that now holds the value; there is no merge from here
   * until the merge dialog (A15) exists.
   */
  failureKey(code: string): string {
    return `recycleBin.failed_${FAILURE_CODES.has(code) ? code : 'failed'}`;
  }

  restoreOperation(operationId: string): void {
    this.run(this.api.post<BinRestoreResult>(`/api/v1/bin/operations/${encodeURIComponent(operationId)}/restore`, {}));
  }

  private run(request: Observable<BinRestoreResult>): void {
    this.busy.set(true);
    this.error.set(null);
    request.subscribe({
      next: result => { this.busy.set(false); this.result.set(result); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
