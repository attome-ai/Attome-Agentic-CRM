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

/** `recycle_bin::BinRestoreResult`. */
export interface BinRestoreResult {
  restored: number;
  failed: { entity: string; id: string; code: string }[];
}

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
