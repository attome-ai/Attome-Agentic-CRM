import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { forkJoin } from 'rxjs';
import { switchMap } from 'rxjs/operators';

/** One stored forecast cell (`forecast_cell`). */
export interface ForecastCell {
  id: string;
  rowVersion: number;
  nodeKey: string;
  owner: string | null;
  categoryId: string;
  pipeline: number;
  adjusted: number;
  quota: number | null;
}

/** One node of the forecast (a person or a position) across the categories. */
export interface ForecastRow {
  nodeKey: string;
  label: string;
  cells: Record<string, ForecastCell>;
  quota: number | null;
}

interface Category {
  id: string;
  name: string;
  nameAr: string | null;
  counts: boolean;
}

interface Period {
  id: string;
  name: string;
  status: string;
}

/** A row's committed total: its adjusted amounts in the categories that count in commit. Pure. */
export function commitTotal(row: ForecastRow, committing: ReadonlySet<string>): number {
  return Object.values(row.cells)
    .filter(c => committing.has(c.categoryId))
    .reduce((sum, c) => sum + c.adjusted, 0);
}

const num = (v: unknown): number => (v == null || v === '' ? 0 : Number(v));

/**
 * The forecast grid (roadmap D11-T3): for a period, one row per person or
 * position and one column per forecast category, each cell showing the
 * adjusted amount over the pipeline the engine computed, and each row its
 * committed total against its quota. A manager adjusts a cell in place
 * with a reason: the change is kept as an append-only adjustment (the
 * previous and new amount) and the cell takes the new amount at its row
 * version, so two people adjusting at once cannot overwrite each other
 * silently. Read and write rights are the records' own. Numbers follow the
 * reader's locale and the layout mirrors in Arabic.
 */
@Component({
  selector: 'xrm-forecast-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  template: `
    <section class="fc" aria-labelledby="fc-title">
      <h2 id="fc-title">{{ 'forecast.title' | translate }}</h2>
      @if (periods().length) {
        <label class="fc-period">
          <span>{{ 'forecast.period' | translate }}</span>
          <select [value]="periodId() ?? ''" (change)="choose($any($event.target).value)">
            @for (p of periods(); track p.id) { <option [value]="p.id">{{ p.name }}</option> }
          </select>
        </label>
      }
      @if (error(); as message) { <p class="fc-error" role="alert">{{ message }}</p> }
      @if (rows().length) {
        <div class="fc-scroll">
          <table class="fc-grid">
            <thead>
              <tr>
                <th scope="col">{{ 'forecast.owner' | translate }}</th>
                @for (c of categories(); track c.id) { <th scope="col">{{ label(c) }}</th> }
                <th scope="col">{{ 'forecast.commit' | translate }}</th>
                <th scope="col">{{ 'forecast.quota' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (r of rows(); track r.nodeKey) {
                <tr [attr.data-node]="r.nodeKey">
                  <th scope="row">{{ r.label }}</th>
                  @for (c of categories(); track c.id) {
                    <td>
                      @if (r.cells[c.id]; as cell) {
                        @if (editing() === cell.id) {
                          <form class="fc-edit" (submit)="$event.preventDefault(); save(cell, amount.value, reason.value)">
                            <input #amount type="number" [value]="cell.adjusted" [attr.aria-label]="'forecast.amount' | translate" />
                            <input #reason type="text" [placeholder]="'forecast.reason' | translate" [attr.aria-label]="'forecast.reason' | translate" />
                            <button type="submit" [disabled]="busy()">{{ 'forecast.save' | translate }}</button>
                            <button type="button" (click)="editing.set(null)">{{ 'forecast.cancel' | translate }}</button>
                          </form>
                        } @else {
                          <button type="button" class="fc-cell" [attr.data-cell]="cell.id" (click)="editing.set(cell.id)">
                            <strong>{{ cell.adjusted | localNumber }}</strong>
                            <small>{{ cell.pipeline | localNumber }}</small>
                          </button>
                        }
                      }
                    </td>
                  }
                  <td data-commit>{{ commit(r) | localNumber }}</td>
                  <td>
                    @if (r.quota !== null) {
                      {{ r.quota | localNumber }}
                      <small data-attainment>{{ attainment(r) | localNumber: { style: 'percent' } }}</small>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      } @else if (periodId()) {
        <p class="fc-muted">{{ 'forecast.empty' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .fc { display: flex; flex-direction: column; gap: 0.75rem; padding-block: 1rem; padding-inline: 1rem; }
    .fc h2 { margin-block: 0; font-size: 1.125rem; }
    .fc-period { display: flex; gap: 0.5rem; align-items: center; }
    .fc-scroll { overflow-x: auto; }
    .fc-grid { border-collapse: collapse; min-inline-size: 100%; }
    .fc-grid th, .fc-grid td { padding-block: 0.375rem; padding-inline: 0.5rem; border-block-end: 1px solid var(--color-border); text-align: start; white-space: nowrap; }
    .fc-cell { display: flex; flex-direction: column; align-items: flex-start; background: none; border: 0; cursor: pointer; padding: 0; font: inherit; }
    .fc-cell small, .fc-grid td small { color: var(--color-text-secondary); margin-inline-start: 0.25rem; }
    .fc-edit { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .fc-edit input[type=number] { inline-size: 8rem; }
    .fc-muted { color: var(--color-text-secondary); margin: 0; }
    .fc-error { color: var(--color-danger); margin: 0; }
  `],
})
export class ForecastGridComponent {
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly periods = signal<Period[]>([]);
  readonly periodId = signal<string | null>(null);
  readonly categories = signal<Category[]>([]);
  readonly cells = signal<ForecastCell[]>([]);
  readonly editing = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  private readonly committing = computed(() => new Set(this.categories().filter(c => c.counts).map(c => c.id)));

  readonly rows = computed<ForecastRow[]>(() => {
    const byNode = new Map<string, ForecastRow>();
    for (const cell of this.cells()) {
      const row = byNode.get(cell.nodeKey) ?? { nodeKey: cell.nodeKey, label: cell.owner ?? cell.nodeKey, cells: {}, quota: null };
      row.cells[cell.categoryId] = cell;
      if (row.quota === null && cell.quota !== null) row.quota = cell.quota;
      byNode.set(cell.nodeKey, row);
    }
    return [...byNode.values()].sort((a, b) => a.label.localeCompare(b.label));
  });

  constructor() {
    forkJoin({
      periods: this.entities.list('forecast_period', { sorts: [{ field: 'starts_on', dir: 'desc' }], limit: 24 }),
      categories: this.entities.list('forecast_category', { sorts: [{ field: 'rank', dir: 'asc' }], limit: 50 }),
    }).subscribe({
      next: ({ periods, categories }) => {
        this.categories.set(categories.data.map(c => ({
          id: c.id,
          name: String(c.data['name'] ?? ''),
          nameAr: (c.data['name_ar'] as string | null) ?? null,
          counts: c.data['counts_in_commit'] === true,
        })));
        const list = periods.data.map(p => ({
          id: p.id, name: String(p.data['name'] ?? ''), status: String(p.data['status'] ?? ''),
        }));
        this.periods.set(list);
        const open = list.find(p => p.status === 'open') ?? list[0];
        if (open) this.choose(open.id);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  label(c: Category): string {
    return this.lang.current() === 'ar' && c.nameAr ? c.nameAr : c.name;
  }

  commit(row: ForecastRow): number {
    return commitTotal(row, this.committing());
  }

  attainment(row: ForecastRow): number {
    return row.quota ? this.commit(row) / row.quota : 0;
  }

  choose(id: string): void {
    this.periodId.set(id);
    this.editing.set(null);
    this.entities.list('forecast_cell', {
      filters: [{ field: 'period_ref', op: 'eq', value: id }],
      limit: 1000,
    }).subscribe({
      next: page => this.cells.set(page.data.map(r => ({
        id: r.id,
        rowVersion: r.row_version,
        nodeKey: String(r.data['node_key'] ?? ''),
        owner: r.lookups?.['owner_ref']?.name ?? null,
        categoryId: String(r.data['category_ref'] ?? ''),
        pipeline: num(r.data['pipeline_amount']),
        adjusted: num(r.data['adjusted_amount']),
        quota: r.data['quota'] == null ? null : num(r.data['quota']),
      }))),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Keeps the adjustment, then moves the cell to the new amount at its version. */
  save(cell: ForecastCell, value: string, reason: string): void {
    const amount = Number(value);
    if (!Number.isFinite(amount)) return;
    this.busy.set(true);
    this.entities.create('forecast_adjustment', {
      cell_ref: cell.id,
      amount,
      previous_amount: cell.adjusted,
      reason: reason.trim() || null,
      adjusted_at: new Date().toISOString().slice(0, 10),
    }).pipe(
      switchMap(() => this.entities.update('forecast_cell', cell.id, { adjusted_amount: amount }, cell.rowVersion)),
    ).subscribe({
      next: () => {
        this.busy.set(false);
        this.editing.set(null);
        this.cells.update(all => all.map(c => c.id === cell.id ? { ...c, adjusted: amount, rowVersion: c.rowVersion + 1 } : c));
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
