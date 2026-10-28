import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { Observable, forkJoin, map, of } from 'rxjs';

/** The statuses a whitespace cell takes (sales pack 0005). */
export const WHITESPACE_STATUSES = ['owned', 'in_progress', 'opportunity', 'not_a_fit', 'competitor'] as const;
export type WhitespaceStatus = (typeof WHITESPACE_STATUSES)[number];

/** One `account_whitespace` row. */
export interface WhitespaceCell {
  id: string;
  product_ref: string;
  department: string;
  status: string;
  estimated_value: number | null;
  row_version: number;
}

/** The grid: products down, departments across, a cell where one is recorded. */
export interface WhitespaceGrid {
  products: { id: string; name: string }[];
  departments: string[];
  cells: Map<string, WhitespaceCell>;
  /** The estimated value of every cell still an opportunity. */
  open_value: number;
}

export function cellKey(product: string, department: string): string {
  return `${product}|${department}`;
}

/** Rows as a grid; products by name, departments alphabetically. Pure. */
export function pivot(rows: readonly WhitespaceCell[], names: ReadonlyMap<string, string>): WhitespaceGrid {
  const cells = new Map<string, WhitespaceCell>();
  const products = new Map<string, string>();
  const departments = new Set<string>();
  let openValue = 0;
  for (const row of rows) {
    const department = row.department.trim();
    if (!row.product_ref || !department) continue;
    products.set(row.product_ref, names.get(row.product_ref) ?? row.product_ref);
    departments.add(department);
    cells.set(cellKey(row.product_ref, department), { ...row, department });
    if (row.status === 'opportunity') openValue += row.estimated_value ?? 0;
  }
  return {
    products: [...products].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name)),
    departments: [...departments].sort((a, b) => a.localeCompare(b)),
    cells,
    open_value: openValue,
  };
}

type Row = Record<string, unknown>;

function field(record: Row, name: string): unknown {
  return record[name];
}

/**
 * D27-T2: an account plan's whitespace (the account plan's Whitespace tab):
 * products down, the account's departments across, each cell the product's
 * standing in that department. A status is changed in place; a department
 * is added by naming it, and an empty cell is filled by choosing a status.
 */
@Component({
  selector: 'xrm-whitespace-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './whitespace-grid.component.html',
  styleUrl: './whitespace-grid.component.css',
})
export class WhitespaceGridComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly entityName = input('account_plan');
  readonly recordId = input<string | null>(null);

  readonly statuses = WHITESPACE_STATUSES;
  readonly rows = signal<WhitespaceCell[]>([]);
  readonly names = signal<ReadonlyMap<string, string>>(new Map());
  readonly extraDepartments = signal<string[]>([]);
  readonly error = signal<string | null>(null);
  readonly grid = computed(() => {
    const grid = pivot(this.rows(), this.names());
    const departments = [...new Set([...grid.departments, ...this.extraDepartments()])]
      .sort((a, b) => a.localeCompare(b));
    return { ...grid, departments };
  });

  constructor() {
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  /** Records of `entity` matching `filters`, through `query/execute` (the
   *  sales entry point must not import the entity screens, which load it). */
  private records(entity: string, filters: unknown[], size: number): Observable<Row[]> {
    return this.api.post<{ data: { records: Row[] } }>('/api/v1/query/execute', {
      entity, page: 1, page_size: size, order_by: '', order_dir: 'asc', filters, include_total: false,
    }).pipe(map(res => res.data?.records ?? []));
  }

  load(planId: string): void {
    this.error.set(null);
    this.records('account_whitespace', [{ field: 'account_plan_ref', op: 'eq', value: planId }], 500).subscribe({
      next: page => {
        const rows: WhitespaceCell[] = page.map(r => ({
          id: String(r['id'] ?? ''),
          product_ref: String(field(r, 'product_ref') ?? ''),
          department: String(field(r, 'department') ?? ''),
          status: String(field(r, 'status') ?? ''),
          estimated_value: typeof field(r, 'estimated_value') === 'number' ? field(r, 'estimated_value') as number : null,
          row_version: Number(field(r, 'row_version') ?? 0),
        }));
        this.rows.set(rows);
        this.loadNames([...new Set(rows.map(r => r.product_ref).filter(Boolean))]);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private loadNames(ids: string[]): void {
    if (!ids.length) { this.names.set(new Map()); return; }
    this.records('product', [{ field: 'id', op: 'in', value: ids }], ids.length).pipe(
      map(page => new Map(page.map(r => [String(r['id']), String(field(r, 'name') ?? r['id'])] as [string, string]))),
    ).subscribe({ next: names => this.names.set(names), error: () => this.names.set(new Map()) });
  }

  addDepartment(event: Event): void {
    const input = event.target as HTMLInputElement;
    const name = input.value.trim();
    if (name && !this.grid().departments.includes(name)) this.extraDepartments.update(d => [...d, name]);
    input.value = '';
  }

  cell(product: string, department: string): WhitespaceCell | undefined {
    return this.grid().cells.get(cellKey(product, department));
  }

  /** Sets a cell's status, creating the cell when there is none yet. */
  setStatus(product: string, department: string, event: Event): void {
    const status = (event.target as HTMLSelectElement).value;
    const plan = this.recordId();
    if (!plan || !status) return;
    const existing = this.cell(product, department);
    const saved = existing
      ? this.api.patch(`/api/v1/account_whitespace/${encodeURIComponent(existing.id)}`, { status }, existing.row_version)
      : this.api.post('/api/v1/account_whitespace', {
        account_plan_ref: plan, product_ref: product, department, status,
      });
    forkJoin([saved, of(plan)]).subscribe({
      next: ([, id]) => this.load(id),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  formatValue(value: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale(), { maximumFractionDigits: 0 }).format(value);
  }
}
