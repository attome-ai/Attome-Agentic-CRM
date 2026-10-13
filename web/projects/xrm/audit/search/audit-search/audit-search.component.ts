import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  AuditExportFormat,
  AuditSearchFilters,
  AuditSearchRow,
  AuditSearchService,
} from '../data/audit-search.service';

const PAGE_SIZE = 50;

/**
 * M19 (Audit) gap list — the dedicated audit search surface the module
 * plan's gap list calls for, over `GET /api/v1/admin/audit/search`.
 * Filters: entity, record, user, operation, date range, field (the six
 * dimensions the plan names) — CSV/JSONL/CEF export is a direct download
 * from `GET /api/v1/admin/audit/export` (see `AuditSearchService.
 * exportUrl`'s doc for why this isn't the generic M12 job+poll flow).
 */
@Component({
  selector: 'attome-audit-search',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
  templateUrl: './audit-search.component.html',
  styleUrl: './audit-search.component.css',
})
export class AuditSearchComponent {
  private readonly auditSearch = inject(AuditSearchService);

  protected readonly entityName = signal('');
  protected readonly recordId = signal('');
  protected readonly userId = signal('');
  protected readonly userEmail = signal('');
  protected readonly operation = signal('');
  protected readonly fieldName = signal('');
  protected readonly dateFrom = signal('');
  protected readonly dateTo = signal('');

  protected readonly rows = signal<AuditSearchRow[]>([]);
  protected readonly total = signal(0);
  protected readonly page = signal(1);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly totalPages = computed(() =>
    Math.max(1, Math.ceil(this.total() / PAGE_SIZE)),
  );

  constructor() {
    this.runSearch();
  }

  protected currentFilters(): AuditSearchFilters {
    const filters: AuditSearchFilters = {};
    if (this.entityName().trim()) filters.entity_name = this.entityName().trim();
    if (this.recordId().trim()) filters.record_id = this.recordId().trim();
    if (this.userId().trim()) filters.user_id = this.userId().trim();
    if (this.userEmail().trim()) filters.user_email = this.userEmail().trim();
    if (this.operation() !== '') filters.operation = Number(this.operation());
    if (this.fieldName().trim()) filters.field_name = this.fieldName().trim();
    if (this.dateFrom()) filters.date_from = new Date(this.dateFrom()).toISOString();
    if (this.dateTo()) filters.date_to = new Date(this.dateTo()).toISOString();
    return filters;
  }

  protected search(): void {
    this.page.set(1);
    this.runSearch();
  }

  protected goToPage(page: number): void {
    if (page < 1 || page > this.totalPages()) return;
    this.page.set(page);
    this.runSearch();
  }

  private runSearch(): void {
    this.loading.set(true);
    this.error.set(null);
    this.auditSearch.search(this.currentFilters(), this.page(), PAGE_SIZE).subscribe({
      next: res => {
        this.rows.set(res.items);
        this.total.set(res.total);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Failed to load audit search results.');
        this.loading.set(false);
      },
    });
  }

  protected exportHref(format: AuditExportFormat): string {
    return this.auditSearch.exportUrl(this.currentFilters(), format);
  }
}
