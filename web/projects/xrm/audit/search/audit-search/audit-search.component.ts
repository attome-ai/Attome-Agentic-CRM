import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  AuditExportFormat,
  AuditSearchFilters,
  AuditSearchRow,
  AuditSearchService,
} from '../data/audit-search.service';

const PAGE_SIZE = 50;
/** Q17-T1: where this browser keeps the person's saved searches. */
export const SAVED_SEARCHES_KEY = 'attome.auditSearch.saved';
/** The most saved searches kept. */
const MAX_SAVED = 20;

/** A named set of filters. */
export interface SavedAuditSearch {
  name: string;
  filters: AuditSearchFilters;
}

/** `attome_audit::model::AuditOperation` discriminants and their label keys. */
export const OPERATIONS: ReadonlyArray<{ value: number; key: string }> = [
  { value: 0, key: 'create' },
  { value: 1, key: 'update' },
  { value: 2, key: 'softDelete' },
  { value: 3, key: 'hardDelete' },
  { value: 4, key: 'restore' },
  { value: 9, key: 'login' },
  { value: 10, key: 'logout' },
  { value: 11, key: 'failedLogin' },
  { value: 12, key: 'permissionChange' },
  { value: 13, key: 'roleChange' },
  { value: 14, key: 'ownerChange' },
  { value: 23, key: 'accountDisabled' },
  { value: 24, key: 'accountEnabled' },
];

/**
 * M19 / Q17-T1 — the audit search surface over `GET /api/v1/admin/audit/search`.
 * Filters: entity, record, user, operation, field and date range. Results page
 * the way the route does (one-based pages of the shared list envelope). A
 * search can be saved under a name in this browser and applied again. Exports
 * are the streamed CSV/JSONL/CEF download (`GET /api/v1/admin/audit/export`)
 * and the Q16 evidence pack (`POST /api/v1/admin/audit/evidence-packs`): the
 * filtered range's sealed events with their inclusion proofs and the public
 * keys to verify them offline, downloaded as one JSON file.
 */
@Component({
  selector: 'attome-audit-search',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  templateUrl: './audit-search.component.html',
  styleUrl: './audit-search.component.css',
})
export class AuditSearchComponent {
  private readonly auditSearch = inject(AuditSearchService);

  protected readonly operations = OPERATIONS;

  readonly entityName = signal('');
  readonly recordId = signal('');
  readonly userId = signal('');
  readonly userEmail = signal('');
  readonly operation = signal('');
  readonly fieldName = signal('');
  readonly dateFrom = signal('');
  readonly dateTo = signal('');

  readonly rows = signal<AuditSearchRow[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly saved = signal<SavedAuditSearch[]>(readSaved());
  readonly saveName = signal('');
  readonly packBusy = signal(false);
  readonly packError = signal<string | null>(null);

  readonly totalPages = computed(() => Math.max(1, Math.ceil(this.total() / PAGE_SIZE)));

  /** An evidence pack needs a date range or one record. */
  readonly canBuildPack = computed(
    () =>
      (this.dateFrom() !== '' && this.dateTo() !== '') ||
      (this.entityName().trim() !== '' && this.recordId().trim() !== ''),
  );

  constructor() {
    this.runSearch();
  }

  currentFilters(): AuditSearchFilters {
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

  search(): void {
    this.page.set(1);
    this.runSearch();
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.totalPages()) return;
    this.page.set(page);
    this.runSearch();
  }

  /** The label key of an operation discriminant. */
  operationKey(value: number): string {
    const op = OPERATIONS.find(o => o.value === value);
    return op ? `auditSearch.op.${op.key}` : 'auditSearch.op.other';
  }

  // ── Saved searches ─────────────────────────────────────────────────────

  saveSearch(): void {
    const name = this.saveName().trim();
    if (!name) return;
    const next = [
      { name, filters: this.currentFilters() },
      ...this.saved().filter(s => s.name !== name),
    ].slice(0, MAX_SAVED);
    this.saved.set(next);
    writeSaved(next);
    this.saveName.set('');
  }

  applySaved(search: SavedAuditSearch): void {
    const f = search.filters;
    this.entityName.set(f.entity_name ?? '');
    this.recordId.set(f.record_id ?? '');
    this.userId.set(f.user_id ?? '');
    this.userEmail.set(f.user_email ?? '');
    this.operation.set(f.operation === undefined ? '' : String(f.operation));
    this.fieldName.set(f.field_name ?? '');
    this.dateFrom.set(f.date_from ? toLocalInput(f.date_from) : '');
    this.dateTo.set(f.date_to ? toLocalInput(f.date_to) : '');
    this.search();
  }

  removeSaved(name: string): void {
    const next = this.saved().filter(s => s.name !== name);
    this.saved.set(next);
    writeSaved(next);
  }

  // ── Exports ────────────────────────────────────────────────────────────

  exportHref(format: AuditExportFormat): string {
    return this.auditSearch.exportUrl(this.currentFilters(), format);
  }

  /** Downloads the evidence pack of the filtered range or record. */
  downloadEvidencePack(): void {
    if (!this.canBuildPack() || this.packBusy()) return;
    const f = this.currentFilters();
    this.packBusy.set(true);
    this.packError.set(null);
    this.auditSearch
      .evidencePack({
        from: f.date_from ?? null,
        to: f.date_to ?? null,
        entity_name: f.entity_name ?? null,
        record_id: f.record_id ?? null,
      })
      .subscribe({
        next: pack => {
          this.packBusy.set(false);
          saveJson(pack, 'audit-evidence-pack.json');
        },
        error: (err: ApiError) => {
          this.packBusy.set(false);
          this.packError.set(err.message);
        },
      });
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
        this.error.set('auditSearch.loadFailed');
        this.loading.set(false);
      },
    });
  }
}

function readSaved(): SavedAuditSearch[] {
  try {
    const raw = localStorage.getItem(SAVED_SEARCHES_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed)
      ? parsed.filter(
          (s): s is SavedAuditSearch =>
            typeof s === 'object' && s !== null && typeof (s as SavedAuditSearch).name === 'string',
        )
      : [];
  } catch {
    return [];
  }
}

function writeSaved(saved: SavedAuditSearch[]): void {
  try {
    localStorage.setItem(SAVED_SEARCHES_KEY, JSON.stringify(saved));
  } catch {
    // Storage blocked or full: the searches stay for this page only.
  }
}

/** An ISO timestamp as a `datetime-local` input value, in local time. */
function toLocalInput(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function saveJson(value: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
