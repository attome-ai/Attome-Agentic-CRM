import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataCatalogService, type CatalogEntityDetail, type CatalogEntitySummary,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/** `attribute_info.data_classification`'s vocabulary
 * (P-data-protection-governance §4). */
export const DATA_CLASSIFICATIONS = ['general', 'personal', 'sensitive_special_category'] as const;

/**
 * U19 / M18 — the data catalog browser over `/api/v1/catalog/entities*`:
 * a searchable entity list (by name or classification) and one entity's
 * aggregated detail — fields with their classification, lineage (which
 * queries, workflows, dashboards and rules read it), the nightly usage
 * rollup, and glossary terms. `?entity=<logicalname>` deep-links the
 * detail (bound through `withComponentInputBinding()`).
 */
@Component({
  selector: 'xrm-data-catalog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, LocalNumberPipe, TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './data-catalog.component.css'],
  templateUrl: './data-catalog.component.html',
})
export class DataCatalogComponent implements OnInit {
  private readonly svc = inject(DataCatalogService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  /** Query param `?entity=` — the entity whose detail is open on load. */
  readonly entity = input<string | undefined>(undefined);

  readonly classifications = DATA_CLASSIFICATIONS;

  readonly query = signal('');
  readonly classification = signal('');
  readonly items = signal<CatalogEntitySummary[]>([]);
  readonly total = signal(0);
  /** One-based (D-347, D-793) — this endpoint's first page is 1. */
  readonly page = signal(1);
  readonly pageSize = 50;
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly selected = signal<string | null>(null);
  readonly detail = signal<CatalogEntityDetail | null>(null);
  readonly detailLoading = signal(false);
  readonly detailError = signal<string | null>(null);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  ngOnInit(): void {
    this.search();
    const initial = this.entity();
    if (initial) this.openDetail(initial, false);
  }

  /** New search from the first page. */
  search(): void {
    this.page.set(1);
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.searchEntities(
      { q: this.query(), classification: this.classification() || undefined },
      this.page(), this.pageSize,
    ).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.items.set(res.items); this.total.set(res.total); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.pages()) return;
    this.page.set(page);
    this.load();
  }

  setClassification(value: string): void {
    this.classification.set(value);
    this.search();
  }

  /** Opens one entity's detail and records it in the URL so it can be shared. */
  openDetail(logicalname: string, updateUrl = true): void {
    this.selected.set(logicalname);
    this.detail.set(null);
    this.detailLoading.set(true);
    this.detailError.set(null);
    if (updateUrl) {
      void this.router.navigate([], { queryParams: { entity: logicalname }, queryParamsHandling: 'merge' });
    }
    this.svc.getEntity(logicalname).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => { this.detail.set(d); this.detailLoading.set(false); },
      error: (e: ApiError) => { this.detailError.set(e.message); this.detailLoading.set(false); },
    });
  }

  closeDetail(): void {
    this.selected.set(null);
    this.detail.set(null);
    void this.router.navigate([], { queryParams: { entity: null }, queryParamsHandling: 'merge' });
  }
}
