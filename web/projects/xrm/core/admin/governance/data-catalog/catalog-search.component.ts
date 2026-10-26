import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataCatalogService, type CatalogAssetSearch, type CatalogAssetSummary, type CatalogFacet,
} from '@attome/xrm/core/admin/data';
import { AssetPageComponent, assetName } from './asset-page.component';

/** The facet groups, in the order the column shows them. */
export const FACET_GROUPS = ['kind', 'domain', 'label'] as const;
export type FacetGroup = (typeof FACET_GROUPS)[number];

/**
 * L4-T6: search every asset the person may see, by words in English or
 * Arabic, narrowed by kind, domain and label. The facet column sits on the
 * inline-start side (left in English, right in Arabic) and above the results
 * on a phone; each count says what choosing it would give. Picking an asset
 * opens its page.
 */
@Component({
  selector: 'xrm-catalog-search',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalNumberPipe, TranslatePipe, AssetPageComponent],
  styleUrls: ['./catalog-assets.css'],
  template: `
    <form class="gov-filters" role="search" (ngSubmit)="search()">
      <label for="ca-q">{{ 'governance.catalog.search' | translate }}</label>
      <input id="ca-q" name="q" class="mono-input" type="search"
             [placeholder]="'governance.catalog.assets.searchPlaceholder' | translate"
             [ngModel]="query()" (ngModelChange)="query.set($event)" data-testid="asset-q" />
      <button type="submit" class="btn-ghost" [disabled]="loading()">
        <i class="las la-search" aria-hidden="true"></i> {{ 'governance.catalog.searchButton' | translate }}
      </button>
    </form>

    <div class="ca-layout" [attr.dir]="dir()" data-testid="asset-layout">
      <aside class="ca-facets" [attr.aria-label]="'governance.catalog.assets.facetsLabel' | translate">
        @for (group of groups; track group) {
          @if (facets(group).length) {
            <div>
              <h4>{{ 'governance.catalog.assets.facets.' + group | translate }}</h4>
              <ul>
                @for (f of facets(group); track f.value) {
                  <li>
                    <button type="button" class="ca-facet" [class.ca-facet--on]="isOn(group, f.value)"
                            [attr.aria-pressed]="isOn(group, f.value)" [attr.data-facet]="group + ':' + f.value"
                            (click)="toggle(group, f.value)">
                      <span>{{ facetLabel(group, f.value) }}</span>
                      <span class="count">{{ f.count | localNumber }}</span>
                    </button>
                  </li>
                }
              </ul>
            </div>
          }
        }
      </aside>

      <section class="card ca-results" aria-labelledby="ca-results-title">
        <h3 id="ca-results-title">
          {{ 'governance.catalog.assets.title' | translate }}
          <span class="count">{{ total() | localNumber }}</span>
        </h3>
        @if (loading()) {
          <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
        } @else if (error()) {
          <p class="error-msg" role="alert">{{ error() }}</p>
        } @else if (items().length === 0) {
          <div class="empty-state"><p>{{ 'governance.catalog.assets.none' | translate }}</p></div>
        } @else {
          <ul>
            @for (a of items(); track a.id) {
              <li>
                <button type="button" class="ca-asset" [class.ca-asset--active]="selected() === a.id"
                        [attr.aria-pressed]="selected() === a.id" [attr.data-asset]="a.id"
                        (click)="selected.set(a.id)">
                  <strong>{{ name(a) }}</strong>
                  <span class="badge">{{ 'governance.catalog.assets.kinds.' + a.kind | translate }}</span>
                  <span class="cell-mono">{{ a.ref }}</span>
                  @if (description(a); as d) { <span class="ca-asset__desc">{{ d }}</span> }
                </button>
              </li>
            }
          </ul>
          @if (pages() > 1) {
            <nav class="gov-pager" [attr.aria-label]="'governance.common.pagination' | translate">
              <button type="button" class="btn-ghost" (click)="goToPage(page() - 1)" [disabled]="page() <= 1">
                {{ 'governance.common.previous' | translate }}
              </button>
              <span>{{ 'governance.common.pageOf' | translate: { page: page(), pages: pages() } }}</span>
              <button type="button" class="btn-ghost" (click)="goToPage(page() + 1)" [disabled]="page() >= pages()">
                {{ 'governance.common.next' | translate }}
              </button>
            </nav>
          }
        }
      </section>
    </div>

    @if (selected(); as id) {
      <xrm-catalog-asset-page class="ca-panel" [assetId]="id" (closed)="selected.set(null)" />
    }
  `,
})
export class CatalogSearchComponent implements OnInit {
  private readonly svc = inject(DataCatalogService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  readonly groups = FACET_GROUPS;
  readonly pageSize = 25;

  readonly query = signal('');
  readonly chosen = signal<Partial<Record<FacetGroup, string>>>({});
  readonly result = signal<CatalogAssetSearch | null>(null);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly selected = signal<string | null>(null);

  readonly items = computed<CatalogAssetSummary[]>(() => this.result()?.items ?? []);
  readonly total = computed(() => this.result()?.total ?? 0);
  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));

  ngOnInit(): void {
    this.load();
  }

  search(): void {
    this.page.set(1);
    this.load();
  }

  facets(group: FacetGroup): CatalogFacet[] {
    return this.result()?.facets?.[group] ?? [];
  }

  isOn(group: FacetGroup, value: string): boolean {
    return this.chosen()[group] === value;
  }

  /** Choosing a chosen value clears it; any change searches from page 1. */
  toggle(group: FacetGroup, value: string): void {
    const next = { ...this.chosen() };
    if (next[group] === value) delete next[group]; else next[group] = value;
    this.chosen.set(next);
    this.search();
  }

  facetLabel(group: FacetGroup, value: string): string {
    if (group === 'kind') return this.lang.translate('governance.catalog.assets.kinds.' + value);
    if (group === 'domain') return value.slice(0, 8);
    return value;
  }

  name(a: CatalogAssetSummary): string {
    return assetName(a, this.lang.isRtl());
  }

  description(a: CatalogAssetSummary): string | null {
    const rtl = this.lang.isRtl();
    return (rtl ? a.description_ar : a.description_en) || (rtl ? a.description_en : a.description_ar) || null;
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.pages()) return;
    this.page.set(page);
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const chosen = this.chosen();
    this.svc.searchAssets(
      { q: this.query(), kind: chosen.kind, domain: chosen.domain, label: chosen.label },
      this.page(), this.pageSize,
    ).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.result.set(res); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }
}
