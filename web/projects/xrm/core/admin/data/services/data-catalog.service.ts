import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

/**
 * M18 Data Catalog Phase 1 (D-466) — `GET /api/v1/catalog/entities` and
 * `GET /api/v1/catalog/entities/{logicalname}`
 * (`crates/engine/attome-api/src/catalog_admin.rs`, `Authorized<Admin>`).
 * The list is **one-based** (`page=1` is the first page, D-347, D-793).
 */
export type CatalogEntitySummary = ApiComponents['schemas']['CatalogEntitySummary'];
export type CatalogEntityDetail  = ApiComponents['schemas']['CatalogEntityDetail'];
export type CatalogField         = ApiComponents['schemas']['CatalogFieldSummary'];
export type CatalogLineageEntry  = ApiComponents['schemas']['CatalogLineageEntry'];
export type CatalogGlossaryTerm  = ApiComponents['schemas']['CatalogGlossaryTerm'];

export interface CatalogSearch {
  q?:              string;
  classification?: string;
}

@Injectable({ providedIn: 'root' })
export class DataCatalogService {
  private readonly api = inject(ApiService);

  searchEntities(search: CatalogSearch, page = 1, pageSize = 50): Observable<Page<CatalogEntitySummary>> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    const q = search.q?.trim();
    if (q) params['q'] = q;
    if (search.classification) params['classification'] = search.classification;
    return this.api.get<Page<CatalogEntitySummary>>('/api/v1/catalog/entities', params);
  }

  getEntity(logicalname: string): Observable<CatalogEntityDetail> {
    return this.api.get<CatalogEntityDetail>(`/api/v1/catalog/entities/${encodeURIComponent(logicalname)}`);
  }
}
