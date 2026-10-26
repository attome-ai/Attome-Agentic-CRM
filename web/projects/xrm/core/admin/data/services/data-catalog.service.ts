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

// L4-T6: the asset catalogue (`/api/v1/catalog/assets*`, the access
// requests and the personal data map), behind `metadata.read`.
export type CatalogAssetSearch    = ApiComponents['schemas']['CatalogAssetSearch'];
export type CatalogAssetSummary   = ApiComponents['schemas']['CatalogAssetSummary'];
export type CatalogAssetPage      = ApiComponents['schemas']['CatalogAssetPage'];
export type CatalogFacet          = ApiComponents['schemas']['CatalogFacet'];
export type CatalogAccessRequest  = ApiComponents['schemas']['CatalogAccessRequest'];
export type PersonalDataItem      = ApiComponents['schemas']['PersonalDataItem'];
export type PersonalDataReader    = ApiComponents['schemas']['PersonalDataReader'];

/** What an asset search narrows to. */
export interface AssetSearch {
  q?:      string;
  kind?:   string;
  domain?: string;
  label?:  string;
}

/** A bilingual description; either side may be left out. */
export interface AssetDescription {
  description_en?: string | null;
  description_ar?: string | null;
}

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

  /** L4-T6: a page of the assets the caller may see, with facet counts. */
  searchAssets(search: AssetSearch, page = 1, pageSize = 25): Observable<CatalogAssetSearch> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    const q = search.q?.trim();
    if (q) params['q'] = q;
    if (search.kind) params['kind'] = search.kind;
    if (search.domain) params['domain'] = search.domain;
    if (search.label) params['label'] = search.label;
    return this.api.get<CatalogAssetSearch>('/api/v1/catalog/assets', params);
  }

  getAsset(id: string): Observable<CatalogAssetPage> {
    return this.api.get<CatalogAssetPage>(`/api/v1/catalog/assets/${encodeURIComponent(id)}`);
  }

  /** Saves a description as a draft, at the asset's `row_version`. */
  setDescription(id: string, rowVersion: number, body: AssetDescription): Observable<CatalogAssetSummary> {
    return this.api.patch<CatalogAssetSummary>(
      `/api/v1/catalog/assets/${encodeURIComponent(id)}/description`, body, rowVersion,
    );
  }

  /** A builder approves the draft, at the asset's `row_version`. */
  approveDescription(id: string, rowVersion: number): Observable<CatalogAssetSummary> {
    return this.api.post<CatalogAssetSummary>(
      `/api/v1/catalog/assets/${encodeURIComponent(id)}/description/approve`, {}, { ifMatch: rowVersion },
    );
  }

  requestAccess(id: string, reason: string): Observable<CatalogAccessRequest> {
    return this.api.post<CatalogAccessRequest>(
      `/api/v1/catalog/assets/${encodeURIComponent(id)}/access-requests`, { reason },
    );
  }

  personalDataMap(page = 1, pageSize = 50): Observable<Page<PersonalDataItem>> {
    return this.api.get<Page<PersonalDataItem>>('/api/v1/catalog/personal-data-map', {
      page: String(page), page_size: String(pageSize),
    });
  }
}
