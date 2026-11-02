import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { SdkService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

type Schemas = ApiComponents['schemas'];

export type SearchResponse = Schemas['SearchResponse'];
export type SearchHit = Schemas['SearchHit'];
export type SearchFacets = Schemas['SearchFacets'];
export type FacetCount = Schemas['FacetCount'];
export type ScoreParts = Schemas['ScoreParts'];
export type SearchEntitySettings = Schemas['SearchEntitySettings'];
export type SearchEntitySettingsBody = Schemas['SearchEntitySettingsBody'];
export type SearchAttributeSetting = Schemas['SearchAttributeSetting'];
export type SearchSynonym = Schemas['SearchSynonym'];
export type SearchStopword = Schemas['SearchStopword'];
export type SearchPin = Schemas['SearchPin'];
export type SearchPinBody = Schemas['SearchPinBody'];
export type SearchQuality = Schemas['SearchQuality'];
export type SearchIndexSize = Schemas['SearchIndexSize'];
export type SearchStatus = Schemas['SearchStatus'];

/** One citation of a direct answer (`search.answer_records`). */
export interface AskCitation {
  entity: string;
  record_id: string;
  title?: string | null;
}

/**
 * A25-T7's `ask` block. Read through this narrow shape until the generated
 * `SearchResponse` carries it; the server sends exactly these fields.
 */
export interface AskResult {
  status: 'parsed' | 'declined';
  filter?: { entity: string; where?: unknown } | null;
  reason?: string | null;
  answer?: { answer: string | null; citations?: AskCitation[]; reason?: string } | null;
}

// The generated `ask` is free-form JSON (`Record<string, never>`); this
// shape replaces it rather than intersecting with it.
export type AskingSearchResponse = Omit<SearchResponse, 'ask'> & { ask?: AskResult | null };

/** The admin lists are short; one page of 100 holds them. */
const ADMIN_PAGE: Record<string, string> = { page: '1', page_size: '100' };

/** What a page search asks for beside the query. */
export interface PageSearchOptions {
  ask?: boolean;
  explain?: boolean;
  pageSize?: number;
}

/** The search page's and the search settings' calls (A25-T11). */
@Injectable({ providedIn: 'root' })
export class SearchPageService {
  private readonly sdk = inject(SdkService);

  /** `GET /api/v1/search` with facets, and explanations or asking in words when chosen. */
  search(q: string, opts: PageSearchOptions = {}): Observable<AskingSearchResponse> {
    const params: Record<string, string> = { q, facets: 'true' };
    if (opts.pageSize) params['page_size'] = String(opts.pageSize);
    if (opts.explain) params['explain'] = 'true';
    if (opts.ask) params['mode'] = 'ask';
    return this.sdk.get<AskingSearchResponse>('/api/v1/search', { query: params });
  }

  /**
   * A25-T6: a short-lived address of a document's file, to open it at the
   * page a search matched.
   */
  documentFileUrl(documentId: string): Observable<{ download_url: string }> {
    return this.sdk.get<{ download_url: string }>(
      `/api/v1/attome_document/${encodeURIComponent(documentId)}/files/file/download-url`,
    );
  }

  /** Saves the query as the caller's own saved search; `alert` emails them new results. */
  saveSearch(name: string, query: string, alert: boolean): Observable<unknown> {
    return this.sdk.post(
      '/api/v1/saved_search',
      { body: {
      name,
      query_text: query,
      alert_enabled: alert,
    } },
    );
  }

  entitySettings(entity: string): Observable<SearchEntitySettings> {
    return this.sdk.get<SearchEntitySettings>(`/api/v1/admin/search/entities/${encodeURIComponent(entity)}`);
  }

  /** Replaces an entity's settings at `rowVersion` (`If-Match`). */
  saveEntitySettings(entity: string, body: SearchEntitySettingsBody, rowVersion: number): Observable<SearchEntitySettings> {
    return this.sdk.put<SearchEntitySettings>(
      `/api/v1/admin/search/entities/${encodeURIComponent(entity)}`,
      { body: body },
      { ifMatch: rowVersion },
    );
  }

  synonyms(): Observable<Schemas['PaginatedResponse_SearchSynonym']> {
    return this.sdk.get<Schemas['PaginatedResponse_SearchSynonym']>('/api/v1/admin/search/synonyms', { query: ADMIN_PAGE });
  }

  addSynonym(terms: string[], lang: string | null): Observable<SearchSynonym> {
    return this.sdk.post<SearchSynonym>('/api/v1/admin/search/synonyms', { body: { terms, lang } });
  }

  deleteSynonym(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/search/synonyms/${encodeURIComponent(id)}`);
  }

  stopwords(): Observable<Schemas['PaginatedResponse_SearchStopword']> {
    return this.sdk.get<Schemas['PaginatedResponse_SearchStopword']>('/api/v1/admin/search/stopwords', { query: ADMIN_PAGE });
  }

  addStopword(word: string, lang: string): Observable<SearchStopword> {
    return this.sdk.post<SearchStopword>('/api/v1/admin/search/stopwords', { body: { word, lang } });
  }

  deleteStopword(word: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/search/stopwords/${encodeURIComponent(word)}`);
  }

  pins(): Observable<Schemas['PaginatedResponse_SearchPin']> {
    return this.sdk.get<Schemas['PaginatedResponse_SearchPin']>('/api/v1/admin/search/pins', { query: ADMIN_PAGE });
  }

  addPin(body: SearchPinBody): Observable<SearchPin> {
    return this.sdk.post<SearchPin>('/api/v1/admin/search/pins', { body: body });
  }

  deletePin(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/search/pins/${encodeURIComponent(id)}`);
  }

  size(): Observable<SearchIndexSize> {
    return this.sdk.get<SearchIndexSize>('/api/v1/admin/search/size');
  }

  status(): Observable<SearchStatus> {
    return this.sdk.get<SearchStatus>('/api/v1/admin/search/status');
  }

  quality(): Observable<SearchQuality> {
    return this.sdk.get<SearchQuality>('/api/v1/admin/search/quality');
  }
}
