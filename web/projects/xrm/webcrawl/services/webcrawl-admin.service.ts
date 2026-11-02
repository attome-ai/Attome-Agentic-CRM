import { inject, Injectable } from '@angular/core';
import { Observable, map, switchMap } from 'rxjs';
import { SdkService } from '@attome/base';

// ── Response/request types (mirror attome-webcrawl/src/model.rs exactly) ─────────

export interface TargetListItem {
  id:               string;
  url:              string;
  /** `pending | crawling | completed | failed`. */
  status:           string;
  max_depth:        number;
  pages_found:      number;
  pages_imported:   number;
  last_error:       string | null;
  last_crawled_at:  string | null;
  created_at:       string;
  /** K6-T1 source settings. */
  include_patterns?: string;
  exclude_patterns?: string;
  languages?:        string[];
  /** `internal | partner | customer`. */
  audience?:         string;
  /** `review | automatic`. */
  import_mode?:      string;
  /** `manual | daily | weekly`. */
  schedule?:         string;
  sitemap_url?:      string | null;
  watch_only?:       boolean;
  allow_host?:       string;
  credential_ref?:   string | null;
  /** K6-T10: sent back as `If-Match` to change the settings. */
  row_version?:      number;
}

/** K6-T10: the settings a knowledge manager changes; each one left out keeps its value. */
export interface TargetSettings {
  max_depth?:        number;
  include_patterns?: string;
  exclude_patterns?: string;
  languages?:        string[];
  audience?:         string;
  import_mode?:      string;
  schedule?:         string;
  sitemap_url?:      string;
  watch_only?:       boolean;
}

/** K6-T10: one crawl of a source. */
export interface CrawlRun {
  id:             string;
  started_at:     string;
  finished_at:    string | null;
  /** `running | completed | failed`. */
  status:         string;
  pages_found:    number;
  items_imported: number;
  items_updated:  number;
  items_flagged:  number;
  error:          string | null;
}

/** K6-T10: an imported item a recrawl changed, waiting for review. */
export interface CrawlChange {
  page_id:    string;
  url_path:   string;
  item_id:    string;
  title:      string | null;
  version:    number | null;
  changed_at: string;
}

interface Page<T> { items: T[]; total: number; page: number; page_size: number; }

export interface PageListItem {
  id:                      string;
  url_path:                string;
  parent_path:             string | null;
  depth:                   number;
  size_bytes:              number | null;
  /** `pending | crawled | failed`. */
  status:                  string;
  is_selected:             boolean;
  imported_data_item_ref:  string | null;
  /** K6-T11: the language the page declared, once crawled. */
  language?:               string | null;
}

export interface ImportResult {
  data_source_ref: string;
  imported_count:  number;
}

@Injectable({ providedIn: 'root' })
export class WebcrawlAdminService {
  private readonly sdk = inject(SdkService);

  /** One-based, like every offset list (D-347, D-793) — `getAllPages`' default. */
  listTargets(): Observable<TargetListItem[]> {
    return this.sdk.getAllPages<TargetListItem>('/api/v1/webcrawl/targets');
  }

  createTarget(url: string, maxDepth?: number): Observable<TargetListItem> {
    return this.sdk.post<TargetListItem>(
      '/api/v1/webcrawl/targets',
      { body: {
      url,
      max_depth: maxDepth ?? null,
    } },
    );
  }

  recrawlTarget(id: string): Observable<TargetListItem> {
    return this.sdk.post<TargetListItem>(`/api/v1/webcrawl/targets/${id}/recrawl`, { body: {} });
  }

  deleteTarget(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/webcrawl/targets/${id}`);
  }

  listPages(targetId: string): Observable<PageListItem[]> {
    return this.sdk.get<PageListItem[]>(`/api/v1/webcrawl/targets/${targetId}/pages`);
  }

  updateSelection(targetId: string, pageIds: string[], selected: boolean): Observable<void> {
    return this.sdk.patch(
      `/api/v1/webcrawl/targets/${targetId}/pages/selection`,
      { body: {
      page_ids: pageIds,
      selected,
    } },
    );
  }

  /** K6-T10: changes a source's settings under its row version. */
  updateTarget(id: string, rowVersion: number, settings: TargetSettings): Observable<TargetListItem> {
    return this.sdk.patch<TargetListItem>(`/api/v1/webcrawl/targets/${id}`, { body: settings, ifMatch: rowVersion });
  }

  /** K6-T10: the source's runs, newest first (the first page). */
  listRuns(id: string): Observable<CrawlRun[]> {
    return this.sdk.get<Page<CrawlRun>>(`/api/v1/webcrawl/targets/${id}/runs`, { query: { page: '1', page_size: '50' } })
      .pipe(map(p => p.items));
  }

  /** K6-T10: the source's items waiting for review (the first page). */
  listChanges(id: string): Observable<CrawlChange[]> {
    return this.sdk.get<Page<CrawlChange>>(`/api/v1/webcrawl/targets/${id}/changes`, { query: { page: '1', page_size: '100' } })
      .pipe(map(p => p.items));
  }

  /** Keeps the editor's text: clears the item's review flag under its row version. */
  keepItem(itemId: string): Observable<unknown> {
    return this.sdk.get<{ row_version: number }>(`/api/v1/knowledge_data_item/${itemId}`).pipe(
      switchMap(item => this.sdk.patch(`/api/v1/knowledge_data_item/${itemId}`, { body: { needs_review: false }, ifMatch: item.row_version })),
    );
  }

  importPages(targetId: string, pageIds: string[]): Observable<ImportResult> {
    return this.sdk.post<ImportResult>(
      `/api/v1/webcrawl/targets/${targetId}/import`,
      { body: {
      page_ids: pageIds,
    } },
    );
  }
}
