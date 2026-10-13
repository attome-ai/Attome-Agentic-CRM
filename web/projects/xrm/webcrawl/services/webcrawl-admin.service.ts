import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

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
}

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
}

export interface ImportResult {
  data_source_ref: string;
  imported_count:  number;
}

@Injectable({ providedIn: 'root' })
export class WebcrawlAdminService {
  private readonly api = inject(ApiService);

  /** One-based, like every offset list (D-347, D-793) — `getAllPages`' default. */
  listTargets(): Observable<TargetListItem[]> {
    return this.api.getAllPages<TargetListItem>('/api/v1/webcrawl/targets');
  }

  createTarget(url: string, maxDepth?: number): Observable<TargetListItem> {
    return this.api.post<TargetListItem>('/api/v1/webcrawl/targets', {
      url,
      max_depth: maxDepth ?? null,
    });
  }

  recrawlTarget(id: string): Observable<TargetListItem> {
    return this.api.post<TargetListItem>(`/api/v1/webcrawl/targets/${id}/recrawl`, {});
  }

  deleteTarget(id: string): Observable<void> {
    return this.api.delete(`/api/v1/webcrawl/targets/${id}`);
  }

  listPages(targetId: string): Observable<PageListItem[]> {
    return this.api.get<PageListItem[]>(`/api/v1/webcrawl/targets/${targetId}/pages`);
  }

  updateSelection(targetId: string, pageIds: string[], selected: boolean): Observable<void> {
    return this.api.patch(`/api/v1/webcrawl/targets/${targetId}/pages/selection`, {
      page_ids: pageIds,
      selected,
    });
  }

  importPages(targetId: string, pageIds: string[]): Observable<ImportResult> {
    return this.api.post<ImportResult>(`/api/v1/webcrawl/targets/${targetId}/import`, {
      page_ids: pageIds,
    });
  }
}
