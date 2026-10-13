import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { Block } from '@attome/xrm/content/view';

// `Block`/`BlockKind` are defined in `@attome/xrm/content/view` (the
// smaller, public-facing entry point) and re-exported here as types only —
// erased at compile time, so this import costs nothing at runtime and
// doesn't drag the view entry's components into this (admin) chunk. See
// that entry's `content-public.service.ts` doc comment for why.
export type { Block, BlockKind } from '@attome/xrm/content/view';

// ── Response/request types (mirror attome-content/src/model.rs exactly) ──────────

export interface PageSummary {
  id:                string;
  parent_page_id:    string | null;
  content_space_id:  string;
  title:             string;
  url_path:          string;
  /** `draft | published`. */
  status:            string;
  updated_at:        string;
}

export interface PageDetail {
  id:                 string;
  parent_page_id:     string | null;
  content_space_id:   string;
  title:              string;
  url_path:           string;
  /** `draft | published`. */
  status:             string;
  /** `null` if this page was built from scratch, not from a template. */
  template_id:        string | null;
  blocks_draft:       Block[];
  blocks_published:   Block[] | null;
  seo_title:          string | null;
  seo_description:    string | null;
  published_at:       string | null;
  row_version:        number;
  created_at:         string;
  updated_at:         string;
  /** M37 Phase 2 (D-452) — `null` means no review cadence set, not "never
   *  review". ISO date (`YYYY-MM-DD`), not a full timestamp. */
  review_by:          string | null;
}

/** M37 Phase 2 (D-452) — full replace, `null` clears. */
export interface ReviewByBody {
  review_by: string | null;
}

/** M37 Phase 2 (D-452) — read model `attome_content::analytics::
 *  rollup_page_stats` maintains; zeroed if the nightly rollup hasn't run
 *  for this page yet. */
export interface PageStats {
  page_ref:          string;
  views:             number;
  retrievals:        number;
  helpfulness_up:    number;
  helpfulness_down:  number;
  last_useful_at:    string | null;
  updated_at:        string;
}

export interface CreatePageBody {
  parent_page_id?:   string | null;
  content_space_id:  string;
  title:             string;
  url_path:          string;
  /** Must be one of `content_space_id`'s allowed templates; copies its
   *  blocks into the new page once, at create time. */
  template_id?:      string | null;
}

/** `seo_title`/`seo_description`: omit to leave unchanged, `''` to clear. */
export interface UpdatePageBody {
  title?:           string;
  url_path?:        string;
  blocks?:          Block[];
  seo_title?:       string;
  seo_description?: string;
}

export interface ContentSpace {
  id:           string;
  name:         string;
  description:  string | null;
  row_version:  number;
  created_at:   string;
  updated_at:   string;
}

export interface CreateSpaceBody {
  name:         string;
  description?: string | null;
}

/** `description`: omit to leave unchanged, `''` to clear. */
export interface UpdateSpaceBody {
  name?:        string;
  description?: string;
}

export interface ContentTemplate {
  id:           string;
  name:         string;
  description:  string | null;
  blocks:       Block[];
  row_version:  number;
  created_at:   string;
  updated_at:   string;
}

export interface CreateTemplateBody {
  name:         string;
  description?: string | null;
  blocks?:      Block[];
}

/** `description`: omit to leave unchanged, `''` to clear. */
export interface UpdateTemplateBody {
  name?:        string;
  description?: string;
  blocks?:      Block[];
}

export interface AncestorRow {
  id:    string;
  title: string;
  depth: number;
}

export interface PublishResult {
  id:            string;
  status:        string;
  published_at:  string;
}

@Injectable({ providedIn: 'root' })
export class ContentAdminService {
  private readonly api = inject(ApiService);

  /** Children of `parentId` within `spaceId` (omit `parentId` for
   *  root-level pages). */
  listPages(spaceId: string, parentId?: string): Observable<PageSummary[]> {
    const params: Record<string, string> = { content_space_id: spaceId };
    if (parentId) params['parent_page_id'] = parentId;
    return this.api.getAllPages<PageSummary>('/api/v1/admin/content/pages', params);
  }

  searchPages(spaceId: string, query: string): Observable<PageSummary[]> {
    return this.api.getAllPages<PageSummary>('/api/v1/admin/content/pages', {
      content_space_id: spaceId, search: query,
    });
  }

  getPage(id: string): Observable<PageDetail> {
    return this.api.get<PageDetail>(`/api/v1/admin/content/pages/${id}`);
  }

  createPage(body: CreatePageBody): Observable<PageDetail> {
    return this.api.post<PageDetail>('/api/v1/admin/content/pages', body);
  }

  /** `rowVersion` is sent as `If-Match` (D-079's contract), not in the body. */
  updatePage(id: string, body: UpdatePageBody, rowVersion: number): Observable<PageDetail> {
    return this.api.patch<PageDetail>(`/api/v1/admin/content/pages/${id}`, body, rowVersion);
  }

  deletePage(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/content/pages/${id}`);
  }

  publishPage(id: string): Observable<PublishResult> {
    return this.api.post<PublishResult>(`/api/v1/admin/content/pages/${id}/publish`, {});
  }

  movePage(id: string, newParentId: string | null): Observable<PageDetail> {
    return this.api.post<PageDetail>(`/api/v1/admin/content/pages/${id}/move`, {
      parent_page_id: newParentId,
    });
  }

  ancestors(id: string): Observable<AncestorRow[]> {
    return this.api.get<AncestorRow[]>(`/api/v1/admin/content/pages/${id}/ancestors`);
  }

  relatedPages(id: string): Observable<PageSummary[]> {
    return this.api.get<PageSummary[]>(`/api/v1/admin/content/pages/${id}/related`);
  }

  /** Full-set replace, symmetric — the server writes both directions. */
  setRelatedPages(id: string, relatedPageIds: string[]): Observable<PageSummary[]> {
    return this.api.put<PageSummary[]>(`/api/v1/admin/content/pages/${id}/related`, {
      related_page_ids: relatedPageIds,
    });
  }

  /** M37 Phase 2 (D-452) — full replace, `null` clears. `PATCH` (not `PUT`
   *  — see the handler's doc comment for why). */
  setReviewBy(id: string, reviewBy: string | null, rowVersion: number): Observable<PageDetail> {
    return this.api.patch<PageDetail>(
      `/api/v1/admin/content/pages/${id}/review-by`,
      { review_by: reviewBy } as ReviewByBody,
      rowVersion,
    );
  }

  /** M37 Phase 2 (D-452) — the page stats panel's only query. */
  pageStats(id: string): Observable<PageStats> {
    return this.api.get<PageStats>(`/api/v1/admin/content/pages/${id}/stats`);
  }

  // ── Spaces ──────────────────────────────────────────────────────────────

  listSpaces(): Observable<ContentSpace[]> {
    return this.api.get<ContentSpace[]>('/api/v1/admin/content/spaces');
  }

  getSpace(id: string): Observable<ContentSpace> {
    return this.api.get<ContentSpace>(`/api/v1/admin/content/spaces/${id}`);
  }

  createSpace(body: CreateSpaceBody): Observable<ContentSpace> {
    return this.api.post<ContentSpace>('/api/v1/admin/content/spaces', body);
  }

  updateSpace(id: string, body: UpdateSpaceBody, rowVersion: number): Observable<ContentSpace> {
    return this.api.patch<ContentSpace>(`/api/v1/admin/content/spaces/${id}`, body, rowVersion);
  }

  deleteSpace(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/content/spaces/${id}`);
  }

  spaceTemplates(id: string): Observable<string[]> {
    return this.api.get<string[]>(`/api/v1/admin/content/spaces/${id}/templates`);
  }

  /** Full-set replace of which templates `id`'s editors may pick from. */
  setSpaceTemplates(id: string, templateIds: string[]): Observable<string[]> {
    return this.api.put<string[]>(`/api/v1/admin/content/spaces/${id}/templates`, {
      template_ids: templateIds,
    });
  }

  // ── Templates ───────────────────────────────────────────────────────────

  listTemplates(): Observable<ContentTemplate[]> {
    return this.api.get<ContentTemplate[]>('/api/v1/admin/content/templates');
  }

  getTemplate(id: string): Observable<ContentTemplate> {
    return this.api.get<ContentTemplate>(`/api/v1/admin/content/templates/${id}`);
  }

  createTemplate(body: CreateTemplateBody): Observable<ContentTemplate> {
    return this.api.post<ContentTemplate>('/api/v1/admin/content/templates', body);
  }

  updateTemplate(id: string, body: UpdateTemplateBody, rowVersion: number): Observable<ContentTemplate> {
    return this.api.patch<ContentTemplate>(`/api/v1/admin/content/templates/${id}`, body, rowVersion);
  }

  deleteTemplate(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/content/templates/${id}`);
  }
}
