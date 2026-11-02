import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { SdkService } from '@attome/base';
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
  private readonly sdk = inject(SdkService);

  /** Children of `parentId` within `spaceId` (omit `parentId` for
   *  root-level pages). */
  listPages(spaceId: string, parentId?: string): Observable<PageSummary[]> {
    const params: Record<string, string> = { content_space_id: spaceId };
    if (parentId) params['parent_page_id'] = parentId;
    return this.sdk.getAllPages<PageSummary>('/api/v1/admin/content/pages', params);
  }

  searchPages(spaceId: string, query: string): Observable<PageSummary[]> {
    return this.sdk.getAllPages<PageSummary>('/api/v1/admin/content/pages', {
      content_space_id: spaceId, search: query,
    });
  }

  getPage(id: string): Observable<PageDetail> {
    return this.sdk.get<PageDetail>(`/api/v1/admin/content/pages/${id}`);
  }

  createPage(body: CreatePageBody): Observable<PageDetail> {
    return this.sdk.post<PageDetail>('/api/v1/admin/content/pages', { body: body });
  }

  /** `rowVersion` is sent as `If-Match` (D-079's contract), not in the body. */
  updatePage(id: string, body: UpdatePageBody, rowVersion: number): Observable<PageDetail> {
    return this.sdk.patch<PageDetail>(`/api/v1/admin/content/pages/${id}`, { body: body, ifMatch: rowVersion });
  }

  deletePage(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/content/pages/${id}`);
  }

  publishPage(id: string): Observable<PublishResult> {
    return this.sdk.post<PublishResult>(`/api/v1/admin/content/pages/${id}/publish`, { body: {} });
  }

  movePage(id: string, newParentId: string | null): Observable<PageDetail> {
    return this.sdk.post<PageDetail>(
      `/api/v1/admin/content/pages/${id}/move`,
      { body: {
      parent_page_id: newParentId,
    } },
    );
  }

  ancestors(id: string): Observable<AncestorRow[]> {
    return this.sdk.get<AncestorRow[]>(`/api/v1/admin/content/pages/${id}/ancestors`);
  }

  relatedPages(id: string): Observable<PageSummary[]> {
    return this.sdk.get<PageSummary[]>(`/api/v1/admin/content/pages/${id}/related`);
  }

  /** Full-set replace, symmetric — the server writes both directions. */
  setRelatedPages(id: string, relatedPageIds: string[]): Observable<PageSummary[]> {
    return this.sdk.put<PageSummary[]>(
      `/api/v1/admin/content/pages/${id}/related`,
      { body: {
      related_page_ids: relatedPageIds,
    } },
    );
  }

  /** M37 Phase 2 (D-452) — full replace, `null` clears. `PATCH` (not `PUT`
   *  — see the handler's doc comment for why). */
  setReviewBy(id: string, reviewBy: string | null, rowVersion: number): Observable<PageDetail> {
    return this.sdk.patch<PageDetail>(
      `/api/v1/admin/content/pages/${id}/review-by`,
      { body: { review_by: reviewBy } as ReviewByBody, ifMatch: rowVersion },
    );
  }

  /** M37 Phase 2 (D-452) — the page stats panel's only query. */
  pageStats(id: string): Observable<PageStats> {
    return this.sdk.get<PageStats>(`/api/v1/admin/content/pages/${id}/stats`);
  }

  // ── Spaces ──────────────────────────────────────────────────────────────

  listSpaces(): Observable<ContentSpace[]> {
    return this.sdk.get<ContentSpace[]>('/api/v1/admin/content/spaces');
  }

  getSpace(id: string): Observable<ContentSpace> {
    return this.sdk.get<ContentSpace>(`/api/v1/admin/content/spaces/${id}`);
  }

  createSpace(body: CreateSpaceBody): Observable<ContentSpace> {
    return this.sdk.post<ContentSpace>('/api/v1/admin/content/spaces', { body: body });
  }

  updateSpace(id: string, body: UpdateSpaceBody, rowVersion: number): Observable<ContentSpace> {
    return this.sdk.patch<ContentSpace>(`/api/v1/admin/content/spaces/${id}`, { body: body, ifMatch: rowVersion });
  }

  deleteSpace(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/content/spaces/${id}`);
  }

  spaceTemplates(id: string): Observable<string[]> {
    return this.sdk.get<string[]>(`/api/v1/admin/content/spaces/${id}/templates`);
  }

  /** Full-set replace of which templates `id`'s editors may pick from. */
  setSpaceTemplates(id: string, templateIds: string[]): Observable<string[]> {
    return this.sdk.put<string[]>(
      `/api/v1/admin/content/spaces/${id}/templates`,
      { body: {
      template_ids: templateIds,
    } },
    );
  }

  // ── Templates ───────────────────────────────────────────────────────────

  listTemplates(): Observable<ContentTemplate[]> {
    return this.sdk.get<ContentTemplate[]>('/api/v1/admin/content/templates');
  }

  getTemplate(id: string): Observable<ContentTemplate> {
    return this.sdk.get<ContentTemplate>(`/api/v1/admin/content/templates/${id}`);
  }

  createTemplate(body: CreateTemplateBody): Observable<ContentTemplate> {
    return this.sdk.post<ContentTemplate>('/api/v1/admin/content/templates', { body: body });
  }

  updateTemplate(id: string, body: UpdateTemplateBody, rowVersion: number): Observable<ContentTemplate> {
    return this.sdk.patch<ContentTemplate>(`/api/v1/admin/content/templates/${id}`, { body: body, ifMatch: rowVersion });
  }

  deleteTemplate(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/content/templates/${id}`);
  }
}
