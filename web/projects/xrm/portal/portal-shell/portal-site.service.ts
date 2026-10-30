import { Injectable, inject, signal } from '@angular/core';
import { ApiService, Page } from '@attome/base';
import type { PageBinding, PageDoc, PageRows } from '@attome/xrm/core/page-runtime';
import { Observable, map, of, throwError } from 'rxjs';

/** The signed-in portal user (`GET /{keyword}/api/v1/me`). */
export interface PortalMe {
  id: string;
  name: string;
  email: string | null;
  username: string | null;
  row_version: number;
  profile: Record<string, unknown>;
}

/** One page in the portal's navigation (`GET /{keyword}/api/v1/pages`). */
export interface PortalPageSummary {
  name: string;
  page_type: string;
  title_en: string | null;
  title_ar: string | null;
}

/** A page as the portal renders it (`GET /{keyword}/api/v1/pages/{name}`). */
export interface PortalPage {
  id: string;
  name: string;
  entity_name: string | null;
  doc: PageDoc;
}

/** The portal's current terms and whether they are accepted. */
export interface PortalConsent {
  terms_version: string | null;
  privacy_version: string | null;
  accepted: boolean;
}

/** A record as a portal sees it. */
interface PortalRecord {
  id: string;
  row_version: number;
  created_at: string | null;
  data: Record<string, unknown>;
}

/** The most rows a portal page component reads. */
export const PORTAL_ROWS = 50;

/**
 * D1-T2's binding filters as the portal record API takes them: equality
 * only, one query parameter per field. An `in` condition has no portal form,
 * so a binding with one cannot be shown (`null`). Pure.
 */
export function portalFilters(binding: PageBinding, recordId: string | null): Record<string, string> | null {
  const out: Record<string, string> = {};
  if (binding.related_by) {
    if (!recordId) return null;
    out[binding.related_by] = recordId;
  }
  for (const c of binding.where ?? []) {
    if (c.op !== 'eq' || Array.isArray(c.value)) return null;
    out[c.field] = String(c.value);
  }
  return out;
}

/**
 * G12-T1: one web portal's API (`/{keyword}/api/v1/...`) for the portal
 * app: its session, the signed-in user, consent, its pages and its records.
 * Every call is the portal user's own; the server's role plan decides what
 * they may see and do.
 */
@Injectable({ providedIn: 'root' })
export class PortalSiteService {
  private readonly api = inject(ApiService);

  /** The portal the app shows, set by the shell from the route. */
  readonly keyword = signal<string | null>(null);
  /** Bumped when the session or consent changes (signed in, accepted), so the shell reads them again. */
  readonly changed = signal(0);

  private base(keyword: string): string {
    return `/${encodeURIComponent(keyword)}/api/v1`;
  }

  login(keyword: string, login: string, password: string, code?: string): Observable<unknown> {
    return this.api.post(`${this.base(keyword)}/auth/login`, { login, password, code: code || undefined });
  }

  logout(keyword: string): Observable<unknown> {
    return this.api.post(`${this.base(keyword)}/auth/logout`, {});
  }

  me(keyword: string): Observable<PortalMe> {
    return this.api.get<PortalMe>(`${this.base(keyword)}/me`);
  }

  updateProfile(keyword: string, changes: Record<string, unknown>, rowVersion: number): Observable<PortalMe> {
    return this.api.patch<PortalMe>(`${this.base(keyword)}/me`, changes, rowVersion);
  }

  consent(keyword: string): Observable<PortalConsent> {
    return this.api.get<PortalConsent>(`${this.base(keyword)}/me/consent`);
  }

  acceptConsent(keyword: string, consent: PortalConsent): Observable<unknown> {
    return this.api.post(`${this.base(keyword)}/me/consent`, {
      terms_version: consent.terms_version,
      privacy_version: consent.privacy_version,
    });
  }

  pages(keyword: string): Observable<PortalPageSummary[]> {
    return this.api.get<Page<PortalPageSummary>>(`${this.base(keyword)}/pages`).pipe(map(p => p.items));
  }

  page(keyword: string, name: string): Observable<PortalPage> {
    return this.api.get<PortalPage>(`${this.base(keyword)}/pages/${encodeURIComponent(name)}`);
  }

  /** A page component's rows: an entity binding through the portal's record API. */
  rows(keyword: string, binding: PageBinding, recordId: string | null): Observable<PageRows> {
    if (!binding.entity) return of({ records: [], total: 0 });
    const filters = portalFilters(binding, recordId);
    if (!filters) return of({ records: [], total: 0 });
    return this.api
      .get<Page<PortalRecord>>(`${this.base(keyword)}/records/${encodeURIComponent(binding.entity)}`, {
        page: '1',
        page_size: String(PORTAL_ROWS),
        ...filters,
      })
      .pipe(map(page => ({ records: page.items.map(r => ({ id: r.id, ...r.data })), total: page.total })));
  }

  record(keyword: string, entity: string, id: string): Observable<Record<string, unknown>> {
    return this.api
      .get<PortalRecord>(`${this.base(keyword)}/records/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`)
      .pipe(map(r => r.data));
  }

  create(keyword: string, entity: string, data: Record<string, unknown>): Observable<unknown> {
    return this.api.post(`${this.base(keyword)}/records/${encodeURIComponent(entity)}`, data);
  }
}

/**
 * G12-T1: the page runtime's data source inside the portal, standing in for
 * `PageDataService` (provided by the page host): pages by name from the
 * portal, rows and records through the portal's record API, no staff roles,
 * and no flows or actions (a portal user starts neither).
 */
@Injectable()
export class PortalPageData {
  private readonly site = inject(PortalSiteService);

  private keyword(): string {
    return this.site.keyword() ?? '';
  }

  page(name: string): Observable<PageDoc> {
    return this.site.page(this.keyword(), name).pipe(map(p => p.doc));
  }

  myRoles(): Observable<string[]> {
    return of([]);
  }

  rows(binding: PageBinding, recordId: string | null = null): Observable<PageRows> {
    return this.site.rows(this.keyword(), binding, recordId);
  }

  record(entity: string, id: string): Observable<Record<string, unknown>> {
    return this.site.record(this.keyword(), entity, id);
  }

  startFlow(): Observable<unknown> {
    return throwError(() => ({ status: 403, kind: 'forbidden', message: '' }));
  }

  runAction(): Observable<unknown> {
    return throwError(() => ({ status: 403, kind: 'forbidden', message: '' }));
  }
}
