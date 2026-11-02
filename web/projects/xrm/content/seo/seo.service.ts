import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, SdkService } from '@attome/base';

/** E13-T12: the generated wire types of the SEO routes (E13-T8). */
export type PageSeo = ApiComponents['schemas']['PageSeo'];
export type PageSeoView = ApiComponents['schemas']['PageSeoView'];
export type SeoFinding = ApiComponents['schemas']['SeoFinding'];
export type SeoAuditRun = ApiComponents['schemas']['SeoAuditRun'];
export type SeoTopic = ApiComponents['schemas']['SeoTopic'];
export type SeoTopicBody = ApiComponents['schemas']['SeoTopicBody'];
export type SeoRobotsView = ApiComponents['schemas']['SeoRobotsView'];

export interface Page<T> { items: T[]; total: number; page: number; page_size: number }

const ADMIN = '/api/v1/admin/content';

/** The SEO admin routes: a page's settings, findings and audit; topics; robots.txt. */
@Injectable({ providedIn: 'root' })
export class SeoService {
  private readonly sdk = inject(SdkService);

  pageSeo(pageId: string): Observable<PageSeoView> {
    return this.sdk.get<PageSeoView>(`${ADMIN}/pages/${pageId}/seo`);
  }

  /** `rowVersion` goes as `If-Match`. */
  savePageSeo(pageId: string, settings: PageSeo, rowVersion: number): Observable<PageSeoView> {
    return this.sdk.put<PageSeoView>(`${ADMIN}/pages/${pageId}/seo`, { body: settings }, { ifMatch: rowVersion });
  }

  findings(pageId: string, page = 1): Observable<Page<SeoFinding>> {
    return this.sdk.get<Page<SeoFinding>>(
      `${ADMIN}/pages/${pageId}/seo/findings`,
      { query: {
      page: String(page), page_size: '50',
    } },
    );
  }

  audit(pageId: string): Observable<SeoAuditRun> {
    return this.sdk.post<SeoAuditRun>(`${ADMIN}/pages/${pageId}/seo/audit`, { body: {} });
  }

  topics(page = 1): Observable<Page<SeoTopic>> {
    return this.sdk.get<Page<SeoTopic>>(`${ADMIN}/seo/topics`, { query: { page: String(page), page_size: '100' } });
  }

  createTopic(body: SeoTopicBody): Observable<SeoTopic> {
    return this.sdk.post<SeoTopic>(`${ADMIN}/seo/topics`, { body: body });
  }

  deleteTopic(id: string): Observable<void> {
    return this.sdk.delete(`${ADMIN}/seo/topics/${id}`);
  }

  robots(siteKey: string): Observable<SeoRobotsView> {
    return this.sdk.get<SeoRobotsView>(`${ADMIN}/sites/${encodeURIComponent(siteKey)}/robots`);
  }

  saveRobots(siteKey: string, body: string): Observable<SeoRobotsView> {
    return this.sdk.put<SeoRobotsView>(`${ADMIN}/sites/${encodeURIComponent(siteKey)}/robots`, { body: { body } });
  }
}
