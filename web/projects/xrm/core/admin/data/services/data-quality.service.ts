import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

/**
 * M14 Phase 1 (Data Quality) — the admin read surface plus the one
 * issue-resolution action, `/api/v1/admin/data/quality*`
 * (`crates/engine/attome-api/src/quality_admin.rs`, `Authorized<Admin>`).
 * Every list is one-based (`page` defaults to 1 server-side, D-347).
 */
export type QualityScore = ApiComponents['schemas']['QualityScoreView'];
export type QualityIssue = ApiComponents['schemas']['QualityIssueView'];

/** The two dimensions the Phase 1 sweep computes — mirrors `DIMENSIONS` in
 * `quality_admin.rs`; any other value is a 422 there. */
export const QUALITY_DIMENSIONS = ['completeness', 'uniqueness'] as const;
export type QualityDimension = typeof QUALITY_DIMENSIONS[number];

export type QualityIssueStatus = 'open' | 'resolved';

export interface QualityIssueFilter {
  entity?:    string;
  dimension?: QualityDimension;
  status?:    QualityIssueStatus;
}

@Injectable({ providedIn: 'root' })
export class DataQualityService {
  private readonly api = inject(ApiService);

  /** The latest score per (entity, dimension), every page walked. */
  listScores(entity?: string): Observable<QualityScore[]> {
    return this.api.getAllPages<QualityScore>(
      '/api/v1/admin/data/quality/scores', entity ? { entity } : {},
    );
  }

  /** One entity+dimension's period series, newest first — the trend. */
  scoreHistory(entity: string, dimension: QualityDimension, pageSize = 30): Observable<Page<QualityScore>> {
    return this.api.get<Page<QualityScore>>('/api/v1/admin/data/quality/scores/history', {
      entity, dimension, page: '1', page_size: String(pageSize),
    });
  }

  listIssues(filter: QualityIssueFilter, page = 1, pageSize = 50): Observable<Page<QualityIssue>> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (filter.entity)    params['entity'] = filter.entity;
    if (filter.dimension) params['dimension'] = filter.dimension;
    if (filter.status)    params['status'] = filter.status;
    return this.api.get<Page<QualityIssue>>('/api/v1/admin/data/quality/issues', params);
  }

  /** 204 on success; 409 when the issue is already resolved. */
  resolveIssue(id: string): Observable<void> {
    return this.api.post<void>(`/api/v1/admin/data/quality/issues/${id}/resolve`, {});
  }
}
