import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

/**
 * M14 / L2 (Data Quality) — `/api/v1/admin/data/quality*`
 * (`crates/engine/attome-api/src/quality_admin.rs`): scores and their
 * history, the issue queue and its statuses, rules, targets, and fixes
 * (a preview, then one undoable bulk edit). Every list is one-based
 * (`page` defaults to 1 server-side, D-347).
 */
export type QualityScore = ApiComponents['schemas']['QualityScoreView'];
export type QualityIssue = ApiComponents['schemas']['QualityIssueView'];
export type QualityRule = ApiComponents['schemas']['QualityRuleView'];
export type QualityTarget = ApiComponents['schemas']['QualityTargetView'];
export type CreateQualityRule = ApiComponents['schemas']['CreateRuleBody'];
export type UpdateQualityRule = ApiComponents['schemas']['UpdateRuleBody'];
export type PutQualityTarget = ApiComponents['schemas']['PutTargetBody'];
export type QualityFixBody = ApiComponents['schemas']['QualityFixBody'];
export type QualityFixPreview = ApiComponents['schemas']['BulkEditPreview'];
export type QualityFixSubmitted = ApiComponents['schemas']['BulkEditSubmitted'];

/** The dimensions whose history and issues the API filters by — mirrors
 * `DIMENSIONS` in `quality_admin.rs`; any other value is a 422 there. The
 * scores list itself carries every dimension the sweep writes. */
export const QUALITY_DIMENSIONS = ['completeness', 'uniqueness'] as const;
export type QualityDimension = typeof QUALITY_DIMENSIONS[number];

/** Every dimension a score row may name (L2-T2), `overall` last. */
export const SCORE_DIMENSIONS = [
  'completeness', 'uniqueness', 'validity', 'consistency', 'timeliness', 'overall',
] as const;

/** `quality::routing::STATUSES`; accepting needs a reason. */
export const QUALITY_ISSUE_STATUSES = ['open', 'in_progress', 'fixed', 'accepted', 'resolved'] as const;
export type QualityIssueStatus = typeof QUALITY_ISSUE_STATUSES[number];

/** `RULE_DIMENSIONS` and `SEVERITIES` in `quality_admin.rs`. */
export const RULE_DIMENSIONS = ['validity', 'consistency'] as const;
export const RULE_SEVERITIES = ['info', 'warning', 'error'] as const;

/** `attome_records::quality_fix::Fix`'s names. */
export const QUALITY_FIXES = ['trim_spaces', 'title_case', 'digits_to_western', 'phone_e164'] as const;
export type QualityFixKind = typeof QUALITY_FIXES[number];

/** The most records one fix may pick. */
export const MAX_FIX_RECORDS = 500;

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

  /** L2-T4: moves an issue to `status`; `accepted` needs a reason. */
  setIssueStatus(id: string, status: QualityIssueStatus, acceptedReason?: string): Observable<void> {
    return this.api.patch<void>(`/api/v1/admin/data/quality/issues/${id}`, {
      status,
      accepted_reason: acceptedReason ?? null,
    });
  }

  /** The rules of one entity, or of every entity. */
  listRules(entity?: string): Observable<QualityRule[]> {
    return this.api.getAllPages<QualityRule>(
      '/api/v1/admin/data/quality/rules', entity ? { entity } : {},
    );
  }

  createRule(body: CreateQualityRule): Observable<QualityRule> {
    return this.api.post<QualityRule>('/api/v1/admin/data/quality/rules', body);
  }

  /** `body.row_version` is the version the edit was made against. */
  updateRule(id: string, body: UpdateQualityRule): Observable<QualityRule> {
    return this.api.patch<QualityRule>(`/api/v1/admin/data/quality/rules/${id}`, body);
  }

  deleteRule(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/data/quality/rules/${id}`);
  }

  listTargets(entity?: string): Observable<QualityTarget[]> {
    return this.api.getAllPages<QualityTarget>(
      '/api/v1/admin/data/quality/targets', entity ? { entity } : {},
    );
  }

  putTarget(entity: string, body: PutQualityTarget): Observable<QualityTarget> {
    return this.api.put<QualityTarget>(
      `/api/v1/admin/data/quality/targets/${encodeURIComponent(entity)}`, body,
    );
  }

  /** L2-T5: what a fix would change, without changing it. */
  previewFix(body: QualityFixBody): Observable<QualityFixPreview> {
    return this.api.post<QualityFixPreview>('/api/v1/admin/data/quality/fixes/preview', body);
  }

  /** L2-T5: applies the fix as one bulk edit; its `undo` puts it back. */
  applyFix(body: QualityFixBody): Observable<QualityFixSubmitted> {
    return this.api.post<QualityFixSubmitted>('/api/v1/admin/data/quality/fixes/apply', body);
  }

  /** B5-T3: undoes an applied fix with the list its answer carried. */
  undoFix(entity: string, undo: QualityFixSubmitted['undo']): Observable<unknown> {
    return this.api.post<unknown>(`/api/v1/${encodeURIComponent(entity)}/bulk-edit/undo`, { undo });
  }
}
