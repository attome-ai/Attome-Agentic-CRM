import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// D-432 / M13 (Master Data Management, scoped to dedup + survivorship only) —
// mirrors attome_api::duplicates_admin / duplicates_match exactly
// (crates/engine/attome-api/src/duplicates_admin.rs, duplicates_match.rs).

export type MatchComparator = 'exact' | 'normalized' | 'trigram' | 'embedding';

export interface MatchField {
  field:          string;
  comparator:     MatchComparator;
  weight:         number;
  /** `trigram` only — the `pg_trgm` similarity floor. */
  min_similarity: number | null;
}

export interface MatchRule {
  id:                  string;
  entity_logicalname:  string;
  name:                string;
  is_active:           boolean;
  fields:              MatchField[];
  threshold:           number;
  auto_merge:          boolean;
  row_version:         number;
  created_at:          string;
  updated_at:          string;
  created_by:          string;
}

export interface MatchRulesPage {
  items: MatchRule[]; total: number; page: number; page_size: number;
}

export interface CreateMatchRuleBody {
  entity:      string;
  name:        string;
  is_active?:  boolean;
  fields:      MatchField[];
  threshold:   number;
  auto_merge?: boolean;
}

export type SurvivorshipStrategy = 'most_recent' | 'most_complete' | 'source_priority' | 'manual';

export interface SurvivorshipRule {
  id:                  string;
  entity_logicalname:  string;
  field_logicalname:   string;
  strategy:            SurvivorshipStrategy;
  priority_owner_ids:  string[] | null;
  row_version:         number;
  created_at:          string;
  updated_at:          string;
  created_by:          string;
}

export interface SurvivorshipRulesPage {
  items: SurvivorshipRule[]; total: number; page: number; page_size: number;
}

export interface CreateSurvivorshipRuleBody {
  entity:              string;
  field:               string;
  strategy:            SurvivorshipStrategy;
  priority_owner_ids?: string[];
}

export type CandidateStatus = 'open' | 'merged' | 'dismissed';

export interface DuplicateCandidate {
  id:                   string;
  entity_logicalname:   string;
  record_a:             string;
  record_b:             string;
  match_rule_id:        string;
  score:                number;
  status:                CandidateStatus;
  auto_merge_eligible:  boolean;
  approval_request_id:  string | null;
  detected_at:          string;
  resolved_at:          string | null;
  resolved_by:          string | null;
  resolution_note:      string | null;
  row_version:          number;
}

export interface DuplicateCandidatesPage {
  items: DuplicateCandidate[]; total: number; page: number; page_size: number;
}

/** Mirrors `EntityRecordResponse` flattened alongside `survivorship_conflicts`
 *  (`entity_crud::merge::MergeResponse`) — only the fields the review page
 *  actually reads are typed here; the rest pass through as `unknown`. */
export interface MergeResponse {
  id: string;
  survivorship_conflicts: string[];
  [key: string]: unknown;
}

@Injectable({ providedIn: 'root' })
export class DuplicatesService {
  private readonly api = inject(ApiService);

  // ── Match rules ──────────────────────────────────────────────────────

  listMatchRules(page = 1, pageSize = 50, entity?: string): Observable<MatchRulesPage> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (entity) params['entity'] = entity;
    return this.api.get<MatchRulesPage>('/api/v1/admin/data/match-rules', params);
  }

  createMatchRule(body: CreateMatchRuleBody): Observable<MatchRule> {
    return this.api.post<MatchRule>('/api/v1/admin/data/match-rules', body);
  }

  deleteMatchRule(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/data/match-rules/${id}`);
  }

  // ── Survivorship rules ───────────────────────────────────────────────

  listSurvivorshipRules(page = 1, pageSize = 50, entity?: string): Observable<SurvivorshipRulesPage> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (entity) params['entity'] = entity;
    return this.api.get<SurvivorshipRulesPage>('/api/v1/admin/data/survivorship-rules', params);
  }

  createSurvivorshipRule(body: CreateSurvivorshipRuleBody): Observable<SurvivorshipRule> {
    return this.api.post<SurvivorshipRule>('/api/v1/admin/data/survivorship-rules', body);
  }

  deleteSurvivorshipRule(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/data/survivorship-rules/${id}`);
  }

  // ── Duplicate candidates (steward queue) ────────────────────────────

  /** Defaults to `status=open` — the steward queue's own default view. */
  listCandidates(
    page = 1, pageSize = 50, status: CandidateStatus | null = 'open', entity?: string,
  ): Observable<DuplicateCandidatesPage> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (status) params['status'] = status;
    if (entity) params['entity'] = entity;
    return this.api.get<DuplicateCandidatesPage>('/api/v1/admin/data/duplicates', params);
  }

  getCandidate(id: string): Observable<DuplicateCandidate> {
    return this.api.get<DuplicateCandidate>(`/api/v1/admin/data/duplicates/${id}`);
  }

  /** `canonicalId` must equal the candidate's `record_a` or `record_b` — the
   *  other one becomes the duplicate and is soft-deleted. Runs the exact
   *  same merge (`entity_crud::do_merge_core`) the ordinary per-record merge
   *  endpoint runs, so a `manual`-strategy survivorship conflict comes back
   *  in the response, not silently resolved. */
  mergeCandidate(id: string, canonicalId: string): Observable<MergeResponse> {
    return this.api.post<MergeResponse>(`/api/v1/admin/data/duplicates/${id}/merge`, {
      canonical_id: canonicalId,
    });
  }

  dismissCandidate(id: string, rowVersion: number, note?: string): Observable<DuplicateCandidate> {
    return this.api.post<DuplicateCandidate>(`/api/v1/admin/data/duplicates/${id}/dismiss`, {
      row_version: rowVersion, note: note ?? null,
    });
  }

  /** The record form's "possible duplicate" banner — no `Admin` gate
   *  server-side, only the caller's own read access to `recordId`. */
  candidatesForRecord(entity: string, recordId: string): Observable<DuplicateCandidate[]> {
    return this.api.get<DuplicateCandidate[]>('/api/v1/data/duplicates/for-record', {
      entity, record_id: recordId,
    });
  }
}
