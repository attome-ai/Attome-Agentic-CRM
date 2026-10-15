import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService, DuplicateMatchRef } from '@attome/base';

// D-432 / M13 (Master Data Management, scoped to dedup + survivorship only) —
// mirrors attome_api::duplicates_admin / duplicates_match exactly
// (crates/engine/attome-api/src/duplicates_admin.rs, duplicates_match.rs).

export type MatchComparator =
  | 'exact' | 'normalized' | 'trigram' | 'embedding'
  // A15-T3: compared through stored match keys.
  | 'phone' | 'email' | 'id' | 'name' | 'phonetic';

/** The comparators a rule editor offers (`embedding` is never runnable). */
export const MATCH_COMPARATORS: readonly MatchComparator[] = [
  'exact', 'normalized', 'trigram', 'phone', 'email', 'id', 'name', 'phonetic',
];

/** A15-T4: what saving a likely duplicate does. */
export type OnSave = 'off' | 'warn' | 'allow_with_reason' | 'block';

export const ON_SAVE_MODES: readonly OnSave[] = ['off', 'warn', 'allow_with_reason', 'block'];

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
  /** A15-T6: `hourly`, `daily` or `weekly`; `null` scans only on demand. */
  scan_schedule:       string | null;
  last_scan_at:        string | null;
  on_save:             OnSave;
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
  scan_schedule?: string | null;
  on_save?: OnSave;
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
  /** A15-T5: the merge log row; undoing the merge names it. */
  merge_log_id: string;
  [key: string]: unknown;
}

/** A15-T7: `POST /api/v1/data/duplicates/check`. */
export interface DuplicateCheckResult {
  /** What saving would do; `null` when nothing matches. */
  action: Exclude<OnSave, 'off'> | null;
  matches: DuplicateMatchRef[];
  hidden: number;
}

/** A15-T10: per field, whose value the survivor keeps. */
export type MergePicks = Record<string, 'survivor' | 'merged'>;

/** A15-T5: `entity_crud::merge::MergePreview`. */
export interface MergePreview {
  moved: { relationship: string; count: number }[];
  flows: string[];
  /** The survivor's values after the merge. */
  result: Record<string, unknown>;
  conflicts: string[];
  merge_mode: 'soft_delete' | 'keep_merged';
}

/** A15-T5: `entity_crud::merge::MergeUndone`. */
export interface MergeUndone {
  survivor_id: string;
  merged_ids: string[];
  rows_moved_back: number;
}

/** A15-T7: one field of `GET /admin/data/duplicates/{id}/explain`. */
export interface FieldExplanation {
  field: string;
  comparator: MatchComparator;
  weight: number;
  /** 1 matched, 0 differed, `null` no evidence. */
  score: number | null;
  key_a: string | null;
  key_b: string | null;
}

export interface CandidateExplanation {
  candidate_id: string;
  rule_id: string;
  score: number;
  threshold: number;
  fields: FieldExplanation[];
}

/** A15-T7: `GET /admin/data/duplicates/stats`, one row per entity. */
export interface DuplicateStats {
  entity: string;
  open: number;
  merged: number;
  dismissed: number;
}

/** A15-T7: `POST /admin/data/match-rules/preview`. */
export interface RulePreview {
  sampled: number;
  pairs: number;
  examples: { record_a: string; record_b: string; score: number }[];
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

  /** A15-T6: queues a full-table scan of the rule's entity. */
  scanMatchRule(id: string): Observable<{ queued: boolean }> {
    return this.api.post<{ queued: boolean }>(`/api/v1/admin/data/match-rules/${id}/scan`, {});
  }

  /** A15-T7: scores a draft rule over a sample of live rows; saves nothing. */
  previewMatchRule(body: { entity: string; fields: MatchField[]; threshold: number }): Observable<RulePreview> {
    return this.api.post<RulePreview>('/api/v1/admin/data/match-rules/preview', body);
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

  /** A15-T7: why a pair was flagged, field by field. */
  explainCandidate(id: string): Observable<CandidateExplanation> {
    return this.api.get<CandidateExplanation>(`/api/v1/admin/data/duplicates/${id}/explain`);
  }

  /** A15-T7: open, merged and dismissed pair counts per entity. */
  stats(entity?: string): Observable<DuplicateStats[]> {
    return this.api.get<DuplicateStats[]>('/api/v1/admin/data/duplicates/stats', entity ? { entity } : undefined);
  }

  /** A15-T7: the records saving `values` would duplicate; writes nothing. */
  check(entity: string, values: Record<string, unknown>, recordId?: string | null): Observable<DuplicateCheckResult> {
    return this.api.post<DuplicateCheckResult>('/api/v1/data/duplicates/check', {
      entity, values, record_id: recordId ?? null,
    });
  }

  /** A15-T5/T7: what merging `mergedId` into `survivorId` would do. */
  mergePreview(entity: string, survivorId: string, mergedId: string, picks: MergePicks = {}): Observable<MergePreview> {
    return this.api.post<MergePreview>(`/api/v1/${entity}/${survivorId}/merge/preview`, {
      duplicate_id: mergedId, picks,
    });
  }

  /** Merges `mergedId` into `survivorId` with the person's field picks; a
   *  `candidateId` closes that queue row in the same transaction. */
  mergeRecords(
    entity: string, survivorId: string, mergedId: string,
    options: { picks?: MergePicks; candidateId?: string; rowVersion?: number } = {},
  ): Observable<MergeResponse> {
    return this.api.post<MergeResponse>(`/api/v1/${entity}/${survivorId}/merge`, {
      duplicate_id: mergedId,
      picks: options.picks ?? {},
      ...(options.candidateId ? { candidate_id: options.candidateId } : {}),
    }, { ifMatch: options.rowVersion });
  }

  /** A15-T5/T7: undoes a merge as one unit. */
  undoMerge(entity: string, mergeId: string): Observable<MergeUndone> {
    return this.api.post<MergeUndone>(`/api/v1/${entity}/merges/${mergeId}/undo`, {});
  }

  /** The record form's "possible duplicate" banner — no `Admin` gate
   *  server-side, only the caller's own read access to `recordId`. */
  candidatesForRecord(entity: string, recordId: string): Observable<DuplicateCandidate[]> {
    return this.api.get<DuplicateCandidate[]>('/api/v1/data/duplicates/for-record', {
      entity, record_id: recordId,
    });
  }
}
