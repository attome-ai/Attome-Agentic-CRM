import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiComponents, SdkService } from '@attome/base';

export type RecordShare = ApiComponents['schemas']['RecordShare'];
export type AccessExplanation = ApiComponents['schemas']['AccessExplanation'];
export type AccessSource = ApiComponents['schemas']['AccessSource'];
type EntityRecordResponse = ApiComponents['schemas']['EntityRecordResponse'];

export type PrincipalKind = 'user' | 'team';
export type ExplainAction = 'read' | 'update' | 'delete';
export const EXPLAIN_ACTIONS: readonly ExplainAction[] = ['read', 'update', 'delete'];

/** A user or team a person can pick, with the text shown for it. */
export interface PrincipalOption {
  kind: PrincipalKind;
  id: string;
  label: string;
}

/** Where each kind of principal lives and the field that names it. */
const PRINCIPALS: Record<PrincipalKind, { entity: string; field: string }> = {
  user: { entity: 'user_account', field: 'email' },
  team: { entity: 'team', field: 'name' },
};

interface QueryRows {
  data: { records: Record<string, unknown>[] };
}

/**
 * Q14-T6 — the record-level sharing routes (Q14-T1: list, share, unshare,
 * needing `{entity}.share`), the access explainer (Q14-T4), and the reads the
 * panel shows names with. The server decides every answer; this only asks.
 */
@Injectable({ providedIn: 'root' })
export class SharingPanelService {
  private readonly sdk = inject(SdkService);

  record(entity: string, id: string): Observable<EntityRecordResponse> {
    return this.sdk.get<EntityRecordResponse>(`/api/v1/${entity}/${id}`);
  }

  shares(entity: string, id: string): Observable<RecordShare[]> {
    return this.sdk.getAllPages<RecordShare>(`/api/v1/${entity}/${id}/shares`);
  }

  share(entity: string, id: string, who: PrincipalOption, capability: 'view' | 'action'): Observable<RecordShare> {
    return this.sdk.post<RecordShare>(
      `/api/v1/${entity}/${id}/shares`,
      { body: {
      capability,
      user_id: who.kind === 'user' ? who.id : null,
      team_id: who.kind === 'team' ? who.id : null,
    } },
    );
  }

  unshare(entity: string, id: string, shareId: string): Observable<void> {
    return this.sdk.delete(`/api/v1/${entity}/${id}/shares/${shareId}`);
  }

  explain(entity: string, id: string, userId: string, action: ExplainAction): Observable<AccessExplanation> {
    return this.sdk.get<AccessExplanation>(`/api/v1/${entity}/${id}/access/explain`, { query: { user: userId, action } });
  }

  /** Users (by email) or teams (by name) whose name contains `term`, the first 20. */
  search(kind: PrincipalKind, term: string): Observable<PrincipalOption[]> {
    const { entity, field } = PRINCIPALS[kind];
    const text = term.trim();
    return this.sdk.post<QueryRows>(
      '/api/v1/query/execute',
      { body: {
      entity,
      page: 1,
      page_size: 20,
      order_by: field,
      order_dir: 'asc',
      filters: text ? [{ field, op: 'contains', value: text }] : [],
      include_total: false,
    } },
    ).pipe(
      map(res => res.data.records.map(r => ({
        kind,
        id: String(r['id'] ?? ''),
        label: String(r[field] ?? r['id'] ?? ''),
      }))),
    );
  }

  /** The name of one user or team, or its id when it cannot be read. */
  name(kind: PrincipalKind, id: string): Observable<string> {
    const { entity, field } = PRINCIPALS[kind];
    return this.record(entity, id).pipe(
      map(r => {
        const value = (r.data as Record<string, unknown>)[field];
        return typeof value === 'string' && value ? value : id;
      }),
    );
  }
}
