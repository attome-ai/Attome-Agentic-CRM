import { inject, Injectable } from '@angular/core';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';
import { map, Observable } from 'rxjs';

export type ScheduleSummary = ApiComponents['schemas']['ScheduleSummary'];
export type AssignmentView = ApiComponents['schemas']['AssignmentView'];
export type LiveRow = ApiComponents['schemas']['LiveRow'];
export type Published = ApiComponents['schemas']['Published'];

/** One day of a build's coverage (`coverage_json`): per-interval agents. */
export interface DayCoverage {
  day: string;
  requirement: number[];
  before: number[];
  after: number[];
  under: number;
  over: number;
}

/** A schedule with its assignments and coverage. */
export interface ScheduleDetail extends ScheduleSummary {
  assignments: AssignmentView[];
  coverage: DayCoverage[];
}

/** A choice in a picker. */
export interface PickOption {
  id: string;
  label: string;
}

/** A swap request as the generic list returns it. */
export interface SwapRow {
  id: string;
  from_assignment_ref: string | null;
  to_user_ref: string | null;
  status: string | null;
  reason: string | null;
}

/** An intraday proposal (`wfm_offer`). */
export interface OfferRow {
  id: string;
  kind: string | null;
  status: string | null;
  start_at: string | null;
  end_at: string | null;
  people: number | null;
  reason: string | null;
}

function text(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v : null;
}

function field(row: Record<string, unknown>, name: string): unknown {
  const data = row['data'];
  if (data !== null && typeof data === 'object' && name in (data as Record<string, unknown>)) {
    return (data as Record<string, unknown>)[name];
  }
  return row[name];
}

/** The coverage a schedule read carries, as days (anything else is none). Pure. */
export function coverageDays(raw: unknown): DayCoverage[] {
  if (!Array.isArray(raw)) return [];
  const nums = (v: unknown): number[] => (Array.isArray(v) ? v.map(n => (typeof n === 'number' ? n : 0)) : []);
  return raw
    .filter((d): d is Record<string, unknown> => d !== null && typeof d === 'object')
    .map(d => ({
      day: String(d['day'] ?? ''),
      requirement: nums(d['requirement']),
      before: nums(d['before']),
      after: nums(d['after']),
      under: typeof d['under'] === 'number' ? d['under'] : 0,
      over: typeof d['over'] === 'number' ? d['over'] : 0,
    }));
}

/** G17-T13: the workforce routes (G17-T7..T11) and the generic lists the screens read. */
@Injectable({ providedIn: 'root' })
export class WorkforceApiService {
  private readonly api = inject(ApiService);

  private list(entity: string, params: Record<string, string>): Observable<Record<string, unknown>[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>(`/api/v1/${entity}`, { page_size: '200', ...params })
      .pipe(map(r => r.items ?? []));
  }

  groups(): Observable<PickOption[]> {
    return this.list('wfm_planning_group', { sort: 'name' }).pipe(
      map(rows => rows.map(r => ({ id: String(r['id']), label: text(field(r, 'name')) ?? String(r['id']) }))),
    );
  }

  users(): Observable<PickOption[]> {
    return this.list('user_account', { select: 'id,user_name,email', sort: 'email' }).pipe(
      map(rows => rows.map(r => ({
        id: String(r['id']),
        label: text(field(r, 'user_name')) ?? text(field(r, 'email')) ?? String(r['id']),
      }))),
    );
  }

  schedules(groupId: string | null): Observable<ScheduleSummary[]> {
    const params: Record<string, string> = { page_size: '50' };
    if (groupId) params['group_id'] = groupId;
    return this.api
      .get<{ items: ScheduleSummary[] }>('/api/v1/workforce/schedules', params)
      .pipe(map(r => r.items ?? []));
  }

  schedule(id: string): Observable<ScheduleDetail> {
    return this.api
      .get<ScheduleSummary & { assignments: AssignmentView[]; coverage: unknown }>(
        `/api/v1/workforce/schedules/${encodeURIComponent(id)}`,
      )
      .pipe(map(s => ({ ...s, assignments: s.assignments ?? [], coverage: coverageDays(s.coverage) })));
  }

  build(groupId: string, from: string, to: string): Observable<{ run_id: string }> {
    return this.api.post<{ run_id: string }>(
      `/api/v1/workforce/groups/${encodeURIComponent(groupId)}/schedules/build`,
      { from, to },
    );
  }

  publish(id: string, rowVersion: number): Observable<Published> {
    return this.api.post<Published>(
      `/api/v1/workforce/schedules/${encodeURIComponent(id)}/publish`,
      {},
      { ifMatch: rowVersion },
    );
  }

  moveAssignment(id: string, rowVersion: number, patch: { user_id?: string; start_at?: string; end_at?: string; reason?: string }): Observable<AssignmentView> {
    return this.api.patch<AssignmentView>(`/api/v1/workforce/assignments/${encodeURIComponent(id)}`, patch, rowVersion);
  }

  swaps(): Observable<SwapRow[]> {
    return this.list('wfm_swap_request', { 'filter[status][in]': 'requested,accepted' }).pipe(
      map(rows => rows.map(r => ({
        id: String(r['id']),
        from_assignment_ref: text(field(r, 'from_assignment_ref')),
        to_user_ref: text(field(r, 'to_user_ref')),
        status: text(field(r, 'status')),
        reason: text(field(r, 'reason')),
      }))),
    );
  }

  decideSwap(id: string, approve: boolean, reason: string | null): Observable<{ status: string }> {
    return this.api.post<{ status: string }>(
      `/api/v1/workforce/swaps/${encodeURIComponent(id)}/decide`,
      { approve, reason },
    );
  }

  proposals(): Observable<OfferRow[]> {
    return this.list('wfm_offer', { 'filter[status][eq]': 'proposed' }).pipe(
      map(rows => rows.map(r => ({
        id: String(r['id']),
        kind: text(field(r, 'kind')),
        status: text(field(r, 'status')),
        start_at: text(field(r, 'start_at')),
        end_at: text(field(r, 'end_at')),
        people: typeof field(r, 'people') === 'number' ? (field(r, 'people') as number) : null,
        reason: text(field(r, 'reason')),
      }))),
    );
  }

  sendOffer(id: string): Observable<unknown> {
    return this.api.post(`/api/v1/workforce/offers/${encodeURIComponent(id)}/send`, {});
  }

  live(groupId: string): Observable<LiveRow[]> {
    return this.api.get<LiveRow[]>('/api/v1/workforce/adherence/live', { group: groupId });
  }
}
