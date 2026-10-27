import { inject, Injectable } from '@angular/core';
import { ApiService } from '@attome/base';
import { map, Observable } from 'rxjs';

/** A member's access to the deal (D7-T2). */
export type TeamAccess = 'read' | 'edit';

/** One member of an opportunity's team, as the generic list returns it. */
export interface TeamMember {
  id: string;
  user_ref: string | null;
  partner_contact_ref: string | null;
  team_role_ref: string | null;
  access_level: string | null;
}

/** A choice in a picker. */
export interface PickOption {
  id: string;
  label: string;
}

/** A split type (`sales_split_type`): revenue types must total 100. */
export interface SplitType {
  id: string;
  name: string;
  must_total_100: boolean;
}

/** One split as the generic list returns it; `amount` is absent when field security hides it. */
export interface SplitRow {
  id?: string;
  member_ref: string;
  split_type_ref: string;
  line_ref: string | null;
  percent: string;
  amount?: string | null;
}

/** The answer of a split change: the splits, or the approval a won deal's change waits on. */
export interface SplitsOutcome {
  opportunity_id: string;
  splits: unknown[];
  approval_request_id: string | null;
}

function text(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v : null;
}

/** A generic list row's field: the row itself or its `data`. */
function dataOf(row: Record<string, unknown>): Record<string, unknown> | null {
  const data = row['data'];
  return data !== null && typeof data === 'object' ? (data as Record<string, unknown>) : null;
}

function field(row: Record<string, unknown>, name: string): unknown {
  const data = dataOf(row);
  return data !== null && name in data ? data[name] : row[name];
}

function has(row: Record<string, unknown>, name: string): boolean {
  const data = dataOf(row);
  return (data !== null && name in data) || name in row;
}

/** D7-T7: the deal team (D7-T2, D7-T3) and split (D7-T4) routes, and the generic lists they read. */
@Injectable({ providedIn: 'root' })
export class SalesTeamApiService {
  private readonly api = inject(ApiService);

  private list(entity: string, params: Record<string, string>): Observable<Record<string, unknown>[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>(`/api/v1/${entity}`, { page_size: '200', ...params })
      .pipe(map(r => r.items ?? []));
  }

  members(opportunity: string): Observable<TeamMember[]> {
    return this.list('opportunity_team_member', { 'filter[opportunity_ref][eq]': opportunity }).pipe(
      map(rows => rows.map(r => ({
        id: String(r['id']),
        user_ref: text(field(r, 'user_ref')),
        partner_contact_ref: text(field(r, 'partner_contact_ref')),
        team_role_ref: text(field(r, 'team_role_ref')),
        access_level: text(field(r, 'access_level')),
      }))),
    );
  }

  roles(): Observable<PickOption[]> {
    return this.list('sales_team_role', { sort: 'name' }).pipe(
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

  addMember(opportunity: string, body: { user_ref: string; team_role_ref: string; access_level: TeamAccess }): Observable<unknown> {
    return this.api.post(`/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/team`, body);
  }

  removeMember(opportunity: string, member: string): Observable<unknown> {
    return this.api.delete(
      `/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/team/${encodeURIComponent(member)}`,
    );
  }

  copyAccountTeam(opportunity: string, roles: string[]): Observable<{ added: number; skipped: number }> {
    return this.api.post<{ added: number; skipped: number }>(
      `/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/team/copy-account-team`,
      { roles },
    );
  }

  splitTypes(): Observable<SplitType[]> {
    return this.list('sales_split_type', { sort: 'name' }).pipe(
      map(rows => rows.map(r => ({
        id: String(r['id']),
        name: text(field(r, 'name')) ?? String(r['id']),
        must_total_100: field(r, 'must_total_100') === true,
      }))),
    );
  }

  splits(opportunity: string): Observable<SplitRow[]> {
    return this.list('opportunity_split', { 'filter[opportunity_ref][eq]': opportunity }).pipe(
      map(rows => rows.map(r => {
        const row: SplitRow = {
          id: String(r['id']),
          member_ref: String(field(r, 'member_ref') ?? ''),
          split_type_ref: String(field(r, 'split_type_ref') ?? ''),
          line_ref: text(field(r, 'line_ref')),
          percent: String(field(r, 'percent') ?? ''),
        };
        if (has(r, 'amount')) row.amount = text(String(field(r, 'amount') ?? ''));
        return row;
      })),
    );
  }

  saveSplits(opportunity: string, splits: SplitRow[], changeReason: string | null): Observable<SplitsOutcome> {
    return this.api.put<SplitsOutcome>(`/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/splits`, {
      splits: splits.map(s => ({
        member_id: s.member_ref,
        split_type_id: s.split_type_ref,
        line_id: s.line_ref,
        percent: s.percent.trim(),
      })),
      change_reason: changeReason,
    });
  }
}
