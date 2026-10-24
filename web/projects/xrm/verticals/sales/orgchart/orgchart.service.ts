import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { Observable, map, switchMap } from 'rxjs';

/** One person on the chart (`OrgNode`). */
export interface OrgNode {
  id: string;
  full_name?: string | null;
  job_title?: string | null;
  department?: string | null;
  department_ar?: string | null;
  account_id?: string | null;
  dotted_line_id?: string | null;
  is_former_employee: boolean;
  children: OrgNode[];
  collapsed_children?: number | null;
}

/** `GET /api/v1/sales/accounts/{id}/org-chart`. */
export interface OrgChart {
  roots: OrgNode[];
  unplaced: OrgNode[];
  companies: { id: string; name?: string | null }[];
  next_cursor?: string | null;
}

/** The answer to a manager change (`SalesManagerSet`). */
export interface ManagerSet {
  contact_id: string;
  manager_id?: string | null;
  /** The manager before this change: set it back to undo. */
  previous_manager_id?: string | null;
  row_version: number;
}

/** One contact on a deal (`DealContact`); `influence` and `attitude` are
 * absent for a caller without the Deal Attitude field profile. */
export interface DealContact {
  contact_id: string;
  full_name?: string | null;
  role?: string | null;
  is_primary: boolean;
  influence?: string | null;
  attitude?: string | null;
  met_recently: boolean;
  /** O7 relationship strength (0-100), only when the API returns it. */
  strength?: number | null;
}

/** An "influences" link between two contacts on the deal. */
export interface InfluenceLink {
  from_contact: string;
  to_contact: string;
}

/** A coverage gap (`Gap`). */
export interface CoverageGap {
  kind: 'missing_role' | 'unmet_high_influence';
  role?: string | null;
  contact_id?: string | null;
}

/** `GET /api/v1/sales/opportunities/{id}/committee-map`. */
export interface DealMap {
  opportunity_id: string;
  account_id?: string | null;
  chart?: OrgChart | null;
  contacts: DealContact[];
  influences: InfluenceLink[];
  required_roles: string[];
  gaps: CoverageGap[];
  gaps_computed_at?: string | null;
}

/** D23's org chart routes. */
@Injectable({ providedIn: 'root' })
export class OrgChartService {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);

  /** The account's chart (its group's with `group`), opening the `expand` branches. */
  chart(account: string, group: boolean, expand: readonly string[]): Observable<OrgChart> {
    const params: Record<string, string> = { group: String(group) };
    if (expand.length) params['expand'] = expand.join(',');
    return this.api.get<OrgChart>(`/api/v1/sales/accounts/${encodeURIComponent(account)}/org-chart`, params);
  }

  /** The deal's buying committee and its coverage gaps (D23-T7). */
  committeeMap(opportunity: string): Observable<DealMap> {
    return this.api.get<DealMap>(`/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/committee-map`);
  }

  /** Records that `from` influences `to`: a `record_relationship` row
   * through the generic entity API. */
  addInfluence(from: string, to: string): Observable<unknown> {
    return this.entities.create('record_relationship', {
      from_entity_name: 'contact', from_record_id: from,
      to_entity_name: 'contact', to_record_id: to,
      relationship_type: 'influences',
    });
  }

  /**
   * Sets who `contact` reports to (`null` clears it), reading the contact's
   * current row version for `If-Match` first.
   */
  setManager(contact: string, manager: string | null): Observable<ManagerSet> {
    return this.entities.get('contact', contact).pipe(
      map(record => record.row_version),
      switchMap(version => this.api.put<ManagerSet>(
        `/api/v1/sales/contacts/${encodeURIComponent(contact)}/manager`,
        { manager_id: manager, line: 'solid' },
        { ifMatch: version },
      )),
    );
  }
}
