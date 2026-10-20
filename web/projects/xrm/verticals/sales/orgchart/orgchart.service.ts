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
