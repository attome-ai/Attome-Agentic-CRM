import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';

export interface QueryMeta {
  id:                  string;
  name:                string;
  sql_preview:         string;
  entity_logical_name: string | null;
  is_active:           boolean;
  /** Solution 7 (D-785): the owning layer, typed from the generated `QueryMeta`. */
  owner_layer?: ApiComponents['schemas']['QueryMeta']['owner_layer'];
}

export interface QueryDetail {
  id:                  string;
  name:                string;
  sql_query:           string;
  table_definition:    string;
  entity_logical_name: string | null;
  is_active:           boolean;
  /** P1.1e: when set, query/execute requires this exact privilege key instead of admin-only. */
  required_privilege:  string | null;
  /** P1.1e: raises the read-only transaction's statement_timeout to 5s. */
  is_report:           boolean;
  /** Solution 7 (D-785): the owning layer, typed from the generated `QueryDetail`. */
  owner_layer?: ApiComponents['schemas']['QueryDetail']['owner_layer'];
}

export interface CreateQueryBody {
  name?:                string;
  sql_query:            string;
  table_definition?:    string;
  entity_logical_name?: string;
  required_privilege?:  string;
  is_report?:           boolean;
}

export interface UpdateQueryBody {
  name?:                string;
  sql_query?:           string;
  table_definition?:    string;
  entity_logical_name?: string | null;
  required_privilege?:  string;
  is_report?:           boolean;
}

export interface DescribedQueryColumn {
  name:      string;
  data_type: string;
}

@Injectable({ providedIn: 'root' })
export class QueryAdminService {
  private readonly api = inject(ApiService);

  listQueries(): Observable<QueryMeta[]> {
    return this.api.getAllPages<QueryMeta>('/api/v1/admin/queries');
  }

  getQuery(id: string): Observable<QueryDetail> {
    return this.api.get<QueryDetail>(`/api/v1/admin/queries/${id}`);
  }

  describeQuery(sqlQuery: string): Observable<DescribedQueryColumn[]> {
    return this.api.post<DescribedQueryColumn[]>('/api/v1/admin/queries/describe', {
      sql_query: sqlQuery,
    });
  }

  createQuery(body: CreateQueryBody): Observable<QueryDetail> {
    return this.api.post<QueryDetail>('/api/v1/admin/queries', body);
  }

  updateQuery(id: string, body: UpdateQueryBody): Observable<QueryDetail> {
    return this.api.patch<QueryDetail>(`/api/v1/admin/queries/${id}`, body);
  }

  deleteQuery(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/queries/${id}`);
  }
}
