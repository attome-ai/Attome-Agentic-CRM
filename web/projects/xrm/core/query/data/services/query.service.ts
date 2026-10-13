import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import { QueryExecParams, QueryExecResponse } from './types';

@Injectable({ providedIn: 'root' })
export class QueryService {
  private readonly api = inject(ApiService);

  execute(params: QueryExecParams): Observable<QueryExecResponse> {
    return this.api.post<QueryExecResponse>('/api/v1/query/execute', {
      entity:    params.entity,
      entity_logical_name: params.entity_logical_name,
      query_id:  params.query_id,
      view_id:   params.view_id,
      page:      params.page      ?? 1,
      page_size: params.page_size ?? 50,
      search:    params.search    ?? '',
      order_by:  params.order_by  ?? '',
      order_dir: params.order_dir ?? 'asc',
      filters:   params.filters   ?? [],
      include_total: params.include_total ?? false,
      after_id: params.after_id,
      query_version_id: params.query_version_id,
    });
  }
}
