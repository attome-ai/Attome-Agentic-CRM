import { Injectable, inject } from '@angular/core';
import { ApiService, Page } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { QueryService } from '@attome/xrm/core/query/data';
import { Observable, catchError, map, of, switchMap, throwError } from 'rxjs';

import type { PageBinding, PageDoc } from './page-model';

/** One cooked artefact of the current version (`GET /api/v1/cooked/{kind}`). */
interface CookedRef { key: string; hash: string; url: string; }

/** The rows a list, chart or metric node shows. */
export interface PageRows {
  records: Record<string, unknown>[];
  total: number | null;
}

/** The most rows a page component reads at once. */
export const PAGE_ROWS = 50;

/** D1-T2: the query filters a binding adds. Pure. */
export function bindingFilters(binding: PageBinding, recordId: string | null): { field: string; op: string; value?: string }[] {
  const filters: { field: string; op: string; value?: string }[] = [];
  if (binding.related_by && recordId) filters.push({ field: binding.related_by, op: 'eq', value: recordId });
  for (const c of binding.where ?? []) {
    // The query API takes an `in` list as the array itself.
    filters.push({ field: c.field, op: c.op, value: c.value as unknown as string });
  }
  return filters;
}

/**
 * T2-T2: what a page reads and does, under the signed-in person's own
 * rights: the published page (its cooked artefact), the rows a view or a
 * stored query returns, a record, the person's role names for visibility,
 * and the events' targets (starting a flow, running an action).
 */
@Injectable({ providedIn: 'root' })
export class PageDataService {
  private readonly api = inject(ApiService);
  private readonly query = inject(QueryService);
  private readonly entities = inject(EntityService);

  /** The published page `id`; a page not in the current version is a 404. */
  page(id: string): Observable<PageDoc> {
    return this.api.get<Page<CookedRef>>('/api/v1/cooked/page').pipe(
      map(list => list.items.find(i => i.key === `page:${id}`)),
      switchMap(ref => (ref
        ? this.api.get<PageDoc>(ref.url)
        : throwError(() => ({ status: 404, kind: 'not_found', message: '' })))),
    );
  }

  /** The caller's role names; none when they cannot be read. */
  myRoles(): Observable<string[]> {
    return this.api.get<{ items: string[] }>('/api/v1/me/roles').pipe(
      map(r => r.items ?? []),
      catchError(() => of([])),
    );
  }

  /**
   * The rows of a view, stored query or entity binding. On a record page
   * `related_by` keeps the rows whose lookup names `recordId`; with no
   * record yet such a binding shows nothing rather than every row.
   */
  rows(binding: PageBinding, recordId: string | null = null): Observable<PageRows> {
    const params = binding.view ? { view_id: binding.view }
      : binding.query ? { query_id: binding.query }
      : binding.entity ? { entity: binding.entity }
      : null;
    if (!params) return of({ records: [], total: 0 });
    if (binding.related_by && !recordId) return of({ records: [], total: 0 });
    const filters = bindingFilters(binding, recordId);
    return this.query.execute({ ...params, page: 1, page_size: PAGE_ROWS, include_total: true, filters }).pipe(
      map(res => ({ records: res.data.records, total: res.data.total })),
    );
  }

  /** One record's values. */
  record(entity: string, id: string): Observable<Record<string, unknown>> {
    return this.entities.get(entity, id).pipe(
      map(r => ((r as unknown as { data?: Record<string, unknown> }).data ?? {})),
    );
  }

  /** Starts the flow definition `definitionId` about a record. */
  startFlow(definitionId: string, entity: string | null, recordId: string | null): Observable<unknown> {
    return this.api.get<{ logicalname: string }>(`/api/v1/workflow/definitions/${encodeURIComponent(definitionId)}`).pipe(
      switchMap(def => this.api.post('/api/v1/workflow/instances', {
        definition_logicalname: def.logicalname,
        context: recordId ? { entity, record_id: recordId } : {},
        correlation_entity_id: recordId ?? undefined,
      })),
    );
  }

  /** Runs the action `actionId` with the record as its arguments. */
  runAction(actionId: string, entity: string | null, recordId: string | null): Observable<unknown> {
    return this.api.post(`/api/v1/actions/${encodeURIComponent(actionId)}/invoke`, {
      args: recordId ? { entity, id: recordId } : {},
    });
  }
}
