import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

// Wire shapes come from the generated OpenAPI contract (M26 R-15 — the
// "generated api-types.ts doesn't compile" justification `attome-project`'s own
// `services/project.service.ts` still carries was stale here too, same as
// `dashboard.service.ts`'s own note: `entity.service.ts`/`search.service.ts`
// already use this exact pattern).
//
// **Known drift, not fixed here.** `MetricDefinitionSummary` below still
// carries `is_active: boolean` because the committed `openapi.json`/
// `api-types.ts` predate M26 R-12's removal of that field from the Rust
// struct (`crates/engine/attome-metric/src/metric.rs`) — regenerating needs a full
// `server --print-openapi` run, which this session could not do safely
// (severe local disk pressure at the time, see R-15's own report). Nothing
// in this file or its consumers reads `.is_active` (verified by grep), so
// the drift is a type-accuracy gap only, not a functional one; `npm run
// generate:api` will clear it the next time it runs.
export type MetricDefinitionSummary = ApiComponents['schemas']['MetricDefinitionSummary'];
export type PaginatedMetricDefinitions = ApiComponents['schemas']['PaginatedResponse_MetricDefinitionSummary'];

export type SnapshotStatus = ApiComponents['schemas']['SnapshotRow']['status'];
export type MetricSnapshot = ApiComponents['schemas']['SnapshotRow'];
export type ComputeMetricRequest = ApiComponents['schemas']['ComputeMetricBody'];
export type ComputeMetricResponse = ApiComponents['schemas']['ComputeMetricResponse'];

@Injectable({ providedIn: 'root' })
export class MetricService {
  private readonly api = inject(ApiService);

  listMetrics(page = 1, pageSize = 50): Observable<PaginatedMetricDefinitions> {
    return this.api.get<PaginatedMetricDefinitions>('/api/v1/metrics', {
      page: String(page), page_size: String(pageSize),
    });
  }

  listSnapshots(metricId: string, page = 1, pageSize = 50): Observable<Page<MetricSnapshot>> {
    return this.api.get<Page<MetricSnapshot>>(`/api/v1/metrics/${metricId}/snapshots`, {
      page: String(page), page_size: String(pageSize),
    });
  }

  compute(metricId: string, body: ComputeMetricRequest = {}): Observable<ComputeMetricResponse> {
    return this.api.post<ComputeMetricResponse>(`/api/v1/metrics/${metricId}/compute`, body);
  }
}
