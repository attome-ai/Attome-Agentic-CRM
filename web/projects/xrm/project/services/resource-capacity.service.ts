import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService, Page } from '@attome/base';

// Wire shape mirrors `crates/engine/attome-project/src/model.rs`'s `CapacityRow`
// field-for-field, same "hand-mirrored, not imported from the generated
// schema" posture `project.service.ts` documents for `ProjectSummary` — see
// that file's comment for why (a pre-existing, unrelated generated-file
// compile break).
export interface CapacityRow {
  resource_id: string;
  resource_name: string | null;
  capacity_hours: number;
  allocated_hours: number;
  actual_hours: number;
  utilization_pct: number;
  over_allocated: boolean;
}

export interface CapacityQuery {
  from: string; // yyyy-MM-dd
  to: string; // yyyy-MM-dd
  team?: string;
  skill?: string;
  page?: number;
  page_size?: number;
}

@Injectable({ providedIn: 'root' })
export class ResourceCapacityService {
  private readonly api = inject(ApiService);

  /** `GET /api/v1/resources/capacity` (M72) — one page of per-resource
   *  capacity/allocated/actual/utilization figures for `[from, to]`. */
  getCapacity(query: CapacityQuery): Observable<Page<CapacityRow>> {
    const params: Record<string, string> = { from: query.from, to: query.to };
    if (query.team) params['team'] = query.team;
    if (query.skill) params['skill'] = query.skill;
    if (query.page != null) params['page'] = String(query.page);
    if (query.page_size != null) params['page_size'] = String(query.page_size);
    return this.api.get<Page<CapacityRow>>('/api/v1/resources/capacity', params);
  }
}
