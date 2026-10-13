import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Response types (mirror profiler_admin.rs exactly) ─────────────────────────

export interface StatRow {
  name:     string;
  count:    number;
  total_ms: number;
  avg_ms:   number;
  min_ms:   number;
  max_ms:   number;
}

export interface ApiGroup {
  api:   StatRow;
  parts: StatRow[];
}

export interface TracePart {
  name: string;
  ms:   number;
}

export interface TraceSample {
  ts:       number;
  total_ms: number;
  parts:    TracePart[];
}

@Injectable({ providedIn: 'root' })
export class ProfilerAdminService {
  private readonly api = inject(ApiService);

  stats(): Observable<ApiGroup[]> {
    return this.api.get<ApiGroup[]>('/api/v1/admin/profiler/stats');
  }

  trace(name: string, limit = 20): Observable<TraceSample[]> {
    return this.api.get<TraceSample[]>('/api/v1/admin/profiler/trace', {
      name, limit: String(limit),
    });
  }
}
