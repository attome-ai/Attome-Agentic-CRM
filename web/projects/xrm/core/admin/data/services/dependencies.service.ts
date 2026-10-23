import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/** One gated capability, as `GET /health/dependencies` reports it. */
export interface CapabilityRow {
  capability: string;
  state: 'unknown' | 'available' | 'unavailable' | 'disabled';
  consecutive_failures: number;
  enforced: boolean;
  down_for_secs?: number;
}

/** AB6-T9: one outbound service: its breaker, errors and retries. */
export interface OutboundRow {
  service: string;
  state: 'closed' | 'half_open' | 'open';
  /** Failed calls over all calls in the last hour, 0 to 1; null before the first. */
  error_rate: number | null;
  retries_1h: number;
  /** Endpoints under this name (each webhook target or connector host has its own breaker). */
  endpoints: number;
}

export interface DependencyReport {
  capabilities: { gated_routes: CapabilityRow[] };
  outbound?: OutboundRow[];
}

/**
 * AB6-T9 — the dependency map (`GET /health/dependencies`, administrators
 * only): what each gated capability's probe says, and each outbound
 * service's breaker on the node that answered.
 */
@Injectable({ providedIn: 'root' })
export class DependenciesService {
  private readonly api = inject(ApiService);

  report(): Observable<DependencyReport> {
    return this.api.get<DependencyReport>('/health/dependencies');
  }
}
