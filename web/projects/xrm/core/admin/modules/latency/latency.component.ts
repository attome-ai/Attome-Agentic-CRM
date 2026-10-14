import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `attome_server::metrics::RouteLatency`. */
export interface RouteLatency {
  method: string;
  endpoint: string;
  count: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
}

/** `system_health::LatencyReport`. */
export interface LatencyReport {
  enabled: boolean;
  routes: RouteLatency[];
}

/** Routes whose p95 is at or above this are marked slow. */
export const SLOW_P95_MS = 500;

/**
 * Latency (roadmap AA1-T7): each route's p50, p95 and p99 on this node since
 * it started, slowest first, with a filter. Logical CSS only.
 */
@Component({
  selector:        'xrm-latency',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './latency.component.html',
  styleUrls:       ['./latency.component.css'],
})
export class LatencyComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly report = signal<LatencyReport | null>(null);
  readonly error = signal<string | null>(null);
  readonly filter = signal('');
  readonly slow = SLOW_P95_MS;
  readonly routes = computed(() => {
    const needle = this.filter().trim().toLowerCase();
    const all = this.report()?.routes ?? [];
    return needle ? all.filter(r => `${r.method} ${r.endpoint}`.toLowerCase().includes(needle)) : all;
  });

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<LatencyReport>('/api/v1/admin/latency').subscribe({
      next: r => this.report.set(r),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
