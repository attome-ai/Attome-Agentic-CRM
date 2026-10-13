import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { entityListRoute } from '@attome/xrm/core/entity';
import {
  ComputeMetricResponse, MetricDefinitionSummary, MetricService, MetricSnapshot,
} from '../../../services/metric.service';

/**
 * M27 Phase 1 (KPI & Metrics, D-407) admin page — `xrm/metric/scorecard`.
 *
 * Deliberately NOT a replacement for the generic `xrm/metric/definition/
 * form`/`list` pages: creating/editing a definition or a target is plain
 * field CRUD the generic entity engine already handles (guidelines §9 — "do
 * not duplicate generic CRUD as per-entity code"), so this page only adds
 * what the generic engine cannot express — the two bespoke `metric.rs`
 * routes: the snapshot trend (`GET .../snapshots`) and the on-demand
 * compute trigger (`POST .../compute`). It doubles as the "scorecard" the
 * plan describes (plan §3: "a dashboard section listing metrics with
 * status") — same metric list + weighted score shape as the `scorecard`
 * widget type (`widget_registry.rs`), just as a standalone admin page
 * rather than embedded in a dashboard.
 */
@Component({
  selector: 'attome-metric-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, DecimalPipe, RouterLink, TranslatePipe],
  styleUrls: ['./metric-list.component.css'],
  templateUrl: './metric-list.component.html',
})
export class MetricListComponent {
  private readonly svc = inject(MetricService);

  /** U16 — reports and their schedules have no sidebar entry (sidebar rows
   * are seeded data, not UI code), so this page — the report module's one
   * screen — links their generic entity lists. */
  readonly reportsRoute   = entityListRoute('attome_report');
  readonly schedulesRoute = entityListRoute('report_schedule');

  readonly metrics = signal<MetricDefinitionSummary[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly selected = signal<MetricDefinitionSummary | null>(null);
  readonly snapshots = signal<MetricSnapshot[]>([]);
  readonly snapshotsLoading = signal(false);
  readonly computing = signal(false);
  readonly computeError = signal<string | null>(null);

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listMetrics(1, 200).subscribe({
      next: r => { this.metrics.set(r.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  select(metric: MetricDefinitionSummary): void {
    this.selected.set(metric);
    this.computeError.set(null);
    this.snapshotsLoading.set(true);
    this.svc.listSnapshots(metric.id, 1, 24).subscribe({
      next: r => { this.snapshots.set(r.items); this.snapshotsLoading.set(false); },
      error: (e: ApiError) => { this.computeError.set(e.message); this.snapshotsLoading.set(false); },
    });
  }

  computeNow(force: boolean): void {
    const metric = this.selected();
    if (!metric) return;
    this.computing.set(true);
    this.computeError.set(null);
    this.svc.compute(metric.id, { force }).subscribe({
      next: (res: ComputeMetricResponse) => {
        this.computing.set(false);
        // A skipped compute still returns the current row — prepend it only
        // when it's genuinely new, so a repeated idempotent click doesn't
        // duplicate the list's own head entry.
        if (!res.skipped || !this.snapshots().some(s => s.id === res.snapshot.id)) {
          this.snapshots.set([res.snapshot, ...this.snapshots()]);
        }
      },
      error: (e: ApiError) => { this.computing.set(false); this.computeError.set(e.message); },
    });
  }

  /** The status-dot CSS class — same green/amber/red convention
   *  `attome-project`'s own health dot already uses. */
  statusClass(status: string): string {
    switch (status) {
      case 'ok': return 'metric-dot metric-dot--ok';
      case 'warn': return 'metric-dot metric-dot--warn';
      case 'crit': return 'metric-dot metric-dot--crit';
      default: return 'metric-dot metric-dot--failed';
    }
  }

  /** A bounded 0-100 sparkline-bar height for the trend table's inline
   *  visual column — `references/marks-and-anatomy.md`'s "thin marks,
   *  rounded ends" spirit, kept as a plain CSS bar rather than a full SVG
   *  chart since the accessible primary view is the table itself. */
  barHeightPct(snapshot: MetricSnapshot, all: MetricSnapshot[]): number {
    if (snapshot.actual == null) return 0;
    const values = all.map(s => s.actual).filter((v): v is number => v != null);
    if (values.length === 0) return 0;
    const min = Math.min(...values);
    const max = Math.max(...values);
    if (max === min) return 100;
    return Math.round(((snapshot.actual - min) / (max - min)) * 100);
  }
}
