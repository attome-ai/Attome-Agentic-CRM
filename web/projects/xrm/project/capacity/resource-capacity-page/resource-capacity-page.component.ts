import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { forkJoin } from 'rxjs';
import { ApiError } from '@attome/base';
import { ResourceCapacityService } from '../../services/resource-capacity.service';

/** One resource's utilization figure for one week bucket — `null` means the
 *  resource had no capacity row at all in that bucket's response (not the
 *  same as a `0%` bucket, which means "had capacity, wasn't allocated"). */
interface Cell {
  utilizationPct: number | null;
  overAllocated: boolean;
}

interface GridRow {
  resourceId: string;
  resourceName: string;
  cells: Cell[];
}

interface WeekBucket {
  from: string; // yyyy-MM-dd
  to: string; // yyyy-MM-dd
  label: string;
}

const WEEK_COUNT = 6;

/**
 * `GET /api/v1/resources/capacity` (M72) rendered as a resource × week heat
 * grid. The endpoint itself aggregates over one `[from, to]` window (no
 * server-side time-bucketing — see `capacity.rs`'s own module doc on why:
 * Phase 1 scope, EXPLAIN-able as a single query), so the "period" axis here
 * is built client-side: `WEEK_COUNT` consecutive Mon-Sun buckets starting
 * this week's Monday, one request per bucket via the same endpoint,
 * assembled into one matrix.
 *
 * Color follows the dataviz skill's "status, not sequential" rule for this
 * metric: utilization has a meaningful threshold (100% = fully booked, and
 * M72's own alert fires at sustained >85%), so a cell's color is one of four
 * fixed, icon+label-paired states — never a bare color swatch — rather than
 * a smooth magnitude ramp. The 85% "warning" boundary intentionally matches
 * `utilization.rs::sweep_utilization_alerts`'s own alert threshold.
 */
@Component({
  selector: 'xrm-resource-capacity-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
  styleUrls: ['./resource-capacity-page.component.css'],
  templateUrl: './resource-capacity-page.component.html',
})
export class ResourceCapacityPageComponent implements OnInit {
  private readonly svc = inject(ResourceCapacityService);

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly buckets = signal<WeekBucket[]>([]);
  readonly rows = signal<GridRow[]>([]);

  readonly teamFilter = signal('');
  readonly skillFilter = signal('');

  readonly hasData = computed(() => this.rows().length > 0);

  ngOnInit(): void {
    this.buckets.set(this.buildWeekBuckets());
    this.load();
  }

  private buildWeekBuckets(): WeekBucket[] {
    const today = new Date();
    const day = today.getDay(); // 0=Sun..6=Sat
    const daysSinceMonday = (day + 6) % 7;
    const monday = new Date(today);
    monday.setDate(today.getDate() - daysSinceMonday);
    monday.setHours(0, 0, 0, 0);

    const buckets: WeekBucket[] = [];
    for (let i = 0; i < WEEK_COUNT; i++) {
      const start = new Date(monday);
      start.setDate(monday.getDate() + i * 7);
      const end = new Date(start);
      end.setDate(start.getDate() + 6);
      buckets.push({
        from: this.toIso(start),
        to: this.toIso(end),
        label: start.toLocaleDateString(undefined, { month: 'short', day: '2-digit' }),
      });
    }
    return buckets;
  }

  private toIso(d: Date): string {
    return d.toISOString().slice(0, 10);
  }

  reload(): void {
    this.buckets.set(this.buildWeekBuckets());
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const buckets = this.buckets();
    const team = this.teamFilter().trim() || undefined;
    const skill = this.skillFilter().trim() || undefined;

    forkJoin(
      buckets.map(b => this.svc.getCapacity({ from: b.from, to: b.to, team, skill, page_size: 200 })),
    ).subscribe({
      next: pages => {
        // resource_id -> { name, cells[bucketIndex] }
        const byResource = new Map<string, { name: string; cells: (Cell | null)[] }>();
        pages.forEach((page, idx) => {
          for (const r of page.items) {
            let entry = byResource.get(r.resource_id);
            if (!entry) {
              entry = { name: r.resource_name ?? r.resource_id.slice(0, 8), cells: buckets.map(() => null) };
              byResource.set(r.resource_id, entry);
            }
            entry.cells[idx] = { utilizationPct: r.utilization_pct, overAllocated: r.over_allocated };
          }
        });
        const rows: GridRow[] = Array.from(byResource.entries())
          .map(([resourceId, v]) => ({
            resourceId,
            resourceName: v.name,
            cells: v.cells.map(c => c ?? { utilizationPct: null, overAllocated: false }),
          }))
          .sort((a, b) => a.resourceName.localeCompare(b.resourceName));
        this.rows.set(rows);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  /** Fixed four-state bucketing — see this component's class doc comment on
   *  why this is status coloring, not a sequential ramp. */
  statusClass(cell: Cell): string {
    if (cell.utilizationPct == null) return 'rc-cell-empty';
    if (cell.overAllocated || cell.utilizationPct >= 100) return 'rc-cell-critical';
    if (cell.utilizationPct >= 85) return 'rc-cell-warning';
    if (cell.utilizationPct >= 50) return 'rc-cell-healthy';
    return 'rc-cell-under';
  }

  statusLabel(cell: Cell): string {
    if (cell.utilizationPct == null) return '—';
    if (cell.overAllocated || cell.utilizationPct >= 100) return 'Over';
    if (cell.utilizationPct >= 85) return 'High';
    if (cell.utilizationPct >= 50) return 'Healthy';
    return 'Under';
  }

  cellText(cell: Cell): string {
    return cell.utilizationPct == null ? '—' : `${Math.round(cell.utilizationPct)}%`;
  }
}
