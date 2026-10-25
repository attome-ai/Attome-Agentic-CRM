import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, ATTOME_CONFIG, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';

/** `attome_ops::freshness::Freshness`. */
export interface DrillFreshness {
  kind: string;
  status: 'fresh' | 'stale' | 'failed' | 'never';
  last_run_at: string | null;
  last_ok_run_at: string | null;
  period_days: number;
  failing_checks: string[];
}

/** `attome_ops::drills::DrillRun`. */
export interface DrillRun {
  id: string;
  kind: string;
  started_at: string;
  finished_at: string;
  overall_ok: boolean;
  restore_ok: boolean;
  provenance_ok: boolean;
  rpo_seconds: number | null;
  rto_seconds: number | null;
  data_size_bytes: number | null;
  platform_version: string;
  key_id: string;
  sha256: string;
  uploaded_by: string | null;
  created_at: string;
}

/** `attome_ops::drill_schedules::DrillSchedule`. */
export interface DrillSchedule {
  id: string;
  kind: string;
  cadence: 'weekly' | 'monthly' | 'quarterly';
  enabled: boolean;
  next_due_at: string | null;
  last_run_id: string | null;
  row_version: number;
  updated_by: string | null;
  updated_at: string | null;
}

interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

const PAGE_SIZE = 20;
export const CHART_WIDTH = 320;
export const CHART_HEIGHT = 80;

/**
 * An SVG polyline's points for one measure over the runs, oldest first,
 * scaled to the chart; runs without the measure are skipped.
 */
export function trendPoints(
  runs: readonly DrillRun[],
  key: 'rpo_seconds' | 'rto_seconds',
  max: number,
): string {
  const values = [...runs]
    .sort((a, b) => a.finished_at.localeCompare(b.finished_at))
    .map(r => r[key])
    .filter((v): v is number => typeof v === 'number');
  if (values.length === 0 || max <= 0) return '';
  const step = values.length > 1 ? CHART_WIDTH / (values.length - 1) : 0;
  return values
    .map((v, i) => `${Math.round(i * step)},${Math.round(CHART_HEIGHT - (v / max) * CHART_HEIGHT)}`)
    .join(' ');
}

/**
 * Recovery drills (roadmap AB4-T11): each kind's freshness, the runs with
 * their recovery point and time over time, the drill schedules (with a
 * one-click switch for the proposed monthly restore drill) and, for an
 * auditor, the evidence pack for a period.
 */
@Component({
  selector: 'attome-ops-drill-history',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, TranslatePipe, LocalDatePipe],
  template: `
    <section class="dh-page">
      <h2>{{ 'ops.drills.title' | translate }}</h2>

      @if (error(); as message) {
        <p class="dh-error" role="alert">{{ message }}</p>
      }

      @if (restoreOff(); as restore) {
        <div class="dh-banner" role="status" data-testid="dh-restore-off">
          <span>{{ 'ops.drills.restoreOff' | translate }}</span>
          @if (canManage()) {
            <button type="button" data-testid="dh-restore-on" [disabled]="busy()" (click)="toggle(restore)">
              {{ 'ops.drills.turnOn' | translate }}
            </button>
          }
        </div>
      }

      <ul class="dh-badges" [attr.aria-label]="'ops.drills.freshness' | translate">
        @for (f of freshness(); track f.kind) {
          <li class="dh-badge" [attr.data-status]="f.status" data-testid="dh-badge">
            <strong>{{ 'ops.drills.kind.' + f.kind | translate }}</strong>
            <span>{{ 'ops.drills.status.' + f.status | translate }}</span>
            @if (f.failing_checks.length > 0) {
              <span class="dh-checks" dir="ltr">{{ f.failing_checks.join(', ') }}</span>
            }
          </li>
        }
      </ul>

      @if (runs().length > 0) {
        <figure class="dh-chart">
          <svg [attr.viewBox]="'0 0 ' + chartWidth + ' ' + chartHeight" role="img"
               [attr.aria-label]="'ops.drills.trend' | translate">
            <polyline class="dh-rpo" fill="none" [attr.points]="rpoPoints()" />
            <polyline class="dh-rto" fill="none" [attr.points]="rtoPoints()" />
          </svg>
          <figcaption>
            <span class="dh-key dh-rpo-key">{{ 'ops.drills.rpo' | translate }}</span>
            <span class="dh-key dh-rto-key">{{ 'ops.drills.rto' | translate }}</span>
          </figcaption>
        </figure>

        <div class="dh-scroll">
          <table class="dh-table" data-testid="dh-runs">
            <thead>
              <tr>
                <th scope="col">{{ 'ops.drills.when' | translate }}</th>
                <th scope="col">{{ 'ops.drills.kindLabel' | translate }}</th>
                <th scope="col">{{ 'ops.drills.result' | translate }}</th>
                <th scope="col">{{ 'ops.drills.rpo' | translate }}</th>
                <th scope="col">{{ 'ops.drills.rto' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (r of runs(); track r.id) {
                <tr>
                  <td><a [routerLink]="[r.id]">{{ r.finished_at | localDate }}</a></td>
                  <td>{{ 'ops.drills.kind.' + r.kind | translate }}</td>
                  <td>{{ (r.overall_ok ? 'ops.drills.passed' : 'ops.drills.failed') | translate }}</td>
                  <td dir="ltr">{{ r.rpo_seconds ?? '—' }}</td>
                  <td dir="ltr">{{ r.rto_seconds ?? '—' }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="dh-pages">
          <button type="button" [disabled]="page() <= 1" (click)="loadRuns(page() - 1)">{{ 'ops.drills.prev' | translate }}</button>
          <button type="button" [disabled]="page() * pageSize >= total()" (click)="loadRuns(page() + 1)">{{ 'ops.drills.next' | translate }}</button>
        </div>
      } @else {
        <p>{{ 'ops.drills.noRuns' | translate }}</p>
      }

      <h3>{{ 'ops.drills.schedules' | translate }}</h3>
      <ul class="dh-schedules">
        @for (s of schedules(); track s.id) {
          <li data-testid="dh-schedule">
            <label>
              <input type="checkbox" [checked]="s.enabled" [disabled]="!canManage() || busy()"
                     data-testid="dh-schedule-switch" (change)="toggle(s)" />
              {{ 'ops.drills.kind.' + s.kind | translate }} · {{ 'ops.drills.cadence.' + s.cadence | translate }}
            </label>
            @if (s.enabled && s.next_due_at) {
              <span> · {{ 'ops.drills.nextDue' | translate }} {{ s.next_due_at | localDate }}</span>
            }
          </li>
        }
      </ul>

      @if (canAudit()) {
        <h3>{{ 'ops.drills.auditorPack' | translate }}</h3>
        <form class="dh-pack" data-testid="dh-pack" (submit)="$event.preventDefault()">
          <label>{{ 'ops.drills.from' | translate }} <input type="date" [(ngModel)]="from" name="from" /></label>
          <label>{{ 'ops.drills.to' | translate }} <input type="date" [(ngModel)]="to" name="to" /></label>
          @if (from && to) {
            <a class="dh-download" [href]="packUrl()" download data-testid="dh-pack-download">
              {{ 'ops.drills.download' | translate }}
            </a>
          }
        </form>
      }
    </section>
  `,
  styles: [`
    .dh-page { padding-inline: 1rem; max-inline-size: 64rem; }
    .dh-banner { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; padding: 0.75rem; margin-block-end: 1rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .dh-badges { display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0; list-style: none; }
    .dh-badge { display: flex; flex-direction: column; gap: 0.125rem; padding-block: 0.375rem; padding-inline: 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; min-inline-size: 8rem; }
    .dh-badge[data-status='fresh'] { border-inline-start: 4px solid var(--color-success); }
    .dh-badge[data-status='stale'], .dh-badge[data-status='never'] { border-inline-start: 4px solid var(--color-warning); }
    .dh-badge[data-status='failed'] { border-inline-start: 4px solid var(--color-danger); }
    .dh-checks { font-size: 0.75rem; }
    .dh-chart { margin-block: 1rem; margin-inline: 0; }
    .dh-chart svg { inline-size: 100%; max-inline-size: 32rem; block-size: auto; }
    .dh-rpo { stroke: var(--color-primary); stroke-width: 2; }
    .dh-rto { stroke: var(--color-warning); stroke-width: 2; }
    .dh-key { margin-inline-end: 1rem; font-size: 0.8125rem; }
    .dh-scroll { overflow-x: auto; }
    .dh-table { border-collapse: collapse; inline-size: 100%; }
    .dh-table th, .dh-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start; border-block-end: 1px solid var(--color-border); }
    .dh-pages { display: flex; gap: 0.5rem; margin-block: 0.5rem; }
    .dh-schedules { padding-inline-start: 0; list-style: none; }
    .dh-pack { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; }
    .dh-pack label { display: flex; flex-direction: column; gap: 0.25rem; }
    .dh-error { color: var(--color-danger); }
  `],
})
export class DrillHistoryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly access = inject(AccessService);
  private readonly lang = inject(LangService);
  private readonly config = inject(ATTOME_CONFIG);

  readonly freshness = signal<DrillFreshness[]>([]);
  readonly runs = signal<DrillRun[]>([]);
  readonly schedules = signal<DrillSchedule[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly canManage = signal(false);
  readonly canAudit = signal(false);
  readonly pageSize = PAGE_SIZE;
  readonly chartWidth = CHART_WIDTH;
  readonly chartHeight = CHART_HEIGHT;

  from = '';
  to = '';

  /** The seeded restore schedule while it is off. */
  readonly restoreOff = computed(() =>
    this.schedules().find(s => s.kind === 'restore' && !s.enabled) ?? null);

  private readonly chartMax = computed(() =>
    Math.max(0, ...this.runs().flatMap(r => [r.rpo_seconds ?? 0, r.rto_seconds ?? 0])));
  readonly rpoPoints = computed(() => trendPoints(this.runs(), 'rpo_seconds', this.chartMax()));
  readonly rtoPoints = computed(() => trendPoints(this.runs(), 'rto_seconds', this.chartMax()));

  ngOnInit(): void {
    this.access.ready().subscribe(() => {
      this.canManage.set(this.access.hasPrivilege('ops.drill.manage'));
      this.canAudit.set(this.access.hasPrivilege('ops.auditor.read'));
    });
    this.api.get<Page<DrillFreshness>>('/api/v1/ops/drills/freshness').subscribe({
      next: p => this.freshness.set(p.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.loadSchedules();
    this.loadRuns(1);
  }

  loadRuns(page: number): void {
    this.api.get<Page<DrillRun>>('/api/v1/ops/drills', {
      page: String(page), page_size: String(PAGE_SIZE),
    }).subscribe({
      next: p => {
        this.runs.set(p.items ?? []);
        this.total.set(p.total ?? 0);
        this.page.set(page);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private loadSchedules(): void {
    this.api.get<Page<DrillSchedule>>('/api/v1/ops/drill-schedules').subscribe({
      next: p => this.schedules.set(p.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  /** Turns a schedule on or off; `If-Match` carries its row version. */
  toggle(schedule: DrillSchedule): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.api.patch<DrillSchedule>(
      `/api/v1/ops/drill-schedules/${schedule.id}`,
      { enabled: !schedule.enabled },
      schedule.row_version,
    ).subscribe({
      next: updated => {
        this.busy.set(false);
        this.schedules.update(list => list.map(s => (s.id === updated.id ? updated : s)));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
        this.loadSchedules();
      },
    });
  }

  /** The auditor pack's address for the chosen period. */
  packUrl(): string {
    const query = new URLSearchParams({ from: this.from, to: this.to }).toString();
    return `${this.config.apiUrl}/api/v1/ops/drills/auditor-pack?${query}`;
  }
}
