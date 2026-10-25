import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `attome_api::jobs_admin::JobLane`. */
export interface JobLane {
  queue: 'fast' | 'batch';
  pending: number;
  running: number;
  retrying: number;
  dead_letters: number;
  oldest_pending_age_secs?: number | null;
  done_last_hour: number;
  failed_last_hour: number;
  failure_rate_last_hour?: number | null;
}

/** A wait in seconds as the largest whole unit: `45 s`, `12 min`, `3 h`. */
export function ageLabel(secs: number | null | undefined): string {
  if (secs === null || secs === undefined) return '—';
  const s = Math.max(0, Math.floor(secs));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  return `${Math.floor(s / 3600)} h`;
}

/** A 0–1 rate as a whole percent, or a dash when nothing finished. */
export function rateLabel(rate: number | null | undefined): string {
  return rate === null || rate === undefined ? '—' : `${Math.round(rate * 100)}%`;
}

/**
 * The job queues at a glance (roadmap Z7-T6): per queue, what waits, what
 * runs, what retries, what is dead-lettered, how long the oldest job has
 * waited and how much failed in the last hour. Sits above the dead letters
 * on the failed-jobs screen. Logical CSS only.
 */
@Component({
  selector: 'xrm-job-lanes',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="jl">
      <div class="jl-head">
        <h3>{{ 'jobLanes.title' | translate }}</h3>
        <button type="button" (click)="load()" [disabled]="busy()">{{ 'jobLanes.refresh' | translate }}</button>
      </div>
      @if (error(); as message) { <p class="jl-error" role="alert">{{ message }}</p> }
      <table class="jl-table">
        <thead>
          <tr>
            <th scope="col">{{ 'jobLanes.queue' | translate }}</th>
            <th scope="col">{{ 'jobLanes.pending' | translate }}</th>
            <th scope="col">{{ 'jobLanes.running' | translate }}</th>
            <th scope="col">{{ 'jobLanes.retrying' | translate }}</th>
            <th scope="col">{{ 'jobLanes.deadLetters' | translate }}</th>
            <th scope="col">{{ 'jobLanes.oldest' | translate }}</th>
            <th scope="col">{{ 'jobLanes.failureRate' | translate }}</th>
          </tr>
        </thead>
        <tbody>
          @for (lane of lanes(); track lane.queue) {
            <tr [attr.data-lane]="lane.queue">
              <th scope="row">{{ ('jobLanes.' + lane.queue) | translate }}</th>
              <td>{{ lane.pending }}</td>
              <td>{{ lane.running }}</td>
              <td>{{ lane.retrying }}</td>
              <td [class.jl-warn]="lane.dead_letters > 0">{{ lane.dead_letters }}</td>
              <td>{{ age(lane.oldest_pending_age_secs) }}</td>
              <td [class.jl-warn]="(lane.failure_rate_last_hour ?? 0) > 0.1">
                {{ rate(lane.failure_rate_last_hour) }}
                <span class="jl-muted">({{ lane.failed_last_hour }}/{{ lane.failed_last_hour + lane.done_last_hour }})</span>
              </td>
            </tr>
          }
        </tbody>
      </table>
    </section>
  `,
  styles: [`
    .jl { margin-block-end: 1.5rem; }
    .jl-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    .jl-table { inline-size: 100%; border-collapse: collapse; }
    .jl-table th, .jl-table td { padding-block: 0.4rem; padding-inline: 0.6rem; text-align: start; border-block-end: 1px solid var(--border, #e5e7eb); }
    .jl-warn { color: var(--danger, #b91c1c); font-weight: 600; }
    .jl-muted { color: var(--text-muted, #6b7280); font-weight: 400; }
    .jl-error { color: var(--danger, #b91c1c); }
  `],
})
export class JobLanesComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly lanes = signal<JobLane[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  readonly age = ageLabel;
  readonly rate = rateLabel;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.get<{ items: JobLane[] }>('/api/v1/admin/jobs/lanes').subscribe({
      next: page => {
        this.lanes.set(page.items);
        this.busy.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.busy.set(false);
      },
    });
  }
}
