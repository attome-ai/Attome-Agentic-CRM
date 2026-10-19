import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import type { Page } from '@attome/base';

/** M12-T4: one batch job the caller started (`GET /api/v1/jobs`). */
export interface MyJob {
  id: string;
  name: string;
  status: 'running' | 'finished' | 'cancelled' | string;
  done: number;
  total: number | null;
  cancel_requested: boolean;
  created_at: string;
  finished_at: string | null;
}

/** How often a running job's progress is read again, in milliseconds. */
export const MY_JOBS_REFRESH_MS = 5000;

/**
 * M12-T4 — "My background work": the long jobs this person started (imports,
 * bulk edits, exports, merges), newest first, with their progress, and a
 * Cancel for one still running. Cancelling stops it after its current chunk;
 * what it already did stays done. While any job runs the list refreshes
 * every few seconds.
 */
@Component({
  selector: 'xrm-my-jobs',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styles: `
    :host { display: block; padding: 16px; }
    h2 { margin-block: 0 12px; font-size: 18px; }
    .jobs { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
    .job { display: flex; align-items: center; gap: 12px; padding-block: 10px; padding-inline: 12px;
           border: 1px solid var(--color-border, #e5e7eb); border-radius: 8px; }
    .job-main { flex: 1; min-inline-size: 0; }
    .job-name { font-weight: 600; }
    .job-meta { font-size: 12px; opacity: 0.75; }
    progress { inline-size: 100%; block-size: 6px; }
    .state { font-size: 12px; padding-inline: 8px; border-radius: 4px; background: var(--color-bg-alt, #f1f5f9); }
  `,
  template: `
    <h2>{{ 'myJobs.title' | translate }}</h2>
    @if (error(); as e) {
      <p role="alert">{{ e }}</p>
    }
    @if (loading()) {
      <p>{{ 'myJobs.loading' | translate }}</p>
    } @else if (!jobs().length) {
      <p data-my-jobs-empty>{{ 'myJobs.empty' | translate }}</p>
    } @else {
      <ul class="jobs">
        @for (job of jobs(); track job.id) {
          <li class="job" [attr.data-my-job]="job.id">
            <div class="job-main">
              <div class="job-name">{{ job.name }}</div>
              @if (job.total) {
                <progress [value]="job.done" [max]="job.total"></progress>
              }
              <div class="job-meta">
                {{ (job.total ? 'myJobs.progress' : 'myJobs.done') | translate: { done: job.done, total: job.total ?? 0 } }}
                · {{ time(job.created_at) }}
              </div>
            </div>
            <span class="state">{{ ('myJobs.status.' + statusKey(job)) | translate }}</span>
            @if (job.status === 'running' && !job.cancel_requested) {
              <button type="button" class="btn btn-secondary" [attr.data-my-job-cancel]="job.id"
                      [disabled]="cancelling() === job.id" (click)="cancel(job)">
                {{ 'myJobs.cancel' | translate }}
              </button>
            }
          </li>
        }
      </ul>
    }
  `,
})
export class MyJobsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly jobs = signal<MyJob[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly cancelling = signal<string | null>(null);
  readonly anyRunning = computed(() => this.jobs().some(j => j.status === 'running'));

  private timer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit(): void {
    this.destroyRef.onDestroy(() => this.stopTimer());
    this.load();
  }

  load(): void {
    this.api.get<Page<MyJob>>('/api/v1/jobs', { page_size: '50' }).subscribe({
      next: page => {
        this.jobs.set(page.items);
        this.loading.set(false);
        this.schedule();
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  cancel(job: MyJob): void {
    this.cancelling.set(job.id);
    this.api.post<MyJob>(`/api/v1/jobs/${job.id}/cancel`, {}).subscribe({
      next: updated => {
        this.cancelling.set(null);
        this.jobs.update(list => list.map(j => (j.id === updated.id ? { ...j, ...updated } : j)));
      },
      error: (e: ApiError) => {
        this.cancelling.set(null);
        this.error.set(this.lang.errorText(e));
        this.load();
      },
    });
  }

  statusKey(job: MyJob): string {
    if (job.status === 'running' && job.cancel_requested) return 'stopping';
    return ['running', 'finished', 'cancelled'].includes(job.status) ? job.status : 'running';
  }

  time(at: string): string {
    const date = new Date(at);
    return Number.isNaN(date.getTime())
      ? at
      : new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }

  private schedule(): void {
    this.stopTimer();
    if (!this.anyRunning()) return;
    this.timer = setTimeout(() => this.load(), MY_JOBS_REFRESH_MS);
  }

  private stopTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
