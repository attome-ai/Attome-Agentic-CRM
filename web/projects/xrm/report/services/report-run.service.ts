import { inject, Injectable } from '@angular/core';
import { Observable, switchMap } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';
import { BulkJobRunner } from '@attome/xrm/core/entity';
import type { PollOptions } from '@attome/xrm/core/entity';

// Wire shapes from the generated contract — `crates/engine/attome-report/src/run.rs`.
export type RunReportBody      = ApiComponents['schemas']['RunReportBody'];
export type RunEnqueueResponse = ApiComponents['schemas']['RunEnqueueResponse'];
export type ReportRunStatus    = ApiComponents['schemas']['RunStatusResponse'];

/** `report_run.status` values the run job never leaves. */
export const TERMINAL_RUN_STATUSES: ReadonlySet<string> = new Set(['completed', 'failed']);

export function isTerminalRun(run: ReportRunStatus): boolean {
  return TERMINAL_RUN_STATUSES.has(run.status);
}

/** Reports render in memory up to 100k rows (`run.rs::MAX_REPORT_ROWS`), so
 * they get a longer budget than a bulk edit: 2 s × 90 = 3 minutes. Past it
 * the run keeps going server-side and the caller says so. */
export const REPORT_POLL: Required<PollOptions> = { intervalMs: 2000, maxPolls: 90 };

/**
 * U16 (M25) — runs a saved report and follows the run to a terminal state.
 * `POST /api/v1/reports/{id}/run` enqueues (202, `pending`) using the report
 * record's own `format` (csv/xlsx — the body carries only optional filter
 * overrides); `GET /api/v1/reports/runs/{run_id}` reports progress and, once
 * `completed`, a short-lived presigned `download_url`. Both need
 * `attome_report.read`; a run is visible only to whoever requested it (or an
 * admin), which the server enforces.
 */
@Injectable({ providedIn: 'root' })
export class ReportRunService {
  private readonly api    = inject(ApiService);
  private readonly runner = inject(BulkJobRunner);

  run(reportId: string, body: RunReportBody = {}): Observable<RunEnqueueResponse> {
    return this.api.post<RunEnqueueResponse>(`/api/v1/reports/${encodeURIComponent(reportId)}/run`, body);
  }

  status(runId: string): Observable<ReportRunStatus> {
    return this.api.get<ReportRunStatus>(`/api/v1/reports/runs/${encodeURIComponent(runId)}`);
  }

  /** Enqueues a run, then polls it (bounded, `REPORT_POLL`). Emits the last
   * status seen — check `isTerminalRun` to tell "done" from "still running
   * when the poll budget ran out". */
  runAndWait(reportId: string, options: PollOptions = REPORT_POLL): Observable<ReportRunStatus> {
    return this.run(reportId).pipe(
      switchMap(enqueued => this.runner.poll(() => this.status(enqueued.id), isTerminalRun, options)),
    );
  }
}
