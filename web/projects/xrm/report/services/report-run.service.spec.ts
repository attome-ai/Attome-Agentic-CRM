import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReportRunService, ReportRunStatus, isTerminalRun } from './report-run.service';

const API = 'http://localhost:7865';

function status(state: string, extra: Partial<ReportRunStatus> = {}): ReportRunStatus {
  return {
    id: 'run-1', report_ref: 'rep-1', format: 'csv', status: state,
    requested_at: '2026-09-23T10:00:00Z', ...extra,
  };
}

describe('ReportRunService', () => {
  let service: ReportRunService;
  let http: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(ReportRunService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
    vi.useRealTimers();
  });

  it('treats completed and failed as terminal, pending and running as not', () => {
    expect(isTerminalRun(status('completed'))).toBe(true);
    expect(isTerminalRun(status('failed'))).toBe(true);
    expect(isTerminalRun(status('pending'))).toBe(false);
    expect(isTerminalRun(status('running'))).toBe(false);
  });

  it('enqueues a run with an empty body (the report record supplies the format)', () => {
    service.run('rep-1').subscribe();
    const req = http.expectOne(`${API}/api/v1/reports/rep-1/run`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});
    req.flush({ id: 'run-1', status: 'pending' });
  });

  it('runs, then polls the run until it completes, emitting the final status', () => {
    const results: ReportRunStatus[] = [];
    service.runAndWait('rep-1', { intervalMs: 1000, maxPolls: 10 }).subscribe(r => results.push(r));

    http.expectOne(`${API}/api/v1/reports/rep-1/run`).flush({ id: 'run-1', status: 'pending' });
    vi.advanceTimersByTime(0);
    http.expectOne(`${API}/api/v1/reports/runs/run-1`).flush(status('running'));
    vi.advanceTimersByTime(1000);
    http.expectOne(`${API}/api/v1/reports/runs/run-1`).flush(
      status('completed', { row_count: 3, download_url: 'http://storage/r.csv', expires_in_secs: 900 }),
    );
    vi.advanceTimersByTime(5000);

    expect(results).toEqual([
      status('completed', { row_count: 3, download_url: 'http://storage/r.csv', expires_in_secs: 900 }),
    ]);
  });

  it('stops after the poll budget and emits the still-running status', () => {
    const results: ReportRunStatus[] = [];
    service.runAndWait('rep-1', { intervalMs: 1000, maxPolls: 2 }).subscribe(r => results.push(r));

    http.expectOne(`${API}/api/v1/reports/rep-1/run`).flush({ id: 'run-1', status: 'pending' });
    vi.advanceTimersByTime(0);
    http.expectOne(`${API}/api/v1/reports/runs/run-1`).flush(status('running'));
    vi.advanceTimersByTime(1000);
    http.expectOne(`${API}/api/v1/reports/runs/run-1`).flush(status('running'));
    vi.advanceTimersByTime(5000);
    http.expectNone(`${API}/api/v1/reports/runs/run-1`);

    expect(results.map(r => r.status)).toEqual(['running']);
  });
});
