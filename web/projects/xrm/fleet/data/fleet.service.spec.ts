import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Observable } from 'rxjs';
import { ATTOME_CONFIG } from '@attome/base';
import { StepUpService } from '@attome/base/step-up';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FLEET_STEP_UP_OPERATION, FleetService } from './fleet.service';

describe('FleetService', () => {
  const API = 'http://localhost:7865';
  const BASE = `${API}/api/v1/fleet`;
  let service: FleetService;
  let http: HttpTestingController;
  let run: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    run = vi.fn().mockImplementation((_op: string, request: () => Observable<unknown>) => request());
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: StepUpService, useValue: { run } },
      ],
    });
    service = TestBed.inject(FleetService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('uses the step-up operation the server asks for (attome_fleet::routes::STEP_UP_OPERATION)', () => {
    expect(FLEET_STEP_UP_OPERATION).toBe('api_key_create');
  });

  it('lists deployments one-based with the inactive filter', () => {
    service.listDeployments(true, 2, 25).subscribe();
    const req = http.expectOne(r => r.url === `${BASE}/deployments`);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('2');
    expect(req.request.params.get('page_size')).toBe('25');
    expect(req.request.params.get('include_inactive')).toBe('true');
    req.flush({ items: [], total: 0, page: 2, page_size: 25 });
  });

  it('registers through the step-up wrapper', () => {
    service.registerDeployment({ project_code: 'BMD', label: 'BMD prod', base_url: 'https://bmd.example' }).subscribe();
    expect(run).toHaveBeenCalledWith('api_key_create', expect.any(Function));
    const req = http.expectOne(`${BASE}/deployments`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body.project_code).toBe('BMD');
    req.flush({});
  });

  it('sets a credential with PUT, the row_version and verify, through the step-up wrapper', () => {
    service.setCredential('d1', 4, { s2s_client_id: 'c', s2s_key_id: 'k', secret: 's' }, true).subscribe();
    expect(run).toHaveBeenCalledWith('api_key_create', expect.any(Function));
    const req = http.expectOne(`${BASE}/deployments/d1/credential`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ row_version: 4, s2s_client_id: 'c', s2s_key_id: 'k', secret: 's', verify: true });
    req.flush({});
  });

  it('edits with PATCH and the row_version in the body', () => {
    service.updateDeployment('d1', { row_version: 2, label: 'New' }).subscribe();
    const req = http.expectOne(`${BASE}/deployments/d1`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ row_version: 2, label: 'New' });
    expect(req.request.headers.has('If-Match')).toBe(false);
    req.flush({});
  });

  it('syncs one and all', () => {
    service.syncDeployment('d1').subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${BASE}/deployments/d1/sync`).flush({});
    service.syncAll().subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${BASE}/sync`).flush({ queued: true });
  });

  it('sends Use mine with the item and the record row_version', () => {
    service.decideItem('d1', 'i1', 'use-mine', 3, 9).subscribe();
    const req = http.expectOne(`${BASE}/deployments/d1/release-report-items/i1/use-mine`);
    expect(req.request.body).toEqual({ row_version: 3, record_row_version: 9 });
    req.flush({});
  });

  it('sends Accept and Dismiss with the item row_version only', () => {
    service.decideItem('d1', 'i1', 'accept', 3).subscribe();
    const accept = http.expectOne(`${BASE}/deployments/d1/release-report-items/i1/accept`);
    expect(accept.request.body).toEqual({ row_version: 3 });
    accept.flush({});
    service.decideItem('d1', 'i2', 'dismiss', 5).subscribe();
    const dismiss = http.expectOne(`${BASE}/deployments/d1/release-report-items/i2/dismiss`);
    expect(dismiss.request.body).toEqual({ row_version: 5 });
    dismiss.flush({});
  });

  it('reads a report\'s items with its filters', () => {
    service.listItems('d1', 'r1', { status: 'open', kind: 'conflict' }, 1, 50).subscribe();
    const req = http.expectOne(r => r.url === `${BASE}/deployments/d1/release-reports/r1/items`);
    expect(req.request.params.get('status')).toBe('open');
    expect(req.request.params.get('kind')).toBe('conflict');
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
  });

  it('guards start, apply and resume with the step-up wrapper, but not halt, skip or cancel', () => {
    service.startRollout({ title: 't', changeset_ids: ['c1'], deployment_ids: ['d1'] }).subscribe();
    http.expectOne(`${BASE}/rollouts`).flush({});
    service.applyTarget('r1', 't1', { row_version: 1, backup_ref: 'b' }).subscribe();
    http.expectOne(`${BASE}/rollouts/r1/targets/t1/apply`).flush({});
    service.resumeRollout('r1', 2).subscribe();
    http.expectOne(`${BASE}/rollouts/r1/resume`).flush({});
    expect(run).toHaveBeenCalledTimes(3);

    service.haltRollout('r1', 2).subscribe();
    http.expectOne(`${BASE}/rollouts/r1/halt`).flush({});
    service.skipTarget('r1', 't1', 1).subscribe();
    http.expectOne(`${BASE}/rollouts/r1/targets/t1/skip`).flush({});
    service.cancelRollout('r1', 3).subscribe();
    const cancel = http.expectOne(`${BASE}/rollouts/r1/cancel`);
    expect(cancel.request.body).toEqual({ row_version: 3 });
    cancel.flush({});
    expect(run).toHaveBeenCalledTimes(3);
  });

  it('walks every changeset page one-based', () => {
    let files: unknown[] = [];
    service.allChangesets().subscribe(f => { files = f; });
    const first = http.expectOne(r => r.url === `${BASE}/changesets`);
    expect(first.request.params.get('page')).toBe('1');
    first.flush({ items: [{ id: 'c1' }], total: 1, page: 1, page_size: 200 });
    expect(files.length).toBe(1);
  });
});
