import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AdminApiError } from './admin-http';
import { ReleaseReportService } from './release-report.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('ReleaseReportService', () => {
  const API = 'http://localhost:7865';
  const BASE = `${API}/api/v1/admin/metadata`;
  let service: ReleaseReportService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(ReleaseReportService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('lists reports one-based with the filters it was given', async () => {
    service.listReports({ status: 'ready', source: 'boot' }, 2, 10).subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${BASE}/release-reports`);
    expect(req.request.params.get('page')).toBe('2');
    expect(req.request.params.get('page_size')).toBe('10');
    expect(req.request.params.get('status')).toBe('ready');
    expect(req.request.params.get('source')).toBe('boot');
    req.flush({ items: [], total: 0, page: 2, page_size: 10 });
    await tick();
  });

  it('lists items with kind, status and entity filters', async () => {
    service.listItems('r1', { kind: 'conflict', status: 'open', entity: 'contact' }).subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${BASE}/release-reports/r1/items`);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('kind')).toBe('conflict');
    expect(req.request.params.get('status')).toBe('open');
    expect(req.request.params.get('entity')).toBe('contact');
    req.flush({ items: [], total: 0, page: 1, page_size: 25 });
    await tick();
  });

  it('sends If-Match with the item row_version on accept and dismiss', async () => {
    service.accept({ id: 'i1', row_version: 3 }).subscribe();
    await tick();
    const accept = http.expectOne(`${BASE}/release-report-items/i1/accept`);
    expect(accept.request.method).toBe('POST');
    expect(accept.request.headers.get('If-Match')).toBe('"3"');
    accept.flush({ id: 'i1', row_version: 4, status: 'accepted' });
    await tick();

    service.dismiss({ id: 'i2', row_version: 0 }).subscribe();
    await tick();
    const dismiss = http.expectOne(`${BASE}/release-report-items/i2/dismiss`);
    expect(dismiss.request.headers.get('If-Match')).toBe('"0"');
    dismiss.flush({ id: 'i2', row_version: 1, status: 'dismissed' });
    await tick();
  });

  it('sends the record row_version in the use-mine body', async () => {
    let status = '';
    service.useMine({ id: 'i1', row_version: 5 }, 12).subscribe(item => (status = item.status));
    await tick();
    const req = http.expectOne(`${BASE}/release-report-items/i1/use-mine`);
    expect(req.request.headers.get('If-Match')).toBe('"5"');
    expect(req.request.body).toEqual({ record_row_version: 12 });
    req.flush({ id: 'i1', row_version: 6, status: 'used_mine' });
    await tick();
    expect(status).toBe('used_mine');
  });

  it('sends an empty use-mine body for a rule conflict', async () => {
    service.useMine({ id: 'i1', row_version: 1 }).subscribe();
    await tick();
    const req = http.expectOne(`${BASE}/release-report-items/i1/use-mine`);
    expect(req.request.body).toEqual({});
    req.flush({ id: 'i1', row_version: 2, status: 'used_mine' });
    await tick();
  });

  it('turns a stale item into a version_conflict error', async () => {
    let error = null as AdminApiError | null;
    service.accept({ id: 'i1', row_version: 1 }).subscribe({ error: e => (error = e) });
    await tick();
    http.expectOne(`${BASE}/release-report-items/i1/accept`)
      .flush({ error: 'version_conflict', message: 'version conflict' }, { status: 409, statusText: 'Conflict' });
      await tick();
    expect(error!.kind).toBe('version_conflict');
    expect(error!.status).toBe(409);
  });

  it('posts restore without If-Match', async () => {
    service.restore('i9').subscribe();
    await tick();
    const req = http.expectOne(`${BASE}/release-report-items/i9/restore`);
    expect(req.request.headers.has('If-Match')).toBe(false);
    req.flush({ restore: { restored: 1, skipped_filled: 0, skipped_not_convertible: 0, missing_records: 0, remaining: 0 }, remaining: 0, item: {} });
    await tick();
  });

  it('reads the record row_version through the generic record route', async () => {
    let rv = -1;
    service.recordRowVersion('contact', 'rec1').subscribe(v => (rv = v));
    await tick();
    http.expectOne(`${API}/api/v1/contact/rec1`).flush({ id: 'rec1', entity_id: 'e', data: {}, row_version: 7 });
    await tick();
    expect(rv).toBe(7);
  });
});
