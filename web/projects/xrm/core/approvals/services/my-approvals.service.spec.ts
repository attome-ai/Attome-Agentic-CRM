import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import type { ApiError } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MyApprovalsService } from './my-approvals.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('MyApprovalsService', () => {
  const API = 'http://localhost:7865';
  const REQ = '01900000-0000-7000-8000-0000000000a1';
  let service: MyApprovalsService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: ATTOME_CONFIG, useValue: { apiUrl: API } }],
    });
    service = TestBed.inject(MyApprovalsService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('lists the caller\'s approvals from the My Work provider, with the cursor when given', async () => {
    service.list().subscribe();
    await tick();
    const first = http.expectOne(r => r.url === `${API}/api/v1/my-work/approvals`);
    expect(first.request.method).toBe('GET');
    expect(first.request.params.get('limit')).toBe('50');
    expect(first.request.params.has('cursor')).toBe(false);
    first.flush({ items: [], next_cursor: 'c1' });

    service.list('c1').subscribe();
    await tick();
    const second = http.expectOne(r => r.url === `${API}/api/v1/my-work/approvals`);
    expect(second.request.params.get('cursor')).toBe('c1');
    second.flush({ items: [] });
  });

  it('decides through the action\'s own non-admin route with the item\'s row_version', async () => {
    service.decide({ key: 'approve', method: 'POST', route: `/api/v1/approvals/${REQ}/decide` }, 'approve', 3).subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ decision: 'approve', row_version: 3 });
    req.flush({ id: REQ, status: 'approved' });
  });

  it('sends a trimmed comment, and omits a blank one', async () => {
    const action = { key: 'reject', method: 'POST', route: `/api/v1/approvals/${REQ}/decide` };
    service.decide(action, 'reject', 1, '  not enough detail  ').subscribe();
    await tick();
    const withComment = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(withComment.request.body).toEqual({ decision: 'reject', row_version: 1, comment: 'not enough detail' });
    withComment.flush({ id: REQ, status: 'rejected' });

    service.decide(action, 'reject', 1, '   ').subscribe();
    await tick();
    const blank = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(blank.request.body).toEqual({ decision: 'reject', row_version: 1 });
    blank.flush({ id: REQ, status: 'rejected' });
  });

  it('refuses an action that is not a POST to an /api/v1/ route, without calling anything', () => {
    let error: ApiError | undefined;
    service.decide({ key: 'approve', method: 'POST', route: 'https://elsewhere.example/x' }, 'approve', 0)
      .subscribe({ error: e => (error = e) });
    expect(error?.kind).toBe('validation');
    service.decide({ key: 'approve', method: 'DELETE', route: `/api/v1/approvals/${REQ}/decide` }, 'approve', 0)
      .subscribe({ error: e => (error = e) });
    expect(error?.kind).toBe('validation');
  });

  it('bulkDecide posts all items with one decision and the trimmed comment', async () => {
    service.bulkDecide(
      [{ id: REQ, row_version: 2 }, { id: 'other', row_version: 0 }], 'approve', '  ok  ',
    ).subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/approvals/bulk-decide`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({
      items: [{ id: REQ, row_version: 2 }, { id: 'other', row_version: 0 }],
      decision: 'approve',
      comment: 'ok',
    });
    req.flush({ results: [] });
  });

  it('recalls with If-Match, resubmits the payload and reads recommendations', async () => {
    service.recall(REQ, 4).subscribe();
    await tick();
    const recall = http.expectOne(`${API}/api/v1/approvals/${REQ}/recall`);
    expect(recall.request.headers.get('If-Match')).toBe('"4"');
    recall.flush({});

    service.resubmit(REQ, { amount: 10 }).subscribe();
    await tick();
    const resubmit = http.expectOne(`${API}/api/v1/approvals/${REQ}/resubmit`);
    expect(resubmit.request.body).toEqual({ payload: { amount: 10 } });
    resubmit.flush({ id: 'new' });

    service.recommendations(REQ).subscribe();
    await tick();
    const recs = http.expectOne(`${API}/api/v1/approvals/${REQ}/recommendations`);
    expect(recs.request.method).toBe('GET');
    recs.flush({ items: [], total: 0, page: 1, page_size: 100 });
  });
});
